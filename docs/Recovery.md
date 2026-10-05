# Startup, backup and recovery runbook

This procedure implements the recovery contracts in Design.md. It does not
authorize inference during an unresolved incident or certify a restored backup
as current production state. Use one API worker and one operator/fault controller.
Never remove persistent volumes as a recovery step.

## Startup and normal stop

1. Provision protected secret files and the approved local model cache as in
   README.md. Retain the API-key pepper, fingerprint key/version and cursor key;
   database backups do not contain these files. Never pull a model at request time.
2. Start PostgreSQL and Redis with `docker compose up -d --wait postgres redis`.
   Confirm actual container health, PostgreSQL connectivity, and Redis AOF and
   no-eviction configuration. A health check is not governance readiness.
3. Run the operations-profile `bootstrap` and `migrate` commands explicitly.
   Bootstrap establishes the fixed login and restricted function-owner roles;
   migrations are not run by API startup. Use the release matching the schema.
4. Start Ollama and API using `docker compose up -d --wait ollama api`. Register
   and bind only an operator-approved pinned model with the existing operator
   commands. `/api/tags` proves availability only, never model authority.
5. Redis requires a full 60-second recovery epoch on restart or state loss.
   Unknown work reconstructed from PostgreSQL blocks admission until audited
   clearance. Liveness/healthy containers do not waive either gate; the current
   public readiness endpoint remains conservative.

For normal stop, stop accepting new requests, allow supervised in-flight work to
reach a durable terminal result where possible, then `docker compose stop api`
followed by `docker compose stop ollama redis postgres`. A forced stop is not
proof that an authorized provider operation completed. Preserve PostgreSQL,
Redis and model volumes. Never use `down --volumes`, reset counters, erase
unknown records, or reissue an admitted idempotency key to obtain a retry.

## Dependency and application recovery

- **PostgreSQL:** stop/start or restart the actual service, then wait for both
  crash/WAL recovery and Docker health. fsync and recovery duration depend on the
  host; verifier restoration allowances are bounds, not startup guarantees.
  Admission and terminal persistence failures remain unavailable/fail-closed.
  Do not bypass health, alter accounting, or reset the database to speed recovery.
- **Redis:** a real process restart/state loss must establish a new readiness
  epoch only after the full 60-second barrier. Outage/barrier requests cause no
  provider invocation. A successful PING alone cannot resume admission. Do not
  delete limiter keys, shorten the barrier, or change Redis eviction policy.
- **API/provider process:** stop the previous API before starting another worker.
  Maintenance marks prior dispatched work unknown, reconstructs quarantined
  capacity from durable records, and never dispatches that work again. Unknown
  requests remain charged even if their capacity was administratively cleared.
  A provider restart does not itself classify an unknown result as succeeded or
  failed.

### Operator unknown-capacity clearance

Independently verify that Ollama has no running work for the affected request;
stop/restart it if necessary. Stop any previous API worker that could still issue
an authorized invocation. Only then run the privileged attestation:

```powershell
docker compose --profile operations run --rm clearance `
  python -m arbiter.operations.clearance `
  --tenant '<tenant UUID>' --request '<unknown request UUID>' --provider-stopped
```

This appends content-free audit evidence, frees the tenant slot, and lets the next
maintenance pass release local quarantine exactly once. Repetition is idempotent.
Provider outcome remains unknown and committed credits/quota are unchanged.
The flag records an operator assertion; it does not inspect or cancel Ollama.

## PostgreSQL logical backup

The Windows helper uses the pinned PostgreSQL container's native `pg_dump`, with
a consistent snapshot and custom archive format. It includes all database schema
and data, owners, grants, policies, function bodies, triggers and the Alembic
marker. It reads the bootstrap secret inside the container, never in host CLI
arguments or logged environment values. It does not modify source rows.

```powershell
$backup = .\scripts\backup-restore.ps1 -Operation backup `
  -PostgresContainer arbiter-postgres-1 -Database arbiter `
  -ArchiveDirectory 'D:\AI & ML\ArbiterData\backups\release-checkpoint'
$backup.archive
$backup.sha256
```

The helper creates a new UUID-named archive, does not overwrite prior archives,
and requires a protected directory outside the repository. Directory readers
are restricted to the invoking Windows identity, SYSTEM and Administrators.
Treat the archive as sensitive: it contains API-key verifiers, tenant identities
and governance history, although assistant output and prompts are not persisted.
Do not inspect/copy it into logs or Git. The helper restricts local access; it
does not encrypt the archive or supply an independent/off-host backup. Arrange
an encrypted, access-controlled independent copy and protect the external secrets
separately before claiming disaster recovery. A checksum detects accidental
change, not authenticity. Accept archives only from a trusted operator source.

## Fresh-target restore

Never restore over the source or any existing database. Use the same supported
PostgreSQL major version and matching Arbiter release. For a fresh cluster, first
provision its bootstrap credential and run the matching bootstrap command to
create all fixed roles; pg_dump does not copy cluster roles or passwords. The
proof uses a fresh database in the existing disposable cluster, not a rebuilt
host or cluster.

```powershell
$target = 'arbiter_restore_' + [Guid]::NewGuid().ToString('N')
.\scripts\backup-restore.ps1 -Operation restore `
  -PostgresContainer arbiter-postgres-1 -Database arbiter `
  -ArchiveDirectory 'D:\AI & ML\ArbiterData\backups\release-checkpoint' `
  -Archive $backup.archive -RestoreDatabase $target
```

The helper creates fresh targets explicitly from `template0`, refuses an existing
target, revokes PUBLIC database access before restoring, and uses
`pg_restore --exit-on-error --single-transaction` preserving
owners and ACLs. A failed restore is an isolated unusable target, not permission
to start API; the helper never drops/cleans a source or target. Restricted
database-level CONNECT grants are recreated explicitly because cluster/database
provisioning is outside a logical database dump. Roles must already be trusted
and correctly bootstrapped.

Before promotion, validate the schema marker against the release, owners/grants,
FORCE RLS and tenant isolation; compare durable table counts/selected identities,
allocation totals and states against the snapshot. Verify revoked-key denial,
tombstone duplicate/conflict behavior, immutable dispatched model binding and
audited unknown-capacity clearance. Reuse the same pepper/fingerprint version
required by retained key/idempotency records. Do not downgrade or automatically
upgrade a restored archive before its compatibility has been established.

A backup is a point-in-time snapshot. It cannot prove that requests dispatched
after that snapshot never executed. Fence the old deployment and provider before
promotion and reconcile any missing post-backup execution/idempotency evidence
under operator incident control. Do not automatically retry lost work or claim
zero data loss/at-most-once coverage for evidence missing from the snapshot.
Logical restore is not a substitute for WAL/PITR or an independently tested
disaster-recovery policy.

## Repeatable focused proof

Use the existing prepared `arbiter-p34` disposable PostgreSQL/Redis stack and
verification image. Confirm both services healthy and no overlapping verification
container/controller. Run only:

```powershell
.\scripts\verify-phase3.ps1 -Phase recovery
```

The new test creates and seeds a disposable migrated source, takes a native dump,
restores a distinct database, compares every durable table using counts and
in-memory digests, and tests restored security/lifecycle behavior. Only the test
fixture's generated source/target databases are dropped, without FORCE/CASCADE.
It never backs up or mutates the dev application database. Protected archives,
sanitized counts, JUnit and fault timing remain outside Git under the verifier's
evidence directory. No credential/prompt/completion/provider body enters reports.

The same entry point reuses the existing actual Redis outage/full restart-barrier
tests and a spawned process killed during provider execution, followed by fresh
unknown reconstruction and audited clearance. No real-model generation/pull is
needed. This focused proof does not replace the final previous-phase full gate,
clean Compose/real-model release smoke, alerts, logging/metrics or release scans.
