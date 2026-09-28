# Arbiter

Phase 1/2 foundation and bounded Phase 3 accounting, reservation, dispatch, terminal
lifecycle and Redis rate governance. Read
[the agent workflow](docs/Agents.md) and [project memory](docs/Memory.md) before changes.
The API exposes health, authenticated tenant audit reads, admin key creation/listing/revocation,
and tenant-approved model catalogs for OIDC members/admins and workload API keys. Liveness returns 200;
readiness deliberately returns 503 until all required security gates exist.
Inference, usage and request metadata endpoints remain unavailable; Phase 3 is incomplete.

Migration `0011_accounting_foundation` adds tenant-owned UTC quota/budget windows,
request/idempotency records, reservations and append-only accounting events with FORCE RLS.
Scoped repositories read these records; runtime and operator roles have no direct write grants.
Migration `0012_reservation_transactions` grants runtime execution of one scoped reservation
capability owned by a non-login, non-bypass role. The internal transaction revalidates keys,
serializes quota/budget/concurrency checks, and commits the request, reservation, accounting
and API-key audit evidence together. Matching retries return prior-admission metadata; conflicting
fingerprints fail without allocating again. Secrets and message content are never persisted.
The internal Redis tenant/key rate gate runs after authenticated deduplication and before
this reservation capability. It uses one Redis-server-time script and a 60-second
process-incarnation recovery barrier. Migration `0016_rate_preflight` adds a restricted
preflight capability that reads committed idempotency and rate policy before Redis;
the locked reservation then rechecks the policy revision and authority. It does not
reserve quota or credits before Redis accepts. The existing raw reservation
component remains an internal PostgreSQL primitive for its established regression tests.
No public admission or inference route exists.
Migration `0013_undispatched_release` adds a separate restricted cleanup capability, using the
verified in-flight key binding. It releases only reserved requests without a dispatch marker,
restores the original windows' reserved totals, and commits terminal state, accounting and
tenant audit together. Repeated release preserves the original outcome and evidence. Released
requests cannot be resurrected by stale handlers; committed allocations cannot be refunded.
No usage/request route exposes these records; dispatch settlement and lifetime maintenance remain
future work. Cleanup is internal and has no HTTP or operator command surface.
Migrations create no usage or production model rows.

Model catalogs return only active, registered aliases approved by the tenant's current policy:
`alias`, `output_cap`, `credit_charge`, and `policy_revision`. They use encrypted tenant-bound
cursors with default page size 50 and maximum 100. Workload catalog access requires a valid
key, with no additional scope beyond the approved key scopes. An empty registry or current
policy yields an empty catalog; catalog access never invokes or downloads a model.

Local registry provisioning uses `operator register-model` and `operator update-model`.
These commands append immutable global journal evidence in the same transaction; updates
require `--expected-revision`. Runtime and tenant HTTP identities cannot mutate this registry
or access its journal. Tenant audit records remain separate.

Before registration, the trusted operator must verify the text model's exact digest, pinned
runtime, context/output behavior and license approval. Put that prior-verification attestation
in a protected file under `ARBITER_MODEL_APPROVALS_DIR`; preparation creates an empty protected
directory, and only the operator container mounts it read-only at `/run/approvals`. No model
is approved automatically. The strict JSON fields are `adapter` (`ollama`), `model_digest`,
`runtime_digest`, `verification_digest` (SHA-256 of the retained verification evidence),
`context_cap`, `output_cap`, `verified_text` and `license_accepted`. All digests must be
`sha256:` followed by 64 lowercase hexadecimal characters; both attestation flags must
describe previously completed approval. The command validates the attestation's structure
and configuration bounds, and trusts the local operator for its truth; it does not itself
benchmark, contact a provider, or accept a license. Retain the referenced evidence privately.

```powershell
docker compose --profile operations run --rm operator register-model `
  --alias '<public alias>' --adapter ollama --digest '<approved sha256 digest>' `
  --context-cap 4096 --output-cap 1024 --credit-charge 10 --state inactive `
  --approval /run/approvals/verified-model.json

docker compose --profile operations run --rm operator update-model `
  --alias '<same public alias>' --adapter ollama --digest '<approved sha256 digest>' `
  --context-cap 4096 --output-cap 1024 --credit-charge 10 --state active `
  --expected-revision 1 --approval /run/approvals/verified-model.json
```

Replace placeholders only with reviewed operator inputs; these examples register nothing.
Context/output caps may not exceed the attested limits; output is at most 1,024 and no greater
than context. Charges are positive checked integers. Duplicate registrations and stale updates
fail without journal success evidence. Deactivation removes the alias from subsequent tenant
catalog reads. No CLI operation enables inference or changes tenant model approvals.

On the validated Windows/WSL2 host, prepare private files on D: and load public paths:

```powershell
.\scripts\prepare-local.ps1
$env:ARBITER_SECRETS_DIR = 'D:/AI & ML/ArbiterData/secrets'
$env:ARBITER_DATA_LINUX_ROOT = '/run/desktop/mnt/host/d/AI & ML/ArbiterData'
docker compose config --quiet
docker compose build api
docker compose up -d --wait postgres redis
docker compose --profile operations run --rm bootstrap
docker compose --profile operations run --rm migrate
docker compose up -d --wait api ollama
```

Secret preparation retains existing values. Bootstrap is an explicit, privileged
local command; it is not part of API startup. Migrations use their own credential.
The API receives only its runtime password, audit cursor key and API key pepper files.
Preparation also retains a separate `request_fingerprint_key` for the internal reservation component;
it is not mounted into or wired to the API yet. `FingerprintSettings` reads that file and its positive
version (`ARBITER_FINGERPRINT_KEY_FILE`, `ARBITER_FINGERPRINT_VERSION`). Retain the key/version while
their idempotency records remain in use; rotation/key-ring and tombstone maintenance are not implemented.
Keep secret values outside Git;
`.env.example` contains public paths only. Local Compose secrets are file mounts,
so protect their host directory as well as restricting per-service mounts.

Only API port 8000 is published, on loopback. PostgreSQL, Redis and Ollama use
internal networks with persistent named volumes backed by the configured D:
directories. The separately provisioned Keycloak issuer is outside this stack.
Startup never pulls a model; the existing approved model cache is reused. Ollama
health checks establish metadata availability only, not model readiness.

Run verification in the pinned Python container image:

```powershell
docker build --target verification -t arbiter-local:verification .
docker run --rm --network none --read-only --tmpfs /tmp arbiter-local:verification
docker run --rm --network none --read-only --tmpfs /tmp arbiter-local:verification ruff check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp arbiter-local:verification ruff format --check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp arbiter-local:verification mypy --cache-dir /tmp/mypy
```

Database foundation and tenant-isolation tests require the real migrated
PostgreSQL instance, `ARBITER_TEST_DATABASE=1`, its network, and explicitly mounted
runtime/operator/migration test credentials. Do not mount privileged test credentials
into the API. Tests exercise FORCE RLS, cross-tenant reads/writes/joins, composite
relationships, immutable ownership, append-only audit grants, and pooled reuse.

```powershell
docker run --rm --read-only --tmpfs /tmp --network arbiter_control `
  -e ARBITER_TEST_DATABASE=1 `
  --mount "type=bind,source=$env:ARBITER_SECRETS_DIR/db_runtime_password,target=/run/secrets/db_runtime_password,readonly" `
  --mount "type=bind,source=$env:ARBITER_SECRETS_DIR/db_operator_password,target=/run/secrets/db_operator_password,readonly" `
  --mount "type=bind,source=$env:ARBITER_SECRETS_DIR/db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider
```

Migration checks create and drop fresh, randomly named test databases. Run them
separately with the bootstrap credential; they never downgrade the application DB:

```powershell
docker run --rm --read-only --tmpfs /tmp --network arbiter_control `
  -e ARBITER_TEST_MIGRATIONS=1 `
  --mount "type=bind,source=$env:ARBITER_SECRETS_DIR/db_bootstrap_password,target=/run/secrets/db_bootstrap_password,readonly" `
  --mount "type=bind,source=$env:ARBITER_SECRETS_DIR/db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider tests/test_migrations.py
```

Tenant transactions take an immutable context from a trusted service and set it
only for that SQLAlchemy transaction. The persistence module does not authenticate
callers; the authenticated audit service establishes authority before access.
Read repositories add explicit tenant predicates;
audit appends derive ownership from context and commit with their caller's work.
Global principal data has no runtime grants. Synchronous database calls must run
outside the event loop. The bounded runtime pool has two connections, no overflow,
five-second acquisition/connect/statement/lock limits, and a ten-second idle
transaction limit. Repositories reject closed transactions or changed context;
unexpected session-wide context discards the connection.

Binary dependency locks include hashes for Python 3.13 on Linux amd64. Regenerate
with `python scripts/lock_dependencies.py` in the pinned base image and review/scan
the result. The production image contains only runtime dependencies; the separate
verification target adds test/lint/type tools. Dependencies are installed with
`--require-hashes`. Never use `docker compose down --volumes` as routine shutdown;
stop with `docker compose down` to retain data.

Local operator provisioning uses only the separate operator secret, through the
operations profile. Start PostgreSQL and apply migrations first; API, Redis and
Ollama are unnecessary for these commands:

```powershell
docker compose --profile operations run --rm operator create-tenant
docker compose --profile operations run --rm operator create-member `
  --tenant '<tenant UUID returned above>' `
  --issuer 'https://localhost:18443/realms/arbiter' `
  --subject '<existing issuer subject>' --role member
docker compose --profile operations run --rm operator set-tenant-status `
  --tenant '<tenant UUID returned above>' --status suspended
```

Replace the placeholders with public identifiers obtained through a trusted local
operator process. Membership input records the exact issuer/subject binding; it
does not verify JWTs, contact OIDC, or create an issuer account. Roles are `member`
and `admin`. Status is `active` or `suspended`; setting the current status returns
`changed=false` with no new mutation/audit. The operator can prepare memberships
while a tenant is suspended. Status changes leave the allocation policy revision
unchanged and lock the tenant row before changing status or creating a member.

Successful mutations return generated object/audit/correlation IDs after commit.
Every mutation and its operator audit event share one transaction; audit failure
rolls back the complete operation, including a newly created global principal.
Duplicate membership attempts fail without changing the existing role or writing
a success event. Every `create-tenant` invocation creates a new UUID tenant; there
is no caller-chosen tenant ID, name-based uniqueness, or automatic retry. Operator
audit identifies the authenticated shared database role `arbiter_operator`, not
an individually authenticated human. Runtime cannot insert operator-labelled
audit rows, invoke operator services, or change tenant/member state. No command
adds an HTTP route or enables inference.

Local foundation diagnostics use only the runtime secret and need no healthy
dependency prerequisite:

```powershell
docker compose --profile operations run --rm --no-deps diagnostics
```

Exit 0 means the PostgreSQL runtime role/schema checks and bounded Redis
PING/INFO configuration/persistence checks passed; exit 1 means a foundation
check failed. Output contains only fixed check names and booleans. These checks
do not prove the complete schema or replace migration/isolation tests. They never
read tenant records or mutate Redis. Dependency details have no HTTP route.
`foundation_ready=true` is distinct from application readiness: output always
reports `ready=false` while the complete admission, recovery and model readiness
gates remain unfinished. Redis PING/AOF health does not establish limiter
state or satisfy its restart barrier. `/health/live` remains responsive during
dependency outages; `/health/ready` remains a minimal 503 without network IO.

For an isolated clean-stack check, use a separate Compose project name, fresh
D: PostgreSQL/Redis directories and separate protected secret files. Reuse the
approved model cache through a volume override; do not duplicate model bytes.
Follow the same explicit bootstrap/migrate/start sequence above, then run the
real isolation and disposable migration suites. Inspect actual mounts, networks
and published ports. Stop/recreate with `down` and `up`, without `--volumes`, to
verify retained data and credentials. See project memory for the actual closure
evidence and Phase 1 assessment. Inference remains unavailable.

OIDC verification and membership authorization back the audit-list endpoint.
Key revocation, other metadata endpoints, admission and inference are unavailable.
`OidcVerifier` is an async context manager with bounded HTTPS JWKS retrieval,
RS256-only signature checks, exact issuer/audience checks, required `exp/iss/sub/aud`
and validation of optional `nbf/iat`. Clock skew is configurable from 0 to 60
seconds; cache lifetime is at most 900 seconds. Unknown key IDs refresh once per
verification attempt. Expired cache entries never authorize using stale keys when
refresh fails. Redirects, environment proxies and token-supplied key URLs cannot
redirect the configured JWKS trust. Credentials and claims are not logged.

Public configuration in `.env.example` references the separately provisioned
Keycloak issuer, its private container JWKS transport and explicit local CA.
API joins that existing identity network and receives the public CA as a read-only
config mount; no Keycloak/admin/client credential is mounted into it. The canonical
issuer stays `https://localhost:18443/realms/arbiter`, even though container JWKS
retrieval uses `arbiter-p0-keycloak:8443`. The development issuer must already exist;
Arbiter Compose does not provision it or create users. Missing/invalid trust fails
closed when creating/using the verifier. Full application readiness remains 503.

`ManagementAccess.run` verifies the token before touching PostgreSQL, resolves
active tenant/membership using the exact `(issuer, subject)`, then constructs
tenant context and executes a server-supplied service callback in the same scoped
transaction. Database work runs in bounded worker threads. Tenant/role/email claims
do not establish membership or permission; admin requirements use the database
membership role. Each call rechecks membership and tenant status; no successful
authorization cache exists. No function constructs context from an unchecked
HTTP header or body. The separate Bearer parser rejects duplicate/mixed credential
headers, and is used by the audit endpoint.

Before applying revision `0004_identity_lookup`, repeat the explicit bootstrap
command. It provisions a dedicated non-login, non-superuser, NOBYPASSRLS lookup
owner and gives only the trusted migration role non-inheriting ownership-management
membership. The lookup owner has column-level SELECT and two explicit SELECT RLS
policies, with no schema-create or write privileges. Its fixed-search-path,
static SECURITY DEFINER function returns only one active binding for the supplied
verified identity and tenant selector; PUBLIC/operator execution is denied. It
does not set tenant context. Runtime can execute that narrow function, cannot
assume the owner role or read the global principal directory, and retains all
ordinary FORCE RLS protections. Arbitrary SQL executing forged identity parameters
is outside the documented application trust boundary. Later dispatch must recheck
authority and serialize security mutations; this task supplies no dispatch-race
or complete Phase 2 claim.

`GET /v1/tenants/{tenant_id}/audit` accepts a member/admin OIDC Bearer token.
The tenant path selects an active membership; headers and JWT tenant/role claims
cannot grant access. Authentication and membership precede cursor validation and
repository reads. Unauthorized and nonexistent tenants both return generic 404;
invalid credentials return 401; invalid list parameters return sanitized 422;
unavailable identity/database dependencies return 503. Responses include
`Cache-Control: no-store`; errors contain a server-generated request ID.

Query parameters are `page_size` (default 50, range 1–100) and optional `cursor`.
Duplicate/unknown query parameters are rejected. The response is
`{"data": [...], "next_cursor": null-or-string}`. Events expose only ID, actor type,
actor membership ID, action, target ID, policy revision, correlation request ID,
UTC timestamp and sanitized outcome. Identity claims, actor-reference text and
conversation content are not serialized. Pagination uses ascending
`(occurred_at, id)` keyset order and retrieves at most page size plus one row.
It does not promise a frozen snapshot across pages while new events are appended.

Cursors use AES-256-GCM with a random nonce and authenticated tenant/list binding;
positions and tenant IDs are encrypted. Foreign, altered or malformed cursors
receive the same 422 after membership authorization. Cursors remain valid after
API restart with the same deployment key and do not require the anchor row to
remain present. Rotation invalidates outstanding cursors; restart pagination
from its first page. Preparation generates an independent 32-byte base64
`audit_cursor_key` in the protected secret directory and retains it on repetition.
Only API mounts it. Missing/invalid cursor key or OIDC configuration prevents
startup; startup performs no schema mutation or JWKS request. HTTPS/DB clients
are disposed during shutdown and file/certificate/database work stays outside
the event loop. Approved behavior contracts remain in [Design.md](docs/Design.md).

`POST /v1/tenants/{tenant_id}/keys` requires a verified OIDC token and an active
database admin membership. The strict JSON body accepts `label` (1–64 printable
ASCII characters, nonblank), `scopes` (a nonempty, duplicate-free subset of
`inference:write` and `usage:read`), and optional `expires_at` (an aware timestamp).
Omitting expiration gives 30 days; explicit expiration must be in the future and
within 90 days, measured by PostgreSQL after acquiring the tenant lock. Unknown
fields, duplicate JSON fields and query parameters are rejected; bodies are
limited to 64 KiB before parsing. JWT tenant/role claims cannot grant permission.

The 201 response contains `id`, `public_id`, `label`, `scopes`, `created_at`,
`expires_at`, `api_key` and a correlation `request_id`, with `Cache-Control: no-store`.
The credential format is `arb1.<32-character public identifier>.<43-character
base64url secret>`; the secret contains 32 random bytes. Store the returned
credential securely at the caller. It cannot be retrieved or replayed after a
lost response. Repeated valid POSTs create distinct keys; creation has no
idempotency contract. Workload verification uses the restricted service described below.
Creating a key does not enable inference.

Preparation provisions an independent base64-encoded 32-byte `api_key_pepper`
file and preserves it on repetition. Missing/invalid pepper prevents startup.
`ARBITER_KEYS_PEPPER_VERSION` defaults to 1; rotation requires reissuing affected
keys under Design.md. The verifier is HMAC-SHA-256 over the domain separator
`arbiter/api-key/v1` followed by a zero byte, public identifier, zero byte and raw
secret. Only the 32-byte verifier and pepper version reach persistence; the pepper
and plaintext credential are never written to the database or audit records.

Repeat bootstrap before migration `0005_api_key_creation`. It creates a separate
NOLOGIN/NOSUPERUSER/NOBYPASSRLS key-writer owner; runtime/operator cannot assume
that role. The fixed-search-path creation function requires matching transaction
context, locks the tenant and rechecks active admin membership before mutation.
It inserts the key and content-free member audit in one transaction. A deferred
composite foreign key also requires a matching audit ID, key target, actor and
tenant at commit. Runtime has scoped metadata-column SELECT and narrowly granted
function execution, with no direct key INSERT/UPDATE/DELETE or verifier reads.
The writer's tenant `UPDATE(status)` grant is required for `FOR UPDATE`; its
NOLOGIN role has no runtime membership or schema CREATE. FORCE RLS applies to
keys and all other tenant tables. Key metadata is immutable; revocation can only
set a previously null timestamp, which cannot later be cleared or changed.

`GET /v1/tenants/{tenant_id}/keys` requires verified OIDC identity and an active
database admin membership. It returns `{"data": [...], "next_cursor": null-or-string}`
with only `id`, `public_id`, `label`, `scopes`, `created_at`, `expires_at` and
`revoked_at` per key. It includes expired and revoked metadata without enabling
those credentials. It never queries verifiers or pepper versions and never issues,
returns or reconstructs secrets. No key-detail route is exposed.

Query parameters are `page_size` (default 50, range 1–100) and optional `cursor`.
Duplicate/unknown parameters are rejected after identity/membership/admin checks.
Pagination uses ascending UUID keyset order on the existing `(tenant_id,id)` index,
fetching at most page size plus one row. UUID order is not creation-time order;
new keys may appear before a previous cursor, so separately fetched pages do not
promise a fixed snapshot. Cursors remain usable without an anchor lookup and after
restart with the same deployment cursor key. They use AES-256-GCM, a random nonce
and a separate key-list purpose plus tenant binding. The existing `audit_cursor_key`
file is reused with domain separation; audit and key-list cursors are not
interchangeable. Rotation invalidates outstanding cursors. Unauthorized and absent
tenants both return generic 404; insufficient admin permission returns 403;
invalid cursors/queries return sanitized 422; unavailable dependencies return 503.
Successful and error responses carry `Cache-Control: no-store`. This read-only task
changes no schema, grants, RLS policy, secret provisioning or approved specification.

`POST /v1/tenants/{tenant_id}/keys/{key_id}/revoke` requires verified OIDC identity
and active database admin membership. It accepts no body or query options and
returns 200 with only `id` and `revoked_at`, with `Cache-Control: no-store`.
Repeated calls preserve the original revocation timestamp and append no duplicate
mutation event. Expired keys can also be revoked. Inaccessible/absent tenant or
key selectors share generic 404; non-admin members receive 403. Malformed input
receives sanitized 422; dependency or audit failures receive sanitized 503.

Migration `0006_api_key_revocation` grants runtime only EXECUTE on the scoped
revocation function. Runtime still cannot directly update keys or read verifiers.
The NOLOGIN key-writer owner receives only the additional metadata SELECT and
`UPDATE(revoked_at)` privileges needed by that function, under FORCE RLS. Its
fixed-search-path function requires matching context and locks the tenant before
the key, rechecking active tenant/admin membership after acquiring the tenant
lock. The timestamp and content-free `api_key_revoked` event commit together;
an audit failure rolls back the mutation. The response is produced after commit.

This establishes durable revocation and the lock order required of future
dispatch checks. Fresh workload verification now rejects committed revocation;
dispatch authorization and its full race gate remain unimplemented. No positive
authorization cache, workload data endpoint, provider call or inference path is introduced.

Workload requests have a reusable `run_workload` transport boundary and
`WorkloadAccess` service. Neither accepts a tenant selector. A server-owned
operation and optional required scope run only after a Bearer key resolves to
its own key/tenant/scopes binding. Transaction-local tenant context is established
only after successful verification and scope checks. Body, model, route and tenant
header values cannot establish authority. Duplicate/mixed credentials deny.
Malformed, unknown, wrong-secret, revoked, expired, wrong-pepper-version and
suspended-tenant credentials share sanitized 401; missing scope returns 403;
unavailable database state returns 503. No positive authorization is cached.

Repeat explicit bootstrap before migration `0007_workload_key_lookup`; it
provisions `arbiter_key_lookup` as a separate NOLOGIN/NOSUPERUSER/NOBYPASSRLS
read-only helper owner. Only trusted migration can assume it, with non-inheriting
membership. Runtime can only execute `resolve_api_key(public_id, candidate, version)`;
it still cannot read stored verifiers or assume the helper role. The fixed-search-path
helper has explicit SELECT policies and only necessary column grants on keys/tenants,
with no mutation, principal-directory, audit-read or schema-create authority.

Parsing requires the exact canonical issued format and 32 decoded secret bytes.
Issuance and verification share the same peppered HMAC implementation. The
candidate HMAC enters only the bound helper call, with SQLAlchemy parameters
hidden; plaintext secrets never reach SQL. The stored verifier stays in PostgreSQL.
The helper executes all 32 bytewise XOR/OR comparison steps, including against
a fixed dummy value for an unknown identifier, before checking status/expiry/version.
There is no mismatch-dependent comparison exit. This fixed-work comparison does
not claim identical total HTTP/query latency across different indexed lookup results.

Tests use a fixture-only HTTP route to exercise this boundary; it is absent from
production. Existing management routes continue to require OIDC membership/admin
authorization. Workload model/usage/request endpoints require their own bounded
implementation. Verified workload identity is not dispatch authority; future
durable admission must recheck tenant/key status under the documented lock order.

Local tenant-policy administration uses the existing separately credentialed
Compose operator command after migration `0008_tenant_policies`:

```powershell
docker compose --profile operations run --rm operator set-tenant-policy `
  --tenant <tenant-uuid> --tenant-rate 60 --key-rate 30 --daily-quota 1000 `
  --monthly-budget 10000 --concurrency 1
```

All five limits are explicit on the CLI; updates replace the complete policy.
Repeat `--model-alias <public-alias>` to approve registered models, or omit it
to approve none. Aliases are 1–64 lowercase ASCII letters/digits/underscore/hyphen,
starting with a letter, unique and bounded to 32. Native model names, URLs and
unregistered/inactive aliases deny. This migration creates only the minimal global
registry schema needed for validation; it registers no model and grants no operator
registry write privilege. Verified registration is a separate bounded task.

Limits accept zero and checked nonnegative signed 64-bit integers. Concurrency is
restricted to 0–2, the current measured deployment capacity recorded in Memory.md;
raising that ceiling requires a reviewed deployment-capacity change. It is not a
new measurement or an admission implementation. Tenant administrators have no
policy route or database mutation grant, and runtime has no operator credential.

Each accepted call, including repeated identical values, creates an immutable
tenant-owned policy revision and content-free operator audit in one transaction.
The first provision advances the tenant's existing revision 1 to 2; later updates
advance by one under the tenant lock. A deferred composite foreign key binds each
policy to its exact tenant, policy object, revision and successful operator event.
Errors roll back policy, audit and tenant revision; output contains only IDs and
revision after commit. ENABLE/FORCE RLS protects history; runtime may read only
within established tenant context and cannot insert/update/delete policy records.

PostgreSQL consumption and in-flight records now exist. The local policy path
must retain its locked consumption/occupancy checks when changing live limits.
The Redis limiter is an internal admission component; no provider call or
public inference is enabled.
