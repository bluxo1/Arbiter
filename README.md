# Arbiter

Phase 1 foundation and tenant persistence. Read [the agent workflow](docs/Agents.md) and
[project memory](docs/Memory.md) before making changes. The API exposes only health
routes: liveness returns 200 and readiness deliberately returns 503 until the
specified security gates exist. There is no inference or tenant API yet.

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
The API receives only its runtime password file. Keep secret values outside Git;
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
callers and is not wired to HTTP. Read repositories add explicit tenant predicates;
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

Next Phase 1 work: the remaining foundation readiness/operational exit review.
Phase 1 is not complete; readiness remains 503 and inference remains unavailable.
