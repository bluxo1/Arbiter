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
reports `ready=false` while identity, enforcement, recovery and model readiness
gates remain unimplemented. Redis PING/AOF health does not establish limiter
state or its future restart barrier. `/health/live` remains responsive during
dependency outages; `/health/ready` remains a minimal 503 without network IO.

For an isolated clean-stack check, use a separate Compose project name, fresh
D: PostgreSQL/Redis directories and separate protected secret files. Reuse the
approved model cache through a volume override; do not duplicate model bytes.
Follow the same explicit bootstrap/migrate/start sequence above, then run the
real isolation and disposable migration suites. Inspect actual mounts, networks
and published ports. Stop/recreate with `down` and `up`, without `--volumes`, to
verify retained data and credentials. See project memory for the actual closure
evidence and Phase 1 assessment. Inference remains unavailable.

The first Phase 2 task supplies OIDC verification and membership authorization as
application services. Management HTTP routes are still unavailable; this task
does not implement API keys, administration endpoints, admission or inference.
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
headers, and is ready for future management endpoints.

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
