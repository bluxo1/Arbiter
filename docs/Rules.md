# Arbiter — Mandatory engineering rules

## Authority

This file owns coding guardrails and non-negotiable tenant invariants. Every implementation, migration, test fixture, maintenance command, and provider integration must satisfy them. A shortcut, deadline, or passing happy-path test does not justify an exception. If a requested change conflicts, surface it before implementation and revise the approved design explicitly.

## Tenant invariants

1. **One authenticated tenant per operation.** Construct immutable tenant context from a verified key or verified identity plus active membership. Never trust a body, header, model response, or unchecked route identifier to establish authority.
2. **Scope every access.** Tenant-owned reads, writes, joins, caches, locks, reservations, cursors, idempotency records, and background operations must use authenticated tenant scope. Object UUIDs are not authorization.
3. **Enforce isolation twice.** Application authorization and database RLS are both required. Context must be transaction-local; connection-pool reuse must not retain it. Missing context denies access.
4. **Prevent mixed-tenant relationships.** Use non-null tenant columns and composite foreign keys. Reject tenant reassignment and tenant IDs supplied through mass assignment.
5. **Govern before dispatch.** No inference without verified identity, tenant/key status, scope/model approval, successful rate enforcement, durable quota/budget reservation, capacity, and committed dispatch authorization.
6. **Fail closed.** Missing, stale beyond its contract, invalid, or unavailable enforcement state never means allow. There is no debug bypass, permissive fallback, or emergency direct-provider route.
7. **Account atomically.** Admission must not exceed limits under concurrency. State transitions and accounting are transactional and idempotent. Never release charges or capacity based solely on an HTTP failure.
8. **Contain privilege.** Runtime credentials cannot migrate schemas, bypass RLS, operate as a superuser, or enumerate arbitrary tenant secrets. Narrow bootstrap/operator exceptions are explicit, separately credentialed, and audited.
9. **Contain information.** Tenant responses, errors, logs, traces, and exports must not reveal another tenant's content, metadata, identifiers, balances, or existence.
10. **Keep provider authority narrow.** Providers receive only admitted requests. Prompts, generated text, and provider errors never authorize actions or change tenant scope.

## Coding guardrails

- Use typed Python, strict request/response models, explicit service interfaces, and parameterized database access. Forbid dynamic SQL built from user values and arbitrary provider option dictionaries.
- Keep endpoint handlers thin. Put authorization/admission in services and scoped queries in repositories. A provider client may be invoked only through the dispatch service; enforce this through import-boundary tests.
- Use Alembic migrations for schema changes. Tenant table creation must include constraints, indexes, RLS policies, and grants in the same migration. Do not use application startup to mutate schemas.
- Use SQLAlchemy transactions consistently; prohibit autocommit tenant queries and session-wide tenant settings. Background tasks establish their own scoped transaction context.
- Use checked integer accounting, aware UTC timestamps, explicit lock ordering, bounded input/output sizes, finite deadlines, and cancellation-safe cleanup. No floating-point credits or read-then-write counters without locks.
- Do not block the FastAPI event loop with synchronous network calls, disk access, or long CPU work. Bound all pools and outbound connection counts.
- Do not add automatic provider retries, stream responses, cross-request conversation caches, or alternative invocation paths without a reviewed contract change.
- Use secrets from deployment secret files or an approved secret store. Never commit real `.env` values, API keys, JWTs, pepper material, database passwords, prompts, or completions. Examples contain inert placeholders.
- Disable unsafe debug surfaces and permissive credentialed CORS. Production errors are sanitized. Trust forwarding headers only from explicitly configured proxies.
- Audit security mutations and admission accounting transactionally. Never make the audit sink an optional best-effort substitute for durable evidence.
- Pin dependencies and images, scan dependencies and repository secrets, and review new packages for necessity. Do not bypass checks with blanket ignores or weaken tests to make them pass.
- Changes stay within the active milestone. Kubernetes, Kafka, microservices, and payments are forbidden in v0.1.

## Required verification

Security-relevant changes require negative tests with two tenants and real PostgreSQL under the production-like restricted role. Redis concurrency behavior requires real Redis. Mocks are appropriate for provider behavior, not proof of isolation or durable admission.

Exercise missing context, forged tenant IDs, cross-tenant joins/writes, pooled connection reuse, revoked/expired keys, quota/budget races, duplicate requests, dependency outages, and crashes around dispatch. Run formatting checks, linting, type checks, relevant tests, migration validation, and secret/dependency checks before release. Phases.md owns the milestone-specific acceptance matrix.

Never report an unrun check as passed. A local edit is not a deployed change; a passing test is not proof of complete tenant isolation. Report exact evidence and unresolved limitations.
