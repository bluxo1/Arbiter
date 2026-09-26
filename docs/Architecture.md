# Arbiter v0.1 — System architecture

## Ownership

This document owns trust boundaries, components, dependencies, and deployment topology. PRD.md defines product scope; Design.md defines concrete interfaces and transactions; Rules.md defines non-negotiable invariants.

## Deployment and trust boundaries

```text
Management client -- OIDC JWT --+
                               |  TLS outside loopback
Application ------- API key ---+--------> FastAPI monolith
                                            |
                    +-----------------------+----------------------+
                    |                       |                      |
             PostgreSQL                  Redis               Provider port
         identity, policies,          request-rate                 |
         reservations, audit          admission gate          Ollama adapter
                    ^                                              |
                    |                                         local Ollama
          local operator command                            approved models
                    |
             operator credential

Existing OIDC issuer --> signed identity + configured JWKS trust
```

Compose runs one API process/worker, PostgreSQL, Redis, and Ollama. A one-shot command using the same application package performs migrations and operator administration. A supervised maintenance loop inside the API reconciles abandoned reservations; it is not a separate service or queue worker.

Only the API binds to host loopback by default. PostgreSQL, Redis, and Ollama use internal Compose networks without published ports. External API exposure requires a TLS-terminating ingress owned by the deployment operator and an explicit trusted-proxy configuration. Compose is the supported v0.1 deployment boundary; horizontal scaling requires a later design review.

Use persistent named volumes for database state, Redis persistence, and Ollama model assets. Pin dependency versions and container digests during implementation and record them in Memory.md. The OIDC issuer is an existing external dependency; do not implement an identity provider.

## Modules and dependency direction

| Module | Responsibility |
| --- | --- |
| Transport | HTTP parsing, size limits, authentication entry points, response serialization. |
| Identity/access | JWT verification, key verification, memberships, scopes, tenant context. |
| Governance | Admission orchestration, policy checks, durable reservations and dispatch authorization. |
| Routing/providers | Alias resolution, provider capabilities, normalized inference and errors. |
| Accounting | Usage records, reservation transitions, window totals and reconciliation. |
| Audit/operations | Content-free audit records, health, metrics, operator commands. |
| Persistence | Scoped repositories, database transactions, Redis operations. |

Transport calls application services; services depend on domain contracts; infrastructure adapters implement those contracts. Provider adapters never authenticate tenants, set budgets, or initiate their own retries. Modules may share a database but must not bypass each other's application interfaces.

## Authoritative state

- PostgreSQL is authoritative for tenants, identity bindings, keys, policies, request state, quotas, budgets, and audit records. Row locks serialize admissions touching the same allocation windows.
- Redis implements only atomic short-term request-rate gates. It is not authoritative for daily quotas, budgets, request ownership, or provider dispatch.
- Provider configuration is operator-controlled. Tenant policy references approved aliases; callers cannot submit URLs, credentials, native model names, or arbitrary provider options.
- A process-local capacity gate protects the single supported API process and Ollama host. Durable in-flight records ensure a restart does not silently forget ambiguous work.

There is no distributed transaction between Redis, PostgreSQL, and Ollama. Rate capacity can be consumed by a request that subsequently fails durable admission; it is never refunded. PostgreSQL reservations and a durable dispatch marker govern accounting. Ambiguous dispatch is charged conservatively and is never automatically retried.

## Isolation and privileged paths

Tenant-owned tables use application query scoping plus PostgreSQL row-level security. The request role is neither a table owner nor a superuser and has no BYPASSRLS privilege. Use FORCE ROW LEVEL SECURITY and both read and write policies; owners otherwise normally bypass row policies. Missing tenant context must deny access. [PostgreSQL row security](https://www.postgresql.org/docs/18/ddl-rowsecurity.html)

Tenant context is transaction-local and established only after authentication and membership/key binding. Composite tenant/object foreign keys protect relationships. RLS supplements application authorization; it does not authorize roles or compensate for arbitrary SQL execution.

Pre-tenant key lookup and operator administration are narrow privileged paths. Key lookup exposes only the verified key's binding through a restricted database function; it does not grant general reads of key tables. Migration and operator credentials are unavailable to the API runtime. Tenant administration and inference use ordinary scoped access after context resolution.

## Reliability and privacy

Admission fails closed when required PostgreSQL or Redis state is unavailable. The API never uses cached budget balances or an emergency ungoverned provider path. Atomic Redis scripts are appropriate for the paired tenant/key rate checks. [Redis programmability](https://redis.io/docs/latest/develop/programmability/)

Redis readiness includes persistence and the recovery barrier specified in Design.md; a successful PING alone is insufficient. After API restart, reconcile durable in-flight records before reopening inference admission.

Ollama receives conversation text only after dispatch authorization. Disable application payload logging and provider debug/prompt logging; validate the deployed provider's logging behavior. Do not persist prompts or completions in Arbiter. Database backups therefore contain identity, policy, and operational metadata but no intended conversation content.

Provider transport timeouts and process failure can leave inference running remotely. Unknown requests retain capacity until terminal completion or operator verification of termination. Availability is deliberately sacrificed rather than allowing unbounded replacement work.

## Operational signals

Emit aggregate counters for admission outcomes, provider outcomes, reconciliation, and dependency failures; histograms for governance and provider latency; gauges for reservations and quarantined capacity. Avoid tenant/key/request IDs as metric labels. Restricted structured logs may carry opaque tenant and request IDs, never content or credentials.

Liveness measures process responsiveness. Readiness checks database schema, required secrets, Redis enforcement readiness, validated identity configuration, reconciled capacity, and the configured model's availability. A model outage must return a controlled error and must not trigger downloads or failover from a request.
