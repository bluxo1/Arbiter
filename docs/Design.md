# Arbiter v0.1 — Implementation contracts

## Ownership and defaults

This document owns HTTP contracts, schema responsibilities, admission sequencing, and failure behavior. Product semantics live in PRD.md; mandatory implementation constraints live in Rules.md.

Defaults: one API worker; tenant rate 60 requests per 60 seconds; key rate 30 per 60 seconds; daily tenant quota 1,000 dispatched requests; monthly budget 10,000 credits; model charge 10 credits/request; tenant concurrency 1; global concurrency 2. Policies may lower or raise allocations within validated deployment capacity. Zero disables new admission; negative and unlimited values are invalid.

HTTP bodies are limited to 64 KiB before JSON parsing. Chat accepts 1–32 messages, at most 32 KiB of combined UTF-8 content, and only `system`, `user`, and `assistant` roles. `max_output_tokens` defaults to 256 and must be 1–1,024, additionally bounded by the selected model. Reject unknown fields and unsupported options. Default provider connection timeout is 5 seconds and total inference deadline is 120 seconds; neither is caller-controlled.

## Authentication and authorization

Management routes accept Bearer JWTs from one configured OIDC issuer. Validate an explicit asymmetric algorithm allowlist, signature, issuer, audience, expiration, and not-before; allow at most 60 seconds of clock skew. Identify people by `(issuer, subject)`, not email. JWT tenant/role claims do not grant membership. Use only the configured JWKS endpoint; ignore token-provided key URLs. Cache keys for at most 15 minutes and refresh once for an unknown key ID; fail closed if no valid key is available.

Workload routes accept Bearer API keys with an opaque public identifier and a 32-byte cryptographically random secret. Persist only HMAC-SHA-256 verifiers with a deployment pepper and pepper version; compare in constant time. Rotation of the pepper requires reissuing affected keys in v0.1. Secrets are returned once and never retrievable.

A narrowly granted key-resolution function accepts the public identifier and candidate verifier, checks status/expiry and the tenant status, and returns only the authenticated binding. It has a fixed search path, no dynamic SQL, no PUBLIC execution, and a separately controlled owner. Invalid IDs and secrets return the same generic 401. Recheck key and tenant status during durable admission. Do not cache positive authorization results in v0.1.

| Credential/role | Permissions |
| --- | --- |
| API key | Its granted `inference:write` and/or `usage:read` scopes within its one tenant; scope set may not expand after creation. |
| Member JWT | List approved models and read usage/request/audit metadata for an active membership. |
| Admin JWT | Member permissions plus create/list/revoke keys for that tenant. |
| Local operator | Create/suspend tenants, manage memberships, set policies, register approved models, and resolve recovery incidents. |

For management routes the tenant path is a selector, validated against an active membership before setting context. For workload routes tenant identity comes only from the key; there is no tenant selector. Reject duplicate/mixed authentication inputs. Revocation/suspension serializes with dispatch authorization: once revocation commits, no later dispatch authorization can succeed; previously authorized work may finish.

## HTTP interface

| Method and route | Contract |
| --- | --- |
| POST `/v1/chat/completions` | API key with inference scope; required `Idempotency-Key`; body: public `model` alias, `messages`, optional `max_output_tokens`. |
| GET `/v1/models` | API key; list only tenant-approved aliases, output caps, fixed credit charges, and policy version. |
| GET `/v1/usage` | API key with usage scope; current UTC daily/monthly allocation totals. |
| GET `/v1/requests/{id}` | API key with usage scope; tenant-scoped state, charge, token counts if known, sanitized outcome; no completion replay. |
| GET `/v1/tenants/{tenant_id}/models` | Member/admin JWT; tenant model catalog. |
| GET `/v1/tenants/{tenant_id}/usage` | Member/admin JWT; current totals; optional bounded historical window selector. |
| GET `/v1/tenants/{tenant_id}/requests/{id}` | Member/admin JWT; same metadata contract as the workload status route. |
| GET `/v1/tenants/{tenant_id}/audit` | Member/admin JWT; cursor-paginated content-free audit events. |
| POST/GET `/v1/tenants/{tenant_id}/keys` | Admin JWT; create or list keys. Creation accepts label, allowed scopes, and expiration no more than 90 days away; default 30 days. |
| POST `/v1/tenants/{tenant_id}/keys/{key_id}/revoke` | Admin JWT; idempotent revocation. |
| GET `/health/live`, `/health/ready` | Minimal status; dependency details available only through operator diagnostics. |

Chat success returns server-generated `request_id`, public model alias, assistant message, available input/output token counts, and `charged_credits`. This is a deliberately limited interface, not a claim of full OpenAI API compatibility. Historical usage accepts UTC day or month starts within retained history. Lists use opaque tenant-bound cursors and page size 50, maximum 100.

Errors contain `error.code`, a sanitized `error.message`, and `request_id`. Use 401 for invalid credentials, 403 for missing scope or denied model, 404 for an inaccessible tenant/object, 409 for idempotency conflict or prior admission, 413 for body size, 422 for invalid fields, 429 for rate/quota/budget/tenant capacity, 503 for unavailable dependencies or global capacity, 502 for provider failure, and 504 for provider deadline. Include `Retry-After` only when a time-based retry is meaningful. Never expose raw provider bodies or another tenant's existence.

## Persistence model

All identifiers are server-generated UUIDs unless stated otherwise. Store timestamps as UTC-aware values and counters/credits as checked nonnegative 64-bit integers. Required logical records:

| Record | Responsibility and key constraints |
| --- | --- |
| tenants | Status and policy revision; runtime access scoped by its own ID. |
| principals | Global `(issuer, subject)` identity directory; only restricted identity/operator access. |
| memberships | Tenant/principal binding and member/admin role; unique within tenant. |
| api_keys | Tenant binding, unique public identifier, verifier/version, scopes, expiration, revocation; no secret. |
| tenant_policies | Versioned rate/quota/budget/concurrency settings and tenant-approved model aliases. |
| provider_models | Operator-managed global registry: public alias, adapter, pinned model digest, caps, fixed credit charge, active revision. No tenant-facing credentials. |
| quota_windows / budget_windows | Unique `(tenant_id, UTC window start)`; committed and reserved totals. |
| requests | Tenant, key, idempotency key, payload HMAC/version, policy/model snapshot, window IDs, state, timestamps, safe outcome and usage. Unique `(tenant_id, key_id, idempotency_key)`. |
| reservations | One per request; reserved request count and credits, disposition. |
| accounting_events | Append-only reserve/commit/release evidence; unique event kind per request. |
| audit_events | Tenant, actor reference/type, action, target ID, policy revision, request correlation, timestamp, sanitized outcome. |

Tenant-owned records carry non-null `tenant_id`; parent relationships use `(tenant_id, id)` foreign keys. RLS checks both visibility and writes against transaction-local authenticated context. Tenant/member lookup required to establish context uses narrow identity access, not arbitrary global repositories. Global model configuration cannot contain tenant content.

Runtime grants prohibit audit/accounting UPDATE or DELETE. Mutations, reservations, and dispatch transitions append their evidence in the same transaction. Metadata retention defaults to 90 days for terminal requests/audit/accounting and 13 months for aggregate windows. Unresolved requests are never purged. Retain minimal idempotency tombstones for the lifetime of the key plus 90 days so old retries cannot redispatch. Cleanup is a privileged, audited maintenance operation; revoked key records remain while referenced.

## Admission and dispatch

```text
parse -> authenticate -> establish tenant -> authorize -> deduplicate
                                                       |
                                             Redis rate gate
                                                       |
                                      PostgreSQL reserve transaction
                                                       |
                                          acquire local capacity
                                                       |
                                      PostgreSQL dispatch transaction
                                                       |
                                               provider call once
                                                       |
                                           persist terminal outcome
```

1. Validate payload, identity, scopes, active tenant, approved alias, and model caps. Compute a keyed HMAC over canonical validated request content; persist the fingerprint, never the content. Use a separate versioned fingerprint secret.
2. Validate idempotency key as 16–128 printable ASCII characters. Within the authenticated tenant/key scope, an existing key with different content returns 409 `idempotency_conflict`; matching content returns 409 `request_already_admitted` with its status URL. Do not replay stored output because output is not stored. Retried requests denied before reservation may try admission again.
3. Run one Redis script checking tenant and key sliding 60-second windows with Redis server time. Use sorted sets and unique server request IDs; prune expired entries, check both limits, and add to both only if both pass. Set expiry slightly beyond the window. A later PostgreSQL denial still consumes this rate entry. Atomicity covers both limits.
4. In one PostgreSQL transaction lock, in order, tenant admission row, key row, policy, quota window, budget window; all operations needing multiple locks use this order. Revalidate authority and insert/check the unique idempotency record. Locking the tenant row also serializes policy, membership/key changes, and tenant concurrency checks. Require `committed + reserved + requested <= limit` for both windows and count reserved/dispatched/unknown requests against tenant concurrency. Persist policy/model snapshots, reservations, state `reserved`, and audit/accounting evidence together. Commit before any provider operation.
5. Acquire the process-local global slot without queueing. If none is available, release the undispatched reservation and persist `rejected_capacity`, then return 503. It remains an admitted idempotency record; a new attempt needs a new key.
6. In another transaction using the same lock order, revalidate tenant/key and current alias permission. Deny if the relevant policy/model revision changed since reservation; release and require a fresh request. If the UTC day/month changed, release with `admission_window_changed` and require a new request. Otherwise transition `reserved -> dispatched`, move reserved totals to committed, and append evidence. This commit is the dispatch authorization point.
7. Invoke the provider once with the bounded, normalized request. No database transaction stays open across network I/O. Never retry an ambiguous dispatch, including transport connection errors after the marker commits. Persist outcome and token telemetry before returning a success response. Failure to persist yields a controlled unavailable response and leaves recovery evidence intact.

Global model revision updates are serialized with dispatch checks using registry-row locks, acquired after allocation-window locks whenever both are needed. Registry-only updates must not subsequently acquire tenant locks. Operators cannot lower limits below current committed-plus-reserved consumption or in-flight occupancy; they can suspend admission immediately. Tenant-specific changes use the same admission lock. Fixed charges are immutable snapshots after dispatch.

## Request state and recovery

```text
reserved -----> dispatched -----> succeeded
    |               +----------> failed
    |               +----------> unknown
    v                                 |
released / rejected_capacity          +--> terminal confirmation
```

A failure before the dispatch marker releases reservations exactly once. Any request bearing a dispatch marker retains its full charge regardless of outcome. Completion token counts may be unknown; never invent zero usage.

Disconnect before dispatch cancels admission and releases safely. Disconnect after dispatch keeps a supervised task reading the provider to a terminal result while its deadline allows. Timeout, crash, malformed terminal output, and inconclusive transport failure produce `unknown`; they do not refund or release quarantined capacity merely because time elapsed.

Maintenance runs every 10 seconds. It releases reservations older than 30 seconds under a row lock; a late handler must then fail its state check. Terminal completion releases concurrency. Unknown work retains a slot until provider termination is confirmed. After process restart, mark prior nonterminal dispatched work unknown and block inference readiness until the operator verifies that Ollama has no such running work, restarting Ollama if needed. Record the evidence and release only capacity, never committed credits or quota. Reconciliation updates are idempotent.

Redis uses AOF persistence, a no-eviction policy, and a readiness epoch keyed to its process incarnation. On Redis restart, missing limiter sentinel, or detected state reset, block new inference for a full 60 seconds before initializing a new epoch. Reject during the barrier; serialize initialization in Redis so simultaneous probes cannot shorten it. Restrict administrative Redis commands, and treat unexpected key loss as an enforcement incident. Redis exhaustion or script failure returns 503.

## Provider contract

The provider port exposes three operations: report capabilities/health, validate a normalized request against registered caps, and perform one non-streaming generation with an absolute deadline. Its request carries only an approved model reference, messages, output cap, and opaque request correlation. Its response carries assistant text, optional input/output token counts, finish reason, and safe provider metadata. Normalized errors distinguish unavailable, rejected input, deadline, malformed response, and unknown outcome. Adapter validation must not initiate inference.

The Ollama adapter uses `/api/chat` with streaming disabled, a pinned model and server-owned finite generation options. Map `prompt_eval_count` and `eval_count` when valid; do not use telemetry as accounting authority. The provider exposes these usage fields in its API. [Ollama API reference](https://github.com/ollama/ollama/blob/main/docs/api.md)

Only operator-verified text models are enabled. Verify output caps and context behavior against the pinned runtime/model before registration; reject oversize requests rather than silently accepting known truncation. Enforce a bounded provider response size of 1 MiB. Provider endpoints come from deployment configuration, redirects are disabled, and no request-driven model pull, tool invocation, or endpoint override is permitted. A future adapter must pass the same governance and lifecycle contract tests before it can be selected.
