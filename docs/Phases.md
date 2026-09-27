# Arbiter v0.1 — Delivery milestones

## Ownership and gating

This document owns delivery order and milestone exit evidence. It does not redefine API or security behavior. Complete gates in order; do not enable an inference path before governance gates pass. Record evidence and remaining limitations in Memory.md.

## Phase 0 — Validate the specification and environment

Deliverables: reviewed document boundaries; confirmed OIDC inputs; approved model/runtime/dependency versions; host capacity assessment; agreed credit/default-limit semantics; a threat review covering spoofed tenants, authorization bypass, resource races, provider bypass, crash recovery, and secret exposure.

Exit: no unresolved choice prevents implementation; each external input has a verified value or an explicitly assigned blocker. Record model licensing approval and whether hardware supports the default concurrency. No application readiness claim is made.

## Phase 1 — Foundation and isolation

Deliverables: modular FastAPI skeleton; Compose dependency topology; migrations; separate runtime/migration/operator roles; tenant-scoped persistence; liveness/readiness; local tenant/member provisioning commands. Inference remains unavailable.

Exit: a clean environment can migrate and start; the runtime role cannot bypass RLS or migrate; absent tenant context returns no tenant data; tenant A cannot read/write/join tenant B's records; composite relationships reject mixed tenants; pooled connections do not leak tenant context. Validate migrations from empty and previous supported schema states, and inspect published ports and secret handling.

## Phase 2 — Identity and tenant administration

Deliverables: OIDC verification; membership authorization; API key creation/list/revocation; scoped model metadata; transactional security audit; operator policy administration.

Exit: invalid signatures/issuer/audience/algorithms, expired JWTs/keys, forged tenant claims, missing scopes, unauthorized memberships, and mixed credentials fail safely. Key secrets appear only once and never in storage/logs. Cross-tenant object references do not disclose existence. No provider inference is enabled.

## Phase 3 — Governance and durable admission

Deliverables: Redis paired sliding-window limiter and recovery barrier; PostgreSQL quota/budget windows and reservations; idempotency; dispatch state machine using a deterministic provider double; accounting and reconciliation; capacity gates; scoped usage and request metadata after their authoritative request/window/accounting state exists. These metadata surfaces retain Design.md's HTTP contracts and all existing tenant isolation, authentication, authorization, RLS and audit requirements; no placeholder or fabricated usage/request state is permitted.

Exit: with at least 100 simultaneous attempts against limits of 10 requests and 100 credits at 10 credits/request, exactly 10 admissions succeed and totals never overshoot. For this test only, configure rate and capacity limits above the attempted load and use a provider double, so they cannot mask allocation races. Test quota and budget independently as well, with the other allocation nonbinding. Exercise independent tenants, key/tenant rate interaction, UTC day/month transitions, zero limits, policy revisions, duplicates with matching/different bodies, and reservation-release races. Stop PostgreSQL/Redis and reset Redis; denied requests make zero provider calls. Inject crashes immediately before/after reservation, dispatch commit, provider completion, and finalization; prove no automatic redispatch, duplicate charge, or unsafe capacity release. Verify scoped usage/request metadata against authoritative state for both identity paths. Verify revocation and suspension races against the real admission/dispatch locking path once it exists.

## Phase 4 — Ollama integration

Deliverables: provider port and contract suite; local Ollama adapter; approved alias registry; non-streaming chat endpoint; safe response/error mapping; bounded deadlines and payloads.

Exit: a real pinned model completes an admitted request with matching accounting evidence; denied requests never reach Ollama. Verify configured output caps, context limits, unknown aliases, malformed/oversize responses, unavailable models, timeouts, client disconnects, and provider endpoint/option injection attempts. Verify no request causes model download, tool execution, retry, or fallback. A second deterministic adapter passes the port contract without modifying governance.

## Phase 5 — Recovery, hardening, and release

Deliverables: tested startup/stop/recovery procedure; database backup/restore evidence; operational alerts; restricted logging/metrics; retained-history cleanup; dependency/secret scans; repeatable verification entry point. Record operational commands, recovery prerequisites, and tested outcomes in Memory.md; keep behavior contracts in Design.md.

Exit: all previous gates pass at the release revision; clean Compose startup and real Ollama smoke pass; backup restore preserves tenant ownership and accounting; Redis restart cannot reset admission immediately; API/provider restart cannot silently release unknown work; operator recovery is audited. Inspect logs and artifacts for keys, tokens, prompts, and completions. No unresolved isolation, authorization, accounting-integrity, or exploitable critical/high dependency defect remains.

Record hardware, model/runtime digests, load shape, governance latency, end-to-end latency, and observed saturation without turning machine-specific measurements into general promises. Mark v0.1 complete only when the PRD acceptance criteria and these exit gates have evidence.
