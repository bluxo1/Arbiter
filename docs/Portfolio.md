# Arbiter project copy

These descriptions refer to the verified [v0.1.0 release](https://github.com/bluxo1/Arbiter/releases/tag/v0.1.0),
at commit `59e6f299e590a79bb0d9dd1bad25053822acc762`. They describe executed
coverage and implemented behavior, without claiming production adoption or
performance beyond the bounded proof. See [known limitations](../README.md#known-limitations).

## One-line description

Arbiter is a governance/control plane for local AI execution, enforcing tenant
access and resource policy before Ollama inference.

## Portfolio description

Built Arbiter, a multi-tenant control plane that governs local AI execution with
PostgreSQL-backed authorization, accounting, and capacity ownership, plus
Redis-backed rate enforcement. It handles uncertain provider outcomes
conservatively, without automatic retries, fallback, or model pulls. Its signed
v0.1.0 release passed 1,308 regression tests and real PostgreSQL, Redis, Ollama,
security, recovery, and bounded saturation proofs.

## Four technical highlights

- Durable dispatch authorization, transactional quota/budget accounting, and
  idempotency enforce governance before an at-most-once provider invocation.
- Durable capacity ownership survives process failure; ambiguous outcomes stay
  charged and quarantined until verified clearance or terminal confirmation.
- Application tenant scoping, PostgreSQL FORCE RLS, composite foreign keys,
  restricted roles, and guarded retention protect control-plane state.
- An exclusive release coordinator validates real dependencies, fault recovery,
  backup/restore, hardened runtime, security controls, and bounded load evidence.

## Resume bullets

- Built a Python/FastAPI control plane for tenant-governed local AI execution,
  integrating real PostgreSQL, Redis, and Ollama.
- Implemented durable dispatch authorization and transactional resource accounting
  with idempotency, concurrency limits, and conservative crash/timeout handling.
- Enforced tenant isolation through application scoping and PostgreSQL FORCE RLS;
  separated runtime/operator privileges and added audited retention controls.
- Released an SSH-signed v0.1.0 artifact after 1,308 passing regression tests with
  zero failures, errors, skips, or deselections, plus real recovery, security,
  observability, and bounded saturation proofs.

## Recruiter-friendly explanation

Arbiter controls who can use shared local AI models and how much capacity they
can consume. The work combines backend authorization, database isolation,
concurrency, and recovery when a model may still be running after a timeout or
crash. The release was verified against real PostgreSQL, Redis, and Ollama.

## Why this project is hard

PostgreSQL, Redis, and Ollama cannot share one atomic transaction. A timeout does
not prove inference stopped, and a restart must not forget occupied capacity or
authorize duplicate work. Arbiter therefore separates durable authorization from
provider execution, preserves uncertain outcomes, and tests failure boundaries
with real dependencies and controlled faults.
