# Arbiter v0.1 — Product requirements

## Purpose and ownership

Arbiter is a multi-tenant LLM control plane for teams sharing AI infrastructure. It authenticates callers, isolates tenants, and enforces access and resource policies before inference begins.

This document owns product intent, scope, actors, and success criteria. Architecture.md owns system structure; Design.md owns implementation contracts; Rules.md owns mandatory engineering constraints; Memory.md owns project history; Phases.md owns delivery gates; Prompt.md owns the reusable task prompt; Agents.md owns agent workflow. Link to the owner instead of duplicating its specification.

## Users and outcomes

| Actor | Required outcome |
| --- | --- |
| Platform operator | Provision and suspend tenants, set resource policies, configure approved models, and investigate operational failures. |
| Tenant administrator | Manage that tenant's API keys and inspect its usage and audit history. |
| Tenant member | Inspect that tenant's permitted models and usage. |
| Application | Invoke permitted models using a revocable, tenant-bound API key. |

The operator is a trusted infrastructure role accessed through a local administrative command, not a cross-tenant HTTP superuser. Tenant administrators cannot raise platform-assigned limits or access another tenant.

## v0.1 capabilities

- Authenticate management users through an existing OIDC issuer and workload callers through Arbiter API keys. Keep tenant membership and authorization in Arbiter.
- Create, expire, and revoke scoped API keys. Show a secret only at creation.
- Offer text-only, non-streaming chat through an explicitly documented API and an allowlisted model catalog.
- Route each public model alias to one configured local Ollama model. Return a normalized result and usage metadata.
- Enforce tenant and key request rates, a tenant daily request quota, a tenant monthly compute-credit budget, and tenant/global concurrency limits before dispatch.
- Expose tenant-scoped request status, quota/budget consumption, and security audit records without storing conversation content.
- Run on one host through Docker Compose, with reproducible migrations and documented recovery procedures in the delivery record.

## Budget semantics

A compute credit is an internal allocation unit, not money. Each approved model alias has a positive integer charge per dispatched request, disclosed in the model catalog. The charge is fixed regardless of actual token count; output length remains independently capped. Input/output token counts are usage telemetry, not v0.1 quota or budget units.

An admitted request reserves one daily request and its fixed credit charge. Dispatch consumes those allocations, including failed or ambiguous dispatched calls. A request proven never to have reached dispatch releases its reservation. This conservative policy prevents failures from granting unlimited inference attempts.

Request quotas use UTC calendar days; budgets use UTC calendar months. Unused allocations do not roll over. Suspended tenants cannot admit new work. Changes to limits affect subsequent admissions; already dispatched work remains charged under its recorded policy.

## Boundaries

The release is a modular monolith using FastAPI, PostgreSQL, Redis, Docker Compose, and local Ollama. Its provider interface must permit future adapters without moving governance into providers.

Explicitly excluded: Kubernetes, Kafka, microservices, payments, billing/invoicing, currency spending guarantees, cloud provider implementations, streaming, token-based quotas, automatic provider retries or failover, inference queues, tools/function calling, embeddings, RAG, file uploads, tenant-controlled provider URLs, a web dashboard, and self-service signup.

Arbiter provides logical tenant isolation, not dedicated hardware or protection against a compromised host/operator. Shared model execution still shares CPU/GPU capacity. Prompts and model output are untrusted text and grant no control-plane authority.

## Release acceptance

1. Tenant A cannot read, mutate, infer through, or consume allocations belonging to tenant B, including through forged identifiers and reused connections.
2. Invalid identities, revoked keys, denied models, exhausted allocations, and unavailable admission dependencies produce zero provider calls.
3. Parallel admission cannot overspend the documented request quota or credit budget.
4. Retried requests with the same idempotency key produce at most one application dispatch attempt, including after crashes.
5. Every dispatched request has durable identity, policy, accounting, and audit evidence; conversation content and secrets are absent from stored evidence.
6. The Compose stack supports a real Ollama smoke test and controlled outage/recovery exercises. Automated governance tests use deterministic provider doubles.
7. Release claims identify the tested hardware, model digest, runtime versions, test results, and any limitations. No unmeasured throughput or latency claim is a release requirement.
