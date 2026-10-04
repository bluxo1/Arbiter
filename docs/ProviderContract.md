# Phase 4 provider port: first slice

`Phases.md` names this milestone **Phase 4 — Ollama integration** and lists the
provider port and contract suite first. It does not define a numbered `P4-1`.
This document records the bounded first slice without changing `Design.md`.

The port has the three `Design.md` operations: capabilities/health, pure
validation, and one non-streaming generation with an absolute deadline. A
`ProviderRequest` contains only the dispatch snapshot's approved model ID and
pinned digest, bounded messages, output cap, and opaque request correlation.
It carries no endpoint, native model string, provider options, tools, retry,
fallback, or model-pull instruction. `DispatchService.run_double_once` remains
the sole production call site for `generate`; its name is retained for Phase 3
test compatibility. `GovernedExecutionService` uses the deterministic double in
Phase 3 tests and the dispatch-captured Ollama binding for public chat.

`ProviderResult` carries assistant text, optional input/output token counts,
and a finite finish reason. The finish reason is the only safe provider metadata
currently needed by the dispatch path; raw provider metadata and bodies are not
persisted. Dispatch validates the result shape, counts, finish reason, output
cap, and 1 MiB UTF-8 text bound. Usage is telemetry and never changes the fixed
dispatch charge.

`ProviderRejectedInput` and `ProviderModelUnavailable` mean validation or the
provider positively established that no execution remains in flight.
`ProviderDefiniteFailure` likewise permits a failed terminal state.
`ProviderUnavailable`, `ProviderDeadline`, `ProviderMalformed`,
`ProviderOversizedResponse`, and `ProviderAmbiguous` after dispatch are
conservative unknown outcomes: committed accounting stays charged and capacity
remains quarantined. An undocumented adapter exception receives the same
conservative treatment. Validation itself must never initiate inference.

The same contract suite runs against the Phase 3 double and an independent
table-driven deterministic implementation. Real HTTP request mapping to
Ollama `/api/chat`, streaming disabled, pinned native model selection, finite
server-owned options, redirect and endpoint controls, response byte counting,
token-field extraction, no model pull, no tool call, and no retry/fallback are
adapter-specific checks covered by the local Ollama slice. Client disconnect before
dispatch and supervised completion after dispatch belong to the existing
governance/transport lifecycle, not to a provider cancellation method; the
provider receives the absolute deadline and may report an inconclusive timeout.

## Local Ollama adapter slice

`OllamaProvider` now runs the same reusable contract through a counted fake
transport. Its operator-constructed binding maps the dispatch snapshot's exact
model UUID and digest to one local native tag; the approved alias registry and
public inference transport are separate Phase 4 layers. Validation
uses bounded `GET /api/tags` to check the local tag and digest, without a chat
request. The API joins the private Compose provider network, but no production
selection wiring or public generation route is added in this slice.

The only generation operation is one `POST /api/chat` to the exact configured
private service, with explicit messages, `stream: false`, `think: false`,
`truncate: false`, and server-owned `num_ctx`/bounded `num_predict`. The adapter
uses the existing absolute deadline, rejects redirects and compressed or
oversized wire bodies, and disables environment proxies and HTTP retries.
Only the pinned Ollama 0.34.4 chat handler's exact missing-model 404 is definite:
it checks local model existence before scheduling work. All other uncertain
post-request failures retain the existing unknown-capable taxonomy. Usage
counts remain optional telemetry and do not change dispatch accounting.

The model binding is deliberately internal. The operator-only provider-binding
foundation records a finite provider kind and native tag against the registered
model UUID and a new model revision. Its immutable journal entry binds the exact
tag to that revision. Dispatch authorization selects the binding while holding
the model revision lock and stores a tenant-scoped reference to that immutable
binding in the same transaction as the dispatch marker. A later binding update
cannot retarget dispatched work; an earlier update invalidates the old reserved
revision. Runtime can read the selected tag only through a scoped dispatched-
request capability, using the pinned UUID/digest/revision. Missing or mismatched
bindings fail closed. No caller field, alias conversion, or live Ollama discovery
chooses a native tag. Real-model generation remains a separate Phase 4 exit gate.

## Governed non-streaming chat

`POST /v1/chat/completions` accepts an API-key Bearer credential with
`inference:write`, exactly one `Idempotency-Key`, and JSON containing the
approved public `model` alias, 1–32 bounded text messages, and optional
`max_output_tokens` (default 256). The raw body is capped at 64 KiB, combined
message text at 32 KiB of UTF-8, and output tokens at 1–1,024 plus the model
cap. Extra fields, streaming, tools, endpoint choices and provider options are
rejected. The route enters the existing governed admission service; it does not
call Ollama. A server-owned 120-second absolute deadline starts at execution
entry and is passed unchanged to dispatch and provider generation.

The service checks immutable binding history for the reserved model revision
before dispatch. Dispatch authorization still locks and validates the current
model revision, then captures the binding in its commit. The selected provider
uses that captured UUID/digest/revision binding, even if the operator updates
the current binding afterward. Missing bindings release before dispatch; there
is no alias-to-native-tag conversion, discovery authority, retry, or fallback.

The first successful caller receives a transient assistant message, public
alias, request ID, optional token telemetry, and fixed charged credits. No
assistant output is stored. A matching idempotency retry returns 409
`request_already_admitted` with existing request ID/state and a relative
`/v1/requests/{request_id}` status URL; it never calls the provider again.
Failures use sanitized public codes. Definite terminal outcomes release local
capacity once. Inconclusive post-dispatch outcomes retain committed accounting
and quarantine capacity under the existing Phase 3 rules.
