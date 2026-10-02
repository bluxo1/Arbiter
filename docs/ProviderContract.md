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
test compatibility. The internal `GovernedExecutionService` still selects only
the deterministic double, and no HTTP inference route exists in this slice.

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
public inference transport remain separate Phase 4 deliverables. Validation
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

The model binding is deliberately internal. Later alias-registry work must
construct it only from operator-verified approval state and must not expose
native tags, destinations, or options in request data. No real-model generation
is claimed by the fake-transport contract suite.
