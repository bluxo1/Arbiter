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
adapter-specific checks for the later Ollama slice. Client disconnect before
dispatch and supervised completion after dispatch belong to the existing
governance/transport lifecycle, not to a provider cancellation method; the
provider receives the absolute deadline and may report an inconclusive timeout.
