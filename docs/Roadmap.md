# Proposed v0.2 roadmap

This is a planning proposal after the verified [v0.1.0 release](https://github.com/bluxo1/Arbiter/releases/tag/v0.1.0).
It commits no delivery date and authorizes no implementation. [Product scope](PRD.md),
[design contracts](Design.md), and [engineering rules](Rules.md) still govern
changes. v0.1.0 remains one host, one API worker, and one Ollama provider.

The priority is to make the existing system easier to deploy and recover while
preserving its authorization and failure boundaries.

| Priority | Item | Evidence required before claiming completion |
| --- | --- | --- |
| Must | Reproducible deployment and packaging | An operator follows a versioned setup on a clean supported host, provides identity/secrets and an already approved model, and reaches governed execution without hidden local prerequisites. Preserve read-only runtime and no automatic model pull. |
| Must | Fresh-host disaster recovery proof | Restore protected database state, retained external secrets, and approved model/runtime assets on an independent host; verify tenant isolation, accounting, process fencing, and conservative unknown-capacity reconstruction. Document snapshot limits and measured recovery time. |
| Should | Clearer operator diagnostics and external alerts | Offer bounded diagnostics for readiness, Redis recovery, and quarantined capacity, with explicit operator clearance evidence. Deliver content-free alerts to a configured sink without making alert delivery an admission dependency. |
| Should | Broader release security coverage | Add explicit container/OS advisory coverage alongside Python OSV and validate additional secret-detection controls. Record scanner limits and triage applicable findings without blanket suppression. |
| Later | Client SDK or another provider adapter | Select one based on demonstrated integration need. An SDK must expose idempotency/status semantics without automatic retry; a second adapter must pass existing dispatch/lifecycle contracts without fallback. |

## Deliberate deferrals

Persistent metrics storage can follow a demonstrated operational need; first make
reset/stale observations explicit in diagnostics and alerts. Multi-provider
execution is deferred because it expands approval, binding, and failure semantics.
Horizontal scaling, streaming, automatic retries/failover, and a broad dashboard
are outside this proposal.

Each selected item needs a bounded design review and acceptance evidence. A v0.2
release must run its own complete gate on a clean immutable candidate; v0.1.0
evidence cannot certify new behavior.
