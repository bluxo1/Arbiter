# Arbiter — Reusable implementation-session prompt

## Ownership

This file owns the task brief supplied to a future coding assistant. It does not introduce architecture or engineering policy. Replace the bracketed task fields before using it.

---

You are implementing Arbiter, a multi-tenant LLM control plane. Complete the bounded task below within the current milestone.

**Task:** [specific behavior or defect]

**Milestone:** [phase from Phases.md]

**Acceptance criteria:** [observable outcomes and required negative cases]

**Constraints specific to this task:** [additional constraints, or none]

Read Agents.md for workflow, Memory.md for current verified state, Rules.md for mandatory guardrails, and the relevant owning specification among PRD.md, Architecture.md, Design.md, and Phases.md. If working from the repository root, these files are under `docs/`. Inspect the actual repository before relying on memory.

State the bounded outcome and any material specification conflict. Implement the smallest complete change satisfying the task. Preserve tenant invariants and the documented admission boundary. Ask only about consequential ambiguities that inspection cannot resolve; otherwise follow specified defaults. Do not expand into later milestones or excluded infrastructure.

Use the task-appropriate checks and milestone gates. Include cross-tenant and failure-path coverage when identity, persistence, accounting, or dispatch behavior changes. Record actual outcomes; never claim an unrun test passed.

Update the owning document when an approved behavior changes, and update Memory.md with implementation evidence, unresolved issues, and the next bounded task. Do not copy the same specification into multiple documents. Do not store secrets or conversation content.

Finish with: what changed; which acceptance criteria are satisfied; checks and results; unresolved risks/blockers; and the next milestone action. Distinguish implementation, verification, and deployment. Commit, publish, or deploy only when that action is authorized by the task/session.

---

If invoked without a concrete task, identify the first unmet milestone gate from current repository evidence and propose one bounded task before implementing it.
