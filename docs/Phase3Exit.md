# Phase 3 exit verification

This matrix exercises the existing internal `GovernedExecutionService` against
real PostgreSQL and Redis with the deterministic provider double. It adds no
inference route, production architecture, migration, or retention cleanup.

## Test configuration

The isolated Compose project is `arbiter-p34`. Start only `postgres` and `redis`
using `compose.yaml` and `deploy/compose.phase3-exit.yaml`, then run the existing
bootstrap and migrate operations. The override gives PostgreSQL 256 connections,
2 GiB memory, and a 512-process limit for genuinely simultaneous callers.

Protected secrets, data, named verification containers, JUnit XML, logs, and fault
handshake files remain outside Git under:

`D:\AI & ML\ArbiterData\phase3\exit-matrix-20260930\ArbiterData`

Use the pinned Dockerfile `verification` target tagged
`arbiter-local:p3-4-verification`. The runner mounts current source and tests
read-only. It mounts individual test credentials, including bootstrap only for
explicit privileged migration/disposable-database verification. It never starts
API or Ollama, publishes a dependency port, or mounts a Docker socket.

`tests/test_phase3_exit_allocation.py` creates a fresh, retained database named
`arbiter_p34_allocation_<uuid>` and applies all existing migrations. The user
explicitly approved this disposable test configuration: only its SQL concurrency
CHECK and the concurrency-ceiling expression in `assert_policy_limits` change
from 2 to 256. Rate limits are 512 and process capacity is 256. Existing policy
repository transactions publish these test limits. Quota/budget guards, RLS,
identity, locking, accounting and dispatch/terminal capabilities are unchanged.
Tests verify that the main database and Python `PolicyInput` still enforce 2.
This configuration is not a validated production capacity increase.

Each allocation case starts 100 workers behind a shared barrier and holds all
providers open until the other 90 attempts are denied. Each caller completes
authenticated preflight before any first reservation. No connection pool
serializes the callers. Quota-only, budget-only and combined limits each require
exactly 10 dispatches/provider calls and 10 requests/100 credits committed. The
independent-tenant case starts 200 workers, 100 per tenant, requiring 10 admissions
and 100 credits per tenant. Durable totals are checked before provider completion.
Verification connections use 60-second statement/lock timeouts; production
engine timeouts remain unchanged.

The host fault driver accepts only five operations on the two fixed project
containers: Redis stop/start/restart and PostgreSQL stop/start. It checks Compose
project labels, waits for actual health after start, retains all evidence, and
restores stopped dependencies if a verification run fails. Do not run other
database/Redis suites concurrently with these outage/reset tests.

## Invariant coverage

| Invariants | Evidence |
| --- | --- |
| 1–3: quota, budget, tenant independence | Allocation tests: 100/100/100/200 simultaneous attempts; exact admissions and held-provider durable totals |
| 4–5: zero allocations | Matrix: 100 simultaneous attempts each, no request/reservation/provider |
| 6–8: paired rate, denial, outage, recovery | Fault matrix through full execution; real 100-attempt outage; real restart and state loss with repeated probes across the 60-second server-time barrier; existing Redis atomic suite |
| 9–10: duplicate storms/conflicts | Matrix: 100 first preflights for matching bodies and 100 different bodies; one durable request/charge/dispatch/provider; matching/conflicting attempts while first dispatch is active |
| 11–13: authority races | Full execution races with `pg_blocking_pids` proving actual row-lock contention; authority-first and dispatch-first revocation/suspension; policy changes before reservation and before dispatch |
| 14–18: reservation/dispatch crash boundaries | Spawned worker hard exits before reservation, before reservation commit, after reservation, after capacity, before dispatch commit, after dispatch commit before local transfer, and after transfer |
| 19–21: provider/terminal failures | Process death during provider and after completion; death before terminal commit; real PostgreSQL outage after provider; scoped real terminal-write fault; P3-3 cancellation regression |
| 22: confirmed release once | Success/definite-failure full path, terminal-commit crash, P3-3 explicit repeated terminal release |
| 23–25: quarantine/reconstruction/clearance | Fresh gate plus real maintenance capabilities after crashes; two reconstructed unknown claims, separate durable clearances, repeated clearance/reconciliation |
| 26–28: exactly-once accounting/refund/release | Per-request reserve/commit/release/audit counts, final totals, repeated recovery/duplicate/clearance, two concurrent first attempts both failing before dispatch |
| 29: approved provider boundary | AST assertion permits generation only in `DispatchService.run_double_once`; doubles witness dispatch/ownership in P3-3 regression |
| 30: inference unavailable | Exact HTTP route whitelist, including routes hidden from OpenAPI; existing readiness and inference-404 transport tests |

The `mark_unknown`/maintenance race holds a real terminal transaction open after
its mutation, then proves handler cleanup blocks on that transaction. Maintenance
wins; the second finalization changes nothing, the charge remains committed, and
capacity stays quarantined until durable clearance.

Crash workers send only an opaque boundary name and provider-call count through a
pipe, then `os._exit(97)`. This bypasses handler cleanup and all finally blocks.
The parent inspects committed state before death, starts a fresh gate/recovery
coordinator afterward, and repeats the original idempotency key. Uncommitted
transactions roll back; stale reservations use the real 30-second expiration;
unresolved committed dispatches become unknown and never invoke a provider again.

## Verification commands

With the isolated services already bootstrapped/migrated:

```powershell
& .\scripts\verify-phase3.ps1 -Phase matrix
& .\scripts\verify-phase3.ps1 -Phase p33
& .\scripts\verify-phase3.ps1 -Phase related
& .\scripts\verify-phase3.ps1 -Phase migrations
& .\scripts\verify-phase3.ps1 -Phase full
& .\scripts\verify-phase3.ps1 -Phase restart
& .\scripts\verify-phase3.ps1 -Phase checks
```

Every pytest invocation sets `ARBITER_TEST_DATABASE=1`,
`ARBITER_TEST_MIGRATIONS=1`, and `ARBITER_TEST_REDIS=1`. The runner additionally sets
`ARBITER_TEST_EXIT_HOST=1` and services real host fault requests. The `restart`
invocation runs the existing host Redis restart test separately and performs an
actual Redis process restart before starting that test container, using its
original `ARBITER_TEST_REDIS_RESTARTED=1` gate. Without this host
controller, outage tests explicitly skip with their required-controller reason;
the existing restart test requires either that controller or
`ARBITER_TEST_REDIS_RESTARTED=1` immediately after a real host restart.

Quality checks use Ruff, format check, strict mypy and `pip check`. Validate both
Compose configurations, run `git diff --check`, and scan final workspace sources
for secrets separately. Final exact results and evidence paths belong in
`docs/Memory.md`. A passing deterministic matrix establishes governance/recovery
behavior, not production model performance or permission to expose inference.
