# Restricted observability and security checks

This is an operational surface, never governance or accounting authority.
No external alert delivery service or scheduler is configured.

## Logs

The production Uvicorn command uses `deploy/logging.json`. Application/operator
logging uses the same formatter. Only fixed component/level/event fields and
exception presence survive serialization. It discards messages, arguments,
extras, stack information and exception chains rather than attempting string
redaction. Access logs remain disabled; public errors remain sanitized.
Python warning output is routed through the same restricted formatter.
PostgreSQL Compose configuration suppresses routine statements, parameter values
and error SQL below PANIC severity, and uses terse native error output.
Deploy the updated image/configuration to obtain these restrictions;
changing a source file does not reconfigure an existing container.

Never turn on debug, SQL echo, HTTP request tracing, environment dumps or a
second raw logging handler. Prompt/completion/API-key/Authorization/database or
Redis credential/provider-body content must not enter logs or report artifacts.
Secrets returned once by key creation belong only in the authorized response,
never in operator logs. Backup archives are sensitive data handled separately in
[Recovery.md](Recovery.md), not scanned as public textual artifacts.

## Local metrics

```powershell
docker compose exec -T api python -m arbiter.operations.observability
docker compose --profile operations run --rm diagnostics
```

The first command reads the live API's private Unix socket (0600, parent 0700,
same container UID). There is no public metrics route, listener or tenant label.
The second performs existing runtime-only PostgreSQL/Redis diagnostics.
Counters cover execution, actual provider calls, provider validation and
maintenance. Outcomes are success/denied/unavailable/rejected_input/definite_failure/
deadline/invalid_response/unknown/failure. Provider categories come from exception
types, independently of durable lifecycle state. Model/provider unavailability is
unavailable; rejected input and definite failure do not signal unavailability.
Malformed/oversized responses are invalid_response, and ambiguous outcomes are
unknown. An unexpected exception is failure even when lifecycle remains unknown.
Durations are cumulative elapsed seconds, not stored request latency samples.
Capacity reports limit/occupied/quarantined/saturated/recovery_ready only.
Redis last observation is unobserved/healthy/unavailable/barrier/denied.

Labels never contain request/tenant/key/idempotency/correlation identifiers,
model aliases/native tags, paths, free-form error text or caller strings.
Counters reset on restart. Last observations may be stale or unobserved; use
dependency health for current connectivity. A rate denial is not a Redis outage.
Provider validation failure is separate from an actual generation invocation.
These metrics do not expose usage, billing, tenant-level attribution or content.
The existing public `/health/ready` remains 503; local capacity recovery readiness
must not be interpreted as complete public service readiness.

## Alert conditions

| Condition | Machine-readable signal | Interpretation / action |
| --- | --- | --- |
| PostgreSQL unavailable | diagnostics `postgres=false`; Docker unhealthy | Fail closed; wait for actual recovery/health. |
| Redis unavailable | diagnostics `redis=false`; observed `unavailable` | Fail closed; investigate connectivity/persistence. |
| Redis recovery barrier | `redis_last_observation=barrier` | No new inference; full barrier must elapse. |
| Ollama/model unavailable | provider_validation unavailable count increases; provider unavailable count increases; Ollama Docker health | Availability is not model selection authority. No pull/fallback. |
| Readiness closed | `/health/ready` 503; `capacity.recovery_ready=false` | Public gate is conservative; inspect actual recovery state. |
| Unknown work quarantined | `capacity.quarantined>0` | Investigate unknown work; only audited operator clearance can free it. |
| Capacity saturated | `capacity.saturated=true` | Requests may be denied without queueing; do not alter charges/ownership. |
| Maintenance failure | maintenance unavailable/failure count increases | Admission remains closed; investigate restricted DB path. |
| Cleanup failure | operator retention command nonzero exit | No success evidence assumed; inspect transaction/audit safely. |
| Backup/restore proof failure | helper/verifier nonzero exit; JUnit failures/errors | Do not promote target; preserve protected evidence. |

Counter conditions mean an increase since the operator's prior observation, not
an eternal alert on historical events. No alert delay/escalation SLA is promised.
See [Recovery.md](Recovery.md) for dependency restarts, process fencing, unknown
clearance, protected backups and fresh-target restore. An abandoned private socket
after an in-container process crash fails closed; fence the previous process before
removing that exact stale socket/directory. Container restart recreates its tmpfs.

## Repeatable checks

Use the existing Docker verification environment and healthy disposable stack:

```powershell
.\scripts\verify-phase3.ps1 -Phase observability
.\scripts\verify-security.ps1 -Operation dependencies
.\scripts\verify-security.ps1 -Operation secrets
.\scripts\verify-security.ps1 -Operation artifacts -ArtifactDirectory '<text report directory>'
```

Dependency audit checks both hash-pinned lock sets against the installed resolved
environment, then queries the OSV API with finite timeouts. It rejects every
advisory, including unscored/lower-severity ones, rather than silently omitting
HIGH/CRITICAL findings. Partial/paged/malformed replies and network errors fail
the check. Reports contain package/version/advisory identity only. No dependency
upgrade or exception allowlist is implicit. This is not an OS/container CVE scan.

Secret scan uses the existing immutable Trivy 0.74.0 image with built-in rules
plus a narrow sentinel rule. It first requires detection of an external inert
positive-control file, then scans the checkout including docs/tests/config/scripts.
`.git` object storage is excluded. The root `.venv` host environment is excluded
only when Git confirms it is ignored and contains no tracked files; force-added
files keep that entire directory in scope. Git inspection errors fail closed.
Other ignored paths remain in scope; no broad source classes are suppressed.
Matched secret values are never printed or persisted by the runner; it reports
sanitized finding counts and exits nonzero on any finding/scanner failure.
Report validation requires the pinned schema/version, filesystem artifact type,
exact scan root, timestamp/report identity and nonempty, well-formed target results.
Trivy omits result entries for a clean secret-only scan, so the repository scan
uses a separate external inert marker inside its scan root. That exact marker must
be detected; every other secret finding fails. No repository file is replaced or
excluded by this control. Empty/partial reports and scanner errors fail closed.

Artifact inspection covers an explicitly supplied directory of UTF-8 or BOM-marked UTF-16 textual
JSON/JSONL/XML/log/text/exit reports, including JUnit. It rejects symbolic links,
unsupported/binary/oversized files, an empty scan and any forbidden sentinel.
Directory enumeration and file-read errors also fail the entire inspection;
a readable safe report cannot mask an unreadable subtree. Symlinks are refused.
Use a dedicated text-only evidence directory; do not include protected archives.
This is a sentinel leakage proof, not recognition of every possible arbitrary
secret. Pair it with Trivy and manual credential-pattern inspection. Scanner
results are point-in-time evidence, not a permanent clean/release claim.
