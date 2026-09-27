# Arbiter — Persistent project memory

## Purpose and maintenance

This file is the persistent project brain for future sessions. It records verified validation and implementation history, evidence, blockers, and handoffs. It does not redefine specifications. Link to the owning document instead of copying its requirements or baseline decisions.

Update this project-local file after each meaningful validation or implementation session. Record facts with dates and evidence. Label proposals, assumptions, and verified outcomes separately. Preserve historical observations and identify later evidence that supersedes them. Never store credentials, personal JWT claims, prompt/completion content, or raw sensitive logs. Do not claim that installed tools, static reviews, or available hardware prove application readiness.

## Phase Zero prerequisite

Complete the Phase 0 exit criteria in [Phases.md](Phases.md) before beginning Phase 1. Record unresolved inputs as blockers; assigning a blocker does not resolve an implementation-preventing choice. Follow [Agents.md](Agents.md) for workflow and [Prompt.md](Prompt.md) for a task brief. Approved requirements remain in PRD.md, Architecture.md, Design.md, and Rules.md.

## Session record template

- Date and observation time:
- Task and phase:
- Files/revision examined or changed:
- Verified facts and approved decisions, with evidence or specification references:
- Checks performed, commands, environment/version, and results:
- Checks skipped and reasons:
- Security findings and operational changes:
- Blockers, responsible role, and evidence needed to resolve each:
- Phase exit assessment:
- Next bounded action:

## Validation history

### 2026-09-26 — Phase 0 environment and document validation

**Assessment: Phase 0 remains blocked. Phase 1 was not started.** Implementation history is empty; this entry records validation only. Host observations began at approximately 18:43 IST, with follow-up checks after 18:47 IST. This workspace has no Git revision to identify the snapshot.

#### Verified evidence

| Check / command | Observed result and limitation |
| --- | --- |
| Read all eight `docs/*.md` documents; inspect `Get-ChildItem -Force` and `rg --files` | Exactly eight project documents; no application source, dependency manifest, Compose file, migrations, tests, or project configuration found in this workspace. Reviewed document ownership; no material cross-document contradiction requiring specification edits identified. |
| `git --version`; `git -C E:\Arbiter rev-parse --show-toplevel` | Git 2.55.0.windows.5 is available. The workspace is not a Git repository. |
| `Get-CimInstance Win32_OperatingSystem` | Windows 11 Pro, 64-bit, build 26200; 15.91 GiB visible RAM, 3.67 GiB free at the observation time. Free memory is a transient snapshot. |
| `Get-CimInstance Win32_Processor` | Reports Intel Core i5-10400F, 5 cores and 10 logical processors exposed to Windows. Reports `VirtualizationFirmwareEnabled=False`; this alone does not establish the reason Docker is unavailable. |
| `Get-CimInstance Win32_VideoController`; `nvidia-smi --query-gpu=name,memory.total,memory.free,driver_version --format=csv,noheader` | NVIDIA GeForce RTX 5060; NVIDIA reports 8,151 MiB total and 5,908 MiB free VRAM, driver 610.88. GPU visibility does not prove container GPU access or inference capacity. |
| `Get-PSDrive -Name E` | 140.31 GiB free on the workspace volume at the observation time. Docker/model storage capacity was not established from this value. |
| `docker version --format '{{json .}}'`; `docker compose version` | Docker client 29.8.0, context `desktop-linux`; Compose v5.5.1. Server query fails because the `dockerDesktopLinuxEngine` named pipe is absent. No server version verified. |
| Installed `E:\Docker\Docker Desktop.exe` file version; selected resource fields in `%APPDATA%\Docker\settings-store.json` | Desktop product/file version 4.91.0.239619. The settings file exists, but no explicit values for `cpus`, `memoryMiB`, `swapMiB`, `wslEngineEnabled`, `diskSizeMiB`, or `diskImageLocation` were found in the inspected fields. Effective engine resource allocations remain unverified; no defaults were assumed. |
| Inspect only `CustomWslDistroDir` and test its configured directory | A nonempty custom WSL directory is configured, exists, and resides on E:. This establishes its configured storage volume, not effective Docker image capacity or engine readiness. |
| `docker info`; `docker image ls` | Both fail against the unavailable engine. Available images, digests, database/Redis runtimes, container resources, and GPU passthrough could not be inspected. No image was pulled or container created. |
| `wsl --version`; `wsl --status` | WSL 2.7.11.0, kernel 6.18.33.2-2; default distribution `docker-desktop`, default version 2. This does not prove Docker engine readiness. |
| `wsl --list --verbose`; presence of user `.wslconfig`; `Get-CimInstance Win32_LogicalDisk` | `docker-desktop` and `Ubuntu` are both stopped WSL 2 distributions. No user `.wslconfig` exists. Free fixed-volume space at follow-up: C: 11.30 GiB, D: 169.56 GiB, E: 140.31 GiB. These snapshots do not prove sufficient image/model storage or usable container resources. |
| `ollama --version`; `ollama list` | Initially no running instance; client version 0.34.1. The list command unexpectedly auto-started the installed desktop app/server; it then returned an empty model list. |
| GET `http://127.0.0.1:11434/api/version`, `/api/tags`, `/api/ps` after that launch | Server reports 0.34.1; installed and running model lists are empty. These were metadata requests only; no generation was requested. |
| Inspect presence of `ARBITER_*`, `OIDC_*`, `OLLAMA_*`, `DATABASE_URL`, and `REDIS_URL` environment names, without displaying values | Only `OLLAMA_MODELS` matched. Its configured directory does not exist; its manifests directory is absent. No Arbiter/OIDC/database/Redis configuration was found in this inspected workspace/process environment. Configuration elsewhere was not searched. |
| `Get-Command` for development tools | Docker, Ollama, Git, Node, and NVIDIA utilities resolve. `python` resolves to a WindowsApps entry; an operational Python interpreter was not verified. `py`, `uv`, `psql`, and `redis-cli` do not resolve on PATH; standalone database clients are not required by the approved Compose topology. |

#### Static threat review

This reviews specified controls only; no application exists to test their implementation.

| Threat reviewed | Specification evidence | Validation remaining |
| --- | --- | --- |
| Spoofed tenants and unauthorized membership | Design.md authentication/authorization; Rules.md tenant invariants | Real issuer verification, negative authorization tests, and revocation races. |
| Cross-tenant persistence and privileged lookup bypass | Architecture.md isolation; Design.md persistence and restricted key resolution | Restricted-role RLS, composite relationships, pooled context reuse, and privileged-function grants. |
| Resource races and reset-based limit bypass | Design.md admission, Redis recovery, and accounting | Real PostgreSQL/Redis concurrency and reset tests; no runtime proof yet. |
| Direct provider invocation or request-controlled endpoints | Architecture.md module boundaries; Design.md provider contract | Import-boundary checks, endpoint injection denial, approved model validation. |
| Crash, cancellation, duplicate dispatch, and unsafe refunds | Design.md lifecycle and reconciliation | Crash-injection and recovery evidence; no inference or crash test performed. |
| Secret/content disclosure | Rules.md secret handling; Architecture.md privacy | Secret provisioning decisions and actual application/provider logging inspection. |

#### Blockers and required resolution

Responsible roles below identify who must supply the missing evidence; no individual owner has been confirmed.

| ID | Blocker | Responsible role / evidence needed |
| --- | --- | --- |
| P0-01 | User confirmed that no OIDC issuer has been selected. | Platform operator/project owner: select an existing issuer and provide public issuer, audience, JWKS endpoint, approved algorithms, reachable discovery/keys, and identity/operator provisioning approach. Do not invent or implement an issuer to bypass this blocker. |
| P0-02 | Docker Linux engine is unreachable. | Platform operator: restore engine availability, then verify server/version, container resource limits, usable storage, and GPU access if selected. Do not infer the root cause from the WMI virtualization field. |
| P0-03 | User confirmed that no local Ollama model is approved; the inspected installation also has no models. | Platform operator/project owner: select and approve the model and its license, record full digest/runtime version, and authorize provisioning. Do not treat an available model or a client version as approval. |
| P0-04 | Approved runtime/dependency versions and container digests are unrecorded. | Project maintainer: approve reproducible version/image selections. Installed client versions above are observations, not approved deployment pins. |
| P0-05 | Model context/output behavior and default concurrency are unverified. | Platform operator/maintainer: after P0-02/P0-03, provide bounded model validation and measured resource evidence for the approved defaults. Static RAM/VRAM inventory is insufficient to pass capacity assessment. |
| P0-06 | Operational provisioning inputs are unconfirmed. | Platform operator: designate secret-file provisioning, separate operator/migration/runtime credential handling, backup destination, and intended restore procedure. Runtime restore evidence belongs to the later release gate in Phases.md. |

The product semantics in the user-approved specifications remain accepted; this validation makes no new policy, model-license, or version approvals. First-tenant workload suitability remains unmeasured.

#### Checks skipped, operational effects, and handoff

- OIDC discovery/signature validation was not attempted because no issuer inputs were supplied. Container/database/Redis checks stopped at the unavailable Docker engine; no package installation, image pull, or stack startup was attempted.
- No model inference, benchmark, context/output-cap test, or licensing verification was performed because no approved local model is available. No application tests, RLS tests, migration checks, or recovery exercises can run against this documentation-only workspace.
- The Ollama CLI probe auto-started desktop app PID 21448 and server PID 6624. Their paths and creation times were checked before stopping only those probe-started processes. Follow-up inspection found zero remaining probe processes and zero listeners on port 11434. No inference or model download was requested. The app emitted an update-availability message; no update command was issued and no update completion was verified.
- Only this memory document was edited to retain maintenance/template instructions and record actual Phase 0 evidence instead of repeating baseline specifications. SHA-256 comparison confirmed that the seven other documents were unchanged.
- Next bounded action: resolve P0-01–P0-06 and rerun the affected Phase 0 checks. Do not start Phase 1 or propose its first implementation task until the Phase 0 exit assessment passes.

### 2026-09-26 — Phase 0 continuation: storage, identity, runtime and capacity

Observations below began approximately 21:18 IST. This is environment validation/provisioning history, not application implementation. All eight documents were read again; the workspace remains documentation-only and has no Git revision. Approved specifications were not changed. This entry supersedes the earlier missing-engine, missing-model and missing-issuer observations; historical failures above remain valid for their observation times.

#### User decisions and verified storage

- Hardware supplied by the user: Intel Core i5-10400F, RTX 5060, 8 GB VRAM, 16 GB RAM. These are input facts, not inferred capacity. GPU/OS probes below establish runtime compatibility and resource pressure only.
- User approved downloading and benchmarking Qwen3-4B-Instruct-2507 Q4_K_M after D: storage verification, and selected a separately provisioned Keycloak issuer outside Arbiter's Compose stack. No external account was created.
- `D:\ArbiterData` creation was denied by existing ACLs. A clean, user-writable alternative was created at `D:\AI & ML\ArbiterData`; its verified paths were shown before downloading. Its inherited ACL was replaced with access for the current user, SYSTEM and Administrators. Unrelated directories/data were not relocated or deleted.

| Use | Verified location / evidence |
| --- | --- |
| Ollama model cache | `D:\AI & ML\ArbiterData\ollama\models`; user-level `OLLAMA_MODELS` persisted, native server configuration checked, installed manifest and weight hashes verified. |
| Temporary/model scratch | `D:\AI & ML\ArbiterData\tmp`; native TEMP/TMP redirected here. Container TMPDIR uses `/models/.tmp` in the same D: cache. |
| Diagnostics and evidence | `D:\AI & ML\ArbiterData\phase0`; only small initial dependency diagnostics were temporarily created under the Windows user TEMP directory. |
| Secret files | `D:\AI & ML\ArbiterData\secrets`; generated local identity bootstrap/probe credentials and private TLS key are here, never in this workspace or this record. |
| Separate identity persistence | `D:\AI & ML\ArbiterData\identity\keycloak-data`. |
| Backup staging | `D:\AI & ML\ArbiterData\backups`; directory prepared only. No application backup or restore has occurred. This is on the same physical disk as live D:/E: data, so it is not disk-failure protection. |
| Existing shared Docker/WSL store | Docker `CustomWslDistroDir=E:\Docker\wsl`. Retained because it contains unrelated running Axiom PostgreSQL/Chroma workloads. Moving shared storage to D: remains a separate operator decision; it is not a reason to copy model weights to C:. |
| Linux model volume | New named volume `arbiter-p0-ollama-models`, local bind driver, device `/run/desktop/mnt/host/d/AI & ML/ArbiterData/ollama/models`, mounted at `/models`. Linux `/api/tags` sees the same manifest. Volume metadata is in the existing Docker store; model bytes stay on D:. |

Post-download `Get-FileHash` matched the model blob below. Inspection of the default C: Ollama model directory found zero files/zero bytes at 22:01 IST. `Get-Partition`/`Get-Disk` showed D: and E: share disk 0, ST1000DM010-2EP102 SATA HDD; C: is the separate 128GB EVM SSD. No second weight download or cache copy was performed.

#### Docker, WSL and provider compatibility

| Check | Verified result |
| --- | --- |
| `docker version`, `docker info`, Desktop file metadata | Engine already available this continuation; no Docker repair/reboot was needed. Desktop 4.91.0.239619, Engine/client 29.8.0, Linux x86_64, overlayfs, root `/var/lib/docker`; Compose v5.5.1. |
| `wsl --version`, distribution status, engine resources | WSL 2.7.11.0; running docker-desktop WSL2, Ubuntu stopped; engine kernel 6.18.33.2-microsoft-standard-WSL2. Docker exposes 10 logical CPUs and 8,276,541,440 bytes RAM. No user `.wslconfig` was found. |
| Pinned disposable container `--gpus all`, `nvidia-smi` | GPU passthrough works; driver 610.88, total VRAM 8,151 MiB. The Ollama Linux runner detects compute capability 12.0, CUDA_v13, driver API 13.3. This is compatibility evidence, not a successful inference claim. |
| Native executable / API | Native Ollama 0.34.1 at `D:\Ollama\ollama.exe`; SHA-256 `1ff56c8b2c791bff69b6457d25aa63ed11073562cd47b14f42dd16dfa4353e05`. Probe-started native server was stopped before the Linux test. |
| Pinned Linux provider | Ollama 0.34.4 API/runtime confirmed. Diagnostic container `arbiter-p0-ollama`: 4 GiB memory, 4 CPUs, GPU access, parallel slots 2, max loaded models 1, per-request context 4,096, flash attention enabled, cloud disabled. Diagnostic port binds only `127.0.0.1:11436`; this is outside the eventual application topology. |
| Redis primitive preflight | Pinned 7.2.16 container, no network/host port, D: persistence, 128 MiB container limit; AOF/appendfsync always, maxmemory 64 MiB, noeviction verified. PING and a sentinel surviving restart passed. Container stopped afterward. This does not validate Arbiter's recovery barrier or admission scripts. |

RTX 5060 is explicitly supported by the [Ollama GPU matrix](https://docs.ollama.com/gpu); the measured driver exceeds its minimum. Parallel contexts increase memory requirements according to the [Ollama FAQ](https://docs.ollama.com/faq). The approved application topology and provider boundaries remain owned by Architecture.md/Design.md.

#### Approved model identity and license evidence

| Item | Verified value |
| --- | --- |
| Ollama reference | `qwen3:4b-instruct-2507-q4_K_M` — Qwen3-4B-Instruct-2507, GGUF, Q4_K_M; metadata reports 4.0B (catalog 4.02B). |
| Full manifest SHA-256 | `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0` |
| Weight blob SHA-256 | `85e4a5b7b8ef0e48af0e8658f5aaab9c2324c76c1641493f4d1e25fce54b18b9` |
| Exact weight size | 2,497,280,480 bytes; registry value equals downloaded file length. |
| Config blob SHA-256 | `b72accf9724e93698c57cbd3b1af2d3341b3d05ec2089d86d273d97964853cd2` |
| License blob SHA-256 | `d18a5cc71b84bc4af394a31116bd3932b42241de70c77d2b76d69a314ec8aa12`; 11,338 bytes, Apache License 2.0. |

`model-pull-result.json` reports success; native and Linux tag metadata agree with the full manifest. Recommended over the inspected 8B Q4_K_M alternative (5,225,374,496-byte weights) for greater resource headroom; the 8B model was not downloaded. Advertised model context 262,144 is metadata only, not a tested usable setting. This deployment's diagnostic context is 4,096; tools/thinking capabilities in metadata do not expand Arbiter's scope.

Public sources: [Ollama exact tag](https://ollama.com/library/qwen3:4b-instruct-2507-q4_K_M), [upstream model license](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507/blob/main/LICENSE), [Apache 2.0 terms](https://www.apache.org/licenses/LICENSE-2.0). Record the user's model/license approval associated with the download instruction; no license was accepted on the user's behalf by the assistant. Redistribution requires retaining the license and applicable attribution/NOTICE, and identifying modifications. Do not equate approval with a completed redistribution/legal review.

#### Separate local Keycloak issuer

The user-selected issuer was provisioned as a separate local Phase 0 dependency, not implemented in Arbiter or added to Arbiter Compose. Keycloak 26.7.4 runs as `arbiter-p0-keycloak`, with D: persisted data, 768 MiB memory, 2 CPUs and JVM heap 128–512 MiB. Dedicated network `arbiter-p0-identity`; only host loopback `127.0.0.1:18443 -> 8443` is published. It uses `start-dev`/H2 and a local certificate: suitable for this developer preflight, not a production identity deployment. Internal HTTP is present under the dev profile but is not host-published.

| Public configuration | Verified value |
| --- | --- |
| Exact issuer | `https://localhost:18443/realms/arbiter` |
| Audience / algorithm allowlist | `arbiter-api` / `RS256` only |
| Discovery | `https://localhost:18443/realms/arbiter/.well-known/openid-configuration` |
| Public JWKS | `https://localhost:18443/realms/arbiter/protocol/openid-connect/certs` |
| Container JWKS transport | `https://arbiter-p0-keycloak:8443/realms/arbiter/protocol/openid-connect/certs` on the separate private identity network. The issuer comparison still uses the exact canonical issuer above. |
| Explicit TLS trust file | `D:\AI & ML\ArbiterData\phase0\identity-ca.pem`; SAN includes localhost, host.docker.internal and arbiter-p0-keycloak. No system trust-store change. |
| Certificate fingerprint | SHA-256 `73:9C:73:DE:7F:4A:08:D0:DF:CE:72:E2:D1:04:59:58:4F:18:A2:8B:E0:DF:96:3B:A5:97:57:F2:A1:B7:6E:32` |
| Certificate validity | 2026-09-26 16:24:38 UTC to 2026-10-26 16:24:38 UTC; renew before expiry and rerun TLS checks. |
| Human client plan | Public `arbiter-cli`, authorization code + PKCE S256, direct grants disabled; local callback `http://127.0.0.1:8765/callback`. Self-registration disabled; access token lifespan 300 seconds. |

Live discovery/JWKS and a disposable service-account access token passed TLS, signature, issuer, audience and expiry verification from Linux; wrong audience and wrong issuer were rejected (`oidc-report.json`). The initial host.docker.internal transport failed TLS EOF; the dedicated network hostname with a matching certificate SAN passed. Tokens/private key contents were neither printed nor persisted in reports. No human tenant memberships exist yet; JWT tenant/role claims remain non-authoritative under Design.md. The probe client is solely an identity diagnostic and must not become an application authorization bypass. See [Keycloak hostname configuration](https://www.keycloak.org/server/hostname).

#### Reproducible version recommendations and dependency checks

Tags were resolved to immutable manifests and pulled; actual Python/PostgreSQL/Redis/Ollama versions were checked. These are concrete implementation pin recommendations under the user's Phase 0 authorization, not project dependency files or a release vulnerability verdict.

| Image | Multi-platform/index digest | Linux amd64 digest |
| --- | --- | --- |
| `python:3.13.15-slim-bookworm` | `sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26` | `sha256:3e2de9c40ca4e3d73240059f9d48baff27908f10293e985a2f382a0378e6df4a` |
| `postgres:17.11-bookworm` | `sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652` | `sha256:91eb910c44c7ed13f7f1a4ccadaa9ca72ef14cddc04cacb6e070e48eb44731a3` |
| `redis:7.2.16-bookworm` | `sha256:0637954999d01b7c9ce9167db2da50656e2590d3b884f1c600c5f63bb6e6773c` | `sha256:ba2aa7b21f4d81ccbb3d190a26f83f2cab308f014cb10f651b1d86a855d392d7` |
| `ollama/ollama:0.34.4` | `sha256:8262851b2846b87c649eddf3e76beb270c52f4d1bc94559f47efde16b0841551` | `sha256:4be1eaabf0dd0152bfbb780347e2888b5fe86ec25d0faa3eb4b1a956173736fb` |
| Separate `quay.io/keycloak/keycloak:26.7.4` | `sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c` | Used the pinned published manifest; no separate architecture digest recorded. |

Redis 7.2 was selected as the BSD-licensed branch with continued support stated in the [official security policy](https://github.com/redis/redis/security/policy); this does not claim future patch coverage without rechecking. [Keycloak release 26.7.4](https://github.com/keycloak/keycloak/releases/tag/26.7.4) was verified as published 2026-09-16.

Disposable Python 3.13.15 install: FastAPI 0.141.1, Uvicorn 0.54.0, SQLAlchemy 2.1.1, Alembic 1.20.0, psycopg[binary] 3.3.6, redis client 8.1.0, Pydantic 2.13.5, pydantic-settings 2.15.0, HTTPX 0.28.1, PyJWT 2.15.0, cryptography 50.0.1. Imports, `pip check`, synthetic RS256 and negative audience validation passed (`runtime-report.json`). Full 29-package resolved list is `phase0\resolved.txt`; an OSV querybatch found no known vulnerable package among those 29 at 21:35 IST (`dependency-audit.json`). No repository dependency manifest, lockfile or application environment was created. Candidate development tools only: pytest 9.1.1, pytest-asyncio 1.4.0, Ruff 0.16.9, mypy 2.3.1, pip-audit 2.10.1; metadata checked, not installed/locked.

#### Capacity evidence and current assessment

Both initial cold tests used the installed exact digest, 4,096 context, two provider slots, flash attention and a 120-second request deadline. Native 0.34.1 and Linux 0.34.4 both timed out before their first generation completed; neither establishes throughput or validates global concurrency 2. Both logged 37/37 GPU layers with a 2,375.91 MiB CUDA model buffer and 304.28 MiB host model buffer. Allocating buffers is not successful generation.

| Failed cold run | Completed requests | Minimum host free RAM | Maximum GPU used / minimum GPU free |
| --- | --- | --- | --- |
| Native 0.34.1 | 0 | 158 MiB | 4,364 / 3,533 MiB |
| Linux 0.34.4 | 0 | 295 MiB | 4,340 / 3,557 MiB |

Each sampled 238 times at approximately 500 ms intervals; preserved as `benchmark-native-cold-failed.json` and `benchmark-linux-cold-failed.json`. Linux cgroup memory events showed no OOM, OOM kill or limit hit. Host memory was under heavy unrelated desktop load. WSL held approximately 6.15 GiB of reclaimable page cache after image pulls (working set approximately 7 GiB). At about 22:04 IST, `wsl -d docker-desktop -u root -- sh -c 'sync && echo 3 > /proc/sys/vm/drop_caches'` reclaimed cache without stopping services or removing data. WSL later used approximately 2.8 GiB and host free RAM reached approximately 4.5 GiB. No `.wslconfig` modification or global WSL restart was performed. Cache pressure is an observed contributor, not a proven sole cause; initialization remained slow after reclaim. [Docker WSL guidance](https://docs.docker.com/desktop/features/wsl/) discusses automatic memory reclaim; persistent resource changes require separate impact review for shared workloads.

An operator-only prewarm with a separate 600-second diagnostic timeout was then attempted; this does not change Design.md's 120-second inference deadline. Final prewarm/benchmark results and the exit assessment are recorded in the follow-up below.

#### Provisioning and security handoff

- Local identity secret files exist under the protected D: secret directory. Application runtime/migration/operator database passwords, key pepper and separate payload-fingerprint secret have **not** been generated or wired. Recommended provisioning: independent cryptographically random secret files, separate credential ownership/grants, explicit pepper/fingerprint versions, runtime access only to its required files; migration/operator credentials excluded from API runtime. Implement and verify this in its owning milestone, not during Phase 0.
- Backup staging is designated on D:, but an independent protected backup copy and a tested restore are later operational deliverables. A same-disk directory is insufficient disaster recovery evidence.
- Static threat-review coverage in the earlier entry was rechecked against unchanged Rules.md/Design.md: tenant spoofing, RLS/context reuse, mixed-tenant references, admission races, provider bypass, crash accounting and secret leakage. No application exists, so none of those runtime guarantees has been tested. No material document contradiction requiring an edit was found.
- Container CVE audit is **incomplete**. Trivy 0.74.0 pinned at `sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969` first timed out downloading its vulnerability database; retry from ghcr.io was denied. No clean-image claim follows from either failure. Further scan outcome is recorded below.
- Existing unrelated Axiom containers and desktop applications were not stopped. Diagnostic provider/identity ports are loopback only; they are preflight services and do not redefine Architecture.md's future Compose exposure. Synthetic benchmark diagnostics store timings/counts/resource samples, not prompts or generated text. Public OIDC configuration/certificate is safe to share; secret-file contents are not.
- Current exit assessment pending measured inference completion. Phase 1 remains unstarted; model capacity P0-05 cannot be marked passed from VRAM allocation alone. Earlier P0-01/P0-02/P0-03 now have verified values; P0-04 has reproducible candidates and successful Python compatibility checks; P0-06 has a concrete local provisioning/staging plan with later implementation/restore checks explicitly unrun.

#### Follow-up: measured inference and Phase 0 disposition

The first extended prewarm returned HTTP 500 after **364.457 seconds**, with `timed out waiting for llama-server to start`. It is preserved in `prewarm-first-failed.json`. Memory pressure recurred during the image audit; the first cache reclaim was not sufficient to establish sustainable cold initialization.

For an isolated retry, only the diagnostic scan was paused and the diagnostic Keycloak container temporarily stopped. The diagnostic Ollama container was recreated using its same immutable image/model volume, with **6 GiB memory, 8 GiB memory+swap ceiling, 4 CPUs and an operator load timeout of 15 minutes**; parallelism 2/context 4,096 remained unchanged. No model was redownloaded, no unrelated process/container stopped, and Design.md's request deadline remained 120 seconds. An early probe before server readiness returned an empty reply; the model attempt began only after version/tag checks succeeded. Prewarm then returned HTTP 200 in **99.588 seconds**, with `done_reason=load`; this loaded the model but generated no completion. All 37 layers remained GPU-resident. Treat this as an observed configuration, not proof that the memory limit alone caused the improvement.

Two subsequent synthetic suites completed, each with 15 requests and every request bounded to 120 seconds:

| Suite / load | Observed result |
| --- | --- |
| First successful generation suite (`benchmark-linux-first-passed.json`) | All 15 passed. First actual generation took 36.625 seconds (prompt evaluation 33.982 seconds); later warm requests were faster. Maximum sampled GPU use 5,802 MiB, minimum GPU free 2,095 MiB, minimum host free 2,644 MiB. Several outputs stopped naturally before their cap; this suite alone did not exercise both cap boundaries. |
| Exact-cap suite (`benchmark-11436.json`) | All 15 passed; output caps 32, 256 and 1,024 were reached exactly with finish reason `length`; no count exceeded its cap. Three single 256-token runs took 2.590–2.686 seconds. Three two-request 256-token batches took 3.712–3.914 seconds. |
| Long-context 1,024 output | Single: 1,389 input + 1,024 output tokens, 14.487 seconds. Pair: same token counts per request, 16.422 and 16.433 seconds. |
| Near-context pair | Each request: 2,877 input + 1,024 output tokens, 15.544/15.582 seconds; observed runner `truncated=0`. Context plus output stayed within 4,096. The earlier suite's 3,127-input requests stopped at 960 output tokens; do not mistake those for a 1,024-token reservation test. |
| Exact-cap resources | 131 approximately 500 ms samples; peak GPU use **5,982 MiB**, minimum GPU free **1,915 MiB**, minimum host free **507 MiB**. Keycloak had been restored and the diagnostic image scan resumed during this suite. Cgroup OOM/limit-hit counters stayed zero. `/api/ps` reports full model digest, context 4,096 and 3,864,977,735 bytes GPU residency. |

**Capacity recommendation:** retain Design.md's tenant concurrency 1/global concurrency 2 for this pinned 4B model at context 4,096 and output cap 1,024, conditional on operator prewarming and the measured deployment settings above. This supports the defaults for the tested warm synthetic workload; it is not tenant-admission enforcement, workload quality, sustained saturation or production latency evidence. Repeated synthetic prefixes also benefit from provider prompt caching; no general throughput promise follows. Real application admission tests remain in their phases.

Cold startup remains fragile under shared desktop/WSL/image-scan load: the successful operator load plus first generation would together exceed a 120-second cold request. Recommended operational approach is to preload/warm the pinned model before accepting inference and reserve host RAM; do not lengthen application deadlines or add request-triggered downloads/retries. Validate that procedure and logging with the actual adapter in Phase 4. Avoid simultaneous image extraction/benchmark cold starts. Automatic WSL memory reclaim/resource ceilings deserve a later operator change review because the shared engine has unrelated workloads; no persistent WSL setting was changed here. Do not treat the 507 MiB minimum host headroom as comfortable capacity for additional services or a larger model.

| Earlier blocker | Current disposition / remaining owner |
| --- | --- |
| P0-01 issuer | Resolved for local development: user selected separate Keycloak; exact public inputs and live verification recorded above. Operator must renew local TLS certificate before 2026-10-26 and provision human identities as needed. Production identity hardening remains outside this local preflight. |
| P0-02 engine | Resolved: Linux engine, WSL2 and GPU passthrough verified. Existing shared E: storage retained intentionally. |
| P0-03 model | Resolved: user approval, completed D: download, exact identity/digests and Apache 2.0 evidence recorded. |
| P0-04 versions | Resolved as implementation inputs: immutable image references and compatible exact Python runtime versions recorded. Generate actual project locks with integrity hashes and recheck vulnerabilities during implementation/release. Container scan status is explicitly separate below. |
| P0-05 capacity | Resolved as an assessment: warm single/pair, exact output caps and bounded context passed with the stated settings; cold failures and memory-pressure limits remain recorded. |
| P0-06 provisioning | Resolved as a concrete local plan/storage designation; app secrets, restricted database grants, backup automation and restore are implementation/release work, not completed checks. |

**Phase 0 passes for beginning foundation work:** no unresolved configuration choice prevents implementation, and the tested hardware supports the default concurrency under the recorded warm-model conditions. This does not claim application readiness or approve later phase gates. Phase 1 has not been started. Seven other document SHA-256 hashes match the pre-session baseline; only Memory.md changed in this workspace. Diagnostic tools/evidence and provisioned service state are outside the workspace on D: and in the existing Docker engine.

**Proposed first task, not executed:** Phase 1 foundation—create the typed modular FastAPI package and digest-pinned Compose dependency topology with secret-file inputs, D-backed persistent named volumes and separate database credential roles; keep inference unavailable. Acceptance for this bounded first task: clean dependency startup, explicit migration entry point, minimal liveness/readiness, no published dependency/provider ports, no runtime access to operator/migration secrets, and no inference endpoint. Tenant persistence/RLS migrations and their two-tenant negative tests remain necessary before Phase 1 exits; this task alone cannot pass that phase.

#### Final checks and service handoff (approximately 22:23 IST)

- The Trivy database finally downloaded from mirror.gcr.io and is cached on D:, but the 15-minute image analysis timed out on `usr/lib/ollama/cuda_v12/libcublas.so.12.8.5.5`. The scanner exited 1 and its disposable container was removed; no vulnerability JSON verdict was produced. Earlier download failures and this analysis failure are not passes. Container OS/library vulnerability review remains assigned to the maintainer before release (Phase 5); only the 29-package Python OSV query completed. The cached database enables a later retry without another database download. This pending release check does not supply a clean-image claim or change the Phase 0 implementation-input assessment.
- Separate Keycloak restarted in 18.860 seconds, retained the existing `arbiter` realm and skipped reimport. A plain localhost discovery probe timed out; explicitly resolving localhost to IPv4 with `curl.exe --resolve localhost:18443:127.0.0.1 --cacert <public certificate>` returned HTTP 200 and preserved hostname/certificate validation. Record/use this Windows loopback transport check; do not disable TLS validation. The Linux configured private-network JWKS path already passed live verification.
- The native provider is stopped. After measurement, the diagnostic Linux provider was stopped as well to release GPU/RAM; its container/model volume are retained for reproducibility. Keycloak remains running on its dedicated network/loopback TLS port. The diagnostic Redis container is stopped, and no scanner remains. Unrelated Axiom containers remain running. Model assets, identity data, secret files, diagnostics and vulnerability database remain under the recorded D: paths; shared Docker storage remains `E:\Docker\wsl`.
- No application code, schema, project dependency file, Compose file, Git repository or Phase 1 implementation was created. No further human decision is required to propose the foundation task above. Before future inference validation, deliberately prewarm the model and reconfirm resource headroom; current stopped-provider state is not inference readiness.
- Final inventory also contains an existing 11-byte root README.md (`# Arbiter`), left untouched. The seven other specification/workflow document hashes still match baseline. Final image inspection by digest confirms all five recorded images exist; tag-only inspection was not applicable to images pulled solely by digest.

### 2026-09-26 — Documentation commit validation (22:31 IST)

- User authorized checking tests/security and committing the files. Git is now present: branch `main`, baseline `53bed8f` (`docs: establish Arbiter v0.1 specification`). Earlier no-Git observations refer to their historical snapshots. Only `docs/Memory.md` is modified; approved specification documents remain unchanged.
- No application source, test suite, test configuration, dependency manifest or CI workflow exists in the tracked inventory. Application tests, lint/type checks, RLS/migration tests and application security tests therefore cannot run; none is reported as passing. No Phase 1 work was started to manufacture tests for this documentation commit.
- `git diff --check` passed. All local Markdown links under `docs/` resolve. A focused credential-pattern/secret-filename check passed over all 10 tracked files without printing candidate values.
- Trivy 0.74.0, using the previously recorded immutable scanner digest, scanned the repository read-only with networking disabled and `.git` excluded: exit 0, zero detected secrets. Public issuer/model/image digests and certificate fingerprint are configuration/integrity evidence, not credentials. Report: `D:\AI & ML\ArbiterData\phase0\repository-secret-scan.json` (outside Git).
- This repository secret scan is separate from the earlier incomplete container vulnerability audit. It does not resolve that timeout or certify application isolation. Only the reviewed memory document is intended for the local commit; no push is authorized by this task.

## Implementation history

### 2026-09-26 — Phase 1, task 1: foundation scaffold

**Bounded task completed; Phase 1 remains incomplete.** User explicitly accepted Phase 0 for foundation work and authorized this one implementation task, with no commit/push. Base revision: `67e4490` on `main`. All eight documents were read; no specification contradiction requiring an edit was found. Approved specification/workflow documents remain unchanged.

Implemented the first foundation task proposed above: typed modular FastAPI package, digest-pinned Compose dependencies, independent database secret files/roles, explicit privileged bootstrap and Alembic migration commands, minimal health, and verification tooling. Files: `src/arbiter/`, `compose.yaml`, Dockerfile, pyproject.toml, hash-pinned runtime/development locks, Alembic configuration/foundation revision, tests, local preparation/lock scripts, ignore files and README operational instructions. No identity verification, tenant persistence/provisioning, admission, accounting or provider adapter was implemented.

#### Observable behavior and security boundaries

- API exposes only health routes; live returns 200 `{"status":"ok"}`, ready always returns 503 `{"status":"not_ready"}`. Readiness does not pretend that dependency connectivity satisfies unimplemented enforcement/schema/identity/recovery gates. Missing/empty runtime secret prevents startup. Secret-file IO runs off the event loop. Debug, generated API documentation, proxy-header trust and access logging are disabled.
- Explicit one-shot bootstrap provisions fixed `arbiter_migration`, `arbiter_operator`, `arbiter_runtime` roles; unexpected existing memberships fail closed. Only the separately held bootstrap credential is a superuser. The three application roles are NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE, with no inheritance. Bootstrap/migration/operator credentials are absent from the API container.
- Alembic revision `0001_foundation` creates the `arbiter` namespace and explicit usage grants; Alembic's version marker resides in public and is migration-owned. No tenant tables exist. Namespace creation occurs in the migration, not API startup or role bootstrap. Only the migration role receives CREATE privileges needed for schema/version management. Future table/RLS/grant creation remains an explicit migration responsibility; there are no blanket future-table grants.
- API uses UID/GID 10001, a read-only root filesystem, dropped capabilities and no-new-privileges. Actual container inspection found only the read-only runtime password mount. Only `127.0.0.1:8000` is published. A dedicated API edge network enables the loopback mapping; PostgreSQL/Redis stay on the internal control network, Ollama on a separate internal provider network. The API is not attached to the provider network in this scaffold. Keycloak remains outside Compose.
- Real secrets were generated independently with 48 random bytes each, stored only in the protected D: secret directory. Password-bearing bootstrap statements disable session statement/error-statement logging; CLI failures print exception classes rather than driver bodies. Existing credential bytes survive repeated local preparation. No pepper/fingerprint secret or tenant/API-key credential was generated in this task.

#### Verification evidence (approximately 22:55–23:13 IST)

| Check | Actual outcome / limit |
| --- | --- |
| Hash-verified image builds | Runtime dependencies installed with `--require-hashes`: 21 locked packages; verification environment: 35 locked packages including runtime. Locks select Python 3.13/Linux amd64 binary artifacts. Docker base/database/Redis/Ollama pins reuse the verified Phase 0 selections. |
| `docker compose --env-file .env.example config --quiet`; clean dependency initialization and `up --wait` | Passed. Fresh PostgreSQL 17.11 data initialized on D: and became healthy; Redis and Ollama metadata health passed. API liveness health passed. Docker service health is not Arbiter inference readiness. |
| Explicit bootstrap; migration from empty; repeated migration | Bootstrap passed. First migration attempt failed with ProgrammingError because the migration role lacked database CREATE permission. Granting CREATE only to migration resolved it. Migration then passed and a second run passed without a new revision/object. No prior supported application schema exists yet. |
| Real PostgreSQL pytest run, including repeat after database restart | **16 passed**, no skips in the integration run. Runtime/operator creation in application/public schemas, database schema creation, privileged SET ROLE and migration-marker reads were denied with SQLSTATE 42501; role flags and migration ownership verified. Two synthetic tenant selectors could not activate nonexistent workload routes. These are boundary-denial tests, not proof of two-tenant RLS. Latest JUnit evidence: `phase1\foundation-tests.xml`. |
| Offline unit run | 13 passed, 3 database tests explicitly skipped without provisioned PostgreSQL. Integration above subsequently ran those three. Starlette reports one TestClient/httpx deprecation warning; tests pass, warning not suppressed. Review its supported replacement before updating test dependencies. |
| Ruff lint / format | Passed after fixing initial import/line-length findings. Whole checkout format check reported 27 files already formatted. Read-only format check initially tried to write its cache; `--no-cache` corrected the verification command. Final frozen verification image checks also passed. |
| Strict mypy; `pip check` | Passed: 17 typed source/test/migration files, no type errors; no broken package requirements. Read-only pip check disabled an unwritable cache; that warning is not a dependency failure. |
| OSV querybatch on development lock (includes runtime) | 35 packages checked at 23:01 IST, no known vulnerable package returned. Evidence: `phase1\dependency-audit.json`. This is not an OS/container-library audit or a general security certification. |
| Trivy 0.74.0 repository secret scan; exact secret comparison against service logs | Secret scan exit 0, zero detected secrets. No actual database password was found in API/PostgreSQL/Redis/Ollama logs; values and raw logs were suppressed. Evidence: `phase1\repository-secret-scan.json`. |
| Runtime topology and live HTTP | Actual ports/mounts/user/read-only-root checks passed; snapshot `phase1\runtime-topology.json`. Wire requests: liveness 200, readiness 503, POST chat 404. The first host HTTP checks failed with an internal-only API network; adding the API-only edge network fixed host reachability without publishing dependencies. A PowerShell array-wrapper error in the initial inspection command was corrected before the passing check. |
| Provider metadata only | Exact approved manifest is present in the reused D: cache; `/api/ps` reports no loaded models. No generation, benchmark, model pull or new external account was performed. |
| Secret provisioning script | Parsing passed; repeated default preparation retained all four actual credential hashes. Fresh and repeated isolated preparation also passed. Initial Set-Acl repetition requested unavailable SeSecurityPrivilege; replacement verifies existing permissions and uses DACL-only icacls for new inherited directories. Only current user/SYSTEM/Administrators with FullControl are accepted. |

#### Storage, operational effects and remaining work

- New persistent named volumes: `arbiter_postgres_data` -> `D:\AI & ML\ArbiterData\postgres`, `arbiter_redis_data` -> `D:\AI & ML\ArbiterData\redis`, `arbiter_ollama_models` -> the existing `D:\AI & ML\ArbiterData\ollama\models`. Their bind devices use the recorded Docker Linux-visible D: root. Initialization/restart established that the PostgreSQL D: mount works on this host; no storage incompatibility was assumed.
- Actual database secret files: `db_bootstrap_password`, `db_migration_password`, `db_operator_password`, `db_runtime_password`, under the existing D: secrets directory. Reports and isolated provisioning probe reside under `D:\AI & ML\ArbiterData\phase1`; scratch remains on D:. Shared Docker/BuildKit/WSL storage stays on E: as previously documented; unrelated data/services were not relocated or stopped.
- Local built image references at verification: runtime `sha256:00e0720fb482afb696a3c2a64f8c65f513f153856b0dd192f9b395e9a0d3b661`; verification `sha256:1edb7187cb2874b87b7b3a61761ec1ef905f56a20d5c4f0f23b0bac84f2cfb25`. These identify local builds, not published release images or a committed source revision.
- Tenant tables, FORCE RLS, composite foreign keys, scoped transactions/connection-pool reuse, tenant/member provisioning and their real two-tenant negative tests remain **unimplemented/unrun**. Full readiness remains deliberately closed. Later identity/governance/inference phases were not started. The earlier container vulnerability-audit timeout remains unresolved release evidence; the successful secret/Python dependency scans do not replace it.
- Next bounded Phase 1 task, proposed only: tenant-owned persistence migrations and authenticated transaction-local tenant context, with restricted-role RLS, composite relationship and pooled-connection negative tests. Stop after this foundation task; do not execute that next task without a new task instruction.
- No changes were staged, committed or pushed in this implementation session. Final service shutdown and document-hash verification are recorded below.
- Final shutdown at 23:16 IST: only this task's API/PostgreSQL/Redis/Ollama containers were stopped; their containers, named volumes and D: data are retained. Separate Keycloak and unrelated Axiom services remained running. The seven other documentation SHA-256 hashes match the session-entry baseline. HEAD remains `67e4490`, index empty; the implementation is an uncommitted working-tree change. Restart using the README sequence before another integration check.

### 2026-09-26–27 — Phase 1, task 2: tenant persistence and database isolation

**Bounded task completed; Phase 1 remains incomplete.** Phase 0 acceptance for foundation work remains the user-authorized prerequisite. Session entry was clean on `main` at `7b99bca200ef9c3763d3f326e990d9cbb774d4f1` (`feat: establish Arbiter Phase 1 foundation`), which supersedes the preceding entry's uncommitted-scaffold snapshot. Read all eight documents and inspected the actual scaffold. No contradiction requiring an approved specification change was found. The seven specification/workflow documents have no diff against HEAD.

#### Files changed and observed implementation

- Added `migrations/versions/0002_tenant_isolation.py`: initial `tenants`, global `principals`, `memberships`, and `audit_events`, with constraints, indexes, policies and explicit grants in one migration. No later-phase records were added. The tenant root's non-null `tenant_id` is generated from its own `id`; membership/audit ownership is explicitly non-null. Root references point to the tenant identity; the tenant-owned object relationship from audit actor to membership uses the composite `(tenant_id, actor_membership_id) -> memberships(tenant_id, id)` foreign key. Principal references address the separately restricted global directory, as specified in [Design.md](Design.md).
- Added `src/arbiter/identity/context.py` and `src/arbiter/persistence/tenant.py`: immutable UUID binding, SQLAlchemy transaction-local `set_config(..., true)`, bounded runtime-only pool, expired/context-changed transaction rejection, and rejection/discard of a connection containing unexpected session-wide context. This is a trusted-service binding value, **not identity verification**; it is not constructed by any HTTP route. Synchronous persistence is not wired into the event loop.
- Added `src/arbiter/persistence/repositories.py`: tenant and membership reads, tenant-qualified audit/member join, and a metadata-only audit append primitive deriving ownership from context. Queries bind values; no caller can supply a tenant to an append. The append uses the existing transaction, with no separate commit. No administration, membership authorization, OIDC, API-key or other Phase 2 service was implemented.
- Added `tests/test_tenant_isolation.py`, `tests/test_tenant_context.py`, and `tests/test_migrations.py`; updated the foundation database test to expect the new head/four tables while retaining its privilege denials. Updated `alembic.ini` with `path_separator=os` to remove the migration configuration deprecation. README now documents the scoped persistence boundary and separate privileged migration-test invocation. This entry updates `docs/Memory.md`.

#### Real PostgreSQL security evidence

- PostgreSQL reports **17.11 (Debian 17.11-1.pgdg12+2)**, numeric version `170011`. The existing D:-backed application database upgraded from `0001_foundation` to `0002_tenant_isolation`; a repeated upgrade and a PostgreSQL restart preserved the schema and passed the final tests.
- All three tenant-owned tables have ENABLE and FORCE RLS, a restrictive ownership policy with both USING/WITH CHECK, and non-null ownership columns. An invoker trigger rejects changes to object/tenant identity; its search path is fixed to `pg_catalog` and runtime execution is not granted. All four tables remain migration-owned.
- Missing context returns zero rows from tenant tables under runtime, operator **and the forced table owner**; missing/invalid/null context writes fail closed. With context A, unfiltered runtime reads and deliberately under-scoped raw joins expose only A. Forged B identifiers return no membership through A's repository.
- A can append its own audit event; an attempted B-owned append under A fails with SQLSTATE `42501`. Scoped operator UPDATE affects zero B rows, while the positive A control updates one row before rollback. Ownership-column changes are denied by operator grants and RLS; an owner object-ID change triggers SQLSTATE `23514`.
- Linking an A audit event to B's membership fails with `23503` on `audit_actor_membership_fk`; a nonexistent membership produces the same code/constraint. Repository actor lookup rejects both as inaccessible. SQL observation independently confirms tenant binds/predicates on reads and both join sides, and context-derived ownership on inserts, rather than relying solely on RLS.
- The single-connection test pool reuses the **same `pg_backend_pid()`** through A, no-context, and B transactions after commit and rollback. No-context reads remain empty; B cannot retrieve A's membership. Deliberately poisoned session-wide context is rejected and its connection discarded; the next backend is different and unscoped reads are empty. Repository reuse after transaction closure or context change is rejected. Audit append rollback removes the event with its caller's transaction.
- Runtime is NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE/NOINHERIT/NOREPLICATION, owns no table and has no role memberships. SET ROLE to operator/migration/bootstrap, role elevation, policy alteration, DISABLE/NO FORCE RLS, migrations/schema creation, migration-marker reads and TRUNCATE are denied. `SET LOCAL row_security=off` does not permit a read. Runtime has only scoped SELECT on tenant tables and INSERT on audit; it cannot administer tenants/memberships, read the global principal directory, or UPDATE/DELETE audit. Direct grant/catalog evidence is in `database-security.json`.
- These tests prove the persistence boundary under established contexts. They do not prove caller authentication or protection against arbitrary SQL executing its own tenant settings; [Architecture.md](Architecture.md) retains that trust boundary. Future identity/operator services must establish authority before constructing context, and all administrative mutations must append audit evidence atomically.

#### Checks run and actual outcomes

Final verification used the rebuilt pinned Python 3.13 container, real Compose PostgreSQL, and separately mounted test credentials. Frozen-image tests below ran without a workspace source mount. Evidence directory: `D:\AI & ML\ArbiterData\phase1\tenant-isolation`.

| Check | Result |
| --- | --- |
| `docker compose --env-file .env.example config --quiet`; `build api`; `docker build --target verification -t arbiter-local:verification .` | Passed. Existing hash-locked runtime/development dependencies and immutable base pins retained; no dependency change. |
| `docker compose --env-file .env.example up -d --wait postgres`; explicit `--profile operations run --rm migrate`; restart PostgreSQL; repeated migration | Passed. Application database was upgraded, never downgraded. Data remains at the previously recorded D: PostgreSQL path. |
| Foundation/context/isolation pytest invocation below, after DB restart | **54 passed, zero failures/errors/skips**. JUnit: `isolation-tests.xml`. One existing Starlette/TestClient/httpx deprecation warning remains unsuppressed. |
| Separate privileged migration pytest invocation below | **2 passed, zero failures/errors/skips**. Each creates a fresh random-name database, tests empty or previous-supported-schema upgrade, repeated head, downgrade/re-upgrade on empty disposable tables, and full base/head round trip. Test databases were removed. JUnit: `migration-tests.xml`. |
| Whole-checkout `ruff check --no-cache .`; `ruff format --check --no-cache .` | Passed; final format check: 34 files already formatted. |
| Frozen-image `mypy --cache-dir /tmp/mypy`; `python -m pip check` with cache disabled | Passed: 24 source/test/migration files, no type errors; no broken requirements. |
| PyPI OSV `POST https://api.osv.dev/v1/querybatch`, generated from `requirements-dev.lock` | 35 locked packages queried, 35 response entries validated, zero known advisories returned. `dependency-audit.json`. This is not an OS/container-library verdict. |
| Digest-pinned Trivy 0.74.0 repository secret scan below; exact comparisons of four real DB passwords against API/PostgreSQL/Redis logs | Passed: zero detected repository secrets and no actual DB password in those service logs. Reports: `repository-secret-scan.json`, `log-secret-comparison.json`; secret values/raw logs were never displayed. |
| `python /reports/database_security_probe.py` in the verification container with migration secret only | Passed role/grant/RLS ownership, fixed invoker function, version/head and zero remaining disposable-database checks. Script and `database-security.json` reside only in the D: evidence directory. |
| `up -d --wait postgres redis`; explicit migration; `up -d --wait api`; actual HTTP and container inspection | Passed. Live 200, ready 503, POST chat 404. API remains UID/GID 10001, read-only, mounted with only the read-only runtime password, and off the provider network. API publishes only loopback 8000; PostgreSQL has no host port. Ollama remained stopped. `runtime-topology.json`. |
| `git diff --check`; `git diff --cached --name-only`; seven approved document diffs | Passed whitespace check; index empty; approved specifications/workflow unchanged. HEAD unchanged; no commit/push. |

Reproducible final test and scanner commands (paths contain public configuration only):

```powershell
$taskSecretRoot = 'D:\AI & ML\ArbiterData\secrets'
$taskReportRoot = 'D:\AI & ML\ArbiterData\phase1\tenant-isolation'
$taskDbMounts = @(
  '--mount', "type=bind,source=$taskSecretRoot\db_runtime_password,target=/run/secrets/db_runtime_password,readonly",
  '--mount', "type=bind,source=$taskSecretRoot\db_operator_password,target=/run/secrets/db_operator_password,readonly",
  '--mount', "type=bind,source=$taskSecretRoot\db_migration_password,target=/run/secrets/db_migration_password,readonly"
)
docker run --rm --read-only --tmpfs /tmp --network arbiter_control `
  -e ARBITER_TEST_DATABASE=1 --mount "type=bind,source=$taskReportRoot,target=/reports" `
  @taskDbMounts arbiter-local:verification python -m pytest -q -p no:cacheprovider `
  tests/test_foundation.py tests/test_database_foundation.py tests/test_tenant_context.py `
  tests/test_tenant_isolation.py --junitxml=/reports/isolation-tests.xml
docker run --rm --read-only --tmpfs /tmp --network arbiter_control `
  -e ARBITER_TEST_MIGRATIONS=1 --mount "type=bind,source=$taskReportRoot,target=/reports" `
  --mount "type=bind,source=$taskSecretRoot\db_bootstrap_password,target=/run/secrets/db_bootstrap_password,readonly" `
  --mount "type=bind,source=$taskSecretRoot\db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider tests/test_migrations.py `
  --junitxml=/reports/migration-tests.xml
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff format --check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  arbiter-local:verification mypy --cache-dir /tmp/mypy
docker run --rm --network none --read-only --tmpfs /tmp -e PIP_NO_CACHE_DIR=1 `
  arbiter-local:verification python -m pip check
docker run --rm --network none --memory 1g --cpus 2 `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' `
  --mount "type=bind,source=$taskReportRoot,target=/reports" `
  --mount 'type=bind,source=D:\AI & ML\ArbiterData\tmp,target=/tmp' `
  aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 `
  fs --scanners secret --skip-dirs /workspace/.git --timeout 3m --exit-code 1 `
  --no-progress --format json --output /reports/repository-secret-scan.json /workspace
```

#### Corrected observations, operational handoff and remaining gates

- Initial integration run: 47 passed and one test failed because it expected NOT NULL SQLSTATE `23502`; the actual null-ownership insert is rejected earlier by RLS with `42501`. Corrected that expectation, retaining the denial and independent NOT NULL catalog assertions. Initial style/type findings were fixed without blanket ignores. A patch context mismatch after formatting was corrected before rerunning checks.
- Initial migration transitions passed, but both teardowns errored on the unsupported `DROP DATABASE ... WITH (FORCE false)` syntax. Replaced it with ordinary non-FORCE DROP. Independently verified ownership and emptiness of exactly the two newly created test databases before removing them; the successful reruns also completed cleanup. No unrelated database was dropped or downgraded. An initial standalone catalog probe assumed Debian suffix `+1`; actual runtime suffix is `+2`. Its assertion failed, then version verification used the numeric version and recorded the full observed string. None of these initial failures is counted as a pass.
- Final builds observed via Docker inspection: runtime `sha256:6b5af84ab04edbc054e37067557b76b46e70b26f3405011b0832ff86e146b1c8`; verification `sha256:e16ff0882fadced1cda67ab3a6299849a02be9c6a878d35d8ed8407a44417451`. These are local builds from an uncommitted working tree, not published release artifacts.
- At approximately **00:10 IST on 2026-09-27**, stopped only this task's API/Redis/PostgreSQL services with `docker compose --env-file .env.example stop api redis postgres`. Containers, named volumes, credentials and D: state are retained. Ollama was never started. Separate Keycloak and unrelated Axiom services remain running. No model download/inference, external account, secret regeneration or unrelated storage relocation occurred.
- All bounded-task persistence criteria have current real-PostgreSQL evidence. **Phase 1 is not complete:** local tenant/member provisioning commands and transactional administrative audit are still missing; a final whole-phase clean-stack/operational exit review remains to be performed. Readiness stays fail-closed rather than claiming unimplemented identity/enforcement gates. Phase 2+ remains unstarted.
- Existing release blocker remains: the prior OS/container-library vulnerability scan timed out and has no clean-image verdict. Assigned to the maintainer before release, as previously recorded. The current Python/secret scans do not resolve it; no repeat of the large Ollama image audit was required for this database-only task.
- **Next bounded Phase 1 task, proposed only:** separately credentialed local tenant/member provisioning commands using the scoped transaction/repository boundary and atomic operator audit events; prove successful provisioning, rollback, duplicate handling and denied privilege/tenant reassignment with real PostgreSQL. Keep OIDC/API keys/governance/inference unavailable. Do not execute this next task without a new instruction.
- No files were staged, committed or pushed. Restart PostgreSQL using the README/Compose commands before another integration run. Stop after this task.

### 2026-09-27 — Phase 1, task 3: local provisioning with atomic operator audit

**Bounded task completed; Phase 1 remains incomplete.** Entry was clean on `main` at `496b4ef9c2904ba93387c79b608b27b28ab20998` (`feat: enforce tenant-scoped persistence and RLS`), superseding task 2's uncommitted snapshot. Read the approved documents/current memory and inspected the actual foundation. Phase 0 acceptance for foundation work remains the prerequisite; no approved specification/workflow document was changed. No Phase 2 implementation or inference enablement occurred.

#### Changed files and observed behavior

- Added `src/arbiter/operations/provision.py`: typed local command service and CLI with `create-tenant`, `create-member`, and `set-tenant-status`. New IDs and correlation IDs are generated by the application. Member binding accepts the exact public issuer/opaque subject and `member`/`admin`; it performs no OIDC discovery, JWT verification, membership authorization or issuer-account creation. HTTPS public issuer validation rejects credentials/query/fragment/control characters/invalid ports; subject bounds/control validation does not normalize the opaque identifier. Argument and driver errors do not echo rejected input or SQL bodies.
- Added `src/arbiter/persistence/operator.py`: separately credentialed, bounded operator engine; authentication of both `current_user` and `session_user` as `arbiter_operator` before constructing context; scoped repositories for tenant/member/status writes and operator audit appends. Membership/status operations lock the tenant row first. The service commits the mutation, any new global principal, and audit together, returning identifiers only after commit. No automatic retry is provided.
- Updated `src/arbiter/persistence/tenant.py` to share the existing tenant-binding logic with an already-open authenticated operator transaction. Active transaction identity is checked; existing transaction-local settings, inherited-setting rejection, pooling and context-change guards remain. Updated its docstring and `persistence/repositories.py`'s docstring to identify the implemented separate operator path.
- Added `migrations/versions/0003_operator_audit.py`: a restrictive INSERT policy prevents `arbiter_runtime` from manufacturing `actor_type='operator'` audit rows. Existing tenant FORCE RLS, composite constraints and grants remain. No operator grant was broadened; no new application table, SECURITY DEFINER helper or runtime administration permission was added.
- Updated `compose.yaml` with an operations-profile, one-shot operator entry point mounting only `db_operator_password`. API mounts only `db_runtime_password`. The same application image, internal control network and existing D: storage are reused. Updated README with actual command examples, result/error behavior and operational boundaries.
- Added `tests/test_provisioning.py` and `tests/test_operator_validation.py`. Updated database foundation head assertions and migration coverage for empty, `0001_foundation` and `0002_tenant_isolation`, including preservation of preexisting tenant/audit records. Updated this memory entry. All seven approved specification/workflow documents remain unchanged.

#### Security and transaction evidence

- Real PostgreSQL successful provisioning creates an active tenant at policy revision 1; member/admin binding creates an active membership and a matching operator audit. The actor is the authenticated **shared database role**, not a claimed individual human. Audit object IDs, target IDs and command correlation IDs match committed results. Local role authentication is not future OIDC authentication.
- Suspended/active status changes affect only the selected scoped tenant and append their evidence in the same transaction. They leave allocation policy revision unchanged. Repeating the current status is a no-op (`changed=false`, no new success event). Trusted local operators can prepare membership records while suspended; no inference/HTTP authority follows from provisioning.
- Duplicate membership attempts and injected tenant UUID collisions fail without changing an existing binding/role or adding false success evidence. Missing tenants cause no new global principal. A single global `(issuer, subject)` identity may legitimately receive independent memberships in two tenants; runtime queries cannot use the other tenant's membership ID. Tenant ownership is never accepted through mass assignment or changed by these commands.
- For tenant creation, status change, and member creation, an injected **real PostgreSQL audit uniqueness violation** rolls back the entire mutation. Member failure also rolls back its newly inserted global principal. These are committed-database checks with a real constraint failure, not a mocked audit sink. Concurrent duplicate attempts on independent operator connections produce exactly one membership/success audit and one conflict.
- RLS rejects an operator audit row targeting tenant B under context A with SQLSTATE `42501`. Runtime credentials are rejected by all operator service actions and direct operator-repository use. Runtime also cannot forge an operator-labelled audit row even using direct parameterized SQL. Existing negative tests still prove missing context, cross-tenant reads/writes/joins, mixed relationships, FORCE RLS owner enforcement, immutable ownership, pooled context reset and denied privilege escalation.
- Operator/runtime roles remain NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE/NOINHERIT, with migration ownership on tenant tables. The new actor policy is restrictive INSERT and targets only runtime. Catalog inspection confirmed the current head and zero leftover disposable migration databases (`database-security.json`). Commands enforce atomic auditing through their service transaction; trusted operator credentials remain an infrastructure privilege, not protection against a compromised operator issuing arbitrary SQL.

#### Exact verification and results

Evidence directory: `D:\AI & ML\ArbiterData\phase1\provisioning`. Tests used PostgreSQL **17.11 (Debian 17.11-1.pgdg12+2)** and the unchanged pinned Python/dependency stack. Final tests ran in the rebuilt verification image without a workspace source mount.

| Check | Actual result |
| --- | --- |
| `docker compose --env-file .env.example config --quiet`; `build api`; `docker build --target verification -t arbiter-local:verification .` | Passed with existing immutable base/dependency pins and hash-verified installs. No package/lock change. |
| `up -d --wait postgres`; `--profile operations run --rm migrate`; repeated migration | Passed; application database is at `0003_operator_audit`. Application data was not downgraded/reset. |
| Restricted-role pytest command below | **85 passed**, zero failures/errors/skips. `provisioning-tests.xml`. Existing Starlette/TestClient/httpx deprecation warning remains unsuppressed. |
| Separate privileged migration pytest command below | **4 passed**, zero failures/errors/skips. `migration-tests.xml`. Empty and both previous revisions, repeated head/base round trips on empty disposable databases, and preservation of seeded previous-revision tenant/audit records proved. Disposable databases removed. |
| Whole-checkout Ruff lint/format, commands below | Passed: final format check reports 39 files already formatted. |
| Verification-image `mypy --cache-dir /tmp/mypy`; `python -m pip check` | Passed: 29 source/test/migration files; no type errors or broken requirements. |
| OSV `POST https://api.osv.dev/v1/querybatch` for `requirements-dev.lock` | 35 locked PyPI packages/35 result entries checked, zero known advisories. `dependency-audit.json`. This is not an OS/container-library verdict. |
| Digest-pinned Trivy 0.74.0 repository secret scan; comparison of four actual DB passwords against API/PostgreSQL/Redis logs | Passed: zero detected repository secrets and zero actual password matches. `repository-secret-scan.json`, `log-secret-comparison.json`. Values and raw logs suppressed. |
| Actual Compose operator `--help`, `create-tenant`, `create-member ... --role admin`, `set-tenant-status ... --status suspended` | All passed. An isolated fake issuer/subject and newly generated tenant were used. `compose-smoke-state.json`; `compose-audit-evidence.json` proves the three committed events and correlations. `compose_audit_probe.py` verified then removed only those synthetic tenant/member/audit/global-principal records using scoped migration-owner cleanup. No real issuer account was created. |
| Actual API/temporary operator container inspection and wire HTTP | Operator and API each run as UID/GID 10001 with read-only roots and exactly their own read-only password mount. Operator probe removed. API publishes loopback 8000; DB has no host port; API stays off provider network. Live 200, ready 503, POST operator/chat 404. Ollama stayed stopped. `operator-topology.json`, `runtime-topology.json`. |
| `git diff --check`; index/HEAD and seven approved document diffs | Passed whitespace check; no staging/commit/push; HEAD unchanged; approved documents unchanged. |

Final test commands, using the actual public mount paths (bootstrap is available only to the dedicated disposable migration test invocation):

```powershell
$taskSecretRoot = 'D:\AI & ML\ArbiterData\secrets'
$taskReportRoot = 'D:\AI & ML\ArbiterData\phase1\provisioning'
$taskDbMounts = @(
  '--mount', "type=bind,source=$taskSecretRoot\db_runtime_password,target=/run/secrets/db_runtime_password,readonly",
  '--mount', "type=bind,source=$taskSecretRoot\db_operator_password,target=/run/secrets/db_operator_password,readonly",
  '--mount', "type=bind,source=$taskSecretRoot\db_migration_password,target=/run/secrets/db_migration_password,readonly"
)
docker run --rm --read-only --tmpfs /tmp --network arbiter_control -e ARBITER_TEST_DATABASE=1 `
  --mount "type=bind,source=$taskReportRoot,target=/reports" @taskDbMounts `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider `
  tests/test_foundation.py tests/test_database_foundation.py tests/test_tenant_context.py `
  tests/test_tenant_isolation.py tests/test_operator_validation.py tests/test_provisioning.py `
  --junitxml=/reports/provisioning-tests.xml
docker run --rm --read-only --tmpfs /tmp --network arbiter_control -e ARBITER_TEST_MIGRATIONS=1 `
  --mount "type=bind,source=$taskReportRoot,target=/reports" `
  --mount "type=bind,source=$taskSecretRoot\db_bootstrap_password,target=/run/secrets/db_bootstrap_password,readonly" `
  --mount "type=bind,source=$taskSecretRoot\db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider tests/test_migrations.py `
  --junitxml=/reports/migration-tests.xml
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff format --check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  arbiter-local:verification mypy --cache-dir /tmp/mypy
docker run --rm --network none --read-only --tmpfs /tmp -e PIP_NO_CACHE_DIR=1 `
  arbiter-local:verification python -m pip check
```

The secret scan uses the task 2 recorded Trivy digest/flags and read-only repository/no-network mounts, changing the report mount to this task's evidence directory. Final source documentation edits refreshed only two stale module docstrings after the frozen-image test runs; executable behavior/SQL is unchanged, and whole-checkout lint/format were repeated successfully afterward.

#### Corrections, handoff and remaining work

- Initial run: 82 passed/one failed/three privileged tests explicitly skipped. The failed test incorrectly assumed FastAPI's internal route objects expose paths directly; replaced it with actual GET/POST denial requests, not a weaker route check. Earlier formatting/import findings and a redundant typing cast were corrected without blanket ignores. A patch inserted a new migration test in the middle of the existing function; inspection caught and corrected it before that intermediate edit was run. Final four migration checks retain the original round-trip assertions.
- Initial operator topology probe incorrectly expected a Compose `user` property; the user comes from Dockerfile USER. A real disposable operator container confirmed UID/GID 10001, read-only root and only its operator secret. The failed assumption is not counted as a pass. No functional privilege workaround was introduced.
- Observed local tested image references: runtime `sha256:a323542fe33f021c50e10fbd1f9cf02f6ea864e523b303b1b06bdd4efc755df2`; verification `sha256:5a907c21b6f60fc5e318d171562f6c881b1d34e0471095e02c206dcfd3594209`. These identify local builds from an uncommitted working tree, not deployed/published releases.
- At **00:51 IST**, stopped only this session's API/Redis/PostgreSQL with `docker compose --env-file .env.example stop api redis postgres`. Existing containers, named volumes, D: data and credentials remain. Separate Keycloak and unrelated Axiom services remain running; Ollama was never started. No model pull/generation, new external account, credential regeneration or unrelated storage move/delete occurred. Synthetic verification records were cleaned up; application schema remains upgraded.
- **Remaining Phase 1 work:** foundation readiness/diagnostic checks and a final whole-phase clean, isolated Compose bootstrap/migrate/start/restart/secret/port exit review at the current implementation state. The bounded provisioning task does not supply that complete review, so Phase 1 is not declared complete. Full readiness is still deliberately closed for unimplemented required identity/enforcement/recovery gates; no Phase 2 work is authorized here.
- Existing release blocker remains the prior incomplete OS/container-library vulnerability scan; maintainer must resolve it before release. Current Python/secret scans do not supply a clean-container verdict. No human decision blocks this completed task.
- **Next bounded Phase 1 task, proposed only:** foundation readiness/operator diagnostics and repeatable isolated clean-stack exit verification, preserving readiness 503 where later mandatory gates are absent and keeping all inference unavailable. Do not implement it without another instruction. No files were staged, committed or pushed. Stop after this task.

### 2026-09-27 — Phase 1, task 4: foundation closure

**Phase 1 exit criteria pass at this working-tree snapshot.** This supersedes task 3's incomplete-phase assessment, not its historical evidence. Entry was clean on `main` at `abfb76a260f77f3097b9363bffdbbc970d37facf` (`feat: add operator provisioning and audit controls`). Read all eight documents and current implementation; Phase 0 acceptance remains the prerequisite. No contradiction requiring a specification change was found. The seven approved specification/workflow documents remain unchanged. No Phase 2 implementation, inference enablement, commit or push occurred.

#### Changes and boundaries

- Added `src/arbiter/operations/diagnostics.py`: local read-only diagnostics using only the runtime credential, catalog checks for runtime authority/ownership/non-null tenant columns/FORCE RLS/policy presence, and bounded Redis PING/INFO checks for the pinned version, primary role, loading, AOF write/rewrite status, memory ceiling and no-eviction policy. PostgreSQL uses the existing finite pool/connect/statement limits. Redis has a two-second socket limit, four-second reply deadline, 128-byte header limit and 64-KiB bulk limit. Replies/errors never become public HTTP diagnostics or raw error messages. These checks do not certify the entire schema, validate identity, implement a rate limiter/recovery epoch, or contact a provider.
- Updated `src/arbiter/config.py` with deployment-only Redis host/validated port settings, and `compose.yaml` with an operations-profile diagnostics command mounting only the runtime password. It has no healthy-dependency prerequisite, so it can report outages. No dependency lock, image pin, schema, role or grant changed.
- Added `tests/test_diagnostics.py`; updated `tests/test_database_foundation.py` to attempt real Alembic upgrades using runtime, including an explicit visible-schema attempt. Updated `README.md` with the diagnostic command, exit semantics and isolated-stack procedure. Updated this memory entry. API handlers/startup remain unchanged: live 200, ready 503, no inference or operator HTTP routes.
- Diagnostic exit 0 means **foundation checks passed**, never application readiness. It always reports `ready=false` and fixed names for unimplemented identity/enforcement/recovery/model-readiness gates. Public readiness remains minimal 503 even when dependencies recover, as required by Architecture.md/Design.md. Redis PING/AOF health cannot replace the later recovery barrier.

#### Fresh environment, storage and real operational evidence

Evidence root: `D:\AI & ML\ArbiterData\phase1\closure`. Fresh application credentials/storage were created on the existing validated Windows/WSL2/Docker host; this is not a claim of testing a freshly installed OS or Docker. Docker Linux Engine **29.8.0**, Compose **v5.5.1**, pinned PostgreSQL **17.11**, Redis **7.2.16**, Python **3.13.15** and Ollama **0.34.4** were used. Preparation began at **01:42 IST**; shutdown/recreation checks at approximately **01:49–01:51 IST**. Tool output and the following external artifacts supply the evidence:

| Check | Observed result / artifact |
| --- | --- |
| Fresh-root preparation, before Compose startup | New `ArbiterData\postgres` and `redis` directories had zero files. Four newly generated independent secrets; protected directory with exactly three allowed ACL entries. `fresh-state.json`. |
| Explicit PostgreSQL/Redis start, bootstrap, empty-schema migration, API/Ollama start | Passed under project `arbiter-phase1-closure`. Diagnostics exited 1 with PostgreSQL false/Redis true both before role bootstrap and after bootstrap before migrations. Following migration, both foundation checks passed, exit 0; application readiness remained false. Missing schema was not treated as ready. |
| `closure-checks.ps1`: actual diagnostics and wire health during outages | PostgreSQL stop and Redis stop each made the corresponding check false, exit 1. A temporary Redis `allkeys-lru` policy also failed diagnostics despite successful PING; restored `noeviction` in `finally`. Restart restored foundation checks, exit 0. Live stayed 200/minimal `ok`; ready stayed 503/minimal `not_ready` throughout. Recorded commands took approximately 1.7–6.5 seconds including Python startup/Docker exec, not an HTTP latency promise. `readiness-outages.json`. |
| Clean stop of API/PostgreSQL/Redis/Ollama, `down` without volume removal, and recreation | All four stopped with exit 0 and `OOMKilled=false`. Recreated dependencies, repeated explicit bootstrap/head migration, and restarted API/Ollama successfully. `shutdown.json`. |
| Local CLI tenant/member/suspension fixture plus scoped runtime reads before/after recreation | Same suspended tenant, active admin membership and same three audit event IDs/actions persisted. Redis AOF sentinel also persisted. Fixture is synthetic, confined to this new cluster; no issuer account was created. `retention-before.json`, `retention-after.json`, `retention_probe.py`. |
| Repeated secret preparation and ACL/value comparisons | Four distinct 64-character secrets retained byte-for-byte; each file reader belongs to current user/SYSTEM/Administrators. Values/hashes not published. `secret-provisioning.json`. |
| Actual container, port, mount and network inspection | Only API publishes `127.0.0.1:18000 -> 8000`; PG/Redis/Ollama and operation containers publish no host ports. All app commands use UID/GID 10001, read-only roots, dropped capabilities and no-new-privileges. API/diagnostics receive runtime only; operator receives operator only; migrate receives migration only; explicit bootstrap receives all four. Secret mounts are read-only. Control/provider networks are internal; API is absent from provider network. `runtime-topology.json`, `networks.json`, `topology-checks.ps1`. |
| Actual named-volume inspection | PostgreSQL: `D:\AI & ML\ArbiterData\phase1\closure\ArbiterData\postgres`; Redis: same root's `redis`; secret files: same root's `secrets`. Separate named volumes reuse **only** `D:\AI & ML\ArbiterData\ollama\models` for the provider. Linux bind devices use `/run/desktop/mnt/host/d/AI & ML/ArbiterData/...`. `storage-volumes.json`. Existing default application storage, separate Keycloak, unrelated Axiom services and shared E: Docker/WSL storage were untouched. |
| Provider metadata only and HTTP surface checks | Existing approved manifest `0edcdef34593eac1aa2be9c7d06c432dcf81945adca5eca2f27662c18f168ba0` visible; zero loaded models. Only `/api/tags` and `/api/ps` were called; no pull/generation/prewarm. GET/POST diagnostics, docs, OpenAPI, chat and operator paths returned 404. `provider-metadata.json`, topology-check script. |

#### Exact verification and security evidence

The final tests ran after stack recreation in a rebuilt frozen verification image, without a workspace source mount. The normal gate mounts runtime/operator/migration files only; the dedicated migration invocation mounts bootstrap/migration only. PostgreSQL isolation was real, not mocked.

```powershell
$taskEvidence = 'D:\AI & ML\ArbiterData\phase1\closure'
$taskSecrets = "$taskEvidence\ArbiterData\secrets"
$taskCompose = @('--env-file', "$taskEvidence\closure.env", '-f', 'compose.yaml',
  '-f', "$taskEvidence\models.override.yaml", '-p', 'arbiter-phase1-closure')
.\scripts\prepare-local.ps1 -DataRoot "$taskEvidence\ArbiterData"
docker compose @taskCompose config --quiet
docker compose @taskCompose build api
docker build --target verification -t arbiter-local:verification .
docker compose @taskCompose up -d --wait --wait-timeout 120 postgres redis
docker compose @taskCompose --profile operations run --rm --no-deps diagnostics
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm --no-deps diagnostics
docker compose @taskCompose --profile operations run --rm migrate
docker compose @taskCompose up -d --wait --wait-timeout 180 api ollama
# The two pre-migration diagnostic invocations above intentionally exit 1.
& "$taskEvidence\closure-checks.ps1"
$taskMounts = @(
  '--mount', "type=bind,source=$taskSecrets\db_runtime_password,target=/run/secrets/db_runtime_password,readonly",
  '--mount', "type=bind,source=$taskSecrets\db_operator_password,target=/run/secrets/db_operator_password,readonly",
  '--mount', "type=bind,source=$taskSecrets\db_migration_password,target=/run/secrets/db_migration_password,readonly")
docker run --rm --read-only --tmpfs /tmp --network arbiter-phase1-closure_control `
  -e ARBITER_TEST_DATABASE=1 -e ARBITER_TEST_REDIS=1 `
  --mount "type=bind,source=$taskEvidence,target=/reports" @taskMounts `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider `
  --ignore=tests/test_migrations.py --junitxml=/reports/phase1-tests.xml
docker run --rm --read-only --tmpfs /tmp --network arbiter-phase1-closure_control `
  -e ARBITER_TEST_MIGRATIONS=1 --mount "type=bind,source=$taskEvidence,target=/reports" `
  --mount "type=bind,source=$taskSecrets\db_bootstrap_password,target=/run/secrets/db_bootstrap_password,readonly" `
  --mount "type=bind,source=$taskSecrets\db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider tests/test_migrations.py `
  --junitxml=/reports/migration-tests.xml
& "$taskEvidence\topology-checks.ps1"
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff format --check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  arbiter-local:verification mypy --cache-dir /tmp/mypy
docker run --rm --network none --read-only --tmpfs /tmp -e PIP_NO_CACHE_DIR=1 `
  arbiter-local:verification python -m pip check
```

| Final check | Actual result |
| --- | --- |
| Full foundation/isolation/provisioning/diagnostics gate | **101 passed**, zero failures/errors/skips, 15.76 seconds. `phase1-tests.xml`. Existing TestClient/httpx deprecation warning remains unsuppressed. |
| Separate disposable migration gate | **4 passed**, zero failures/errors/skips, 32.07 seconds. Empty, `0001_foundation` and `0002_tenant_isolation` upgrades, repeat head, empty-database round trips, and seeded previous-schema tenant/audit preservation passed. Test databases removed; application DB never downgraded. `migration-tests.xml`. |
| Runtime actual Alembic attempts and RLS negative gate | Default migration attempt denied with `3F000` because no accessible default schema exists; explicit `arbiter` search path attempt denied with `42501` on version-table creation. Existing DDL/version-marker/role-elevation denials passed. Missing context, A/B reads/writes/joins, mixed-tenant FK, FORCE RLS including owner, row-security-off denial and same-backend pooled commit/rollback/poisoned-context tests all passed. |
| Catalog probe with migration credential only | Head remains `0003_operator_audit`, four migration-owned tables, three ENABLE/FORCE tenant tables, runtime/operator/migration NOSUPERUSER/NOBYPASSRLS/NOINHERIT with no role memberships. Runtime has tenant SELECT/audit INSERT only, no administration, global principal reads, UPDATE/DELETE/TRUNCATE. Zero leftover disposable databases. `database-security.json`, `security_catalog.py`. |
| Whole-checkout Ruff lint/format, frozen strict mypy and pip check | Passed: 41 Python files formatted; 31 typed source/test/migration files; no broken requirements. |
| OSV querybatch for the unchanged development lock | 35 complete PyPI results, zero known advisories. `dependency-audit.json`. This does not certify OS/container libraries. |
| Actual four DB passwords compared against service logs | Zero matches across recreated API/PostgreSQL/Redis/Ollama logs; values and raw logs suppressed. `log-secret-comparison.json`. |

Local tested image references: runtime `sha256:1942e3d7ee064405354b33d6d7ced248cdc1fbd2c5464d83006e37f04e436b74`; final verification `sha256:87883c1d37831b2a1e09a2df4f7c9801073a633b8d89aa9f7c1ca9da8aa4afc1`. These identify local builds from this uncommitted working tree, not a published or deployed release.

#### Phase exit assessment and handoff

Every exit criterion in [Phases.md, Phase 1](Phases.md) has current evidence: clean migration/start, denied runtime migration/RLS bypass, denied context-free data access, cross-tenant reads/writes/joins, rejected mixed relationships, clean pool reuse, empty/previous migrations, and inspected ports/secrets. Foundation deliverables including local tenant/member commands and health/diagnostics are present and tested. **No Phase 1 work remains.** Application/inference readiness is intentionally not a Phase 1 pass claim; later required gates remain absent.

- Corrections during validation: initial unit typing check required four explicit scalar annotations. Initial full gate was 99 passed/one failed because its test assumed only `42501`; actual default runtime denial was `3F000`. Added the separate explicit-schema denial without broadening privileges. The first OSV summary incorrectly counted PowerShell null arrays as vulnerabilities; inspection found 35 empty results and corrected the count to zero. An unsupported `compose create --no-deps` inspection flag was replaced with verified `--no-recreate`. These initial errors are not passes.
- Remaining release evidence: the historical incomplete container OS/library vulnerability scan remains assigned to the maintainer before Phase 5 release. Current Python/secret checks do not resolve it. No unresolved Phase 1 blocker or human decision remains.
- Next bounded task, proposed only: Phase 2 OIDC JWT verification against the selected issuer with strict issuer/audience/RS256/JWKS/TLS and negative-token tests, keeping inference unavailable. Requires another user instruction; not implemented here.
- Final repository secret scan, source snapshot and retained-state shutdown evidence are recorded below. Stop after this closure pass; do not commit/push or begin Phase 2.

#### Final evidence and stopped-state handoff (01:58 IST)

- Digest-pinned Trivy **0.74.0** repository secret scan exited 0 with **zero findings**. It included the implementation and memory entry, ran with networking disabled/read-only repository, and excluded `.git`. Report: `repository-secret-scan.json`. Exact command:

```powershell
docker run --rm --network none --read-only --tmpfs /tmp --memory 1g --cpus 2 `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' `
  --mount "type=bind,source=$taskEvidence,target=/reports" `
  --mount "type=bind,source=$taskEvidence\ArbiterData\tmp,target=/scratch" `
  aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 `
  fs --cache-dir /scratch/trivy --scanners secret --skip-dirs /workspace/.git `
  --timeout 3m --exit-code 1 --no-progress --format json `
  --output /reports/repository-secret-scan.json /workspace
```

- `source_snapshot.py` in the frozen verification image compared all **31 Python files** under `src/tests/migrations` byte-for-byte against the read-only workspace; all matched. File SHA-256 evidence is in `source-snapshot.json`. JUnit reinspection confirms 101+4 tests, zero failures/errors/skips. Reviewed the complete bounded diff; final `git diff --check` and seven approved-document diffs pass, index empty, HEAD unchanged.
- Final `docker compose @taskCompose stop api ollama redis postgres` again produced exit 0/no OOM for all four (`final-shutdown.json`). `docker compose @taskCompose --profile operations down` removed only the isolated project's containers/networks, retaining all three named volumes, D: data, synthetic retention fixture and protected credentials. No volume removal or unrelated data deletion occurred. At **01:57:52 IST**, only the preexisting separate Keycloak and two unrelated Axiom services were running; the new API port was no longer published. Default Arbiter containers/data remain untouched.
- The closure evidence scripts, public `closure.env`, model-volume override, reports and scratch remain outside Git on D:. To reproduce with retained storage, use `$taskCompose` above and the explicit startup sequence; an actually empty-stack repeat requires another new isolated data/secret root, not deleting this retained cluster. Later validation must verify current state rather than treating this historical run as application readiness. Phase 1 passes; stop here.

### 2026-09-27 — Phase 2 task 1: verified identity and active membership

#### Scope and changed files

- Entry: clean `main`, HEAD `b17cbc129d6f3b8e36fa2e6832e57395001b1757`. Read all eight approved documents and verified the prior Phase 1 handoff against the repository. Implemented only the OIDC verifier and management-service membership boundary. No approved specification contradiction was found; PRD, Architecture, Design, Rules, Agents, Phases and Prompt are unchanged. No commit or push was authorized or performed.
- Added `src/arbiter/identity/oidc.py`, `identity/access.py`, `persistence/identity.py`, `transport/identity.py`, migration `0004_identity_lookup.py`, `tests/test_oidc.py` and `tests/test_membership.py`.
- Modified `src/arbiter/config.py`, `operations/bootstrap.py`, `tests/test_database_foundation.py`, `tests/test_migrations.py`, `pyproject.toml`, both dependency locks, `compose.yaml`, `.env.example`, README and this memory entry. Runtime adds PyJWT **2.15.0**, cryptography **50.0.1**, and moves already-pinned httpx **0.28.1** into runtime requirements. Locks retain hashes; new crypto transitives are cffi **2.1.1** and pycparser **3.0**. Runtime/development locks now contain **28/39** packages.

#### Implemented boundary and reviewed trust

- Verified identity contains only the exact `(issuer, subject)` pair. Explicit RS256, signature, issuer, audience, required expiry and presence of issuer/subject/audience are enforced. Optional `nbf` and `iat` are validated when present; malformed NumericDates are rejected. Clock skew is bounded to 60 seconds. Neither JWT tenant nor role claims authorize membership or administration.
- JWKS comes only from deployment configuration, with verified TLS and an explicit public CA for the approved private endpoint. Header `jku`/`x5u` are ignored. Public keys are cached for at most 900 seconds; unknown key IDs receive one refresh attempt per verification; expired-cache refresh failures deny verification rather than reuse stale keys. Responses, key count, RSA size, tokens, HTTP pool, deadlines and signature workers are bounded. Duplicate JSON members, unsupported algorithms, malformed keys, redirects and unavailable JWKS fail safely. No successful identity/membership result is cached. Implementation reference checked: [PyJWT API documentation](https://pyjwt.readthedocs.io/en/latest/api.html).
- The runtime calls one bound-parameter `arbiter.resolve_membership(tenant, issuer, subject)` function before tenant context exists. It returns only the selected active tenant's active matching member and database role. A dedicated **NOLOGIN/NOSUPERUSER/NOBYPASSRLS** owner has column-only SELECT on tenants, memberships and principals, SELECT policies on the two tenant tables, and no writes, audit read or schema CREATE. Function search path is fixed to `pg_catalog`; PUBLIC execution is revoked; only runtime receives EXECUTE. It checks `session_user` and performs no context mutation. Ordinary global runtime table access remains denied.
- Trusted migration has exactly one explicit membership in `arbiter_identity_lookup`, **INHERIT FALSE, SET TRUE, admin option false**, to manage function ownership. Runtime/operator have no memberships and cannot SET ROLE to the helper. This updates the prior historical zero-memberships observation for migration only. Bootstrap remains repeatable. All tenant tables retain ENABLE/FORCE RLS and original ownership/foreign-key constraints. Downgrade explicitly revokes column ACLs as well as table ACLs.
- `ManagementAccess.run` verifies JWT before any database access, resolves fresh active membership, checks any required administrator role from the database, then constructs tenant context and runs a server-supplied scoped operation in that same transaction. It rejects/discards an inherited session context. Database work runs outside the event loop. The database function trusts parameters supplied by this verified application boundary: it does not itself verify JWTs or protect against an attacker already executing arbitrary SQL as runtime. No general pre-context directory repository was added.
- This task exposes a service boundary and strict future-management bearer parser, **not new production HTTP management routes**. HTTP error mapping, endpoint integration and pagination remain future work. API health still returns readiness 503; chat and tenant audit routes return 404. No API keys, allocation/admission, provider calls or inference were implemented or enabled.

#### Real environment and approved issuer evidence

- Dedicated project `arbiter-phase2-identity`, public env file and all reports/scripts are under **`D:\AI & ML\ArbiterData\phase2\identity`**. Fresh PostgreSQL/Redis state, protected database credentials and scratch are under its `ArbiterData` child. API uses loopback **18002**. Default Arbiter/Phase 1 retained storage, existing model storage and unrelated Docker/WSL data were not moved or deleted. Ollama was not started and no model was downloaded.
- Actual approved Keycloak issuer **`https://localhost:18443/realms/arbiter`**, audience **`arbiter-api`**, RS256 and private JWKS transport **`https://arbiter-p0-keycloak:8443/realms/arbiter/protocol/openid-connect/certs`** were used. Public CA is **`D:\AI & ML\ArbiterData\phase0\identity-ca.pem`**, mounted read-only at `/run/config/oidc-ca.pem`; API joins existing external network `arbiter-p0-identity` and has no provider network. Its only secret mount is the runtime database password. PostgreSQL and Redis publish no host ports. Container UID 10001 and read-only API root were inspected (`runtime-topology.json`).
- The separate live probe reused the existing diagnostic client and its individually mounted secret outside Git; it created no Keycloak account/client/realm. Verified TLS discovery matched the canonical issuer/JWKS; a fresh real token passed the actual verifier and authorized a real scoped PostgreSQL read. Another tenant, altered signature, wrong issuer, wrong audience and an untrusted CA were denied. Transaction context was clear afterwards. Synthetic tenant/member/audit/principal fixtures were removed. Public booleans/configuration only are saved in `live-identity.json`; no token, secret or actual identity claims were saved or printed.
- Initial live attempts failed with connect/read timeouts; an instrumented attempt reached discovery but timed out at the existing token endpoint. Private-network TLS discovery separately returned 200. Keycloak was not OOM-killed; high CPU was observed, but **the root cause was not established**. Restarted only the existing Arbiter development Keycloak container, retaining its data/configuration. The subsequent live probe passed with unchanged verifier deadlines. This is evidence for this run, not a general availability or production-issuer readiness claim. The existing H2 development issuer and CA renewal before 2026-10-26 remain operational release concerns.

#### Exact checks and results

`$taskEvidence = 'D:\AI & ML\ArbiterData\phase2\identity'`; `$taskSecrets = "$taskEvidence\ArbiterData\secrets"`; `$taskCompose = @('--env-file', "$taskEvidence\identity.env", '-p', 'arbiter-phase2-identity')`. Preparation used `scripts/prepare-local.ps1 -DataRoot "$taskEvidence\ArbiterData"`. Lock generation used `python scripts/lock_dependencies.py` in the existing digest-pinned Python 3.13.15 base with repository and D: scratch mounts. Compose configuration, runtime/verification builds, fresh PostgreSQL/Redis startup, bootstrap, migrations, repeated bootstrap/head migration and API startup passed.

```powershell
docker compose --env-file .env.example config --quiet
docker compose @taskCompose up -d --wait --wait-timeout 120 postgres redis
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm migrate
# Repeated bootstrap/migrate succeeded; API startup used the same isolated project.
docker compose @taskCompose up -d --wait --wait-timeout 120 api
$taskMounts = @(
  '--mount', "type=bind,source=$taskSecrets\db_runtime_password,target=/run/secrets/db_runtime_password,readonly",
  '--mount', "type=bind,source=$taskSecrets\db_operator_password,target=/run/secrets/db_operator_password,readonly",
  '--mount', "type=bind,source=$taskSecrets\db_migration_password,target=/run/secrets/db_migration_password,readonly")
docker run --rm --read-only --tmpfs /tmp --network arbiter-phase2-identity_control `
  -e ARBITER_TEST_DATABASE=1 -e ARBITER_TEST_REDIS=1 `
  --mount "type=bind,source=$taskEvidence,target=/reports" @taskMounts `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider `
  --ignore=tests/test_migrations.py --junitxml=/reports/identity-and-isolation-tests.xml
docker run --rm --read-only --tmpfs /tmp --network arbiter-phase2-identity_control `
  -e ARBITER_TEST_MIGRATIONS=1 --mount "type=bind,source=$taskEvidence,target=/reports" `
  --mount "type=bind,source=$taskSecrets\db_bootstrap_password,target=/run/secrets/db_bootstrap_password,readonly" `
  --mount "type=bind,source=$taskSecrets\db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider tests/test_migrations.py `
  --junitxml=/reports/migration-tests.xml
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff format --check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  arbiter-local:verification mypy --cache-dir /tmp/mypy
docker run --rm --network none --read-only --tmpfs /tmp -e PIP_NO_CACHE_DIR=1 `
  arbiter-local:verification python -m pip check
```

| Check | Actual result |
| --- | --- |
| Full Phase 1 regression + bounded identity/membership gate | **169 passed**, zero failures/errors/skips, 24.48 seconds. Includes 58 OIDC tests and 10 real-PostgreSQL membership tests. Existing TestClient/httpx deprecation warning remains unsuppressed. `identity-and-isolation-tests.xml`. |
| Disposable migration gate | **6 passed**, zero failures/errors/skips, 37.31 seconds. Empty and previous `0001`/`0002`/`0003` upgrades, repeat head, disposable round trips and seeded `0002`/`0003` preservation. Application DB never downgraded. `migration-tests.xml`. |
| Isolation/security denials | Missing context; A/B reads/writes/joins; mixed-tenant FKs; FORCE RLS including owner; runtime bypass/role/DDL denials; actual runtime Alembic default `3F000` and explicit-schema `42501`; pooled commit/rollback and poisoned-context rejection all passed. |
| Identity/member negatives | Invalid/expired/malformed JWTs and dates, wrong issuer/audience/algorithms/signatures, duplicate JSON, malformed/unavailable/oversized JWKS, unknown keys, cache expiry/rotation, bounded concurrent refresh, forged tenant/role, unprovisioned/wrong-issuer subjects, unauthorized/admin membership, inactive members and tenant suspension passed. Expired identity caused zero DB calls. |
| Frozen source and static checks | **38** Python files under `src/tests/migrations` byte-identical to the tested image (`source-snapshot.json`); Ruff lint passed, **48** Python files formatted, strict mypy passed for **38** files, pip check reported no broken requirements. |
| Live approved issuer + real scoped membership | Passed after development issuer restart; negative signature/issuer/audience/TLS/tenant tests passed. `live_identity_probe.py`, `live-identity.json`; public-only connectivity probe also retained. |
| Catalog probe | Head `0004_identity_lookup`, function ownership/ACL/search path and restricted helper verified; runtime/operator zero memberships, migration one explicit non-inheriting helper membership. Zero leftover disposable DBs and zero synthetic global principals. `security_catalog.py`, `database-security.json`. |
| Dependency advisory check | OSV querybatch returned all **39** locked PyPI results with **zero** advisory packages. `dependency-audit.json`. Does not certify OS/container libraries. |
| Service log inspection | All four dedicated API/PG/Redis and existing Keycloak logs had **zero** matches against the four actual fresh DB secrets and existing probe-client secret; zero JWT-like patterns. No raw logs/values archived. `log-secret-comparison.json`. |

Local tested images: runtime **`sha256:2585f8701a29577f85c4dabe30635794a3c36a69cb63975e4d83095a13f9ecd2`**, verification **`sha256:e9ece9d4744380a4aac6b1254ecbe8e2e7bae870bb229f25ca0b058b3064d7ef`**. These identify local builds, not a release or deployed revision.

- Validation corrections: initial Ruff/mypy findings were fixed. Initial OIDC unit run had 57 passes/one fixture failure because PyJWT rejected a null issuer while constructing the negative token; a signed raw JSON fixture now exercises the verifier and all 58 pass. Initial live timeouts are recorded above, not counted as passes. No negative assertion, TLS verification, deadline or isolation privilege was weakened to obtain a pass.
- Remaining Phase 2 work: management HTTP integration and safe error/pagination behavior; API key creation/list/revocation and scopes; tenant-scoped model/usage metadata; operator policy administration; transactional audit for new security mutations; full mixed-credential, key-secret, cross-object and revocation/suspension race gates. The current service check does not prove admission-lock race behavior. Identity services do not satisfy the still-unimplemented aggregate API identity/enforcement/recovery/capacity readiness gates.
- **Phase 2 is not complete.** No human decision blocks this finished bounded task. The historical incomplete container OS/library vulnerability scan remains assigned before Phase 5 release. Proposed next bounded task only: integrate an authenticated, tenant-scoped read-only audit-list management endpoint using this identity/membership boundary, with approved error mapping, pagination and transport negative tests; keep keys and inference unavailable. Await the next task instruction.
- No commit/push or further implementation is authorized in this task.

#### Final security review and retained-state handoff (02:39 IST)

- Digest-pinned Trivy **0.74.0** repository secret scan exited 0 with **zero findings**, including this task's implementation and memory entry. Networking was disabled; checkout was read-only; `.git` excluded. Report `repository-secret-scan.json`. Command:

```powershell
docker run --rm --network none --read-only --tmpfs /tmp --memory 1g --cpus 2 `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' `
  --mount "type=bind,source=$taskEvidence,target=/reports" `
  --mount "type=bind,source=$taskEvidence\ArbiterData\tmp,target=/scratch" `
  aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 `
  fs --cache-dir /scratch/trivy --scanners secret --skip-dirs /workspace/.git `
  --timeout 3m --exit-code 1 --no-progress --format json `
  --output /reports/repository-secret-scan.json /workspace
docker compose @taskCompose stop api redis postgres
docker compose @taskCompose --profile operations down
```

- All three isolated services stopped with **exit 0/no OOM**, captured in `final-shutdown.json`. Removed only their project containers/control/edge networks; retained named volumes, all D: data/credentials/reports and the existing external identity network. At **02:39:07 IST**, only the preexisting Keycloak and two unrelated Axiom services were running; port 18002 was no longer published. Keycloak is running after the explicitly recorded development restart; no unrelated service was restarted.
- Frozen source comparison, final JUnit inspection, full diff/security review, `git diff --check`, seven approved-document comparisons and empty-index check passed. HEAD remains the entry revision; all 18 task files are unstaged. Reports are historical evidence from this isolated run; reproduce using the retained project env/storage or prepare a new independent D: root for a genuinely empty cluster. Stop after this bounded task; Phase 2 remains incomplete.

### 2026-09-27 — Phase 2 task 2: authenticated tenant audit list

**Bounded task completed; Phase 2 remains incomplete.** Entry was clean on `main` at `165a39fde7480f6741f07c21194318ee82df48e3` (`feat: add OIDC identity and membership authorization`), superseding task 1's uncommitted snapshot. Read all approved documents and current memory. No contradiction requiring an approved specification change was found; the seven specification/workflow documents remain unchanged. No commit or push was authorized or performed.

#### Files changed and observed boundary

- Added `src/arbiter/transport/audit.py`, `operations/audit.py`, `identity/audit_cursor.py`, `tests/test_audit_endpoint.py` and `tests/test_audit_cursor.py`. Modified `src/arbiter/main.py`, `config.py`, `identity/oidc.py`, `persistence/repositories.py`, `persistence/tenant.py` (stale docstring only), `tests/test_foundation.py`, `tests/test_operator_validation.py`, `compose.yaml`, `scripts/prepare-local.ps1`, README and this memory entry. No dependency lock, image pin, migration, database grant or RLS policy changed. This is 16 unstaged task files, including memory.
- Wired exactly **GET `/v1/tenants/{tenant_id}/audit`** through the existing OIDC and active-membership service. Member/admin permissions follow [Design.md](Design.md). The path UUID is a selector; JWT tenant/role and custom tenant/role headers establish no authority. The service verifies identity, resolves fresh active membership and binds transaction-local context before cursor processing or audit repository access. Synchronous DB work and cursor cryptography run in the existing bounded worker boundary.
- The repository uses an explicit tenant predicate plus the existing FORCE RLS, existing tenant/time/ID index and bound keyset parameters. Response fields are explicitly projected content-free metadata, omitting global identity claims and free-text actor references. Default page size 50/max 100, one-row lookahead, ascending timestamp/UUID order, strict response models, generic 401/404/422/503 errors with generated request IDs and `no-store` were implemented. No read audit mutation was added; provisioning/security mutations retain their existing atomic audit guarantees.
- Cursor implementation choice: fixed-size encrypted positions, AES-256-GCM, random 96-bit nonce, authenticated tenant/list purpose and format version. A cursor from another tenant fails the same validation path as an altered/malformed cursor after membership authorization. Cursor validation performs no cross-tenant object lookup. Deleted anchors still permit keyset continuation; pagination does not claim a frozen snapshot across separately authorized requests. There is no positive membership cache.
- Added independent file-provisioned **32-byte** cursor key `audit_cursor_key`, base64 encoded. Preparation retains all existing values and checks reader ACLs. API mounts only runtime DB password and cursor key, both read-only; no operator/migration/bootstrap or Keycloak client credential is mounted into API. Missing/invalid cursor secret or OIDC configuration denies startup. Certificate/key-file IO is outside the event loop; the verifier accepts only an explicitly server-built trust context, preserving HTTPS verification. Startup performs no schema mutation or JWKS fetch; shutdown closes HTTPS client and DB engine.
- No API keys, policy/model/usage endpoints, quota/budget enforcement, Redis admission or provider inference were implemented. `/health/ready` remains 503; chat remains unavailable. Foundation diagnostics still do not certify complete identity/workload/enforcement/recovery readiness.

#### Environment, live issuer and storage evidence

- Evidence/scripts/public env: **`D:\AI & ML\ArbiterData\phase2\audit`**; isolated fresh PostgreSQL/Redis data and protected secrets: its **`ArbiterData`** child. Compose project **`arbiter-phase2-audit`**, API loopback **18003**. Existing default/Phase 1/task 1 storage and shared E: Docker/WSL data were not moved or deleted. Ollama was never started; no model download or inference occurred.
- Used the approved Keycloak issuer/audience/RS256/private HTTPS JWKS and explicit public CA recorded in task 1 and Phase 0. No Keycloak configuration/account/client was created or changed, and Keycloak was **not restarted** this task. The live diagnostic reused the existing separately held probe client solely to obtain a fresh token, then explicitly provisioned/removed synthetic Arbiter memberships through operator credentials.
- Actual deployed API verified that live token and returned its member's audit metadata. Both an existing unauthorized tenant and absent tenant returned identical generic 404 errors. Missing authentication returned 401; malformed cursor 422; readiness 503; chat 404. The probe held its token/cursor only in memory while the isolated API was restarted. The same cursor then returned the next distinct event and terminal `next_cursor=null`. Report **`live-audit.json`** contains only booleans; `restart-checkpoint.json`/`restart-complete.signal` contain only coordination markers. No JWT, actual identity claims, secret or cursor was saved or printed.
- Inspected actual API: UID/GID 10001, read-only root, exact two read-only secret mounts, read-only public CA, approved identity/control/edge networks and no provider network. PostgreSQL/Redis expose no host ports. `runtime-topology.json`. Repeated preparation preserved all **five** secret files byte-for-byte; cursor file is 44 encoded bytes and its directory is protected. No values/hashes were published (`secret-provisioning.json`).

#### Exact checks and actual results

```powershell
$taskEvidence = 'D:\AI & ML\ArbiterData\phase2\audit'
$taskSecrets = "$taskEvidence\ArbiterData\secrets"
$taskCompose = @('--env-file', "$taskEvidence\audit.env", '-p', 'arbiter-phase2-audit')
.\scripts\prepare-local.ps1 -DataRoot "$taskEvidence\ArbiterData"
docker compose @taskCompose config --quiet
docker compose @taskCompose up -d --wait --wait-timeout 120 postgres redis
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm migrate
docker build --target verification -t arbiter-local:verification .
docker compose @taskCompose build api
docker compose @taskCompose up -d --wait --wait-timeout 120 api
$taskMounts = @(
  '--mount', "type=bind,source=$taskSecrets\db_runtime_password,target=/run/secrets/db_runtime_password,readonly",
  '--mount', "type=bind,source=$taskSecrets\db_operator_password,target=/run/secrets/db_operator_password,readonly",
  '--mount', "type=bind,source=$taskSecrets\db_migration_password,target=/run/secrets/db_migration_password,readonly")
docker run --rm --read-only --tmpfs /tmp --network arbiter-phase2-audit_control `
  -e ARBITER_TEST_DATABASE=1 -e ARBITER_TEST_REDIS=1 `
  --mount "type=bind,source=$taskEvidence,target=/reports" @taskMounts `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider `
  --ignore=tests/test_migrations.py --junitxml=/reports/audit-and-isolation-tests.xml
docker run --rm --read-only --tmpfs /tmp --network arbiter-phase2-audit_control `
  -e ARBITER_TEST_MIGRATIONS=1 --mount "type=bind,source=$taskEvidence,target=/reports" `
  --mount "type=bind,source=$taskSecrets\db_bootstrap_password,target=/run/secrets/db_bootstrap_password,readonly" `
  --mount "type=bind,source=$taskSecrets\db_migration_password,target=/run/secrets/db_migration_password,readonly" `
  arbiter-local:verification python -m pytest -q -p no:cacheprovider tests/test_migrations.py `
  --junitxml=/reports/migration-tests.xml
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' -w /workspace `
  -e PYTHONPATH=/workspace/src arbiter-local:verification ruff format --check --no-cache .
docker run --rm --network none --read-only --tmpfs /tmp `
  arbiter-local:verification mypy --cache-dir /tmp/mypy
docker run --rm --network none --read-only --tmpfs /tmp -e PIP_NO_CACHE_DIR=1 `
  arbiter-local:verification python -m pip check
```

| Check | Actual result and limitation |
| --- | --- |
| Frozen-image full regression with real PostgreSQL/Redis | **214 passed**, zero failures/errors/skips, **27.85 seconds**. Includes prior 169 cases, 29 new audit HTTP cases, 13 cursor/config cases and three startup denials. Existing TestClient/httpx deprecation warning remains unsuppressed. `audit-and-isolation-tests.xml`. |
| Separate disposable migration gate | **6 passed**, zero failures/errors/skips, **20.06 seconds**. Empty/previous `0001`/`0002`/`0003`, repeated head and seeded preservation/round trips remain proven. Application schema was never downgraded. `migration-tests.xml`. |
| HTTP authorization/pagination negatives | Missing/malformed/expired/wrong issuer/audience, duplicate/mixed credentials, unprovisioned subjects, suspension, forged claims/headers/selectors, A/B reads and indistinguishable missing/unauthorized tenants passed. Malformed/foreign/tampered/oversized cursors, duplicate/unknown queries and invalid sizes passed. Tied timestamps, complete nonduplicating pages, max size, empty pages and deleted anchors passed. Failed identities caused zero DB queries; unavailable JWKS returned sanitized 503. |
| HTTP pool/context evidence | A/B/A audit requests used the same PostgreSQL backend with the correct established tenant setting before each explicitly scoped query. Afterwards context was empty and unscoped audit reads returned zero. A deliberately poisoned session produced generic 503 and was discarded; next authorized request passed on a different backend. All prior missing-context/read/write/join/FK/runtime-migration/role-bypass/FORCE-RLS negatives passed. |
| Live approved Keycloak + actual API restart | Passed in `live_audit_probe.py`, run by the frozen verification container on control/external identity networks. Only individual test DB files, public CA and existing diagnostic client secret were mounted to the probe; no Docker socket. Actual `docker compose @taskCompose restart api` then `up -d --wait --wait-timeout 60 api` passed before signalling the in-memory probe. `live-audit.json`. |
| Static/source/package integrity | Ruff lint passed, **53** Python files formatted; frozen strict mypy passed for **43** files; pip check found no broken requirements. `source_snapshot.py` compared all **43** source/test/migration Python files byte-for-byte against the tested image: matched (`source-snapshot.json`). Existing hash locks and immutable image pins are unchanged. |
| Catalog verification | `python /reports/security_catalog.py` in a verification container with migration credential only passed. Head remains `0004_identity_lookup`; restricted owner/EXECUTE/search path/role memberships unchanged; no runtime/operator helper-role membership; zero leftover disposable DBs and synthetic principals. `database-security.json`. The script's historical context-free-row field uses the forced owner; current runtime evidence comes from tests above. |
| Dependency advisory check | Fresh OSV `POST https://api.osv.dev/v1/querybatch`, queries parsed from the unchanged development lock: **39** complete responses, **zero** advisory packages. `dependency-audit.json`. This does not certify OS/container libraries. |
| Repository secret scan and logs | Digest-pinned Trivy **0.74.0**, networking disabled/read-only checkout, `.git` excluded: exit 0, **zero** findings. `repository-secret-scan.json`. Dedicated API/PG/Redis logs: zero matches against all five actual deployment secrets and existing probe-client secret, zero JWT-like patterns; raw logs/values not saved (`log-secret-comparison.json`). |

Local tested images: runtime **`sha256:38dd35d81eb87a4aa5ace903f82b29662dd95f6b2c066efdd90dfe8fe6d88bdb`**; final verification **`sha256:46eb2e293fe13441cbb433bb377da2593bd180019f11d523064153d9cee5a675`**. Local builds are not a published release or committed/deployed revision.

Corrections, not passes: initial static checks caught import/line-length findings and required explicit required OIDC constructor values for strict typing. First focused run had 56 passes/one failure because its SQL observer also intercepted the deliberately unscoped negative probe; narrowed observation to the actual page query while retaining the zero-row assertion. First full run had 213 passes/one failure because an old operator-route fixture lacked the newly required startup configuration/key; it now reuses the complete inert fixture and retains every route denial. Final 214+6 results above supersede these failures; no authority, TLS, negative test or privilege was weakened.

#### Stopped-state handoff and remaining work

At **05:53:14 IST**, `docker compose @taskCompose stop api redis postgres` produced exit 0/no OOM for all three, recorded in `final-shutdown.json`. `docker compose @taskCompose --profile operations down` removed only this project's containers/control/edge networks, retaining named volumes, protected credentials, D: data/reports and the external identity network. Only preexisting Keycloak and two unrelated Axiom services remained running; API port 18003 was no longer published. The disposable live probe was removed after exit 0. No unrelated service restart, storage relocation or volume deletion occurred.

Repository secret scan command (also repeated after this memory update):

```powershell
docker run --rm --network none --read-only --tmpfs /tmp --memory 1g --cpus 2 `
  --mount 'type=bind,source=E:\Arbiter,target=/workspace,readonly' `
  --mount "type=bind,source=$taskEvidence,target=/reports" `
  --mount "type=bind,source=$taskEvidence\ArbiterData\tmp,target=/scratch" `
  aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 `
  fs --cache-dir /scratch/trivy --scanners secret --skip-dirs /workspace/.git `
  --timeout 3m --exit-code 1 --no-progress --format json `
  --output /reports/repository-secret-scan.json /workspace
```

- Full bounded diff/security review, `git diff --check`, seven approved-document comparisons, empty-index and unchanged-HEAD checks passed. Evidence is historical for this isolated run; reproduce with its retained env/storage, not by assuming it is currently serving requests.
- Remaining Phase 2: API key creation/list/revocation and scopes, tenant model/usage/request metadata endpoints, operator policy administration, atomic audit for those new mutations, and complete mixed-credential/key-secret/revocation/suspension admission-lock race gates. The read-only endpoint does not claim dispatch-race guarantees. Phase 2 is **not complete** and inference stays unavailable.
- No human decision blocks this completed task. The earlier OS/container-library vulnerability scan remains incomplete and assigned before Phase 5 release. Development Keycloak hardening and CA renewal remain the previously recorded operational concerns. Current Python/secret checks do not resolve those release items.
- Next bounded task, proposed only: tenant-admin API key creation with tenant-scoped persistence, one-time secret return, separately file-provisioned verifier pepper and atomic audit, keeping workload authentication/inference unavailable until separately authorized. Await another task instruction; do not implement it here. No files were staged, committed or pushed. Stop after this bounded task.

### 2026-09-27 — Phase 2 bounded task 3: admin key creation

#### Entry and scope

- Entry: clean `main`, HEAD `8a0a215bdd0d3a1c49cfbf7048ff518bd44cbfe4`. Read all eight project documents and verified the preceding handoff against the repository. Phase 0 and Phase 1 remain prerequisites with their recorded evidence; this task does not reopen or replace their approved contracts. No contradiction requiring a specification change was found. PRD, Architecture, Design, Rules, Agents, Phases and Prompt remain unchanged.
- Implemented only tenant-admin **POST `/v1/tenants/{tenant_id}/keys`**, its scoped persistence, protected verifier-pepper provisioning and atomic audit evidence. Key authentication, listing/revocation, quotas, budgets, Redis admission and inference remain unimplemented. No staging, commit or push is authorized or performed.
- Added `src/arbiter/identity/keys.py`, `operations/keys.py`, `persistence/keys.py`, `transport/keys.py`, `transport/errors.py`, `migrations/versions/0005_api_key_creation.py`, `tests/test_key_creation.py` and `tests/test_key_material.py`.
- Modified `src/arbiter/config.py`, `main.py`, `operations/bootstrap.py`, `operations/diagnostics.py`, `transport/audit.py`, `tests/test_database_foundation.py`, `test_foundation.py`, `test_membership.py`, `test_migrations.py`, `test_tenant_isolation.py`, `scripts/prepare-local.ps1`, `compose.yaml`, `.env.example`, README and this memory entry: **23 task files**. Audit transport shares the unchanged sanitized error envelope. Existing regression assertions were retained and updated for the new table/head. Dependency locks, package pins and base/service image pins are unchanged.

#### Observed implementation and security boundary

- Existing OIDC verification and fresh database membership resolution precede tenant context and request-field validation in the service. Admin permission comes from the membership row, never JWT tenant/role claims. The repository checks the authorized binding against its immutable transaction context and sends only bound metadata/verifier parameters to the narrow creation function.
- The function locks the scoped tenant first and rereads active tenant/admin membership before mutation. The real lock-race test downgraded the admin while creation waited; creation returned 403 with no key. Missing/mismatched context and operator invocation fail; direct runtime key INSERT/UPDATE/DELETE, verifier/version SELECT and `SET ROLE arbiter_key_writer` all fail with PostgreSQL `42501`.
- Migration `0005_api_key_creation` adds non-null tenant ownership, composite creator FK, ENABLE/FORCE RLS, immutable key metadata and a deferred composite FK requiring the matching audit ID/key target/actor/tenant at commit. Successful creation inserts both records in one transaction. A real audit-ID collision after key insertion returned sanitized 409 and rolled back the key; a subsequent request succeeded on the pool. Orphan, mixed-tenant creator and mismatched audit-target inserts failed with `23503`. A real public-ID collision left one key and one successful creation event.
- Verified stored HMAC-SHA-256 bytes against generated random secret material and the independent deployment pepper/version. Only the verifier reaches SQL; credential objects use redacted secret types. Exact generated credential/secret components were absent from inspected DB rows, audit metadata, validation errors and captured logs. The actual live issuer/API probe also proved verifier/audit consistency and plaintext absence. Wire format and implementation details are in README; policy remains in Design.md.
- Runtime receives metadata-column SELECT and function EXECUTE only. The function has `search_path=pg_catalog`, no dynamic SQL or PUBLIC/operator execution, and a separate NOLOGIN/NOSUPERUSER/NOBYPASSRLS owner. That owner receives scoped column reads, key/audit INSERT and tenant `UPDATE(status)` solely to permit `FOR UPDATE`; schema CREATE is revoked after ownership transfer. Runtime/operator have no helper memberships. Migration has two explicit non-inheriting, SET-only helper memberships with no admin option. The database function rechecks supplied binding parameters; JWT verification remains the trusted application boundary, not a claim that arbitrary SQL can verify OIDC.
- Creation tests prove all allowed scope sets, default 30-day expiration, an explicit expiration near the 90-day boundary, past/overlong/naive/malformed expiration rejection, duplicate JSON fields/scopes and mass-assignment rejection, and declared/chunked 64 KiB body limits. Repeated valid POSTs create different credentials; no creation idempotency or secret replay contract was introduced. Expiration negatives use relative timestamps so the tests do not depend on a fixed calendar date.
- A single-connection creation test alternated A/B/A using verified admin memberships: same backend, correct transaction context and zero context-free key rows after each commit. A deliberately session-scoped tenant setting caused sanitized 503, connection invalidation and successful recovery on a different backend. Existing identity/audit/isolation negatives also passed.

#### Environment and exact verification

Evidence/scripts/reports: `D:\AI & ML\ArbiterData\phase2\keys`, reports under `reports`. Fresh database/Redis files and six protected deployment secret files are under `phase2\keys\ArbiterData`; this is isolated from previous task storage. Public environment file: `keys.env`; project `arbiter-phase2-keys`, API loopback port **18004**. Existing model cache and shared Docker/WSL data were not moved or duplicated; no model was downloaded or started.

Docker's Linux engine was initially absent. Started the installed `E:\Docker\Docker Desktop.exe`; the recovered engine reports **29.8.0**. Docker startup also resumed the existing Axiom containers automatically. Started the existing approved `arbiter-p0-keycloak` for live verification; no identity account/client/configuration change was made. Issuer/audience/RS256, private JWKS hostname and CA are the previously approved values above.

Commands below ran from `E:\Arbiter`; actual invocations are retained in the named D: PowerShell scripts. `$root` denotes the evidence directory and `$secretDir` its `ArbiterData\secrets`. No real credential values, JWTs or returned API-key secrets were saved in reports.

```powershell
$taskCompose = @('--env-file', "$root\keys.env", '-p', 'arbiter-phase2-keys')
.\scripts\prepare-local.ps1 -DataRoot "$root\ArbiterData"
docker compose @taskCompose config --quiet
docker compose @taskCompose up -d --wait postgres redis
docker build --target runtime -t arbiter-local:foundation .
docker build --target verification -t arbiter-local:verification .
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm migrate
docker compose @taskCompose up -d --wait api
docker compose @taskCompose --profile operations run --rm --no-deps diagnostics
```

`test.ps1` runs the frozen image, read-only with `/tmp`, on `arbiter-phase2-keys_control`, mounting runtime/operator/migration test credentials individually and the report directory. Command: `python -m pytest -q -p no:cacheprovider --junitxml=/reports/isolation-tests.xml`, with `ARBITER_TEST_DATABASE=1` and `ARBITER_TEST_REDIS=1`. The eight migration cases are intentionally skipped here and run separately by `migration-tests.ps1`: same read-only image/network, only bootstrap/migration credentials, `ARBITER_TEST_MIGRATIONS=1`, `python -m pytest -q -p no:cacheprovider tests/test_migrations.py --junitxml=/reports/migration-tests.xml`. Privileged test/probe credentials never enter the API.

| Check | Actual evidence |
| --- | --- |
| Full regression and real PostgreSQL/Redis isolation gate | **283 passed; eight migration-only cases skipped**, zero test failures. Includes 41 creation tests, 24 material/input tests and the preserved Phase 1/identity/audit gate. `isolation-tests.xml`, `isolation.exit`, final runner output. |
| Separate privileged migration suite | **8 passed**, exit 0: empty and every earlier supported head through `0004_identity_lookup`; repeated head; disposable downgrade/re-upgrade/base round trips; seeded tenant/audit preservation. `migration-tests.xml`, `migration.exit`. Application DB was not downgraded. |
| Ruff/format/strict typing/package integrity | `ruff check --no-cache .`, `ruff format --check --no-cache .`, `mypy --cache-dir /tmp/mypy`, `python -m pip check`: exit 0; **61** Python files formatted, **51** typed source/test/migration files, no broken requirements. `static-checks.json`, final gate output. Source checks use the whole read-only checkout; tests use frozen source. |
| Source integrity | `python /reports/source_snapshot.py` compares all **51** source/test/migration Python files byte-for-byte against the tested image. `source-snapshot.json`, `snapshot.exit`. |
| Live approved issuer and deployed API | `live_keys_probe.py` obtained a fresh token using the existing diagnostic client, verified approved TLS/JWKS/issuer/audience, then called the actual API. Admin 201/HMAC/matching audit; member 403; foreign/absent tenant identical 404; missing token 401; invalid fields 422; content-free audit 200; key-as-OIDC 401; inference 404; readiness 503. Exit 0, `live-keys.json`. Synthetic tenants/keys/audits/members/principal were cleaned up. |
| Catalog and foundation diagnostics | PostgreSQL **17.11 (Debian 17.11-1.pgdg12+2)**, head `0005_api_key_creation`; function ownership/search path/EXECUTE ACL, FORCE RLS and deferred audit FK verified; context-free forced owner sees zero keys; zero disposable DBs/synthetic principals. `database-security.json`, `catalog.exit`. Runtime-only diagnostics exit 0 with PostgreSQL/Redis foundation true and application ready false. |
| Deployment/provisioning inspection | API UID/GID 10001, read-only, ALL capabilities dropped/no-new-privileges; exactly three read-only secret mounts (runtime/cursor/pepper), public CA, no privileged/issuer credentials, no provider network. Only API loopback 18004 published; PG/Redis unpublished. Six deployment secret files retained byte-for-byte on repeated provisioning; protected host ACL. `runtime-topology.json`, `secret-provisioning.json`. |
| Dependency advisory check | Fresh OSV `POST https://api.osv.dev/v1/querybatch` from the unchanged development lock: **39 complete PyPI results, zero advisory packages** at 12:40 IST. `dependency-audit.json`. Does not certify OS/container libraries. |
| Repository/service secret checks | Digest-pinned Trivy 0.74.0, network disabled/read-only checkout with `.git` excluded: exit 0, **zero findings**, `repository-secret-scan.json`. API/PG/Redis/Keycloak logs had zero matches for all six fresh deployment secrets plus the existing probe-client secret; zero JWT/API-key credential patterns. `log-secret-comparison.json`; raw logs and values suppressed. |

Runtime image: `sha256:176c2ecd68707fe62b7ce4decf458d509847dad9d61ffe7a193f0ab09c2f3c67`. Final verification image: `sha256:40592f69d581ff41f1731b505ded5ecda54ed26d620a491bbf4c6550500ad84f`. These are local tested builds from an uncommitted working tree, not a published release.

Corrections, not passes: initial lint/typing findings were corrected; first full run was **278 passed/two failed** (stale diagnostics policy count and strict JSON datetime conversion after a pre-model validator). Fixed the count and moved explicit expiration-type rejection into raw input validation, preserving strict aware-datetime parsing and every negative case. The successful full gate supersedes these failures. Live probe initially could not mount a CA inside an existing read-only directory; moved its public CA mount outside that directory. An inspection-script JSON array wrapper produced a false hardening mismatch; corrected parsing and retained the actual hardening assertions. Some foreground Docker commands were interrupted by the command host; retained background runs and explicit exit/report files provide completed-check evidence. Automatic approval review rejected one combined dependency/migration launch with only `blocked by policy`; separate fixed launches completed both checks. No policy/privilege/negative test was weakened.

#### Remaining work and stopped-state handoff

- This bounded creation task has no unresolved human decision. Phase 2 is **not complete**: key metadata listing/revocation, workload key resolution/authentication and scope/expiry checks, remaining tenant metadata, operator policy administration and complete mixed-credential/revocation/suspension admission-lock race gates remain. Quotas, budgets, Redis admission and inference belong to later authorized work and are absent.
- Next bounded task, proposed only: authenticated tenant-admin key metadata listing with tenant-bound opaque cursor pagination and no secret/verifier serialization. Do not implement it without another task instruction.
- The historical incomplete OS/container-library vulnerability scan, development Keycloak hardening and CA renewal remain the previously recorded release/operational items. Current Python/secret checks do not resolve them or claim complete release security.
- Final source/secret scan, approved-document/empty-index/unchanged-HEAD checks and isolated stack shutdown are recorded below. Retain D: data, protected credentials and reports; do not delete volumes. No commit or push. Stop after this bounded task.

- Final rebuilt-image gate after relative-expiration test correction: **283 passed/eight migration-only skipped in 67.15 seconds**, exit 0. All eight privileged migration checks separately passed in 30.67 seconds. The existing Starlette/TestClient HTTPX deprecation warning remains; no dependency was changed to silence it. Final strict static checks and 51-file source comparison passed with exit 0.
- Final catalog/provisioning/log inspection repeated successfully after the full gate. At **12:50:09 IST**, API/PostgreSQL/Redis each stopped with exit 0 and no OOM. `down` removed only project containers/control/edge networks; the disposable live probe was removed. Protected secrets, named volumes, D: database/Redis files and reports remain. API 18004 is no longer published; approved Keycloak and the two existing Axiom services remain running. `reports/final-shutdown.json`, `shutdown-completed.txt`.
- Final `git diff --check`, seven approved-document comparisons, empty index and unchanged entry HEAD passed. All **23** task files remain unstaged. Trivy repository secret scan was repeated after the memory update with exit 0 and zero findings; no clean container-vulnerability or complete Phase 2 claim is made. Stop here; do not start the proposed listing task or commit/push.

### 2026-09-27 — Phase 2 bounded task 4: admin key metadata listing

#### Entry, files and bounded outcome

- Entry: clean `main`, HEAD `dbe403446ec9f59b2f12e0033bdbedfd1529478d`. Read the eight project documents, current history and owning listing/authorization contracts. Phase 0/Phase 1 prerequisites and earlier Phase 2 evidence remain historical; this session reverified the relevant running environment and regression gate. No material contradiction was found. All seven approved specification/workflow documents remain unchanged.
- Implemented only **GET `/v1/tenants/{tenant_id}/keys`** for verified OIDC identities with active database admin membership. Added `src/arbiter/identity/key_cursor.py`, `operations/key_listing.py`, `tests/test_key_cursor.py` and `tests/test_key_listing.py`. Modified `src/arbiter/main.py`, `persistence/keys.py`, `transport/keys.py`, `tests/test_key_creation.py`, README and this file: **10 task files**. The creation fixture now wires listing and its obsolete GET-405 assertion becomes GET-200; all creation/security assertions remain.
- No migration, database role/grant/RLS policy, dependency lock/pin, Compose/provisioning configuration or approved contract changed. No revocation, workload authentication, quotas, budgets, Redis admission or inference was implemented. No files were staged, committed or pushed.
- Response models and repository SQL project only seven fields: ID, public ID, label, scopes, creation time, expiration and revocation time. Expired/revoked records remain visible as metadata. Verifier, pepper version, tenant/creator/audit internals and plaintext credential fields are neither queried nor serialized. The listing service has no issuer/pepper dependency; a test forbids key issuance during listing. Implementation details and pagination limitations are documented in README; requirements remain in Design.md.
- Authorization uses the existing `ManagementAccess` with `require_admin=True`, before query/cursor processing or repository access. Tenant scope comes from the active verified membership and transaction-local context. Both first/subsequent queries use a bound tenant predicate, bounded lookahead and FORCE RLS; subsequent pages add a bound UUID comparison. Existing `(tenant_id,id)` uniqueness provides the supporting index without a schema change.
- Pagination implements the approved 50/default and 100/maximum, using ascending UUID order and an opaque encrypted UUID position. The existing cursor-key file is reused with a separate key-list purpose and authenticated tenant binding. Key/audit cursors are not interchangeable; no object/anchor lookup occurs on resume. Codec recreation, real API restart and a deleted-anchor fixture preserve continuation. Separate pages do not claim a fixed snapshot or creation-time ordering.

#### Environment and exact checks

Evidence root: **`D:\AI & ML\ArbiterData\phase2\key-list`**, reports under `reports`. Fresh protected secrets/PG/Redis storage: `key-list\ArbiterData`; public env file `keys.env`; Compose project **`arbiter-phase2-key-list`**, loopback API **18005**. Previous task data, model cache and shared Docker/WSL storage were retained. No model download/inference or identity account/client/configuration change occurred.

Linux engine **29.8.0** was reachable. The approved issuer was observed running during entry inspection; later live preflight found the same container stopped, exit 255/no OOM, finished `2026-09-27T07:49:20Z`. The cause was not established. Started that existing container. The first live probe failed with `ConnectError`; a later public discovery request returned HTTPS 200 with the approved CA, and the repeated Linux probe passed. This is an availability observation, not an inferred cause or an OIDC bypass.

Commands ran from `E:\Arbiter`. Actual scripts are retained outside Git in the evidence root; `$root` below denotes it:

```powershell
$taskCompose = @('--env-file', "$root\keys.env", '-p', 'arbiter-phase2-key-list')
.\scripts\prepare-local.ps1 -DataRoot "$root\ArbiterData"
docker compose @taskCompose config --quiet
docker compose @taskCompose up -d --wait postgres redis
docker build --target runtime -t arbiter-local:foundation .
docker build --target verification -t arbiter-local:verification .
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm migrate
docker compose @taskCompose up -d --wait api
docker compose @taskCompose restart api
docker compose @taskCompose up -d --wait api
```

| Check | Actual result / report |
| --- | --- |
| Frozen-image full isolation/regression suite | `test.ps1`: read-only image with `/tmp`, real `arbiter-phase2-key-list_control`, individual runtime/operator/migration credential mounts, `ARBITER_TEST_DATABASE=1`, `ARBITER_TEST_REDIS=1`; `python -m pytest -q -p no:cacheprovider --junitxml=/reports/isolation-tests.xml`: **320 passed, eight migration-only skipped, zero failures**, exit 0, **66.35 seconds**. Includes **28 listing** and **9 cursor** cases plus every prior gate. |
| Separate privileged migrations | `migration-tests.ps1`: same real network, bootstrap/migration credentials only, `ARBITER_TEST_MIGRATIONS=1`; `python -m pytest -q -p no:cacheprovider tests/test_migrations.py --junitxml=/reports/migration-tests.xml`: **8 passed**, exit 0, **48.63 seconds**. Empty/previous-supported upgrades, repeat head, seeded preservation and disposable round trips; application DB was not downgraded. |
| Static/package checks | `static.ps1`: `ruff check --no-cache .`, `ruff format --check --no-cache .`, `mypy --cache-dir /tmp/mypy`, `python -m pip check`: all exit 0; **65** Python files formatted, **55** typed source/test/migration files, no broken requirements. `static-checks.json`. Existing Starlette/TestClient deprecation remains; no dependency was changed to silence it. |
| Source integrity | `snapshot.ps1`, `python /reports/source_snapshot.py`: all **55** source/test/migration files match the tested frozen image byte-for-byte, exit 0, `source-snapshot.json`. |
| Approved live issuer/deployed API | `live_list_probe.py` in a separate diagnostic container with public CA and only its individual necessary diagnostic credentials: actual Keycloak signature/issuer/audience verification, admin POST/GET, exact metadata preservation, member 403, foreign/absent tenant same 404, missing/key-as-OIDC credentials 401, invalid list fields 422, secret/verifier exclusion. A live in-memory cursor survived a real isolated API restart; revocation/inference remained 404 and readiness 503. Exit 0, `live-list.json`. Tokens/credentials/cursors were not saved. Synthetic rows were cleaned up. |
| Runtime topology/provisioning/logs | `inspect.ps1`: API UID/GID 10001, read-only, ALL capabilities dropped/no-new-privileges, exactly three read-only runtime/cursor/pepper secret mounts, approved public CA, no privileged/issuer secret or provider network. Only API loopback 18005 published, PG/Redis unpublished. Protected six-file secret provisioning preserved every value on repetition. API/PG/Redis/Keycloak logs: zero matches for six deployment secrets plus existing diagnostic-client secret; zero JWT/API-key patterns. `runtime-topology.json`, `secret-provisioning.json`, `log-secret-comparison.json`; values/raw logs suppressed. |
| Dependency advisory check | `dependency.ps1`: OSV `POST https://api.osv.dev/v1/querybatch` from unchanged development lock: **39 complete PyPI results, zero advisory packages**, checked **13:26:41 IST**. `dependency-audit.json`. No OS/container-library verdict follows. |
| Repository secret scan | `scan.ps1`: unchanged digest-pinned Trivy 0.74.0; network disabled, read-only checkout, `.git` excluded, `fs --cache-dir /scratch/trivy --scanners secret --timeout 3m --exit-code 1 --no-progress --format json --output /reports/repository-secret-scan.json /workspace`: exit 0, zero findings. Repeated after the final memory update. |

Runtime image: **`sha256:901a86cea406b6ff9535ce781dbd5d1593d21a94cf8efa0c0070a6058ab8e461`**; final verification image: **`sha256:f74259c9dcfc7962cac5ad17c130e23b071fc9818aa38d83c473cf513b5997a7`**. These identify local uncommitted builds, not a published release.

#### Security evidence and limits

- Member JWT role/tenant forgeries cannot grant admin permission. Unauthorized/absent tenant responses are identical apart from server request IDs; malformed queries do not run before membership/admin checks. Invalid signed tokens and duplicate/mixed credentials produce no DB statements.
- Seeded **115** real keys span default/max pages with complete UUID ordering and no duplication. Exact stored identifier/scope/expiration/revocation metadata was preserved, including expired and revoked fixtures. Those fixtures do not implement a revocation operation.
- Foreign, altered, noncanonical, wrong-version, wrong-purpose and malformed cursors fail safely; cursor decoding performs no cross-tenant lookup. Unknown key filters are rejected; foreign/random key-detail references both remain absent routes. No cross-tenant metadata is returned.
- Observed listing SQL contains only the allowed projection, bound authenticated tenant and at most 51/default rows. A single backend alternated A/B/A correctly; after every transaction, tenant context was cleared and context-free key reads returned zero rows. A deliberately poisoned session caused sanitized 503, connection disposal and recovery on a different backend. Runtime verifier/version reads and attempted key mutation still fail with `42501`.
- Exact generated plaintext secret components and verifier hex/base64 representations were absent from listing, validation errors and captured logs. Creation remains the only secret-returning operation. Real refused PostgreSQL connectivity produced sanitized 503; health/inference remained fail-closed. No secret reconstruction or new privileged lookup exists.
- Initial lint/format findings were corrected; an interim format check failed before the final formatter run. Final static checks supersede it. The initial live connection failure above is not a pass; the later approved-CA probe and full live restart verification are the completed evidence. No negative test, privilege or TLS validation was weakened.

#### Remaining Phase 2 work and handoff

- This bounded listing task has no unresolved implementation blocker or human decision. **Phase 2 remains incomplete**: key revocation and workload verification/scopes/expiry, remaining tenant model/usage/request metadata, operator policy administration and complete revocation/suspension admission-lock race gates remain. No quotas, budgets, Redis admission or inference was enabled.
- Next bounded task, proposed only: tenant-admin key revocation with OIDC/admin authorization, scoped object access, tenant-first locking, idempotent behavior and atomic audit evidence. Do not implement it without another task instruction.
- The previously recorded incomplete OS/container-library vulnerability scan, development issuer hardening and CA renewal remain release/operational items. Current package/secret checks do not resolve them or constitute a complete Phase 2/release security claim.
- Final catalog/log checks, stopped-state evidence and Git/secret review are recorded below. Retain this project's D: files/credentials/reports and named volumes. Do not stage, commit, push or expand the task.

- Final catalog probe exit 0: PostgreSQL **17.11 (Debian 17.11-1.pgdg12+2)**, unchanged head `0005_api_key_creation`, FORCE RLS, fixed helper ownership/search path/EXECUTE grants and deferred matching audit FK intact; restricted migration memberships unchanged; zero leftover disposable DBs or synthetic principals. `reports/database-security.json`, `catalog.exit`. Provisioning/topology/service-log checks repeated successfully after the live API restart and full gate.
- At **13:34:03 IST**, API/PostgreSQL/Redis stopped with exit 0 and no OOM. `down` removed only this project's containers/control/edge networks; the disposable live probe was removed. Protected D: credentials/data/reports and named volumes were retained. API 18005 is no longer published. Approved Keycloak and the two existing Axiom containers remain running. `reports/final-shutdown.json`, `shutdown-completed.txt`.
- Final `git diff --check`, seven approved-document comparisons, unchanged schema/pins/grants/provisioning, empty index and unchanged entry HEAD passed. All **10** task files remain unstaged. The repository secret scan repeated after this final entry with exit 0 and zero findings. This completed bounded task does not close Phase 2. Stop; no commit, push or next-task implementation.

### 2026-09-27 — Phase 2 bounded task 5: admin key revocation

#### Entry, files and observed outcome

- Entry: clean `main`, HEAD `df70fc3312ba217da5cb80524575399154d5a13d`. Read the project documents and current history, inspected the actual implementation and reverified the relevant environment. Phase 0/Phase 1 acceptance remains the prerequisite. No specification contradiction was found; PRD, Architecture, Design, Rules, Agents, Phases and Prompt remain unchanged. No stage, commit or push.
- Added `migrations/versions/0006_api_key_revocation.py`, `src/arbiter/operations/key_revocation.py` and `tests/test_key_revocation.py`. Modified `src/arbiter/main.py`, `persistence/keys.py`, `transport/keys.py`, `tests/test_database_foundation.py`, `tests/test_key_creation.py`, `tests/test_key_listing.py`, `tests/test_migrations.py`, README and this file: **12 task files**. Existing creation/list fixtures wire the new service; the successful creation fixture now expects revocation 200 while preserving secret/isolation assertions. Foundation/migration head assertions advance to the new revision.
- Implemented only the approved admin revocation route. It uses existing verified OIDC/active-membership authorization and scoped transaction capability. The object UUID and unsupported input are validated after membership/admin authorization. The explicit response contains only key ID and aware revocation timestamp, with no-store; no credential/verifier is queried or serialized. No body/query options are accepted. Foreign/absent objects share generic 404. Repeat revocation returns the original timestamp with no duplicate mutation audit.
- The migration adds narrowly granted runtime EXECUTE on a fixed-search-path SECURITY DEFINER function owned by the existing NOLOGIN/NOBYPASSRLS key writer. The writer receives only additional scoped metadata SELECT and `UPDATE(revoked_at)` needed for locking/mutation. Its audit INSERT policy admits the fixed revocation action alongside creation. Runtime retains no direct key UPDATE/DELETE or verifier access and cannot assume the writer role. FORCE RLS and composite relationships remain unchanged.
- The function locks the authenticated tenant first, rechecks active tenant/admin membership, then locks the tenant-qualified key. It sets the timestamp and inserts content-free member audit in the same transaction; service results reach transport only after commit. The existing immutability trigger now also rejects clearing/changing an established revocation timestamp. Expiration, scopes, verifier and all other key fields are preserved. Migration downgrade restores the preceding privileges/policy/trigger without rewriting stored key/audit data.
- No workload resolver/authentication, quotas, budgets, Redis admission, routing, provider or inference path was added. No dependency lock/image pin, Compose, secret provisioning, approved specification or OIDC configuration changed.

#### Real environment and exact verification

Evidence root: **`D:\AI & ML\ArbiterData\phase2\key-revoke`**, reports under `reports`; fresh protected credentials, PostgreSQL/Redis state and scratch under its `ArbiterData` child. Public env `keys.env`, isolated Compose project **`arbiter-phase2-key-revoke`**, API loopback **18006**. Prior project data/model cache and unrelated Docker/WSL storage were retained. No model download/start/inference, external account, issuer account/client/configuration change or unrelated service restart occurred.

Commands ran from `E:\Arbiter`; `$root` denotes the evidence root. Retained PowerShell/Python verification scripts are outside Git. Long-running runners used `Start-Process powershell -WindowStyle Hidden` with redirected logs and explicit result files; command-host interruptions are not counted as completed checks.

```powershell
.\scripts\prepare-local.ps1 -DataRoot "$root\ArbiterData"
$taskCompose = @('--env-file', "$root\keys.env", '-p', 'arbiter-phase2-key-revoke')
docker compose @taskCompose config --quiet
docker compose @taskCompose up -d --wait postgres redis
docker build --target runtime -t arbiter-local:foundation .
docker build --target verification -t arbiter-local:verification .
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm migrate
docker compose @taskCompose up -d --wait api
docker compose @taskCompose restart api
docker compose @taskCompose up -d --wait api
docker compose @taskCompose --profile operations run --rm --no-deps diagnostics
```

| Check | Actual result / artifact |
| --- | --- |
| Focused real-PostgreSQL gate | `focused.ps1`, read-only current source with individual runtime/operator/migration secret mounts: `python -m pytest -q -p no:cacheprovider tests/test_key_revocation.py tests/test_key_creation.py tests/test_key_listing.py --junitxml=/reports/focused-tests.xml`: **95 passed**, exit 0, **65.32 seconds**. |
| Final frozen-image full isolation/regression gate | `test.ps1`, read-only frozen verification image, real control network, individual runtime/operator/migration mounts, `ARBITER_TEST_DATABASE=1`, `ARBITER_TEST_REDIS=1`: `python -m pytest -q -p no:cacheprovider --junitxml=/reports/isolation-tests.xml`: **346 passed, 11 migration-only skipped**, zero failures, exit 0, **92.30 seconds**. Includes **26 revocation cases** and every existing Phase 1/Phase 2 gate. |
| Separate privileged migration gate | `migration-tests.ps1`, bootstrap/migration credentials only, `ARBITER_TEST_MIGRATIONS=1`: `python -m pytest -q -p no:cacheprovider tests/test_migrations.py --junitxml=/reports/migration-tests.xml`: **11 passed**, exit 0, **51.24 seconds**. Empty/all preceding supported heads, repeated head and disposable base/head round trips, tenant/audit preservation, and seeded expired/revoked key preservation through `0005 -> head -> 0005 -> head`. Application DB was not downgraded. |
| Static/package checks | `static.ps1`: `ruff check --no-cache .`, `ruff format --check --no-cache .`, `mypy --cache-dir /tmp/mypy`, `python -m pip check`: all exit 0; **68** formatted Python files, **58** typed source/test/migration files, no broken requirements. `static-checks.json`. |
| Frozen source integrity | `snapshot.ps1`, `python /reports/source_snapshot.py`: all **58** source/test/migration Python files match the tested image byte-for-byte, exit 0, `source-snapshot.json`. |
| Actual approved Keycloak/deployed API | `api-live.ps1`, `live_revoke_probe.py`: approved verified CA/issuer/audience/RS256/JWKS; real admin POST creation/revocation/repeat, member 403, foreign/absent tenant and key identical 404, missing/key-as-OIDC 401, invalid fields 422. Exact one matching audit, secret/verifier exclusion and same committed timestamp after real isolated API restart passed. Exit 0, `live-revoke.json`, `restart.exit`. Tokens/secrets were neither printed nor saved; synthetic records cleaned up. |
| Runtime topology/provisioning/logs | `inspect.ps1`: API UID/GID 10001, read-only, ALL capabilities dropped/no-new-privileges, exactly three read-only runtime/cursor/pepper secret mounts and public CA, no privileged/issuer credential or provider network. Only API loopback 18006 published; PG/Redis unpublished. Six protected secret files preserved byte-for-byte on repetition. API/PG/Redis/Keycloak logs: zero actual matches against six deployment secrets plus existing diagnostic-client secret; zero JWT/API-key patterns. `runtime-topology.json`, `secret-provisioning.json`, `log-secret-comparison.json`; raw logs/values suppressed. |
| Catalog/diagnostics | `security_catalog.py`: PostgreSQL **17.11 (Debian 17.11-1.pgdg12+2)**, head `0006_api_key_revocation`, FORCE RLS, fixed revocation helper owner/search path, EXECUTE only runtime/nonlogin owner, deferred matching creation-audit FK, restricted migration memberships and zero leftover disposable DBs/synthetic principals: exit 0, `database-security.json`. Runtime-only diagnostics exit 0: PG/Redis foundation true, application ready false. |
| Dependency advisory check | `dependency.ps1`: fresh OSV `POST https://api.osv.dev/v1/querybatch` from unchanged development lock: **39 complete PyPI results, zero advisory packages**, **16:03:11 IST**, `dependency-audit.json`. No OS/container-library verdict follows. |

Final runtime image: **`sha256:1bd79d6fdceced682f06b1bafaa1646542c57aac0d711bd2e92a66428dfbe25a`**; verification image: **`sha256:b3e258f762be2a7a0460cd70faf8ea68d1d9fd8b0024a71ee971f1cfc016e04e`**. These are local uncommitted builds, not published releases.

#### Security evidence, corrections and remaining work

- Concurrent **12** revocation requests returned one timestamp and exactly one committed revocation audit. A real audit uniqueness failure caused sanitized 503 and left the key unrevoked with no revocation event; a subsequent valid call recovered. Explicit outer-transaction rollback also removed both changes; another connection observed neither uncommitted change. Matching audit target/member/revision/correlation/time were checked against committed database rows.
- Member/forged role claims, unauthorized tenants, foreign/nonexistent keys, malformed identifiers and duplicate/mixed credentials were denied. Invalid signed issuer/audience/expiry/not-before tokens caused zero runtime DB statements. Unsupported body/query fields could not mutate a key. Existing creation/list/audit secret tests and RLS negatives remain passing.
- Tenant-lock races with admin downgrade, membership deactivation and tenant suspension rechecked authority and denied the waiting revocation without changing the key or writing false success evidence. A subsequent transaction following tenant/key lock order observed committed revocation immediately. This is database ordering/state evidence, **not a future dispatch implementation or complete dispatch-race proof**.
- Direct runtime revocation UPDATE, DELETE, verifier reads, role switching and RLS disabling fail with `42501`. Helper calls with absent/mismatched context, wrong actor/principal, member role or inaccessible key deny. Operator execution is denied. Owner attempts to clear/change an established timestamp fail `23514`. As with existing creation/identity helpers, application-verified identity supplies the binding; these controls do not claim protection against arbitrary SQL or compromised infrastructure credentials.
- A one-connection pool reused the same backend across A/B/A revocations, with cleared transaction-local context and zero context-free key reads afterward. Poisoned session context was discarded and the next operation recovered on a different backend. Expired keys could be revoked while expiration remained unchanged. Exact credential/secret/verifier representations were absent from checked responses/errors/audits/captured logs.
- Initial style/line-length and two scalar/list typing findings were fixed; final static results supersede them. One patch context mismatch made no edit and was corrected. A foreground command-host interruption did not complete its static run; the hidden retained runner later completed all checks. Both focused/full test runs had zero failures. Existing Starlette/TestClient deprecation and pip cache warning remain; no dependency, negative assertion, authority or TLS control was weakened.
- **Phase 2 remains incomplete.** Workload key resolution/authentication is absent internally and over HTTP, so post-revocation workload authentication denial and the full dispatch/revocation/suspension race gate cannot yet be exercised. Revocation state is durable and uncached; all workload/inference routes remain unavailable. Remaining Phase 2 work includes key authentication/scope/expiry checks, tenant model/usage/request metadata, operator policy administration and the outstanding lock-race gates. Existing OS/container vulnerability review, development-issuer hardening and CA renewal remain historical release/operational items.
- **Next bounded task, proposed only:** restricted workload API-key resolution/verification using the approved HMAC/pepper representation, fresh tenant/key status/expiry checks, scoped identity and negative scope/credential tests, including rejection after committed revocation. Keep inference and governance unavailable. Do not implement without another instruction.
- No unresolved human decision blocks the implemented revocation task. Final repository secret scan, Git review and retained-storage shutdown results are recorded below when completed. Do not commit/push or expand this task.

#### Final security review and stopped-state handoff

- Repository secret scan completed after the implementation/main memory entry at **16:08:52 IST**: immutable Trivy 0.74.0 `aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969`, no network, read-only checkout, `.git` excluded; `fs --cache-dir /scratch/trivy --scanners secret --skip-dirs /workspace/.git --timeout 3m --exit-code 1 --no-progress --format json --output /reports/repository-secret-scan.json /workspace`: **exit 0, zero findings**. `scan.ps1`, `secret-scan.exit`. This is a repository secret check, not an OS/container vulnerability verdict.
- Final catalog/provisioning/log inspection repeated successfully after the full gate and live API restart. At **16:09:02 IST**, API/PostgreSQL/Redis stopped with **exit 0, no OOM**. Project-only `down` removed its containers/control/edge networks; the exited diagnostic probe was removed. Named volumes, D: data, protected credentials/reports and external identity network were retained; no volume removal or unrelated data deletion. `shutdown.ps1`, `final-shutdown.json`, `shutdown-completed.txt`.
- Reviewed the bounded production/migration/test diff. `git diff --check` and seven approved-document comparisons passed; index empty, HEAD unchanged from entry. All **12** task files remain unstaged. No commit/push, later task, inference or complete Phase 2 claim. User requested no popping terminal windows; remaining native checks run only through hidden runners with redirected logs.
- This finishes the bounded revocation implementation and its currently available verification. Workload authentication/dispatch-race evidence remains explicitly pending above. Stop here; the next task is a proposal only.

### 2026-09-27 — Phase 2 bounded task 6: restricted workload key verification

#### Entry, files and bounded outcome

- Entry: clean `main`, HEAD `1f3be62cc8443e54c45bb90c2c8608b33e483f88`. Read the approved documents/current history and checked the actual repository and environment. Phase 0 and Phase 1 remain prerequisites with their recorded evidence. No contradiction requiring a specification change was found; PRD, Architecture, Design, Rules, Agents, Phases and Prompt remain unchanged. No staging, commit or push.
- Added `migrations/versions/0007_workload_key_lookup.py`, `src/arbiter/identity/workload.py`, `persistence/workload.py`, `transport/workload.py`, `tests/test_workload_access.py` and `tests/test_workload_material.py`. Modified `src/arbiter/identity/keys.py`, `main.py`, `operations/bootstrap.py`, `tests/test_database_foundation.py`, `tests/test_migrations.py`, README and this memory entry: **13 task files**. Dependency locks, image pins, Compose, protected-secret provisioning and approved issuer configuration are unchanged.
- Implemented the reusable workload HTTP credential boundary and transaction-scoped service, wired into application lifespan. Production workload data/inference routes remain unavailable; fixture-only routes test HTTP authentication without adding a partial production endpoint. Existing OIDC administration routes retain their authentication contract. No quotas, budgets, Redis admission, provider routing or inference was implemented.
- Migration `0007_workload_key_lookup` and explicit bootstrap provision a separate restricted NOLOGIN/NOSUPERUSER/NOBYPASSRLS key-resolution owner. Its pre-tenant RLS exception grants only the specific tenant/key column reads needed by the fixed-search-path SECURITY DEFINER function. Only runtime and the nonlogin owner have EXECUTE; the function returns authenticated key ID, tenant ID and scopes, never verifier or secret. Runtime still has no verifier SELECT, direct key mutation, migration authority or helper-role membership. Migration has three explicit non-inheriting SET-only helper memberships, no admin option. Schema CREATE is revoked after ownership transfer.
- Parsing enforces the existing exact canonical credential representation before database access. HMAC uses the existing deployment pepper/version and issuance representation; candidate bytes use a redacted secret type. The database compares all **32** bytes with XOR/OR accumulation and no mismatch-dependent early exit; unknown public IDs use dummy bytes and execute the same comparison loop. Every wrong-byte position and unknown/dummy case denied. This is fixed-work verifier-comparison evidence, **not a proof of identical end-to-end HTTP/database timing**; no timing threshold or formal cryptographic timing proof is claimed.
- Every operation resolves fresh key/tenant state and checks required scopes before establishing transaction-local tenant context. The sole tenant source is the returned verified key binding; the service accepts no tenant selector. No positive authorization cache exists. Verification is not dispatch authority: future admission must lock and revalidate current key/tenant permission according to Design.md.

#### Real environment and exact checks

Evidence/scripts/reports: **`D:\AI & ML\ArbiterData\phase2\workload-key`**, reports under `reports`; fresh protected credentials and scratch under its `ArbiterData` child, named PostgreSQL/Redis volumes for isolated project **`arbiter-phase2-workload-key`**. Public env `keys.env`, API loopback **18007**. Existing model cache and unrelated Docker/WSL data were retained. No model download/start/inference, external account, issuer client/configuration change or unrelated service restart occurred. Native checks used hidden PowerShell runners with redirected logs as requested.

Commands ran from `E:\Arbiter`; `$root` denotes this evidence directory. Actual commands and individual credential mounts are retained in the named scripts outside Git. Tokens and issued key secrets stayed in probe process memory and were not printed or saved.

```powershell
.\scripts\prepare-local.ps1 -DataRoot "$root\ArbiterData"
$taskCompose = @('--env-file', "$root\keys.env", '-p', 'arbiter-phase2-workload-key')
docker compose @taskCompose config --quiet
docker compose @taskCompose up -d --wait postgres redis
docker build --target runtime -t arbiter-local:foundation .
docker build --target verification -t arbiter-local:verification .
docker compose @taskCompose --profile operations run --rm bootstrap
docker compose @taskCompose --profile operations run --rm migrate
docker compose @taskCompose up -d --wait api
docker compose @taskCompose --profile operations run --rm --no-deps diagnostics
```

| Check | Actual result / artifact |
| --- | --- |
| Focused material/real-PostgreSQL workload gate | `focused.ps1`, read-only current source and individual runtime/operator/migration mounts, `ARBITER_TEST_DATABASE=1`: `python -m pytest -q -p no:cacheprovider tests/test_workload_material.py tests/test_workload_access.py --junitxml=/reports/focused-tests.xml`: **41 passed**, exit 0, **23.88 seconds**. |
| Final frozen-image full regression/isolation gate | `test.ps1`, read-only frozen image without source mount, real PostgreSQL/Redis control network, individual test credentials, `ARBITER_TEST_DATABASE=1`, `ARBITER_TEST_REDIS=1`: `python -m pytest -q -p no:cacheprovider --junitxml=/reports/isolation-tests.xml`: **387 passed, 13 migration-only skipped**, zero failures, exit 0, **95.50 seconds**. All existing Phase 1/Phase 2 tests preserved. |
| Separate privileged migration suite | `migration-tests.ps1`, bootstrap/migration credentials only, `ARBITER_TEST_MIGRATIONS=1`: `python -m pytest -q -p no:cacheprovider tests/test_migrations.py --junitxml=/reports/migration-tests.xml`: **13 passed**, exit 0, **49.03 seconds**. Empty/all preceding supported schemas through `0006_api_key_revocation`, repeated head, disposable base/head round trips, seeded tenant/audit preservation and expired/revoked key preservation across `0005 -> head -> 0005 -> head`. Application DB was not downgraded. |
| Static/package integrity | `ruff check --no-cache .`, `ruff format --check --no-cache .`, `mypy --cache-dir /tmp/mypy`, `python -m pip check`: all exit 0; **74** formatted Python files, **64** typed source/test/migration files, no broken requirements. `static-checks.json`. |
| Tested-source integrity | `snapshot.ps1`, `python /reports/source_snapshot.py`: **64** source/test/migration files byte-match the tested image, exit 0, `source-snapshot.json`. |
| Actual API issuance and restricted runtime verification | `api-live.ps1`, `live.ps1`, `live_workload_probe.py`: approved CA/issuer/audience/RS256/JWKS token used for actual HTTP admin creation/revocation, followed by internal WorkloadAccess with only runtime credentials and the mounted deployment pepper. Verified two tenant bindings, scope/cross-tenant/unknown/malformed/secret-transplant denial, fresh suspension/reactivation, repeated denial after committed HTTP revocation, and a previously valid short-lived key rejected after a measured 20-second expiry wait. Exit 0, `live-workload.json`. Synthetic records cleaned up. No API restart was exercised in this task. |
| Catalog/diagnostics | `catalog.ps1`, `security_catalog.py`: PostgreSQL **17.11 (Debian 17.11-1.pgdg12+2)**, head `0007_workload_key_lookup`, FORCE RLS, fixed helper owner/search path/EXECUTE grants, deferred matching creation-audit FK, restricted migration memberships and zero leftover disposable DBs/synthetic principals: exit 0, `database-security.json`. Runtime-only diagnostics exit 0: PostgreSQL/Redis foundation true, application ready false. |
| Runtime topology/provisioning/logs | `inspect.ps1`: API UID/GID 10001, read-only, ALL capabilities dropped/no-new-privileges, exactly three read-only runtime/cursor/pepper secret mounts and public CA, no privileged or issuer-client secret/provider network. Only loopback 18007 published; PG/Redis unpublished. Six protected secret files preserved on repeated preparation. API/PG/Redis/Keycloak logs: zero exact matches against six deployment secrets plus existing diagnostic-client secret; zero JWT/API-key patterns. `runtime-topology.json`, `secret-provisioning.json`, `log-secret-comparison.json`; raw values/logs suppressed. |
| Dependency advisories | `dependency.ps1`, fresh OSV `POST https://api.osv.dev/v1/querybatch` from unchanged development lock: **39 complete PyPI results, zero advisory packages**, **16:34:16 IST**, `dependency-audit.json`. No OS/container-library vulnerability verdict follows. |

Tested runtime image: **`sha256:4ce7bc09f1f7c935eb203d87da5cd1b52def3fa53c171bc61ab5355fe604ce07`**; verification image: **`sha256:a885f08300d7d46de88bedcdec15afc63a82a58cada740f832b7cc8c5f64182e`**. These are local uncommitted builds, not published releases.

#### Negative/security evidence and handoff

- Malformed/missing/duplicate/mixed credentials, unknown ID, wrong secret, cross-key secret transplant, expired/revoked/old-pepper-version keys, suspended tenants and OIDC tokens on the workload boundary fail safely. Unknown ID and invalid secret return the same sanitized 401 envelope; other invalid-key states use that envelope. Missing scope returns generic 403 and invokes no callback. Malformed keys cause zero database statements. Tenant route/header/body/model and role inputs cannot change the authenticated tenant; foreign scoped object/membership queries return no rows.
- Repeated positive verification of an API-issued key did not cache authorization: actual committed revocation, suspension and elapsed expiry caused subsequent fresh denial. Twelve concurrent A/B requests retained correct isolation. No authentication success mutation/audit was introduced.
- A one-connection pool alternated A/B/A on the same backend, then showed cleared context and zero context-free key reads. Invalid credentials and missing scope also leave no context. A poisoned session was rejected/discarded and recovered on a different backend. Real refused PostgreSQL connectivity produced sanitized unavailable behavior. Runtime direct verifier/version reads, role switching, RLS DDL and migration attempts failed with `42501`; operator/migration execution and runtime resolution inside a preexisting tenant context also failed.
- Exact issued secret components and verifier hex/base64 representations were absent from checked responses/errors/audit records and captured logs. The live probe checked audit/error containment without retaining secrets. Helper catalog tests prove no write/schema-CREATE authority, only two SELECT policies, no PUBLIC EXECUTE, fixed search path and nonlogin/non-bypass ownership.
- Initial lint/format/line-length findings were corrected; final results supersede them. Focused/full/migration runs had zero failures. Existing Starlette/TestClient deprecation and pip cache warning remain; no negative assertion, TLS validation or authority restriction was weakened.
- **Phase 2 remains incomplete.** Remaining work: approved model and tenant policy administration, tenant model/usage/request metadata endpoints, transactional audit for new security mutations, and full revocation/suspension races against the admission/dispatch lock. Authentication tests prove rejection after committed changes, not the future dispatch race gate. Liveness 200, readiness 503 and absent workload data/inference routes 404 were observed. Inference remains unavailable.
- **Next bounded task, proposed only:** local operator tenant-policy persistence/provisioning with validated policy revisions, tenant-first locking, restricted privileges and atomic audit evidence. Do not implement rate/quota/budget enforcement or inference, or begin this task without another instruction.
- No human decision blocks the completed verification task. The previously recorded incomplete OS/container-library vulnerability review, development Keycloak hardening and CA renewal remain release/operational items; these Python/secret checks do not resolve them. Final repository scan, Git review and project-only retained-storage shutdown results are recorded below after completion. Stop after this task; no commit/push.

#### Final review and stopped-state evidence

- Repository secret scan completed at **16:43:49 IST**, immutable Trivy 0.74.0 `aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969`, no network, read-only checkout, `.git` excluded: `fs --cache-dir /scratch/trivy --scanners secret --skip-dirs /workspace/.git --timeout 3m --exit-code 1 --no-progress --format json --output /reports/repository-secret-scan.json /workspace`: **exit 0, zero findings**. `scan.ps1`, `secret-scan.exit`. Repeat this check after this final memory edit; the retained report is the final scan artifact. This does not constitute an OS/container vulnerability scan.
- Catalog/topology/provisioning/log inspection repeated successfully before shutdown. At **16:43:58 IST**, API/PostgreSQL/Redis stopped with **exit 0 and no OOM**. Project-only `down` removed this project's containers/control/edge networks; the exited probe was removed. Named volumes, protected D: credentials/data/reports and external identity network retained. `shutdown.ps1`, `final-shutdown.json`, `shutdown-completed.txt`. API 18007 is no longer published by this stack.
- Reviewed the bounded source/migration/test diff. `git diff --check`, comparisons of the seven approved documents, empty index and unchanged entry HEAD passed before this final entry and are repeated afterward. All **13** task files remain unstaged. No commit, push, later-task implementation, inference or complete Phase 2 claim. Stop here.
