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
