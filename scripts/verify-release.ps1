param(
    # Review the release coordinator before committing it; never permit runtime changes.
    [switch]$AllowReleaseToolingChanges,
    [switch]$DeselectKnownUsageFixture,
    [string]$EvidenceRoot = 'D:\AI & ML\ArbiterData\phase3\exit-matrix-20260930\ArbiterData\tmp',
    [string]$ModelDirectory = 'D:\AI & ML\ArbiterData\ollama\models'
)

# Run from normal host Windows PowerShell, with Docker Desktop's Linux engine.
# No retries, model pulls, volume deletion, result storage, or release tagging.
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$dataRoot = 'D:\AI & ML\ArbiterData\phase3\exit-matrix-20260930\ArbiterData'
$shell = Join-Path $PSHOME 'powershell.exe'
$script:summary = @()
$script:testResults = @()
$script:evidence = $null
$script:stage = 'baseline'
$script:sequence = 0
$script:fullStarted = $false
$script:childEvidence = @()
$script:inspectionDirectories = @()
$lock = $null
$savedEnvironment = @{}
$exitCode = 0

function Invoke-Required([string]$Label, [string]$Command, [string[]]$Arguments, [switch]$Quiet) {
    $script:stage = $Label
    $script:sequence++
    if (-not $Quiet) { Write-Host "RUN $Label" }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    # Resolve first and reset the native status so a missing tool cannot reuse 0.
    $null = Get-Command $Command -CommandType Application -ErrorAction Stop
    # Retain native diagnostics privately; never echo credentials or raw exceptions.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $global:LASTEXITCODE = $null
        $output = @(& $Command @Arguments 2>&1 | ForEach-Object { $_.ToString() })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($null -eq $code) { $code = 1 }
    $watch.Stop()
    if ($script:evidence) {
        $output | Set-Content -LiteralPath (Join-Path $script:evidence ("{0:D2}.log" -f $script:sequence)) -Encoding UTF8
    }
    if (-not $Quiet) { $script:summary += [PSCustomObject]@{ stage = $Label; exit_code = $code; seconds = $watch.Elapsed.TotalSeconds } }
    if ($code -ne 0) {
        $failure = New-Object Exception("Required stage failed: $Label")
        $failure.Data['ExitCode'] = $code
        throw $failure
    }
    if (-not $Quiet) { Write-Host "PASS $Label" }
    return $output
}

function Assert-ReleaseGit([bool]$AllowTooling) {
    $status = @(Invoke-Required 'git status' 'git' @('status', '--porcelain=v1', '--untracked-files=all'))
    $index = @(Invoke-Required 'empty index' 'git' @('diff', '--cached', '--name-only'))
    if ($index.Count) { throw 'Release requires an empty index.' }
    $branch = @(Invoke-Required 'main branch' 'git' @('branch', '--show-current'))
    $divergence = @(Invoke-Required 'main divergence' 'git' @('rev-list', '--left-right', '--count', 'origin/main...main'))
    if ($branch.Count -ne 1 -or $branch[0] -cne 'main' -or $divergence.Count -ne 1 -or $divergence[0] -notmatch '^0\s+0$') {
        throw 'Release requires main equal to origin/main.'
    }
    $allowed = @('README.md', 'docs/Memory.md', 'scripts/verify-release.ps1', 'tests/test_verify_release.ps1')
    foreach ($line in $status) {
        if (-not $AllowTooling -or $line.Length -lt 4 -or $line.Substring(0, 3) -notin @(' M ', '?? ') -or
            $line.Substring(3) -cnotin $allowed) { throw 'Release requires a clean tree; review mode permits only release tooling/docs.' }
    }
    return @(Invoke-Required 'revision' 'git' @('rev-parse', 'HEAD'))[0]
}

function Protect-Evidence([string]$Directory) {
    New-Item -ItemType Directory -Path $Directory -ErrorAction Stop | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # One explicit /grant:r pair per SID; grants bundled after a single /grant:r are not portable.
    $rights = ':(OI)(CI)F'
    $userGrant = '*' + $sid + $rights
    $systemGrant = '*S-1-5-18' + $rights
    $administratorGrant = '*S-1-5-32-544' + $rights
    $arguments = @(
        $Directory,
        '/inheritance:r',
        '/grant:r', $userGrant,
        '/grant:r', $systemGrant,
        '/grant:r', $administratorGrant
    )
    Invoke-Required 'protect evidence' 'icacls.exe' $arguments | Out-Null
    $acl = Get-Acl -LiteralPath $Directory
    if (-not $acl.AreAccessRulesProtected -or @($acl.Access).Count -ne 3) { throw 'Evidence ACL is not private.' }
    foreach ($rule in $acl.Access) {
        if ($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid, 'S-1-5-18', 'S-1-5-32-544') -or
            $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'Unexpected evidence reader.' }
    }
}

function Assert-NoOtherVerifier {
    $active = @(Invoke-Required 'exclusive verifier container check' 'docker' @('ps', '--format', '{{.Image}} {{.Names}}'))
    if (@($active | Where-Object { $_ -match '^arbiter-local:p3-4-verification\s' }).Count) { throw 'A verification container is already running.' }
    # Fence existing canonical host controllers, including their between-container gaps.
    $controllers = @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
        $_.ProcessId -ne $PID -and $_.Name -match '^(powershell|pwsh)\.exe$' -and
        $_.CommandLine -match '(?i)(?:-File\s+|[\\/])(?:verify-phase3|verify-release)\.ps1'
    })
    if ($controllers.Count) { throw 'Another release/fault controller is active.' }
}

function Read-ReleaseJUnit([string]$Path, [string[]]$Required, [int]$Deselected, [string[]]$Output) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'Required JUnit evidence missing.' }
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    try { $xml = New-Object Xml.XmlDocument; $xml.Load($reader) } finally { $reader.Dispose() }
    $suites = @($xml.SelectNodes('/testsuites/testsuite | /testsuite'))
    $cases = @($xml.SelectNodes('//testcase'))
    if (-not $suites.Count -or -not $cases.Count) { throw 'Empty JUnit proof.' }
    $total = 0
    foreach ($suite in $suites) {
        foreach ($attribute in @('tests', 'failures', 'errors', 'skipped')) {
            if ($suite.GetAttribute($attribute) -notmatch '^\d+$') { throw 'Incomplete JUnit totals.' }
        }
        $total += [int]$suite.GetAttribute('tests')
        if ([int]$suite.GetAttribute('failures') -or [int]$suite.GetAttribute('errors') -or [int]$suite.GetAttribute('skipped')) {
            throw 'Release proof contains failures/errors/skips.'
        }
    }
    if ($total -ne $cases.Count -or $xml.SelectNodes('//failure | //error | //skipped').Count) { throw 'JUnit execution mismatch.' }
    foreach ($case in $cases) {
        if (-not $case.GetAttribute('classname') -or -not $case.GetAttribute('name')) { throw 'Unnamed JUnit proof.' }
    }
    foreach ($pattern in $Required) {
        if (-not @($cases | Where-Object { ($_.GetAttribute('classname') + '::' + $_.GetAttribute('name')) -match $pattern }).Count) {
            throw 'A required release proof did not execute.'
        }
    }
    $actualDeselected = 0
    $matches = [regex]::Matches(($Output -join "`n"), '(\d+) deselected')
    if ($matches.Count) { $actualDeselected = [int]$matches[$matches.Count - 1].Groups[1].Value }
    if ($actualDeselected -ne $Deselected) { throw 'Unexpected pytest deselection.' }
    $warningCount = 0
    $matches = [regex]::Matches(($Output -join "`n"), '(\d+) warnings?')
    if ($matches.Count) { $warningCount = [int]$matches[$matches.Count - 1].Groups[1].Value }
    $result = [PSCustomObject]@{ executed = $total; passed = $total; failures = 0; errors = 0; skipped = 0; deselected = $actualDeselected; warnings = $warningCount }
    $script:testResults += [PSCustomObject]@{ report = $Path; counts = $result }
    Write-Host ($result | ConvertTo-Json -Compress)
    return $result
}

function Invoke-Phase([string]$Phase, [string[]]$Required) {
    Assert-NoOtherVerifier
    if ($Phase -eq 'full') {
        if ($script:fullStarted) { throw 'Full regression may run only once.' }
    }
    if ((Assert-ReleaseGit $AllowReleaseToolingChanges.IsPresent) -cne $revision) { throw 'Candidate revision changed.' }
    if ($Phase -eq 'full') { $script:fullStarted = $true }
    $args = @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'verify-phase3.ps1'), '-Phase', $Phase)
    $deselected = 0
    if ($Phase -eq 'full' -and $DeselectKnownUsageFixture) {
        $args += @('-Deselect', 'tests/test_usage_transport.py::test_management_current_and_historical_usage')
        $deselected = 1
    }
    $output = @(Invoke-Required "canonical $Phase" $shell $args)
    $paths = @($output | Where-Object { $_ -match '^Evidence: ' } | ForEach-Object { $_.Substring(10) })
    if ($paths.Count -ne 1 -or -not $paths[0].StartsWith($dataRoot + '\tmp\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Canonical evidence location missing or unexpected.'
    }
    $script:childEvidence += $paths[0]
    if ($Phase -ne 'checks') {
        $counts = Read-ReleaseJUnit (Join-Path $paths[0] "$Phase.xml") $Required $deselected $output
        $counts | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:evidence "$Phase-counts.json") -Encoding UTF8
    }
}

function Set-ComposeRoot([string]$Root) {
    $linux = '/run/desktop/mnt/host/' + $Root.Substring(0, 1).ToLowerInvariant() + '/' + $Root.Substring(3).Replace('\', '/')
    $env:ARBITER_DATA_LINUX_ROOT = $linux
    $env:ARBITER_SECRETS_DIR = Join-Path $Root 'secrets'
    $env:ARBITER_MODEL_APPROVALS_DIR = Join-Path $Root 'model-approvals'
}

function Wait-Healthy([string]$Container) {
    $deadline = [DateTime]::UtcNow.AddSeconds(240)
    do {
        $status = @(Invoke-Required "health $Container" 'docker' @('inspect', '--format', '{{.State.Health.Status}}', $Container) -Quiet)
        if ($status.Count -eq 1 -and $status[0] -ceq 'healthy') { return }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Bounded clean-start health wait expired.'
}

function Invoke-RealProof([string]$Name, [string[]]$Targets, [string[]]$Required, [string]$ProviderNetwork) {
    Assert-NoOtherVerifier
    $container = "arbiter-release-$Name-" + [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $directory = Join-Path $script:evidence $Name
    New-Item -ItemType Directory -Path $directory | Out-Null
    $args = @('create', '--name', $container, '--network', 'arbiter-p34_control', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp', '--memory', '2g', '--pids-limit', '256',
        '--mount', "type=bind,source=$repository,target=/app,readonly", '--mount', "type=bind,source=$directory,target=/evidence",
        '--mount', "type=bind,source=$script:evidence,target=/release,readonly", '-e', 'PYTHONDONTWRITEBYTECODE=1',
        '-e', 'PYTHONPATH=/app/src:/app/tests:/release', '-e', 'ARBITER_DB_HOST=postgres', '-e', 'ARBITER_REDIS_HOST=redis', '-e', 'ARBITER_TEST_DATABASE=1',
        '-e', 'ARBITER_TEST_MIGRATIONS=1', '-e', 'ARBITER_TEST_REDIS=1', '-e', 'ARBITER_TEST_EXIT_HOST=0')
    foreach ($secret in @('db_bootstrap_password', 'db_migration_password', 'db_operator_password', 'db_runtime_password',
            'db_maintenance_password', 'api_key_pepper', 'audit_cursor_key', 'request_fingerprint_key')) {
        $args += @('--mount', "type=bind,source=$dataRoot\secrets\$secret,target=/run/secrets/$secret,readonly")
    }
    $args += @('arbiter-local:p3-4-verification', 'python', '-m', 'pytest', '-q', '-x', '-p', 'no:cacheprovider', '-p', 'release_metadata',
        '--junitxml=/evidence/proof.xml') + $Targets
    Invoke-Required "$Name create" 'docker' $args | Out-Null
    Invoke-Required "$Name provider network" 'docker' @('network', 'connect', $ProviderNetwork, $container) | Out-Null
    Invoke-Required "$Name start" 'docker' @('start', $container) | Out-Null
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        $state = @(Invoke-Required "$Name state" 'docker' @('inspect', '--format', '{{.State.Running}}', $container) -Quiet)
        if ($state.Count -eq 1 -and $state[0] -ceq 'false') { break }
        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($state[0] -cne 'false') {
        Invoke-Required "$Name bounded stop" 'docker' @('stop', '--time', '2', $container) | Out-Null
        throw 'Real proof exceeded its bounded execution allowance; evidence retained.'
    }
    $output = @(Invoke-Required "$Name logs" 'docker' @('logs', $container))
    $output | Set-Content -LiteralPath (Join-Path $directory 'output.log') -Encoding UTF8
    $code = @(Invoke-Required "$Name result" 'docker' @('inspect', '--format', '{{.State.ExitCode}}', $container))
    if ($code.Count -ne 1 -or $code[0] -notmatch '^\d+$') { throw 'Real proof exit missing.' }
    if ([int]$code[0]) { $failure = New-Object Exception('Real proof failed.'); $failure.Data['ExitCode'] = [int]$code[0]; throw $failure }
    Read-ReleaseJUnit (Join-Path $directory 'proof.xml') $Required 0 $output | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $directory 'counts.json') -Encoding UTF8
    $script:childEvidence += $directory
}

function Copy-TextEvidence([string]$Source, [string]$Destination) {
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($Source)) {
        $attributes = [IO.File]::GetAttributes($entry)
        if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Evidence symlink/reparse point refused.' }
        if ($attributes -band [IO.FileAttributes]::Directory) {
            if ([IO.Path]::GetFileName($entry) -ceq 'protected-backups') {
                # Sensitive archives are protected durable data, not public text logs.
                $acl = Get-Acl -LiteralPath $entry
                $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
                if (-not $acl.AreAccessRulesProtected -or @($acl.Access).Count -ne 3) { throw 'Backup directory permissions are not private.' }
                foreach ($rule in $acl.Access) {
                    if ($rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid, 'S-1-5-18', 'S-1-5-32-544') -or
                        $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'Unexpected backup-directory reader.' }
                }
                continue
            }
            Copy-TextEvidence $entry $Destination
        } elseif ([IO.Path]::GetExtension($entry) -cin @('.log', '.xml', '.json', '.jsonl', '.txt', '.exit')) {
            $script:artifactOrdinal++
            Copy-Item -LiteralPath $entry -Destination (Join-Path $Destination ("$script:artifactOrdinal" + [IO.Path]::GetExtension($entry))) -ErrorAction Stop
        }
    }
}

function Invoke-ArtifactProof {
    $textRoot = Join-Path $script:evidence ('text-artifacts-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $textRoot | Out-Null
    $script:inspectionDirectories += $textRoot
    $script:artifactOrdinal = 0
    foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($script:evidence)) {
        # Previous inspection inputs are exact copies; do not recurse into copies.
        if ([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::ReparsePoint) { throw 'Evidence reparse point refused.' }
        if ($entry -cin $script:inspectionDirectories) { continue }
        if ([IO.Directory]::Exists($entry)) { Copy-TextEvidence $entry $textRoot }
        elseif ([IO.Path]::GetExtension($entry) -cin @('.log', '.xml', '.json', '.jsonl', '.txt')) {
            $script:artifactOrdinal++
            Copy-Item -LiteralPath $entry -Destination (Join-Path $textRoot ("$script:artifactOrdinal" + [IO.Path]::GetExtension($entry))) -ErrorAction Stop
        }
    }
    foreach ($parent in $script:childEvidence) {
        if (-not $parent.StartsWith($script:evidence + '\', [StringComparison]::OrdinalIgnoreCase)) { Copy-TextEvidence $parent $textRoot }
    }
    Invoke-Required 'artifact leakage inspection' $shell @('-NoProfile', '-File', 'scripts/verify-security.ps1',
        '-Operation', 'artifacts', '-ArtifactDirectory', $textRoot, '-EvidenceRoot', $script:evidence) | Out-Null
}

function Export-ReleaseProbes([string]$Directory) {
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repository 'scripts/verify-release.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Release probe extraction syntax failed.' }
    foreach ($name in @('loadSource', 'metadataSource', 'inventory', 'metrics', 'migrationSource')) {
        $assignments = @($ast.FindAll({ param($node)
            $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq $name
        }, $true))
        if ($assignments.Count -ne 1) { throw 'Release probe definition missing/duplicated.' }
        $expression = $assignments[0].Right.Expression
        if ($expression -isnot [Management.Automation.Language.StringConstantExpressionAst]) { throw 'Release probe must be a literal.' }
        $expression.Value | Set-Content -LiteralPath (Join-Path $Directory "$name.py") -Encoding UTF8
    }
}

# External test-only measurement harness. Reuse the pinned proof and real fixtures;
# never print/store response content, credentials or provider raw bodies.
$loadSource = @'
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from statistics import median
from threading import Event, Lock, local
from time import monotonic
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from phase3_exit_support import receipts
from phase4_exit_real_ollama import MODEL_DIGEST, NATIVE_NAME, test_real_ollama_governed_chat_exit as real_smoke
from test_provider_binding import binding_store as binding_store
from test_rate_admission import redis_ready as redis_ready

from arbiter.config import RedisSettings
from arbiter.governance.capacity import CapacityGate
from arbiter.governance.execution import GovernedExecutionService
from arbiter.governance.rate import RateGate
from arbiter.main import create_app
from arbiter.providers.ollama import OllamaProvider

pytest_plugins = ('test_migrations',)


def test_release_bounded_load(binding_store, redis_ready, monkeypatch):
    store, _ = binding_store
    generate = OllamaProvider.generate
    execute = GovernedExecutionService.execute
    post = TestClient.post
    thread = local()
    guard = Lock()
    latencies, governance, invocations = [], [], []

    def measured_execute(self, *args, **kwargs):
        thread.started = monotonic()
        return execute(self, *args, **kwargs)

    def measured_generate(self, request, deadline):
        assert request.model_id == store.model and request.model_digest == MODEL_DIGEST
        assert self._binding.native_name == NATIVE_NAME
        with guard:
            governance.append(monotonic() - thread.started)
            invocations.append(str(request.correlation))
        return generate(self, request, deadline)

    def measured_post(self, *args, **kwargs):
        started = monotonic()
        result = post(self, *args, **kwargs)
        if result.status_code == 200:
            with guard:
                latencies.append(monotonic() - started)
        return result

    monkeypatch.setattr(GovernedExecutionService, 'execute', measured_execute)
    monkeypatch.setattr(OllamaProvider, 'generate', measured_generate)
    monkeypatch.setattr(TestClient, 'post', measured_post)
    # Existing proof covers single success, denial, retry and captured revision 3.
    real_smoke(binding_store, redis_ready, monkeypatch)
    assert len(invocations) == len(latencies) == 1
    single_latency = latencies[0]
    capacity = CapacityGate(2)
    service = GovernedExecutionService(store.runtime, store.verifier, store.fingerprint,
                                      RateGate(RedisSettings()), None, capacity)
    actors = [store.actor() for _ in range(3)]
    entered, release = Event(), Event()
    captured = []

    def held_generate(self, request, deadline):
        assert self._binding.native_name == NATIVE_NAME
        with guard:
            captured.append(str(request.correlation))
            if len(captured) == 2:
                entered.set()
        # Deterministic saturation observation, not a claim about model throughput.
        held_at = monotonic()
        assert release.wait(75), 'saturation observation exceeded bounded hold'
        thread.started += monotonic() - held_at
        return measured_generate(self, request, deadline)

    monkeypatch.setattr(OllamaProvider, 'generate', held_generate)
    body = {'model': store.alias, 'messages': [{'role': 'user', 'content': 'Reply with OK.'}],
            'max_output_tokens': 8}

    def request(actor):
        with TestClient(create_app(chat_service=service)) as client:
            return client.post('/v1/chat/completions', json=body, headers={
                'Authorization': 'Bearer ' + actor.credential.get_secret_value(),
                'Idempotency-Key': uuid4().hex})

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(request, actor) for actor in actors[:2]]
        try:
            assert entered.wait(60), 'two authorized requests did not reach provider boundary'
            assert capacity.occupied == 2
            denied = request(actors[2])
            assert denied.status_code == 503
            assert len(captured) == 2 and len(invocations) == 1
        finally:
            release.set()
        results = [future.result(timeout=130) for future in futures]
    assert all(result.status_code == 200 for result in results)
    assert len(invocations) == len(latencies) == 3 and len(set(invocations)) == 3
    assert capacity.occupied == 0
    for actor, result in zip(actors[:2], results, strict=True):
        (receipt,) = receipts(store, actor)
        assert receipt.request_id == UUID(result.json()['request_id'])
        assert receipt.state == 'succeeded'
        assert receipt.reserve_events == receipt.commit_events == 1
        assert receipt.dispatch_audits == receipt.terminal_audits == 1
        assert store.totals(actor) == (1, 0, 10, 0)
    (denied_receipt,) = receipts(store, actors[2])
    assert denied_receipt.state == 'released' and denied_receipt.dispatch_audits == 0
    assert store.totals(actors[2]) == (0, 0, 0, 0)
    report = {'model_uuid': str(store.model), 'digest': MODEL_DIGEST, 'native_tag': NATIVE_NAME,
              'captured_revision': 3, 'samples': 3, 'single_seconds': single_latency,
              'end_to_end_seconds': {'min': min(latencies), 'p50': median(latencies),
                                     'p95': None, 'max': max(latencies)},
              'governance_to_generate_seconds': governance, 'provider_invocations': 3,
              'saturation': {'limit': 2, 'observed_owned': 2, 'denied_status': 503,
                             'denied_provider_calls': 0, 'final_owned': 0},
              'limitations': 'In-process public ASGI route; controlled hold precedes two real generations; no statistical p95 or throughput claim.'}
    Path('/evidence/load.json').write_text(json.dumps(report, sort_keys=True), encoding='utf-8')
'@

$migrationSource = @'
import json
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from arbiter.config import DatabaseSettings
try:
    expected = ScriptDirectory.from_config(Config('/app/alembic.ini')).get_current_head()
    engine = create_engine(DatabaseSettings().url('migration'), poolclass=NullPool,
                           hide_parameters=True, connect_args={'connect_timeout': 5})
    try:
        with engine.begin() as connection:
            actual = connection.execute(text('SELECT version_num FROM alembic_version')).scalar_one()
        assert actual == expected
    finally:
        engine.dispose()
except Exception:
    raise SystemExit('release migration-head verification failed') from None
print(json.dumps({'migration_head': actual, 'matches_source': True}, sort_keys=True))
'@

Push-Location $repository
try {
    $revision = Assert-ReleaseGit $AllowReleaseToolingChanges.IsPresent
    Write-Host "Candidate: $revision"
    $root = [IO.Path]::GetFullPath($EvidenceRoot).TrimEnd('\')
    $models = [IO.Path]::GetFullPath($ModelDirectory).TrimEnd('\')
    if ($root -eq $repository -or $root.StartsWith($repository + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $root -eq $models -or $root.StartsWith($models + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Evidence must be outside Git and the model cache.'
    }
    if (-not (Test-Path -LiteralPath $root -PathType Container) -or -not (Test-Path -LiteralPath $models -PathType Container)) {
        throw 'Existing protected evidence root and installed model cache are required.'
    }
    # A stack-scoped exclusive handle prevents two release coordinators, regardless of EvidenceRoot.
    $lock = [IO.File]::Open((Join-Path $dataRoot 'tmp\release-verifier.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    $run = 'release-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $directory = Join-Path $root $run
    Protect-Evidence $directory
    $script:evidence = $directory
    Write-Host "Evidence: $directory"
    @{ revision = $revision; review_tooling = $AllowReleaseToolingChanges.IsPresent;
        deselected_test = $(if ($DeselectKnownUsageFixture) { 'tests/test_usage_transport.py::test_management_current_and_historical_usage' } else { $null }) } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'candidate.json') -Encoding UTF8
    Get-FileHash -Algorithm SHA256 README.md, docs/Memory.md, scripts/verify-release.ps1, tests/test_verify_release.ps1 |
        Select-Object Path, Hash | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'tooling-hashes.json') -Encoding UTF8
    Invoke-Required 'Docker engine' 'docker' @('version') | Out-Null
    Invoke-Required 'Docker info (no proxy/environment dump)' 'docker' @('info', '--format', '{{.ServerVersion}} {{.OSType}} {{.OperatingSystem}} {{.NCPU}} {{.MemTotal}}') | Out-Null
    Invoke-Required 'Compose version' 'docker' @('compose', 'version') | Out-Null
    Assert-NoOtherVerifier
    # Cheap checks reuse the existing disposable fault stack; never stop another stack.
    foreach ($service in @('postgres', 'redis')) {
        $label = @(Invoke-Required 'fault target identity' 'docker' @('inspect', '--format', '{{index .Config.Labels "com.docker.compose.project"}}', "arbiter-p34-$service-1"))
        if ($label.Count -ne 1 -or $label[0] -cne 'arbiter-p34') { throw 'Existing disposable fault stack required.' }
        Invoke-Required 'restore disposable dependency' 'docker' @('start', "arbiter-p34-$service-1") | Out-Null
        Wait-Healthy "arbiter-p34-$service-1"
    }
    Invoke-Required 'build current verification image' 'docker' @('build', '--target', 'verification', '-t', 'arbiter-local:p3-4-verification', '.') | Out-Null
    Invoke-Phase 'checks' @()
    Export-ReleaseProbes $directory
    Invoke-Required 'generated proof syntax preflight' 'docker' @('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp', '--memory', '256m', '--pids-limit', '64',
        '--mount', "type=bind,source=$directory,target=/release,readonly", '-e', 'PYTHONPYCACHEPREFIX=/tmp/pycache',
        'arbiter-local:p3-4-verification', 'python', '-m', 'py_compile', '/release/loadSource.py', '/release/metadataSource.py',
        '/release/inventory.py', '/release/metrics.py', '/release/migrationSource.py') | Out-Null
    foreach ($path in @(Get-ChildItem scripts, tests -Filter '*.ps1' -File -Recurse -ErrorAction Stop)) {
        $parseErrors = $null; $tokens = $null
        [Management.Automation.Language.Parser]::ParseFile($path.FullName, [ref]$tokens, [ref]$parseErrors) | Out-Null
        if ($parseErrors.Count) { throw 'PowerShell syntax failed.' }
    }
    Invoke-Required 'scanner structural controls' $shell @('-NoProfile', '-File', 'tests/test_verify_security.ps1') | Out-Null
    Invoke-Required 'release coordinator controls' $shell @('-NoProfile', '-File', 'tests/test_verify_release.ps1') | Out-Null
    Invoke-Required 'diff whitespace' 'git' @('diff', '--check') | Out-Null
    foreach ($name in @('ARBITER_DATA_LINUX_ROOT', 'ARBITER_SECRETS_DIR', 'ARBITER_MODEL_APPROVALS_DIR', 'ARBITER_API_PORT')) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    Set-ComposeRoot $dataRoot
    Invoke-Required 'base Compose config' 'docker' @('compose', 'config', '--quiet') | Out-Null
    Invoke-Required 'operations Compose config' 'docker' @('compose', '--profile', 'operations', 'config', '--quiet') | Out-Null
    Invoke-Required 'fault Compose config' 'docker' @('compose', '-f', 'compose.yaml', '-f', 'deploy/compose.phase3-exit.yaml', 'config', '--quiet') | Out-Null
    foreach ($operation in @('dependencies', 'secrets')) {
        Invoke-Required "security $operation (includes positive control)" $shell @('-NoProfile', '-File', 'scripts/verify-security.ps1',
            '-Operation', $operation, '-EvidenceRoot', $directory) | Out-Null
    }

    # Fresh, uniquely named storage; only the dedicated release project is stopped.
    $appRoot = "D:\AI & ML\ArbiterData\phase5\$run\ArbiterData"
    Invoke-Required 'prepare isolated release storage' $shell @('-NoProfile', '-File', 'scripts/prepare-local.ps1', '-DataRoot', $appRoot) | Out-Null
    Set-ComposeRoot $appRoot
    $env:ARBITER_API_PORT = '18080'
    $modelLinux = '/run/desktop/mnt/host/' + $models.Substring(0, 1).ToLowerInvariant() + '/' + $models.Substring(3).Replace('\', '/')
    $override = Join-Path $directory 'compose.release.yaml'
    # Unique bind-volume names avoid accidentally reusing a previous run's database.
    "volumes:`n  postgres_data:`n    name: 'arbiter-$run-postgres'`n  redis_data:`n    name: 'arbiter-$run-redis'`n  ollama_models:`n    name: 'arbiter-$run-models'`n    driver_opts:`n      device: '$($modelLinux.Replace("'", "''"))'" |
        Set-Content -LiteralPath $override -Encoding UTF8
    $compose = @('compose', '-p', 'arbiter-release', '-f', (Join-Path $repository 'compose.yaml'), '-f', $override)
    Invoke-Required 'release Compose config' 'docker' ($compose + @('--profile', 'operations', 'config', '--quiet')) | Out-Null
    Invoke-Required 'clean release service stop (volumes preserved)' 'docker' ($compose + @('down', '--timeout', '30')) | Out-Null
    Invoke-Required 'build current runtime image' 'docker' @('build', '--target', 'runtime', '-t', 'arbiter-local:foundation', '.') | Out-Null
    Invoke-Required 'clean dependencies startup' 'docker' ($compose + @('up', '-d', '--pull', 'never', 'postgres', 'redis')) | Out-Null
    foreach ($service in @('postgres', 'redis')) { Wait-Healthy "arbiter-release-$service-1" }
    foreach ($operation in @('bootstrap', 'migrate')) {
        Invoke-Required "release $operation" 'docker' ($compose + @('--profile', 'operations', 'run', '--rm', '--pull', 'never', $operation)) | Out-Null
    }
    Invoke-Required 'database migration head matches source' 'docker' ($compose + @('--profile', 'operations', 'run', '--rm', '--pull', 'never',
        '--volume', "${directory}\migrationSource.py:/tmp/release-head.py:ro", 'migrate', 'python', '/tmp/release-head.py')) | Out-Null
    Invoke-Required 'provider and API startup' 'docker' ($compose + @('up', '-d', '--pull', 'never', 'ollama', 'api')) | Out-Null
    foreach ($service in @('ollama', 'api')) { Wait-Healthy "arbiter-release-$service-1" }
    Invoke-Required 'foundation diagnostics' 'docker' ($compose + @('--profile', 'operations', 'run', '--rm', '--pull', 'never', 'diagnostics')) | Out-Null
    $live = Invoke-WebRequest 'http://127.0.0.1:18080/health/live' -UseBasicParsing -TimeoutSec 5
    if ($live.StatusCode -ne 200) { throw 'API liveness failed.' }
    $readyStatus = 0
    try { $readyStatus = (Invoke-WebRequest 'http://127.0.0.1:18080/health/ready' -UseBasicParsing -TimeoutSec 5).StatusCode }
    catch { if ($_.Exception.Response) { $readyStatus = [int]$_.Exception.Response.StatusCode } }
    if ($readyStatus -ne 503) { throw 'Expected deliberately fail-closed readiness contract changed.' }
    @{ live = 200; ready = 503; readiness = 'deliberately fail-closed; foundation connectivity is not admission authority' } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'startup.json') -Encoding UTF8
    # Verify exact installed model against the existing proof, not live discovery authority.
    $inventory = @'
import json, re, urllib.request
source = open('/app/tests/phase4_exit_real_ollama.py', encoding='utf-8').read()
name = re.search(r'^NATIVE_NAME = "([^"]+)"', source, re.M).group(1)
digest = re.search(r'^MODEL_DIGEST = "([^"]+)"', source, re.M).group(1)
with urllib.request.urlopen('http://ollama:11434/api/tags', timeout=10) as response:
    models = json.load(response)['models']
assert any(m.get('name') == name and 'sha256:' + m.get('digest', '').removeprefix('sha256:') == digest for m in models), 'approved installed model missing; operator action required, no pull'
print(json.dumps({'native_name': name, 'digest': digest}, sort_keys=True))
'@
    Invoke-Required 'copy public pinned proof metadata' 'docker' @('cp', 'tests/phase4_exit_real_ollama.py', 'arbiter-release-api-1:/tmp/phase4-proof.py') | Out-Null
    $inventory.Replace('/app/tests/phase4_exit_real_ollama.py', '/tmp/phase4-proof.py') |
        Set-Content -LiteralPath (Join-Path $directory 'model-prerequisite.py') -Encoding UTF8
    Invoke-Required 'copy availability probe' 'docker' @('cp', (Join-Path $directory 'model-prerequisite.py'), 'arbiter-release-api-1:/tmp/model-prerequisite.py') | Out-Null
    $modelEvidence = @(Invoke-Required 'exact provider prerequisite' 'docker' @('exec', 'arbiter-release-api-1', 'python', '/tmp/model-prerequisite.py'))
    $modelEvidence | Set-Content -LiteralPath (Join-Path $directory 'model.json') -Encoding UTF8
    $metrics = @'
import json
from arbiter.observability import read_metrics
report = read_metrics()
assert report['capacity']['recovery_ready'] is True
assert report['capacity']['occupied'] == 0
print(json.dumps(report, sort_keys=True))
'@
    $metrics | Set-Content -LiteralPath (Join-Path $directory 'readiness-probe.py') -Encoding UTF8
    Invoke-Required 'copy private metrics probe' 'docker' @('cp', (Join-Path $directory 'readiness-probe.py'), 'arbiter-release-api-1:/tmp/readiness-probe.py') | Out-Null
    Invoke-Required 'private readiness metrics' 'docker' @('exec', 'arbiter-release-api-1', 'python', '/tmp/readiness-probe.py') | Out-Null

    $metadataSource = @'
import json
from pathlib import Path
import pytest
from phase4_exit_real_ollama import MODEL_DIGEST, NATIVE_NAME
from arbiter.providers.ollama import OllamaProvider

@pytest.fixture(autouse=True)
def release_metadata(request, monkeypatch):
    if request.node.name != 'test_real_ollama_governed_chat_exit':
        yield
        return
    store, _ = request.getfixturevalue('binding_store')
    original = OllamaProvider.generate
    calls = []
    def observe(provider, value, deadline):
        calls.append(str(value.correlation))
        return original(provider, value, deadline)
    monkeypatch.setattr(OllamaProvider, 'generate', observe)
    yield
    Path('/evidence/model-execution.json').write_text(json.dumps({
        'model_uuid': str(store.model), 'native_tag': NATIVE_NAME, 'digest': MODEL_DIGEST,
        'revision': 3, 'provider_invocations': len(calls)}, sort_keys=True), encoding='utf-8')
'@
    $metadataSource | Set-Content -LiteralPath (Join-Path $directory 'release_metadata.py') -Encoding UTF8

    Invoke-Phase 'full' @('test_provider_binding', 'test_migrations', 'test_chat_transport', 'test_backup_recovery',
        'test_phase3_exit_faults', 'test_generation_calls_are_confined_to_dispatch_service', 'test_only_governed_chat_and_existing_http_routes_exist')
    Invoke-RealProof 'ollama' @('tests/phase4_exit_real_ollama.py') @('test_real_ollama_governed_chat_exit') 'arbiter-release_provider'
    Invoke-Phase 'recovery' @('test_backup_recovery', 'test_entire_redis_recovery_barrier_blocks_full_pipeline',
        'test_process_crash_and_restart_at_every_durable_boundary')
    Invoke-Phase 'restart' @('test_process_restart_requires_new_full_barrier')
    Invoke-Phase 'observability' @('test_observability', 'test_security_checks', 'test_chat_transport')
    Invoke-ArtifactProof

    # Bounded load probe added below; it reuses the committed real proof/fixtures.
    $probe = Join-Path $directory 'test_release_load.py'
    $loadSource | Set-Content -LiteralPath $probe -Encoding UTF8
    Invoke-RealProof 'load' @('/release/test_release_load.py') @('test_release_bounded_load') 'arbiter-release_provider'
    foreach ($service in @('api', 'postgres', 'redis', 'ollama')) {
        Invoke-Required "runtime identity $service" 'docker' @('inspect', '--format', '{{.Image}} {{.Config.Image}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}', "arbiter-release-$service-1") | Out-Null
        Invoke-Required "runtime logs $service" 'docker' @('logs', "arbiter-release-$service-1") | Out-Null
    }
    foreach ($item in @(@('postgres', 'postgres', '--version'), @('redis', 'redis-server', '--version'), @('ollama', 'ollama', '--version'), @('api', 'python', '--version'))) {
        Invoke-Required "version $($item[0])" 'docker' @('exec', "arbiter-release-$($item[0])-1", $item[1], $item[2]) | Out-Null
    }
    Invoke-Required 'loaded-model processor observation' 'docker' @('exec', 'arbiter-release-ollama-1', 'ollama', 'ps') | Out-Null
    $gpuMemory = @('nvidia-smi unavailable; VRAM not established')
    $gpuTool = Get-Command 'nvidia-smi.exe' -CommandType Application -ErrorAction SilentlyContinue
    if ($gpuTool) {
        $gpuMemory = @(Invoke-Required 'GPU model and VRAM' $gpuTool.Source @('--query-gpu=name,memory.total', '--format=csv,noheader,nounits'))
    }
    @{ os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, TotalVisibleMemorySize);
        cpu = @(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfLogicalProcessors);
        gpu = @(Get-CimInstance Win32_VideoController | Select-Object Name, AdapterRAM);
        gpu_name_memory_mib = $gpuMemory;
        caveat = 'AdapterRAM is not reliable VRAM; three samples are observations, not a benchmark. Readiness remains deliberately 503.' } |
        ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $directory 'hardware.json') -Encoding UTF8

    # Inspect the additional measurement/runtime evidence too; never rerun pytest.
    Invoke-ArtifactProof
    if ((Assert-ReleaseGit $AllowReleaseToolingChanges.IsPresent) -cne $revision) { throw 'Candidate revision changed.' }
    $originalHashes = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText((Join-Path $directory 'tooling-hashes.json')))
    foreach ($entry in $originalHashes) {
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $entry.Path).Hash -cne $entry.Hash) { throw 'Release tooling changed during verification.' }
    }
    Write-Host 'Release verification stages passed. Evidence requires final review; no version/tag/commit created.'
} catch {
    $exitCode = 1
    if ($_.Exception.Data.Contains('ExitCode')) { $exitCode = [int]$_.Exception.Data['ExitCode'] }
    Write-Host "BLOCKED at $script:stage (exit $exitCode). Evidence retained: $script:evidence"
} finally {
    if ($script:evidence) {
        try {
            @{ revision = $revision; stages = $script:summary; tests = $script:testResults; exit_code = $exitCode; full_regression_started = $script:fullStarted;
                limitations = @('same-cluster fresh-database restore, not fresh-host disaster recovery', 'operator provider-stopped attestation',
                    'metrics reset on process restart', 'sentinels do not cover arbitrary unknown secrets', 'Python OSV is not an OS/container CVE scan') } |
                ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $script:evidence 'summary.json') -Encoding UTF8
        } catch {
            if ($exitCode -eq 0) { $exitCode = 1 }
            Write-Host 'Release summary could not be retained; gate failed.'
        }
    }
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
    if ($lock) { $lock.Dispose() }
    Pop-Location
}
exit $exitCode
