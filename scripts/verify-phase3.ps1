param(
    [ValidateSet('matrix', 'boundary', 'p33', 'related', 'migrations', 'full', 'restart', 'checks')][string]$Phase = 'matrix',
    [ValidateSet('', 'tests/test_usage_transport.py::test_management_current_and_historical_usage')][string]$Deselect = '',
    [string]$DataRoot = 'D:\AI & ML\ArbiterData\phase3\exit-matrix-20260930\ArbiterData'
)

# This runner never starts the API/provider, mounts a Docker socket, or removes
# containers, volumes, credentials or evidence. Setup uses existing operations.
$ErrorActionPreference = 'Stop'
$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$resolvedData = [System.IO.Path]::GetFullPath($DataRoot)
if ($resolvedData -ne 'D:\AI & ML\ArbiterData\phase3\exit-matrix-20260930\ArbiterData') {
    throw 'This fault driver is restricted to its dedicated P3-4 data directory.'
}
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$name = "arbiter-p34-$Phase-$stamp"
$evidence = Join-Path $resolvedData "tmp\$name"
$control = Join-Path $evidence 'control'
$timingLog = Join-Path $evidence 'fault-timing.jsonl'
$postgresHealthSeconds = 180
$otherHealthSeconds = 40
$healthPollMilliseconds = 500
New-Item -ItemType Directory -Path $control -Force | Out-Null
$arguments = @('run', '-d', '--name', $name, '--network', 'arbiter-p34_control',
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--tmpfs', '/tmp', '--memory', '2g', '--pids-limit', '512',
    '--mount', "type=bind,source=$repository\src,target=/app/src,readonly",
    '--mount', "type=bind,source=$repository\tests,target=/app/tests,readonly",
    '--mount', "type=bind,source=$repository\migrations,target=/app/migrations,readonly",
    '--mount', "type=bind,source=$repository\scripts,target=/app/scripts,readonly",
    '--mount', "type=bind,source=$evidence,target=/evidence",
    '-e', 'ARBITER_DB_HOST=postgres', '-e', 'ARBITER_REDIS_HOST=redis',
    '-e', 'ARBITER_TEST_DATABASE=1', '-e', 'ARBITER_TEST_MIGRATIONS=1',
    '-e', 'ARBITER_TEST_REDIS=1', '-e', 'ARBITER_TEST_EXIT_HOST=1',
    '-e', 'ARBITER_TEST_EXIT_CONTROL=/evidence/control', '-e', 'PIP_NO_CACHE_DIR=1')
foreach ($secret in @('db_bootstrap_password', 'db_migration_password', 'db_operator_password',
        'db_runtime_password', 'db_maintenance_password', 'api_key_pepper',
        'audit_cursor_key', 'request_fingerprint_key')) {
    $path = Join-Path $resolvedData "secrets\$secret"
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Missing test secret file.' }
    $arguments += @('--mount', "type=bind,source=$path,target=/run/secrets/$secret,readonly")
}
foreach ($service in @('postgres', 'redis')) {
    $labels = & docker inspect --format '{{json .Config.Labels}}' "arbiter-p34-$service-1"
    if ($LASTEXITCODE -ne 0) { throw 'Unexpected fault target.' }
    $label = ($labels | ConvertFrom-Json).'com.docker.compose.project'
    if ($label -ne 'arbiter-p34') { throw 'Unexpected fault target.' }
}
if ($Phase -eq 'restart') {
    # Run the original host-gated test only AFTER a real process restart.
    & docker restart --timeout 2 arbiter-p34-redis-1
    if ($LASTEXITCODE -ne 0) { throw 'Separate Redis restart failed.' }
    $restartDeadline = (Get-Date).AddSeconds($otherHealthSeconds)
    do {
        $restartHealth = & docker inspect --format '{{.State.Health.Status}}' arbiter-p34-redis-1
        if ($LASTEXITCODE -ne 0) { throw 'Restart health probe failed.' }
        if ($restartHealth -eq 'healthy') { break }
        Start-Sleep -Milliseconds $healthPollMilliseconds
    } while ((Get-Date) -lt $restartDeadline)
    if ($restartHealth -ne 'healthy') { throw 'Restarted Redis did not become healthy.' }
    $arguments += @('-e', 'ARBITER_TEST_EXIT_HOST=0', '-e', 'ARBITER_TEST_REDIS_RESTARTED=1')
}
$arguments += @('arbiter-local:p3-4-verification')
if ($Phase -eq 'checks') {
    $arguments += @('python', '-c', "import subprocess; commands=[['ruff','check','--no-cache','.'],['ruff','format','--check','--no-cache','.'],['mypy','--strict','--cache-dir=/tmp/mypy'],['python','-m','pip','check']]; codes=[subprocess.call(c) for c in commands]; raise SystemExit(max(codes))")
} else {
    $arguments += @('python', '-m', 'pytest', '-q', '-x', '-p', 'no:cacheprovider',
        "--junitxml=/evidence/$Phase.xml")
    if ($Deselect -ne '') { $arguments += "--deselect=$Deselect" }
    if ($Phase -eq 'matrix') {
        $arguments += @('tests/test_phase3_exit_matrix.py', 'tests/test_phase3_exit_races.py',
            'tests/test_phase3_exit_crashes.py', 'tests/test_phase3_exit_faults.py',
            'tests/test_phase3_exit_allocation.py')
    } elseif ($Phase -eq 'boundary') {
        $arguments += @('tests/test_phase3_exit_matrix.py::test_generation_calls_are_confined_to_dispatch_service',
            'tests/test_phase3_exit_matrix.py::test_only_governed_chat_and_existing_http_routes_exist')
    } elseif ($Phase -eq 'p33') {
        $arguments += @('tests/test_governed_execution.py')
    } elseif ($Phase -eq 'migrations') {
        $arguments += @('tests/test_migrations.py')
    } elseif ($Phase -eq 'restart') {
        $arguments += @('tests/test_rate_governance.py::test_process_restart_requires_new_full_barrier')
    } elseif ($Phase -eq 'related') {
        $arguments += @('tests/test_governed_execution.py', 'tests/test_rate_admission.py',
            'tests/test_rate_governance.py', 'tests/test_reservation_transactions.py',
            'tests/test_reservation_release.py', 'tests/test_reservation_material.py',
            'tests/test_accounting_persistence.py', 'tests/test_capacity.py',
            'tests/test_dispatch_authorization.py', 'tests/test_terminal_lifecycle.py',
            'tests/test_maintenance.py', 'tests/test_provider_double.py',
            'tests/test_usage_persistence.py', 'tests/test_usage_transport.py',
            'tests/test_migrations.py')
    }
}
& docker @arguments
if ($LASTEXITCODE -ne 0) { throw 'Verification container did not start.' }
$handled = @{}
$faultFailed = $false
try {
    while ($true) {
        foreach ($file in @(Get-ChildItem -LiteralPath $control -Filter '*.request.json' -File)) {
            if ($handled.ContainsKey($file.Name)) { continue }
            if ($faultFailed) { throw 'Fault controller received another request after a failed operation.' }
            $observedUtc = [DateTime]::UtcNow
            $requestUtc = $file.LastWriteTimeUtc
            $request = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            $operation = [string]$request.operation
            if ($operation -notin @('redis_stop', 'redis_start', 'redis_restart', 'postgres_stop', 'postgres_start')) {
                throw 'Unrecognized disposable-stack fault operation.'
            }
            $service = if ($operation.StartsWith('redis_')) { 'redis' } else { 'postgres' }
            $target = "arbiter-p34-$service-1"
            $actionInvokedUtc = [DateTime]::UtcNow
            if ($operation.EndsWith('_stop')) {
                # Short grace deliberately exercises abrupt outages and possible WAL recovery.
                & docker stop --timeout 2 $target
            } elseif ($operation.EndsWith('_restart')) {
                & docker restart --timeout 2 $target
            } else {
                & docker start $target
            }
            $actionCompletedUtc = [DateTime]::UtcNow
            if ($LASTEXITCODE -ne 0) { throw 'Disposable-stack fault operation failed.' }
            $healthWaitStartedUtc = $null
            $healthyUtc = $null
            $timeoutUtc = $null
            $dockerStatus = $null
            $healthStatus = $null
            $lastProbeExit = $null
            if (-not $operation.EndsWith('_stop')) {
                $healthWaitStartedUtc = [DateTime]::UtcNow
                $healthSeconds = if ($operation -eq 'postgres_start') {
                    $postgresHealthSeconds
                } else {
                    $otherHealthSeconds
                }
                $deadline = $healthWaitStartedUtc.AddSeconds($healthSeconds)
                do {
                    $health = & docker inspect --format '{{.State.Health.Status}}' $target
                    if ($LASTEXITCODE -ne 0) { throw 'Health probe failed.' }
                    if ($health -eq 'healthy') {
                        $healthyUtc = [DateTime]::UtcNow
                        $healthStatus = 'healthy'
                        break
                    }
                    if ([DateTime]::UtcNow -ge $deadline) { break }
                    Start-Sleep -Milliseconds $healthPollMilliseconds
                } while ($true)
                if ($null -eq $healthyUtc) {
                    $timeoutUtc = [DateTime]::UtcNow
                    $healthStatus = [string]$health
                    $stateJson = & docker inspect --format '{{json .State}}' $target
                    if ($LASTEXITCODE -eq 0) {
                        $state = $stateJson | ConvertFrom-Json
                        $dockerStatus = [string]$state.Status
                        $healthStatus = [string]$state.Health.Status
                        if ($null -ne $state.Health.Log -and $state.Health.Log.Count -gt 0) {
                            $lastProbeExit = [int]$state.Health.Log[-1].ExitCode
                        }
                    }
                    $faultFailed = $true
                }
            }
            $reply = Join-Path $control ($file.Name.Replace('.request.json', '.reply.json'))
            $temporary = "$reply.tmp"
            $response = if ($faultFailed) {
                [ordered]@{
                    complete = $false
                    error = 'health_timeout'
                    docker_status = $dockerStatus
                    health_status = $healthStatus
                    last_probe_exit = $lastProbeExit
                }
            } else {
                [ordered]@{ complete = $true }
            }
            [System.IO.File]::WriteAllText($temporary, ($response | ConvertTo-Json -Compress))
            Move-Item -LiteralPath $temporary -Destination $reply
            $replyUtc = [DateTime]::UtcNow
            $healthFinishedUtc = if ($null -ne $healthyUtc) { $healthyUtc } else { $timeoutUtc }
            $timing = [ordered]@{
                operation = $operation
                request_utc = $requestUtc.ToString('o')
                observed_utc = $observedUtc.ToString('o')
                docker_action_invoked_utc = $actionInvokedUtc.ToString('o')
                docker_action_completed_utc = $actionCompletedUtc.ToString('o')
                docker_action_seconds = [Math]::Round(($actionCompletedUtc - $actionInvokedUtc).TotalSeconds, 3)
                docker_start_invoked_utc = if ($operation -eq 'postgres_start') { $actionInvokedUtc.ToString('o') } else { $null }
                docker_start_completed_utc = if ($operation -eq 'postgres_start') { $actionCompletedUtc.ToString('o') } else { $null }
                health_wait_started_utc = if ($null -ne $healthWaitStartedUtc) { $healthWaitStartedUtc.ToString('o') } else { $null }
                healthy_utc = if ($null -ne $healthyUtc) { $healthyUtc.ToString('o') } else { $null }
                timeout_utc = if ($null -ne $timeoutUtc) { $timeoutUtc.ToString('o') } else { $null }
                docker_start_seconds = if ($operation -eq 'postgres_start') { [Math]::Round(($actionCompletedUtc - $actionInvokedUtc).TotalSeconds, 3) } else { $null }
                health_wait_seconds = if ($null -ne $healthFinishedUtc) { [Math]::Round(($healthFinishedUtc - $healthWaitStartedUtc).TotalSeconds, 3) } else { $null }
                request_seconds = [Math]::Round(($replyUtc - $requestUtc).TotalSeconds, 3)
                outcome = if ($faultFailed) { 'health_timeout' } else { 'complete' }
                docker_status = $dockerStatus
                health_status = $healthStatus
                last_probe_exit = $lastProbeExit
            }
            [System.IO.File]::AppendAllText($timingLog, (($timing | ConvertTo-Json -Compress) + [Environment]::NewLine))
            $handled[$file.Name] = $true
        }
        $running = & docker inspect --format '{{.State.Running}}' $name
        if ($LASTEXITCODE -ne 0) { throw 'Verification state probe failed.' }
        if ($running -eq 'false') { break }
        Start-Sleep -Milliseconds 500
    }
    $code = & docker inspect --format '{{.State.ExitCode}}' $name
    $previousErrorAction = $ErrorActionPreference
    try {
        # Windows PowerShell treats native stderr as ErrorRecord even on exit 0.
        # Preserve warnings and judge the actual container/log command exit codes.
        $ErrorActionPreference = 'Continue'
        & docker logs $name 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath (Join-Path $evidence 'output.log')
        $logCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($logCode -ne 0) { throw 'Could not retain verification logs.' }
    Write-Output "Evidence: $evidence"
    if ([int]$code -ne 0) { throw "Verification exited $code" }
} finally {
    # Restore either dependency if the test failed while deliberately stopped.
    # Retain this stack and all named containers/data for review; final shutdown
    # is a separate explicit Compose stop with no data deletion.
    foreach ($service in @('postgres', 'redis')) {
        & docker start "arbiter-p34-$service-1" | Out-Null
    }
}
