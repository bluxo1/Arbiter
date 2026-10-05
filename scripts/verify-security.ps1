param(
    [Parameter(Mandatory)][ValidateSet('dependencies', 'secrets', 'artifacts')][string]$Operation,
    [string]$ArtifactDirectory,
    [string]$EvidenceRoot = 'D:\AI & ML\ArbiterData\phase3\exit-matrix-20260930\ArbiterData\tmp'
)

$ErrorActionPreference = 'Stop'

function Read-TrivyReport([string]$Json, [string]$ExpectedRoot, [int]$ExitCode, [int]$ExpectedExit) {
    if ($ExitCode -ne $ExpectedExit) { throw 'Secret scanner exit status failed.' }
    try { $report = ConvertFrom-Json -InputObject $Json -ErrorAction Stop }
    catch { throw 'Secret scanner report is invalid.' }
    if ($report -isnot [PSCustomObject] -or $report.SchemaVersion -isnot [int] -or $report.SchemaVersion -ne 2 -or
        $report.ArtifactType -isnot [string] -or $report.ArtifactName -isnot [string] -or
        $report.Trivy -isnot [PSCustomObject] -or $report.Trivy.Version -isnot [string] -or
        $report.ArtifactType -cne 'filesystem' -or $report.ArtifactName -cne $ExpectedRoot -or
        $report.Trivy.Version -cne '0.74.0' -or -not ($report.CreatedAt -is [string]) -or
        -not ($report.ReportID -is [string]) -or [string]::IsNullOrWhiteSpace($report.ReportID) -or
        -not ($report.Results -is [Array]) -or $report.Results.Count -eq 0) {
        throw 'Secret scanner report is incomplete.'
    }
    $created = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($report.CreatedAt, [ref]$created)) {
        throw 'Secret scanner report timestamp is invalid.'
    }
    foreach ($result in $report.Results) {
        if ($result -isnot [PSCustomObject] -or -not ($result.Target -is [string]) -or
            [string]::IsNullOrWhiteSpace($result.Target) -or $result.Class -isnot [string] -or $result.Class -cne 'secret' -or
            $result.Target.Contains('\') -or ($result.Target.Split('/') -ccontains '..')) {
            throw 'Secret scanner result is invalid.'
        }
        # Trivy emits root-relative targets (including a basename for a file scan).
        # Normalize only after validating the report's exact ArtifactName authority.
        if ($result.Target -ceq $ExpectedRoot.TrimStart('/')) {
            $result.Target = $ExpectedRoot
        } elseif (-not $result.Target.StartsWith('/', [StringComparison]::Ordinal)) {
            $result.Target = $ExpectedRoot + '/' + $result.Target
        }
        if ($result.Target -cne $ExpectedRoot -and
            -not $result.Target.StartsWith($ExpectedRoot + '/', [StringComparison]::Ordinal)) {
            throw 'Secret scanner target is outside the scan root.'
        }
        if ($null -ne $result.PSObject.Properties['Secrets']) {
            if ($result.Secrets -isnot [Array]) { throw 'Secret scanner findings are invalid.' }
            foreach ($secret in $result.Secrets) {
                if ($secret -isnot [PSCustomObject] -or -not ($secret.RuleID -is [string]) -or
                    [string]::IsNullOrWhiteSpace($secret.RuleID) -or $secret.Severity -isnot [string] -or
                    $secret.Severity -cnotin @('UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) {
                    throw 'Secret scanner finding is invalid.'
                }
            }
        }
    }
    return $report
}

function Assert-RepositorySecretReport($Report) {
    $markerTarget = '/scan/control/scan-marker.txt'
    $markerResults = @($Report.Results | Where-Object { $_.Target -ceq $markerTarget })
    if ($markerResults.Count -ne 1) { throw 'Repository scan marker is missing.' }
    $markerFindings = @($markerResults[0].Secrets)
    if ($markerFindings.Count -ne 1 -or $markerFindings[0].RuleID -cne 'arbiter-security-sentinel') {
        throw 'Repository scan marker failed.'
    }
    $findings = @($Report.Results | Where-Object { $_.Target -cne $markerTarget } |
        ForEach-Object { $_.Secrets } | Where-Object { $null -ne $_ })
    if ($findings.Count -ne 0) { throw 'Repository secret scan failed.' }
}

$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidence = [IO.Path]::GetFullPath($EvidenceRoot)
if ($evidence -eq $repository -or $evidence.StartsWith($repository + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Security evidence must be outside Git.'
}
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$base = @('run', '--rm', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--tmpfs', '/tmp', '--mount', "type=bind,source=$repository,target=/app,readonly")
if ($Operation -eq 'secrets') {
    $image = 'aquasec/trivy@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969'
    $probe = Join-Path $evidence ('secret-probe-' + [Guid]::NewGuid().ToString('N') + '.txt')
    try {
        [IO.File]::WriteAllText($probe, ('SENTINEL_' + 'API_KEY_SECRET'))
        $common = @('fs', '--quiet', '--cache-dir', '/tmp/trivy', '--scanners', 'secret',
            '--secret-config', '/app/deploy/trivy-secret.yaml', '--no-progress', '--exit-code', '1',
            '--format', 'json', '--timeout', '3m')
        $output = & docker @base --network none --mount "type=bind,source=$probe,target=/probe.txt,readonly" $image @common /probe.txt 2>$null
        $code = $LASTEXITCODE
        $report = Read-TrivyReport ($output -join "`n") '/probe.txt' $code 1
        $probeFindings = @($report.Results | ForEach-Object { $_.Secrets } | Where-Object { $_.RuleID -eq 'arbiter-security-sentinel' })
        if ($code -ne 1 -or $probeFindings.Count -ne 1) { throw 'Secret scanner positive control failed.' }
        # Capture raw matches in memory only; never print/persist matched credentials.
        # Trivy omits Results on a clean secret-only scan. A separate inert marker
        # inside this scan root forces verifiable result evidence, without changing
        # or excluding any repository file. The original positive control remains.
        $repositoryCommon = @('fs', '--quiet', '--cache-dir', '/tmp/trivy', '--scanners', 'secret',
            '--secret-config', '/app/deploy/trivy-secret.yaml', '--no-progress', '--exit-code', '0',
            '--format', 'json', '--timeout', '3m')
        $output = & docker @base --network none --mount "type=bind,source=$repository,target=/scan/repository,readonly" `
            --mount "type=bind,source=$probe,target=/scan/control/scan-marker.txt,readonly" `
            $image @repositoryCommon --skip-dirs /scan/repository/.git /scan 2>$null
        $code = $LASTEXITCODE
        $report = Read-TrivyReport ($output -join "`n") '/scan' $code 0
        Assert-RepositorySecretReport $report
        @{ scanner = 'Trivy 0.74.0 pinned'; positive_control = $true; findings = 0 } | ConvertTo-Json -Compress
    } finally {
        # Only this exact UUID-named inert probe file is removed. Never recursive.
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe }
    }
} else {
    if ($Operation -eq 'artifacts') {
        if (-not $ArtifactDirectory -or -not (Test-Path -LiteralPath $ArtifactDirectory -PathType Container)) {
            throw 'Expected a textual operational artifact directory, without backups.'
        }
        $target = [IO.Path]::GetFullPath($ArtifactDirectory)
        $base += @('--network', 'none', '--mount', "type=bind,source=$target,target=/artifacts,readonly")
        $root = '/artifacts'
    } else {
        $root = '/app'
    }
    & docker @base arbiter-local:p3-4-verification python -m arbiter.operations.security_checks $Operation --root $root
    if ($LASTEXITCODE -ne 0) { throw 'Security verification incomplete or failed.' }
}
