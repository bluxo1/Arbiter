param([switch]$Integration)

$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$errors = $null
$tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repository 'scripts/verify-security.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Security script syntax failed.' }
foreach ($name in @('Read-TrivyReport', 'Assert-RepositorySecretReport', 'Get-RepositorySecretSkipDirectories')) {
    $function = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    if ($null -eq $function) { throw 'Expected security function missing.' }
    . ([ScriptBlock]::Create($function.Extent.Text))
}

function New-Report {
    return [PSCustomObject]@{
        SchemaVersion = 2; ArtifactName = '/scan'; ArtifactType = 'filesystem'
        Trivy = [PSCustomObject]@{ Version = '0.74.0' }
        CreatedAt = '2026-10-05T00:00:00Z'; ReportID = 'inert-test-report'
        Results = @([PSCustomObject]@{
            Target = '/scan/repository/README.md'; Class = 'secret'; Secrets = @()
        })
    }
}

$script:passed = 0
function Expect-Rejection([ScriptBlock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'Malformed scan was accepted.' }
    $script:passed++
}

foreach ($json in @('{}', '{"Results":[]}', '{"Results":{}}', '{', 'null')) {
    Expect-Rejection { Read-TrivyReport $json '/scan' 0 0 }
}
foreach ($field in @('SchemaVersion', 'ArtifactName', 'ArtifactType', 'Trivy', 'CreatedAt', 'ReportID', 'Results')) {
    $report = New-Report
    $report.PSObject.Properties.Remove($field)
    Expect-Rejection { Read-TrivyReport ($report | ConvertTo-Json -Depth 8) '/scan' 0 0 }
}
foreach ($field in @('SchemaVersion', 'ArtifactName', 'ArtifactType', 'Trivy', 'CreatedAt', 'ReportID')) {
    $report = New-Report
    $report.$field = @($report.$field)
    Expect-Rejection { Read-TrivyReport ($report | ConvertTo-Json -Depth 8) '/scan' 0 0 }
}
$report = New-Report
$report.Results = @()
Expect-Rejection { Read-TrivyReport ($report | ConvertTo-Json -Depth 8) '/scan' 0 0 }
foreach ($badResult in @(
    [PSCustomObject]@{},
    [PSCustomObject]@{ Target = '/elsewhere/file'; Class = 'secret' },
    [PSCustomObject]@{ Target = '/scan/file'; Class = 'os-pkgs' },
    [PSCustomObject]@{ Target = '/scan/file'; Class = @('secret') },
    [PSCustomObject]@{ Target = '../outside/file'; Class = 'secret' },
    [PSCustomObject]@{ Target = '/scan/file'; Class = 'secret'; Secrets = [PSCustomObject]@{} },
    [PSCustomObject]@{ Target = '/scan/file'; Class = 'secret'; Secrets = @($null) }
)) {
    $report = New-Report
    $report.Results = @($badResult)
    Expect-Rejection { Read-TrivyReport ($report | ConvertTo-Json -Depth 8) '/scan' 0 0 }
}
$report = New-Report
$json = $report | ConvertTo-Json -Depth 8
Read-TrivyReport $json '/scan' 0 0 | Out-Null
$script:passed++
foreach ($exitCode in @(1, 2, 125)) {
    Expect-Rejection { Read-TrivyReport $json '/scan' $exitCode 0 }
}
Expect-Rejection { Assert-RepositorySecretReport $report }
$marker = [PSCustomObject]@{
    Target = '/scan/control/scan-marker.txt'; Class = 'secret'
    Secrets = @([PSCustomObject]@{ RuleID = 'arbiter-security-sentinel'; Severity = 'CRITICAL' })
}
$report.Results += $marker
$verified = Read-TrivyReport ($report | ConvertTo-Json -Depth 8) '/scan' 0 0
Assert-RepositorySecretReport $verified
$script:passed++
$report.Results[0].Secrets = @([PSCustomObject]@{ RuleID = 'inert-repository-secret'; Severity = 'HIGH' })
$verified = Read-TrivyReport ($report | ConvertTo-Json -Depth 8) '/scan' 0 0
Expect-Rejection { Assert-RepositorySecretReport $verified }

# A real disposable Git index proves the precise boundary, including force-added
# files under an ignored environment. Optional live scans use only inert material.
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('arbiter-security-' + [Guid]::NewGuid().ToString('N'))
$fixture = Join-Path $temporary 'repository'
function Invoke-FixtureGit([string[]]$Arguments) {
    & git -C $fixture @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Security Git fixture command failed.' }
}
function Assert-SkipDirectories([string[]]$Expected) {
    $actual = @(Get-RepositorySecretSkipDirectories $fixture)
    if (($actual -join ',') -cne ($Expected -join ',')) { throw 'Secret-scan exclusion boundary failed.' }
    $script:passed++
}
try {
    New-Item -ItemType Directory -Path (Join-Path $fixture '.venv'), (Join-Path $fixture 'scripts'),
        (Join-Path $fixture 'deploy') -Force | Out-Null
    Invoke-FixtureGit @('init', '--quiet')
    [IO.File]::WriteAllText((Join-Path $fixture '.venv/probe.txt'), ('SENTINEL_' + 'API_KEY_SECRET'))
    [IO.File]::WriteAllText((Join-Path $fixture 'candidate.txt'), 'safe candidate')
    Assert-SkipDirectories @('/scan/repository/.git')
    [IO.File]::WriteAllText((Join-Path $fixture '.gitignore'), ".venv/`n")
    Invoke-FixtureGit @('add', '.gitignore', 'candidate.txt')
    Assert-SkipDirectories @('/scan/repository/.git', '/scan/repository/.venv')
    Invoke-FixtureGit @('add', '--force', '.venv/probe.txt')
    Assert-SkipDirectories @('/scan/repository/.git')
    Invoke-FixtureGit @('rm', '--cached', '--quiet', '.venv/probe.txt')
    Assert-SkipDirectories @('/scan/repository/.git', '/scan/repository/.venv')
    Expect-Rejection { Get-RepositorySecretSkipDirectories (Join-Path $temporary 'missing') }

    if ($Integration) {
        Copy-Item -LiteralPath (Join-Path $repository 'scripts/verify-security.ps1') -Destination (Join-Path $fixture 'scripts/verify-security.ps1')
        Copy-Item -LiteralPath (Join-Path $repository 'deploy/trivy-secret.yaml') -Destination (Join-Path $fixture 'deploy/trivy-secret.yaml')
        Invoke-FixtureGit @('add', 'scripts/verify-security.ps1', 'deploy/trivy-secret.yaml')
        $runner = Join-Path $fixture 'scripts/verify-security.ps1'
        $clean = & $runner -Operation secrets -EvidenceRoot $temporary | ConvertFrom-Json
        if ($clean.positive_control -ne $true -or $clean.findings -ne 0) { throw 'Ignored environment live scan failed.' }
        $script:passed++

        [IO.File]::WriteAllText((Join-Path $fixture 'candidate.txt'), ('SENTINEL_' + 'API_KEY_SECRET'))
        $rejected = $false
        try { & $runner -Operation secrets -EvidenceRoot $temporary | Out-Null }
        catch { if ($_.Exception.Message -cne 'Repository secret scan failed.') { throw }; $rejected = $true }
        if (-not $rejected) { throw 'Live repository finding was accepted.' }
        $script:passed++

        [IO.File]::WriteAllText((Join-Path $fixture 'candidate.txt'), 'safe candidate')
        Invoke-FixtureGit @('add', '--force', '.venv/probe.txt')
        $rejected = $false
        try { & $runner -Operation secrets -EvidenceRoot $temporary | Out-Null }
        catch { if ($_.Exception.Message -cne 'Repository secret scan failed.') { throw }; $rejected = $true }
        if (-not $rejected) { throw 'Live tracked environment finding was accepted.' }
        $script:passed++
    }
} finally {
    # The resolved UUID-scoped fixture must remain under this test's temp root.
    $resolved = [IO.Path]::GetFullPath($temporary)
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if (-not $resolved.StartsWith($tempRoot + '\arbiter-security-', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unexpected security fixture cleanup path.'
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Output "$script:passed security-script cases passed"
