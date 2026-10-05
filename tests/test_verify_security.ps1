$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$errors = $null
$tokens = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repository 'scripts/verify-security.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Security script syntax failed.' }
foreach ($name in @('Read-TrivyReport', 'Assert-RepositorySecretReport')) {
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
Write-Output "$script:passed security-script cases passed"
