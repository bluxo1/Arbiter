# Non-Docker controls for the release coordinator. Never dot-source its entry point.
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $repository 'scripts/verify-release.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Release coordinator syntax failed.' }
foreach ($name in @('Read-ReleaseJUnit', 'Assert-ReleaseGit', 'Invoke-Required', 'Invoke-Phase', 'Copy-TextEvidence', 'Export-ReleaseProbes', 'Protect-Evidence')) {
    $node = $ast.Find({ param($item)
        $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq $name
    }, $true)
    if ($null -eq $node) { throw 'Required release guard missing.' }
    . ([ScriptBlock]::Create($node.Extent.Text))
}
$script:passed = 0
$script:testResults = @()
function Assert-Proof([bool]$Condition) {
    if (-not $Condition) { throw 'Release guard assertion failed.' }
    $script:passed++
}
function Reject([scriptblock]$Action) {
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    Assert-Proof $rejected
}

$cache = Join-Path $repository '.pytest_cache'
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$temporary = Join-Path $cache ('release-controls-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$junit = Join-Path $temporary 'proof.xml'
$valid = '<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="tests.test_proof" name="test_required" /></testsuite></testsuites>'
try {
    Export-ReleaseProbes $temporary
    Assert-Proof (@(Get-ChildItem -LiteralPath $temporary -Filter '*.py' -File).Count -eq 5)
    Assert-Proof ((Get-Content -LiteralPath (Join-Path $temporary 'loadSource.py') -Raw).Contains('def test_release_bounded_load'))
    [IO.File]::WriteAllText($junit, $valid)
    $result = Read-ReleaseJUnit $junit @('test_required') 0 @('1 passed in 1.00s')
    Assert-Proof ($result.executed -eq 1 -and $result.passed -eq 1 -and $result.skipped -eq 0)
    $result = Read-ReleaseJUnit $junit @('test_required') 1 @('1 passed, 1 deselected, 2 warnings in 1s')
    Assert-Proof ($result.deselected -eq 1 -and $result.warnings -eq 2)
    Assert-Proof ($script:testResults.Count -eq 2 -and $script:testResults[1].counts.deselected -eq 1)
    $multiple = $valid.Replace('tests="1"', 'tests="2"').Replace('</testsuite>', '<testcase classname="tests.test_proof" name="test_second" /></testsuite>')
    [IO.File]::WriteAllText($junit, $multiple)
    $result = Read-ReleaseJUnit $junit @('test_required', 'test_second') 0 @('2 passed')
    Assert-Proof ($result.executed -eq 2 -and $result.passed -eq 2)
    Reject { Read-ReleaseJUnit $junit @('missing_test') 0 @() }
    Reject { Read-ReleaseJUnit $junit @('test_required') 0 @('1 passed, 1 deselected') }
    Reject { Read-ReleaseJUnit $junit @('test_required') 1 @('1 passed') }
    foreach ($bad in @('<testsuites/>', '{', '<testsuite tests="0" failures="0" errors="0" skipped="0"/>',
            $valid.Replace('tests="1"', 'tests="2"'), $valid.Replace('skipped="0"', 'skipped="1"'),
            $valid.Replace('failures="0"', 'failures="1"'), $valid.Replace('errors="0"', 'errors="1"'),
            $valid.Replace(' skipped="0"', ''), $valid.Replace('name="test_required"', 'name=""'),
            $valid.Replace(' />', '><skipped /></testcase>'))) {
        [IO.File]::WriteAllText($junit, $bad)
        Reject { Read-ReleaseJUnit $junit @('test_required') 0 @() }
    }
    Reject { Read-ReleaseJUnit (Join-Path $temporary 'missing.xml') @() 0 @() }

    # Real native process exit propagation, with no Docker/tool downloads.
    $script:summary = @(); $script:sequence = 0; $script:evidence = $null
    $caught = $null
    try { Invoke-Required 'inert failing child' (Join-Path $PSHOME 'powershell.exe') @('-NoProfile', '-Command', 'exit 37') }
    catch { $caught = $_.Exception }
    Assert-Proof ($null -ne $caught -and $caught.Data['ExitCode'] -eq 37)
    Reject { Invoke-Required 'missing tool' 'arbiter-nonexistent-release-tool.exe' @() }
    $output = @(Invoke-Required 'inert passing child' (Join-Path $PSHOME 'powershell.exe') @('-NoProfile', '-Command', "Write-Output 'safe'; exit 0"))
    Assert-Proof ($output.Count -eq 1 -and $output[0] -eq 'safe')

    # Evidence ACL construction: one explicit /grant:r pair per SID, proven against real icacls.
    function Test-EvidenceGrantContract([string[]]$Arguments, [string]$UserSid) {
        # Accepts only: <dir>, '/inheritance:r', then exactly three '/grant:r' <grant> pairs,
        # each grant exactly '*<SID>:(OI)(CI)F' for the current user, SYSTEM, Administrators.
        if ($Arguments.Count -ne 8 -or $Arguments[1] -cne '/inheritance:r') { return $false }
        $expected = @(('*' + $UserSid + ':(OI)(CI)F'), ('*S-1-5-18:(OI)(CI)F'), ('*S-1-5-32-544:(OI)(CI)F'))
        for ($pair = 0; $pair -lt 3; $pair++) {
            if ($Arguments[2 + 2 * $pair] -cne '/grant:r' -or $Arguments[3 + 2 * $pair] -cne $expected[$pair]) { return $false }
        }
        return $true
    }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $script:icaclsArguments = $null
    function Invoke-Required([string]$Label, [string]$Command, [string[]]$Arguments) {
        if ($Label -cne 'protect evidence' -or $Command -cne 'icacls.exe') { throw 'Unexpected child command in evidence guard.' }
        $script:icaclsArguments = @($Arguments)
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $global:LASTEXITCODE = $null
            & $Command @Arguments 2>&1 | Out-Null
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $previousPreference }
        if ($null -eq $code -or $code -ne 0) { throw 'icacls rejected the evidence grant construction.' }
        return @()
    }
    Protect-Evidence (Join-Path $temporary 'protect-construction')
    Assert-Proof (Test-EvidenceGrantContract $script:icaclsArguments $sid)
    foreach ($index in @(2, 4, 6)) { Assert-Proof ($script:icaclsArguments[$index] -ceq '/grant:r') }
    Assert-Proof ($script:icaclsArguments[3] -ceq ('*' + $sid + ':(OI)(CI)F'))
    Assert-Proof ($script:icaclsArguments[5] -ceq '*S-1-5-18:(OI)(CI)F')
    Assert-Proof ($script:icaclsArguments[7] -ceq '*S-1-5-32-544:(OI)(CI)F')
    foreach ($construction in @(
            @('d', '/inheritance:r', '/grant:r', ('*' + $sid + ':(OI)(CI)F'), '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'),
            @('d', '/inheritance:r', '/grant:r', ('*' + $sid + ':(OI)(CI)F'), '/grant:r', '*S-1-5-18:(OI)(CI)F'),
            @('d', '/inheritance:r', '/grant:r', ('*' + $sid + ':(OI)(CI)F'), '/grant:r', '*S-1-5-18', '/grant:r', '*S-1-5-32-544:(OI)(CI)F'),
            @('d', '/inheritance:r', '/grant:r', ('*' + $sid + ':(OI)(CI)F'), '/grant:r', '*S-1-1-0:(OI)(CI)F', '/grant:r', '*S-1-5-32-544:(OI)(CI)F'),
            @('d', '/inheritance:r', '/grant:r', ('*' + $sid + ':(OI)(CI)F'), '/grant:r', '*S-1-5-18:(OI)(CI)F', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)F'),
            @('d', '/grant:r', ('*' + $sid + ':(OI)(CI)F'), '/grant:r', '*S-1-5-18:(OI)(CI)F', '/grant:r', '*S-1-5-32-544:(OI)(CI)F'))) {
        Assert-Proof (-not (Test-EvidenceGrantContract $construction $sid))
    }
    # Restore the real coordinator child runner, then protect a disposable directory for real.
    $node = $ast.Find({ param($item)
        $item -is [Management.Automation.Language.FunctionDefinitionAst] -and $item.Name -eq 'Invoke-Required'
    }, $true)
    if ($null -eq $node) { throw 'Required release guard missing.' }
    . ([ScriptBlock]::Create($node.Extent.Text))
    Protect-Evidence (Join-Path $temporary 'protect-real')
    $acl = Get-Acl -LiteralPath (Join-Path $temporary 'protect-real')
    $protectedSids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value })
    Assert-Proof $acl.AreAccessRulesProtected
    Assert-Proof (@($acl.Access).Count -eq 3)
    Assert-Proof (@($acl.Access | Where-Object { $_.AccessControlType -cne 'Allow' -or $_.FileSystemRights -cne 'FullControl' }).Count -eq 0)
    Assert-Proof (@($protectedSids | Where-Object { $_ -cin @($sid, 'S-1-5-18', 'S-1-5-32-544') }).Count -eq 3)
    # A malformed/missing grant must fail closed through the real tool, never yield a weaker ACL.
    New-Item -ItemType Directory -Path (Join-Path $temporary 'protect-malformed') | Out-Null
    function Invoke-IcaclsFailClosed([string[]]$Arguments) {
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $global:LASTEXITCODE = $null
            & icacls.exe @Arguments 2>&1 | Out-Null
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $previousPreference }
        if ($null -eq $code -or $code -ne 0) { throw 'icacls refused the malformed grant.' }
    }
    Reject { Invoke-IcaclsFailClosed @((Join-Path $temporary 'protect-malformed'), '/inheritance:r', '/grant:r',
        ('*' + $sid + ':(OI)(CI)F'), '/grant:r', '*S-1-5-18:(OI)(CI)F', '/grant:r', '*:(OI)(CI)F') }

    # Scoped native-command double: no actual Git mutations or Docker calls.
    function Invoke-Required([string]$Label, [string]$Command, [string[]]$Arguments) {
        if ($Command -ne 'git') { throw 'Unexpected child command in Git guard.' }
        switch ($Label) {
            'git status' { return $script:status }
            'empty index' { return $script:index }
            'main branch' { return $script:branch }
            'main divergence' { return $script:divergence }
            'revision' { return 'inert-revision' }
            default { throw 'Unexpected Git command.' }
        }
    }
    $script:status = @(); $script:index = @(); $script:branch = 'main'; $script:divergence = "0`t0"
    Assert-Proof ((Assert-ReleaseGit $false) -eq 'inert-revision')
    $script:status = @(' M scripts/verify-release.ps1', '?? tests/test_verify_release.ps1')
    Assert-Proof ((Assert-ReleaseGit $true) -eq 'inert-revision')
    Reject { Assert-ReleaseGit $false }
    foreach ($line in @(' M src/arbiter/main.py', '?? unexpected.txt', 'M  README.md', ' R README.md -> other.md')) {
        $script:status = @($line)
        Reject { Assert-ReleaseGit $true }
    }
    $script:status = @(); $script:index = @('README.md')
    Reject { Assert-ReleaseGit $true }
    $script:index = @(); $script:divergence = "0`t1"
    Reject { Assert-ReleaseGit $true }
    $script:divergence = "0`t0"; $script:branch = 'other'
    Reject { Assert-ReleaseGit $true }

    # The second full-suite call must be rejected before invoking any child.
    function Assert-NoOtherVerifier { }
    $script:fullStarted = $true
    Reject { Invoke-Phase 'full' @() }

    $source = Join-Path $temporary 'source'; $target = Join-Path $temporary 'target'
    New-Item -ItemType Directory -Path $source, $target | Out-Null
    [IO.File]::WriteAllText((Join-Path $source 'safe.log'), 'safe')
    $script:artifactOrdinal = 0
    Copy-TextEvidence $source $target
    Assert-Proof ($script:artifactOrdinal -eq 1 -and (Get-Content -LiteralPath (Join-Path $target '1.log')) -eq 'safe')
    Reject { Copy-TextEvidence (Join-Path $source 'nonexistent') $target }
    # No model-pull, volume deletion or second full-suite call in the coordinator.
    Assert-Proof ($ast.Extent.Text -notmatch '(?i)ollama\s+pull|down[^\r\n]*--volumes')
    Assert-Proof ([regex]::Matches($ast.Extent.Text, "Invoke-Phase 'full'").Count -eq 1)
    Write-Output "Release coordinator controls: $script:passed passed; 0 failed (no Docker)."
} finally {
    # Only known, UUID-scoped test files; no recursive filesystem deletion.
    foreach ($file in @($junit, (Join-Path $temporary 'source\safe.log'), (Join-Path $temporary 'target\1.log'))) {
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    foreach ($name in @('loadSource', 'metadataSource', 'inventory', 'metrics', 'migrationSource')) {
        $file = Join-Path $temporary "$name.py"
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    foreach ($dir in @((Join-Path $temporary 'protect-construction'), (Join-Path $temporary 'protect-real'),
            (Join-Path $temporary 'protect-malformed'), (Join-Path $temporary 'source'), (Join-Path $temporary 'target'), $temporary)) {
        if (Test-Path -LiteralPath $dir -PathType Container) { [IO.Directory]::Delete($dir, $false) }
    }
}
