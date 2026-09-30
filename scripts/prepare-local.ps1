param([string]$DataRoot = 'D:\AI & ML\ArbiterData')

$ErrorActionPreference = 'Stop'
$resolvedRoot = [System.IO.Path]::GetFullPath($DataRoot)
if ([System.IO.Path]::GetPathRoot($resolvedRoot) -ne 'D:\') {
    throw 'Local Arbiter data must use D: on this host.'
}
if ([System.IO.Path]::GetFileName($resolvedRoot.TrimEnd('\')) -ne 'ArbiterData') {
    throw 'Use an Arbiter-specific directory named ArbiterData.'
}
$secretDirectory = Join-Path $resolvedRoot 'secrets'
New-Item -ItemType Directory -Force -Path $secretDirectory | Out-Null
# Protect only Arbiter's secret directory, never unrelated Docker/WSL data.
$secretAcl = Get-Acl -LiteralPath $secretDirectory
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$allowedSids = @($currentSid.Value, 'S-1-5-18', 'S-1-5-32-544')
foreach ($existingRule in @($secretAcl.Access | Where-Object { -not $_.IsInherited })) {
    $ruleSid = $existingRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($ruleSid -notin $allowedSids -or $existingRule.AccessControlType -ne 'Allow') {
        throw 'Unexpected explicit secret-directory permissions; review them before provisioning.'
    }
}
if (-not $secretAcl.AreAccessRulesProtected) {
    # icacls changes only the DACL; it does not request the SACL privilege.
    $grantArguments = @($allowedSids | ForEach-Object { '*' + $_ + ':(OI)(CI)F' })
    & icacls.exe $secretDirectory '/inheritance:r' '/grant:r' @grantArguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the secret directory.' }
}
$verifiedAcl = Get-Acl -LiteralPath $secretDirectory
if (-not $verifiedAcl.AreAccessRulesProtected -or @($verifiedAcl.Access).Count -ne 3) {
    throw 'Secret-directory permissions failed verification.'
}
foreach ($verifiedRule in $verifiedAcl.Access) {
    $verifiedSid = $verifiedRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($verifiedSid -notin $allowedSids -or $verifiedRule.AccessControlType -ne 'Allow' -or
        $verifiedRule.FileSystemRights -ne 'FullControl') {
        throw 'Secret-directory access is not restricted to the expected principals.'
    }
}
foreach ($directory in @('postgres', 'redis', 'ollama\models', 'tmp', 'phase1', 'model-approvals')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $resolvedRoot $directory) | Out-Null
}
$approvalDirectory = Join-Path $resolvedRoot 'model-approvals'
foreach ($existingRule in @((Get-Acl -LiteralPath $approvalDirectory).Access | Where-Object { -not $_.IsInherited })) {
    $ruleSid = $existingRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
    if ($ruleSid -notin $allowedSids -or $existingRule.AccessControlType -ne 'Allow') {
        throw 'Unexpected approval-directory permissions; review them before provisioning.'
    }
}
$approvalGrants = @($allowedSids | ForEach-Object { '*' + $_ + ':(OI)(CI)F' })
& icacls.exe $approvalDirectory '/inheritance:r' '/grant:r' @approvalGrants | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the approval directory.' }
$approvalAcl = Get-Acl -LiteralPath $approvalDirectory
if (-not $approvalAcl.AreAccessRulesProtected -or @($approvalAcl.Access).Count -ne 3) {
    throw 'Approval-directory permissions failed verification.'
}
foreach ($rule in $approvalAcl.Access) {
    if ($rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowedSids -or
        $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') {
        throw 'Approval-directory access is not restricted to the expected principals.'
    }
}
foreach ($secretName in @('db_bootstrap_password', 'db_migration_password', 'db_operator_password', 'db_runtime_password', 'db_maintenance_password', 'audit_cursor_key', 'api_key_pepper', 'request_fingerprint_key')) {
    $secretPath = Join-Path $secretDirectory $secretName
    if (Test-Path -LiteralPath $secretPath) {
        foreach ($fileRule in (Get-Acl -LiteralPath $secretPath).Access) {
            $fileSid = $fileRule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            if ($fileSid -notin $allowedSids -and $fileRule.AccessControlType -eq 'Allow') {
                throw 'Unexpected secret-file reader; review permissions before provisioning.'
            }
        }
        continue
    }
    $byteCount = if ($secretName -in @('audit_cursor_key', 'api_key_pepper', 'request_fingerprint_key')) { 32 } else { 48 }
    $randomBytes = New-Object byte[] $byteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($randomBytes) } finally { $generator.Dispose() }
    $stream = [System.IO.File]::Open($secretPath, 'CreateNew', 'Write', 'None')
    $writer = New-Object System.IO.StreamWriter($stream)
    try { $writer.Write([Convert]::ToBase64String($randomBytes)) } finally { $writer.Dispose() }
}
Write-Output 'Arbiter directories and separate database/cursor/pepper/fingerprint secrets prepared; existing values retained.'
