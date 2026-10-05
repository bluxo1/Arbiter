param(
    [Parameter(Mandatory)][ValidateSet('backup', 'restore')][string]$Operation,
    [string]$PostgresContainer = 'arbiter-postgres-1',
    [string]$Database = 'arbiter',
    [Parameter(Mandatory)][string]$ArchiveDirectory,
    [string]$Archive,
    [string]$RestoreDatabase
)

# Logical backup/restore only. Roles and external application secrets are provisioned
# separately. Never restore an untrusted archive: it contains privileged SQL.
$ErrorActionPreference = 'Stop'
$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$directory = [System.IO.Path]::GetFullPath($ArchiveDirectory).TrimEnd('\')
if ($directory -eq $repository -or $directory.StartsWith($repository + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Backup artifacts must be outside the repository.'
}
if ($Database -cnotmatch '^[a-z][a-z0-9_]{0,62}$' -or
    $PostgresContainer -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$') {
    throw 'Invalid database/container identifier.'
}
$labels = & docker inspect --format '{{json .Config.Labels}}' $PostgresContainer
if ($LASTEXITCODE -ne 0 -or ($labels | ConvertFrom-Json).'com.docker.compose.service' -ne 'postgres') {
    throw 'Expected a Compose PostgreSQL service.'
}
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($sid, 'S-1-5-18', 'S-1-5-32-544')
if (-not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory | Out-Null
    $grants = @($allowed | ForEach-Object { '*' + $_ + ':(OI)(CI)F' })
    & icacls.exe $directory '/inheritance:r' '/grant:r' @grants | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the backup directory.' }
}
$acl = Get-Acl -LiteralPath $directory
if (-not $acl.AreAccessRulesProtected -or ($acl.Access | Where-Object {
    $_.AccessControlType -eq 'Allow' -and
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed
})) { throw 'Backup directory permissions are not restricted.' }

function Invoke-PostgresTool([string]$Command, [string[]]$Values) {
    # Secret values never enter host arguments, output, files or Compose environment.
    # Capture native stderr without echoing SQL/data from a failed dump or restore.
    $previous = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        # Windows PowerShell's legacy native argument marshalling strips embedded
        # quotes unless escaped; sh must retain quotes around positional arguments.
        if ($PSVersionTable.PSVersion.Major -lt 7) { $Command = $Command.Replace('"', '\"') }
        $nativeOutput = & docker exec $PostgresContainer sh -c $Command sh @Values 2>&1
        $nativeCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    if ($nativeCode -ne 0) { throw 'PostgreSQL backup/restore operation failed; target remains isolated.' }
}
$authentication = 'export PGCONNECT_TIMEOUT=5; export PGPASSWORD="$(cat /run/secrets/db_bootstrap_password)"; '
$temporary = '/tmp/arbiter-backup-' + [Guid]::NewGuid().ToString('N') + '.dump'
try {
    if ($Operation -eq 'backup') {
        $Archive = Join-Path $directory ([Guid]::NewGuid().ToString('N') + '.dump')
        Invoke-PostgresTool ($authentication + 'umask 077; pg_dump -U arbiter_bootstrap --lock-wait-timeout=5s --format=custom --file="$2" --dbname="$1"') @($Database, $temporary)
        & docker cp "${PostgresContainer}:$temporary" $Archive | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not retain backup archive.' }
        foreach ($rule in (Get-Acl -LiteralPath $Archive).Access) {
            if ($rule.AccessControlType -eq 'Allow' -and
                $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
                throw 'Backup file permissions are not restricted.'
            }
        }
        [pscustomobject]@{ archive = $Archive; sha256 = (Get-FileHash -LiteralPath $Archive).Hash }
    } else {
        if ($RestoreDatabase -cnotmatch '^arbiter_restore_[a-f0-9]{32}$' -or $RestoreDatabase -eq $Database) {
            throw 'Restore requires a fresh arbiter_restore_<random UUID hex> database.'
        }
        $Archive = [System.IO.Path]::GetFullPath($Archive)
        if (-not $Archive.StartsWith($directory + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw 'Expected a protected backup archive.' }
        foreach ($rule in (Get-Acl -LiteralPath $Archive).Access) {
            if ($rule.AccessControlType -eq 'Allow' -and
                $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed) {
                throw 'Backup file permissions are not restricted.'
            }
        }
        # createdb refuses an existing target. No DROP, --clean, CASCADE or source write.
        Invoke-PostgresTool ($authentication + 'createdb -U arbiter_bootstrap --template=template0 --maintenance-db="$1" "$2"') @($Database, $RestoreDatabase)
        Invoke-PostgresTool ($authentication + 'psql -X -U arbiter_bootstrap -d "$1" -v ON_ERROR_STOP=1 -c "$2"') @($RestoreDatabase, ('REVOKE ALL ON DATABASE ' + $RestoreDatabase + ' FROM PUBLIC;'))
        & docker cp $Archive "${PostgresContainer}:$temporary" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not stage restore archive.' }
        Invoke-PostgresTool ($authentication + 'pg_restore -U arbiter_bootstrap --exit-on-error --single-transaction --dbname="$1" "$2"') @($RestoreDatabase, $temporary)
        # pg_dump excludes cluster roles and database-level CONNECT grants. Apply the
        # deployment's fixed restricted database boundary on this newly created DB.
        $permissions = 'REVOKE ALL ON DATABASE ' + $RestoreDatabase + ' FROM PUBLIC; ' +
            'GRANT CONNECT,CREATE ON DATABASE ' + $RestoreDatabase + ' TO arbiter_migration; ' +
            'GRANT CONNECT ON DATABASE ' + $RestoreDatabase + ' TO arbiter_runtime,arbiter_operator,arbiter_maintenance;'
        Invoke-PostgresTool ($authentication + 'psql -X -U arbiter_bootstrap -d "$1" -v ON_ERROR_STOP=1 -c "$2"') @($RestoreDatabase, $permissions)
        [pscustomobject]@{ restored_database = $RestoreDatabase }
    }
} finally {
    & docker exec $PostgresContainer rm -f -- $temporary | Out-Null
}
