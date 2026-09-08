function Backup-HostsFile {
    <#
    .SYNOPSIS
        Copies the hosts file to a timestamped backup.

    .DESCRIPTION
        Default destination is Documents\DomainBlock\hosts.yyyyMMdd-HHmmss.bak.
        Reading the system hosts file does not require elevation; restoring it does.

    .PARAMETER HostsFilePath
        Hosts file to copy. Defaults to the system hosts file.

    .PARAMETER Destination
        Backup file path. Directories are created as needed.

    .EXAMPLE
        Backup-HostsFile

        Writes a timestamped copy under Documents\DomainBlock.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$HostsFilePath,
        [string]$Destination
    )

    if (-not $HostsFilePath) {
        $HostsFilePath = Get-DefaultHostsFilePath
    }
    if (-not (Test-Path -LiteralPath $HostsFilePath -PathType Leaf)) {
        throw "Hosts file not found: $HostsFilePath"
    }

    if (-not $Destination) {
        $Destination = Join-Path (Get-DefaultHostsBackupDirectory) ('hosts.{0:yyyyMMdd-HHmmss}.bak' -f (Get-Date))
    }

    $destDir = Split-Path -Parent $Destination
    if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    if ($PSCmdlet.ShouldProcess($HostsFilePath, "Copy to $Destination")) {
        Copy-Item -LiteralPath $HostsFilePath -Destination $Destination -Force
        [PSCustomObject]@{
            PSTypeName = 'DomainBlock.HostsBackup'
            SourcePath = $HostsFilePath
            BackupPath = $Destination
            Created    = Get-Date
        }
    }
}
