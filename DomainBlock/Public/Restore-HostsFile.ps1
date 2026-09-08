function Restore-HostsFile {
    <#
    .SYNOPSIS
        Replaces the hosts file with a backup copy.

    .DESCRIPTION
        Restoring the system hosts file requires an elevated session. The DNS
        client cache is flushed afterwards unless -NoFlushDns is specified.

    .PARAMETER Path
        Backup file to restore from.

    .PARAMETER HostsFilePath
        Destination hosts file. Defaults to the system hosts file.

    .PARAMETER NoFlushDns
        Skip flushing the DNS client cache.

    .EXAMPLE
        Restore-HostsFile -Path "$env:USERPROFILE\Documents\DomainBlock\hosts.20260908-153000.bak"
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [Alias('BackupPath', 'Source')]
        [string]$Path,

        [string]$HostsFilePath,

        [switch]$NoFlushDns
    )

    if (-not $HostsFilePath) {
        $HostsFilePath = Get-DefaultHostsFilePath
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Backup file not found: $Path"
    }
    if (Test-IsSystemHostsFile -Path $HostsFilePath) {
        Assert-Administrator
    }

    if ($PSCmdlet.ShouldProcess($HostsFilePath, "Replace with $Path")) {
        Copy-Item -LiteralPath $Path -Destination $HostsFilePath -Force
        if (-not $NoFlushDns) {
            Clear-DomainBlockDnsCache
        }
        [PSCustomObject]@{
            PSTypeName = 'DomainBlock.HostsBackup'
            SourcePath = $Path
            BackupPath = $HostsFilePath
            Created    = Get-Date
        }
    }
}
