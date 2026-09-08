function Import-BlockedDomain {
    <#
    .SYNOPSIS
        Blocks every domain listed in a text or JSON export file.

    .DESCRIPTION
        Wrapper around Block-Domain -Path. Accepts the JSON produced by
        Export-BlockedDomain and plain one-domain-per-line text files.

    .PARAMETER Path
        List file to import.

    .PARAMETER Method
        Hosts, Firewall, or Both. Default is Both.

    .PARAMETER Direction
        Firewall direction. Default is Outbound.

    .PARAMETER NoWww
        Do not also block www. variants.

    .PARAMETER IPv4Only
        Skip IPv6 hosts entries and firewall rules.

    .PARAMETER BackupHosts
        Backup the hosts file first.

    .PARAMETER HostsFilePath
        Hosts file to edit. Defaults to the system hosts file.

    .EXAMPLE
        Import-BlockedDomain -Path .\blocked.txt -Method Hosts
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]
        [Alias('File', 'ListPath')]
        [string]$Path,

        [ValidateSet('Hosts', 'Firewall', 'Both')]
        [string]$Method = 'Both',

        [ValidateSet('Outbound', 'Inbound', 'Both')]
        [string]$Direction = 'Outbound',

        [switch]$NoWww,

        [switch]$IPv4Only,

        [switch]$BackupHosts,

        [string]$HostsFilePath
    )

    $blockParams = @{
        Path       = $Path
        Method     = $Method
        Direction  = $Direction
        NoWww      = $NoWww
        IPv4Only   = $IPv4Only
        BackupHosts = $BackupHosts
    }
    if ($HostsFilePath) {
        $blockParams['HostsFilePath'] = $HostsFilePath
    }

    Block-Domain @blockParams
}
