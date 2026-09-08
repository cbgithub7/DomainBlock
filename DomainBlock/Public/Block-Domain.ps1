function Block-Domain {
    <#
    .SYNOPSIS
        Blocks domains via the hosts file, Windows Firewall, or both.

    .DESCRIPTION
        Adds loopback hosts-file entries and/or outbound (optionally inbound)
        firewall block rules for the current DNS addresses of each domain.
        Entries are tagged so they can be listed, refreshed, and removed later.
        Firewall rules are named per domain and IP; re-running is idempotent.

        Firewall IP blocks go stale when CDNs rotate addresses. Use
        Update-DomainFirewallBlock to refresh them. DNS-over-HTTPS and VPNs can
        bypass hosts-file blocks.

    .PARAMETER Name
        Domain names to block. URLs are accepted and reduced to a host name.

    .PARAMETER Path
        Text or JSON file of domains (one per line, or Export-BlockedDomain JSON).

    .PARAMETER Method
        Hosts, Firewall, or Both. Default is Both.

    .PARAMETER Direction
        Firewall direction: Outbound, Inbound, or Both. Default is Outbound.

    .PARAMETER NoWww
        Do not also block the www. variant of each name.

    .PARAMETER IPv4Only
        Do not write ::1 hosts entries or create IPv6 firewall rules.

    .PARAMETER BackupHosts
        Copy the hosts file to Documents\DomainBlock before changing it.

    .PARAMETER NoFlushDns
        Skip flushing the DNS client cache after hosts-file changes.

    .PARAMETER HostsFilePath
        Hosts file to edit. Defaults to the system hosts file.

    .EXAMPLE
        Block-Domain -Name ads.example.com -Method Hosts

        Redirects ads.example.com (and www.ads.example.com) to loopback.

    .EXAMPLE
        Block-Domain -Path .\examples\DomainList.txt -Method Both -BackupHosts

        Blocks every domain in the list via hosts and firewall, after a backup.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByName')]
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [Parameter(Mandatory, ParameterSetName = 'ByPath')]
        [Alias('File', 'ListPath')]
        [string]$Path,

        [ValidateSet('Hosts', 'Firewall', 'Both')]
        [string]$Method = 'Both',

        [ValidateSet('Outbound', 'Inbound', 'Both')]
        [string]$Direction = 'Outbound',

        [switch]$NoWww,

        [switch]$IPv4Only,

        [switch]$BackupHosts,

        [switch]$NoFlushDns,

        [string]$HostsFilePath
    )

    begin {
        $pending = New-Object System.Collections.Generic.List[string]
        if (-not $HostsFilePath) {
            $HostsFilePath = Get-DefaultHostsFilePath
        }

        $needHosts = $Method -in @('Hosts', 'Both')
        $needFirewall = $Method -in @('Firewall', 'Both')

        if ($needFirewall) {
            Assert-Administrator
            Assert-NetSecurityModule
        } elseif ($needHosts -and (Test-IsSystemHostsFile -Path $HostsFilePath)) {
            Assert-Administrator
        }

        $family = if ($IPv4Only) { 'IPv4' } else { 'All' }
        $directions = @(Get-FirewallDirectionList -Direction $Direction)
        $hostsChanged = $false
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByName') {
            foreach ($item in $Name) {
                [void]$pending.Add($item)
            }
        }
    }

    end {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            foreach ($item in (Read-DomainListFile -Path $Path)) {
                [void]$pending.Add($item)
            }
        }

        $domains = @(ConvertTo-UniqueNormalizedDomain -Name @($pending.ToArray()))
        if ($domains.Count -eq 0) {
            Write-Error 'No domain names were provided.'
            return
        }

        if ($BackupHosts -and $needHosts) {
            if ($PSCmdlet.ShouldProcess($HostsFilePath, 'Backup hosts file')) {
                Backup-HostsFile -HostsFilePath $HostsFilePath | Out-Null
            }
        }

        foreach ($domain in $domains) {
            $domainName = [string]$domain
            $variants = @(Get-RelatedDomainName -Name $domainName -NoWww:$NoWww)
            foreach ($variant in $variants) {
                if ($needHosts) {
                    if ($PSCmdlet.ShouldProcess("$variant", "Block via hosts file ($HostsFilePath)")) {
                        foreach ($entry in @(Add-HostsFileDomainBlock -Domain $variant -Path $HostsFilePath -IPv4Only:$IPv4Only)) {
                            if ($entry.Status -eq 'Blocked') {
                                $hostsChanged = $true
                            }
                            $entry
                        }
                    }
                }

                if ($needFirewall) {
                    $addresses = @(Get-DomainIPAddress -Name $variant -AddressFamily $family -ErrorAction Continue)
                    $usable = @($addresses | Where-Object { -not (Test-IsLoopbackAddress -IPAddress $_.IPAddress) })
                    if ($usable.Count -eq 0) {
                        Write-Error "Could not resolve $variant to a non-loopback IP address; firewall rule was not created."
                        continue
                    }

                    foreach ($address in $usable) {
                        foreach ($dir in $directions) {
                            $target = '{0} {1} {2}' -f $variant, $address.IPAddress, $dir
                            if ($PSCmdlet.ShouldProcess($target, 'Create firewall block rule')) {
                                New-DomainBlockFirewallRule -Domain $variant -IPAddress $address.IPAddress -Direction $dir
                            }
                        }
                    }
                }
            }
        }

        if ($hostsChanged -and -not $NoFlushDns) {
            Clear-DomainBlockDnsCache
        }
    }
}
