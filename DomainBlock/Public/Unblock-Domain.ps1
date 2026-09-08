function Unblock-Domain {
    <#
    .SYNOPSIS
        Removes DomainBlock hosts-file entries and/or firewall rules.

    .DESCRIPTION
        Unblock-Domain -Name removes toolkit-managed hosts lines for that name
        (and matching unmanaged loopback mappings) plus matching firewall rules.
        Unblock-Domain -All removes only tagged toolkit entries unless
        -IncludeUnmanaged is also specified.

    .PARAMETER Name
        Domain names to unblock.

    .PARAMETER All
        Remove every toolkit-managed block for the chosen method.

    .PARAMETER Method
        Hosts, Firewall, or Both. Default is Both.

    .PARAMETER NoWww
        Do not also unblock the www. variant.

    .PARAMETER IncludeUnmanaged
        Also remove untagged loopback hosts entries. Required with -All if you
        want unmanaged lines removed.

    .PARAMETER NoFlushDns
        Skip flushing the DNS client cache after hosts-file changes.

    .PARAMETER HostsFilePath
        Hosts file to edit. Defaults to the system hosts file.

    .EXAMPLE
        Unblock-Domain -Name ads.example.com

        Removes hosts entries and firewall rules for ads.example.com and www.

    .EXAMPLE
        Unblock-Domain -All -Method Firewall

        Deletes every DomainBlock firewall rule.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByName')]
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        [ValidateSet('Hosts', 'Firewall', 'Both')]
        [string]$Method = 'Both',

        [switch]$NoWww,

        [switch]$IncludeUnmanaged,

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
        $domains = @()
        if ($PSCmdlet.ParameterSetName -eq 'All') {
            if (-not $PSCmdlet.ShouldProcess("all DomainBlock $Method entries", 'Unblock')) {
                return
            }
        } else {
            $domains = @(ConvertTo-UniqueNormalizedDomain -Name @($pending.ToArray()))
            if ($domains.Count -eq 0) {
                Write-Error 'No domain names were provided.'
                return
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'All') {
            if ($needHosts) {
                foreach ($entry in @(Remove-HostsFileDomainBlock -Path $HostsFilePath -All -IncludeUnmanaged:$IncludeUnmanaged)) {
                    $hostsChanged = $true
                    $entry
                }
            }
            if ($needFirewall) {
                Remove-DomainBlockFirewallRule -All
            }
        } else {
            foreach ($domain in $domains) {
                $domainName = [string]$domain
                $variants = @(Get-RelatedDomainName -Name $domainName -NoWww:$NoWww)
                foreach ($variant in $variants) {
                    if ($needHosts) {
                        if ($PSCmdlet.ShouldProcess("$variant", "Remove hosts-file block ($HostsFilePath)")) {
                            foreach ($entry in @(Remove-HostsFileDomainBlock -Domain $variant -Path $HostsFilePath -IncludeUnmanaged:$IncludeUnmanaged)) {
                                if ($entry.Status -eq 'Unblocked') {
                                    $hostsChanged = $true
                                }
                                $entry
                            }
                        }
                    }
                    if ($needFirewall) {
                        if ($PSCmdlet.ShouldProcess("$variant", 'Remove firewall block rules')) {
                            Remove-DomainBlockFirewallRule -Domain $variant
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
