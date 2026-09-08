function Get-BlockedDomain {
    <#
    .SYNOPSIS
        Lists domains currently blocked by this toolkit.

    .DESCRIPTION
        Reads tagged hosts-file entries and DomainBlock firewall rules.
        Use -IncludeUnmanaged to also show untagged loopback mappings.

    .PARAMETER Name
        Optional wildcard filter against domain names.

    .PARAMETER Method
        Hosts, Firewall, or Both. Default is Both.

    .PARAMETER IncludeUnmanaged
        Include hosts entries that map a name to loopback but lack the
        DomainBlock comment tag.

    .PARAMETER HostsFilePath
        Hosts file to read. Defaults to the system hosts file.

    .EXAMPLE
        Get-BlockedDomain

        Shows every toolkit-managed hosts and firewall block.
    #>
    [CmdletBinding()]
    param(
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [ValidateSet('Hosts', 'Firewall', 'Both')]
        [string]$Method = 'Both',

        [switch]$IncludeUnmanaged,

        [string]$HostsFilePath
    )

    if (-not $HostsFilePath) {
        $HostsFilePath = Get-DefaultHostsFilePath
    }

    $needHosts = $Method -in @('Hosts', 'Both')
    $needFirewall = $Method -in @('Firewall', 'Both')

    $results = New-Object System.Collections.Generic.List[object]

    if ($needHosts) {
        foreach ($entry in @(Get-HostsFileDomainBlock -Path $HostsFilePath -IncludeUnmanaged:$IncludeUnmanaged | Where-Object { $_ })) {
            [void]$results.Add((
                    New-DomainBlockEntry -Domain $entry.Domain -Method Hosts -Status Blocked -Target $entry.IPAddress -Detail $HostsFilePath
                ))
        }
    }

    if ($needFirewall) {
        try {
            Assert-NetSecurityModule
            foreach ($rule in @(Get-DomainBlockFirewallRule | Where-Object { $_ })) {
                $status = 'Blocked'
                if ($rule.Enabled -ne 'True' -and $rule.Enabled -ne $true) {
                    $status = 'Disabled'
                }
                [void]$results.Add((
                        New-DomainBlockEntry -Domain $rule.Domain -Method Firewall -Status $status -Target $rule.IPAddress -Detail $rule.RuleName
                    ))
            }
        } catch {
            Write-Verbose "Firewall rules could not be read: $($_.Exception.Message)"
        }
    }

    if ($Name) {
        $results = @(
            $results | Where-Object {
                $domain = $_.Domain
                foreach ($pattern in $Name) {
                    if ($domain -like $pattern) {
                        return $true
                    }
                }
                return $false
            }
        )
    }

    $results | Sort-Object Method, Domain, Target
}
