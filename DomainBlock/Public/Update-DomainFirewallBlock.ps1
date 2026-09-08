function Update-DomainFirewallBlock {
    <#
    .SYNOPSIS
        Refreshes firewall block rules to match current DNS addresses.

    .DESCRIPTION
        Re-resolves each managed domain and adds rules for new IPs. Stale IPs
        are removed only when DNS succeeds. If DNS fails, existing rules are
        kept (fail closed) unless -RemoveIfUnresolved is specified.

    .PARAMETER Name
        Domains to refresh. Omit to refresh every toolkit-managed firewall domain.

    .PARAMETER IPv4Only
        Ignore IPv6 addresses.

    .PARAMETER Direction
        Which rule directions to maintain. Default is Outbound.

    .PARAMETER RemoveIfUnresolved
        Delete existing rules for a domain that no longer resolves.

    .PARAMETER NoWww
        Do not also refresh the www. variant when -Name is used.

    .EXAMPLE
        Update-DomainFirewallBlock

        Syncs every DomainBlock firewall rule with current DNS.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [switch]$IPv4Only,

        [ValidateSet('Outbound', 'Inbound', 'Both')]
        [string]$Direction = 'Outbound',

        [switch]$RemoveIfUnresolved,

        [switch]$NoWww
    )

    begin {
        Assert-Administrator
        Assert-NetSecurityModule
        $pending = New-Object System.Collections.Generic.List[string]
        $family = if ($IPv4Only) { 'IPv4' } else { 'All' }
        $directions = @(Get-FirewallDirectionList -Direction $Direction)
    }

    process {
        foreach ($item in @($Name)) {
            if ($item) {
                [void]$pending.Add($item)
            }
        }
    }

    end {
        $existing = @(Get-DomainBlockFirewallRule | Where-Object { $_ })
        $targets = @()
        if ($pending.Count -gt 0) {
            $normalized = @(ConvertTo-UniqueNormalizedDomain -Name @($pending.ToArray()))
            foreach ($domain in $normalized) {
                $targets += @(Get-RelatedDomainName -Name ([string]$domain) -NoWww:$NoWww)
            }
            $targets = @($targets | Select-Object -Unique)
        } else {
            $targets = @($existing | Where-Object { $_.Domain } | Select-Object -ExpandProperty Domain -Unique)
        }

        if ($targets.Count -eq 0) {
            Write-Verbose 'No DomainBlock firewall rules to update.'
            return
        }

        foreach ($domain in $targets) {
            $currentRules = @($existing | Where-Object { $_.Domain -eq $domain })
            $addresses = @(Get-DomainIPAddress -Name $domain -AddressFamily $family -ErrorAction Continue)
            $usable = @(
                $addresses |
                    Where-Object { -not (Test-IsLoopbackAddress -IPAddress $_.IPAddress) } |
                    Select-Object -ExpandProperty IPAddress -Unique
            )

            if ($usable.Count -eq 0) {
                if ($RemoveIfUnresolved) {
                    if ($PSCmdlet.ShouldProcess($domain, 'Remove firewall rules because DNS did not resolve')) {
                        Remove-DomainBlockFirewallRule -Domain $domain
                    }
                } else {
                    Write-Warning "DNS lookup for $domain failed or returned only loopback; existing firewall rules were kept."
                }
                continue
            }

            $needed = @{}
            foreach ($ip in $usable) {
                foreach ($dir in $directions) {
                    $needed[(Get-DomainFirewallRuleName -Domain $domain -IPAddress $ip -Direction $dir)] = @{
                        IP        = $ip
                        Direction = $dir
                    }
                }
            }

            foreach ($key in $needed.Keys) {
                $item = $needed[$key]
                $already = @($currentRules | Where-Object { $_.RuleName -eq $key -or ($_.IPAddress -eq $item.IP -and $_.Direction -eq $item.Direction) })
                if ($already.Count -gt 0) {
                    New-DomainBlockEntry -Domain $domain -Method Firewall -Status AlreadyBlocked -Target $item.IP -Detail $key
                    continue
                }
                $target = '{0} {1} {2}' -f $domain, $item.IP, $item.Direction
                if ($PSCmdlet.ShouldProcess($target, 'Add firewall block rule for current DNS')) {
                    New-DomainBlockFirewallRule -Domain $domain -IPAddress $item.IP -Direction $item.Direction
                }
            }

            foreach ($rule in $currentRules) {
                $stillNeeded = $false
                foreach ($key in $needed.Keys) {
                    if ($rule.RuleName -eq $key) {
                        $stillNeeded = $true
                        break
                    }
                    $item = $needed[$key]
                    if ($rule.IPAddress -eq $item.IP -and $rule.Direction -eq $item.Direction) {
                        $stillNeeded = $true
                        break
                    }
                }
                if (-not $stillNeeded) {
                    if ($PSCmdlet.ShouldProcess($rule.RuleName, "Remove stale firewall rule for $domain")) {
                        Remove-NetFirewallRule -Name $rule.RuleName -ErrorAction Stop
                        New-DomainBlockEntry -Domain $domain -Method Firewall -Status Unblocked -Target $rule.IPAddress -Detail $rule.RuleName
                    }
                }
            }
        }
    }
}
