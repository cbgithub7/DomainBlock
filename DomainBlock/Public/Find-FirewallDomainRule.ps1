function Find-FirewallDomainRule {
    <#
    .SYNOPSIS
        Finds firewall rules whose remote addresses include a domain's IPs.

    .DESCRIPTION
        Resolves the domain, then checks enabled firewall rules for an exact IP,
        CIDR, or range match. Unlike Get-BlockedDomain, this searches all rules
        (not only toolkit-managed ones). Substring matching is not used.

    .PARAMETER Name
        Domain name to search for.

    .PARAMETER Direction
        Limit to Inbound, Outbound, or Both. Default is Outbound.

    .PARAMETER Action
        Limit to Block, Allow, or All. Default is Block.

    .PARAMETER IncludeDisabled
        Include disabled rules.

    .PARAMETER IncludeAny
        Treat RemoteAddress Any as a match. Default is on.

    .PARAMETER IPv4Only
        Resolve and match IPv4 only.

    .EXAMPLE
        Find-FirewallDomainRule -Name example.com

        Lists enabled outbound block rules that cover example.com's addresses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Domain', 'HostName')]
        [string]$Name,

        [ValidateSet('Outbound', 'Inbound', 'Both')]
        [string]$Direction = 'Outbound',

        [ValidateSet('Block', 'Allow', 'All')]
        [string]$Action = 'Block',

        [switch]$IncludeDisabled,

        [switch]$SkipAny,

        [switch]$IPv4Only
    )

    begin {
        Assert-NetSecurityModule
    }

    process {
        $normalized = $null
        try {
            $normalized = ConvertTo-NormalizedDomainName -Name $Name
        } catch {
            Write-Error $_
            return
        }

        $family = if ($IPv4Only) { 'IPv4' } else { 'All' }
        $addresses = @(Get-DomainIPAddress -Name $normalized -AddressFamily $family -ErrorAction Stop)
        if ($addresses.Count -eq 0) {
            Write-Error "Could not resolve $normalized to an IP address."
            return
        }

        $ruleParams = @{ ErrorAction = 'Stop' }
        if ($Action -ne 'All') {
            $ruleParams['Action'] = $Action
        }
        if (-not $IncludeDisabled) {
            $ruleParams['Enabled'] = 'True'
        }

        $rules = @(Get-NetFirewallRule @ruleParams)
        $directions = @(Get-FirewallDirectionList -Direction $Direction)
        $rules = @($rules | Where-Object { $directions -contains [string]$_.Direction })

        $index = 0
        $total = $rules.Count
        foreach ($rule in $rules) {
            $index++
            if ($total -gt 20) {
                Write-Progress -Activity 'Searching firewall rules' -Status $rule.DisplayName -PercentComplete (($index / $total) * 100)
            }

            $filter = $null
            try {
                $filter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
            } catch {
                Write-Verbose "Could not read address filter for $($rule.DisplayName): $($_.Exception.Message)"
                continue
            }

            foreach ($address in $addresses) {
                $match = Test-IPAddressInFirewallRemoteAddress -IPAddress $address.IPAddress -RemoteAddress $filter.RemoteAddress
                if (-not $match.Matches) {
                    continue
                }
                if ($match.MatchedBy -eq 'Any' -and $SkipAny) {
                    continue
                }

                [PSCustomObject]@{
                    PSTypeName    = 'DomainBlock.FirewallMatch'
                    Domain        = $normalized
                    IPAddress     = $address.IPAddress
                    RuleName      = $rule.Name
                    DisplayName   = $rule.DisplayName
                    Direction     = [string]$rule.Direction
                    Action        = [string]$rule.Action
                    Enabled       = $rule.Enabled
                    Profile       = [string]$rule.Profile
                    RemoteAddress = $match.Spec
                    MatchedBy     = $match.MatchedBy
                }
            }
        }

        if ($total -gt 20) {
            Write-Progress -Activity 'Searching firewall rules' -Completed
        }
    }
}
