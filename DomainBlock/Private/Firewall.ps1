function Get-DomainBlockFirewallRule {
    param(
        [string]$Domain
    )

    Assert-NetSecurityModule

    $rules = @{}
    $namePattern = "$($script:RuleNamePrefix)|*"
    foreach ($rule in @(Get-NetFirewallRule -Name $namePattern -ErrorAction SilentlyContinue)) {
        $rules[$rule.Name] = $rule
    }

    foreach ($rule in @(Get-NetFirewallRule -DisplayGroup $script:FirewallGroup -ErrorAction SilentlyContinue)) {
        $rules[$rule.Name] = $rule
    }

    if ($rules.Count -eq 0) {
        foreach ($rule in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
            if (
                $rule.Group -eq $script:FirewallGroup -or
                $rule.DisplayGroup -eq $script:FirewallGroup -or
                ($rule.Description -like "$($script:DescriptionMarker)*")
            ) {
                $rules[$rule.Name] = $rule
            }
        }
    }

    $normalized = $null
    if ($Domain) {
        $normalized = ConvertTo-NormalizedDomainName -Name $Domain
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $rules.Values) {
        $meta = ConvertFrom-FirewallRuleDescription -Description $rule.Description
        if ($normalized -and $meta -and $meta.Domain -ne $normalized) {
            continue
        }
        if ($normalized -and -not $meta) {
            continue
        }

        [void]$results.Add([PSCustomObject]@{
                Domain      = $(if ($meta) { $meta.Domain } else { $null })
                IPAddress   = $(if ($meta) { $meta.IP } else { $null })
                Direction   = $(if ($meta) { $meta.Direction } else { [string]$rule.Direction })
                RuleName    = $rule.Name
                DisplayName = $rule.DisplayName
                Enabled     = $rule.Enabled
                Action      = $rule.Action
                Description = $rule.Description
                Rule        = $rule
            })
    }

    foreach ($item in $results) {
        $item
    }
}

function New-DomainBlockFirewallRule {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [Parameter(Mandatory)]
        [ValidateSet('Outbound', 'Inbound')]
        [string]$Direction
    )

    Assert-NetSecurityModule

    $canonicalIP = ConvertTo-CanonicalIPAddress -IPAddress $IPAddress
    $ruleName = Get-DomainFirewallRuleName -Domain $Domain -IPAddress $canonicalIP -Direction $Direction
    $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        return New-DomainBlockEntry -Domain $Domain -Method Firewall -Status AlreadyBlocked -Target $canonicalIP -Detail $ruleName
    }

    $params = @{
        Name          = $ruleName
        DisplayName   = (Get-DomainFirewallDisplayName -Domain $Domain -IPAddress $canonicalIP -Direction $Direction)
        Group         = $script:FirewallGroup
        Description   = (ConvertTo-FirewallRuleDescription -Domain $Domain -IPAddress $canonicalIP -Direction $Direction)
        Direction     = $Direction
        Action        = 'Block'
        RemoteAddress = $canonicalIP
        Profile       = 'Any'
        Enabled       = $true
        ErrorAction   = 'Stop'
    }

    try {
        New-NetFirewallRule @params | Out-Null
    } catch {
        $withoutGroup = $params.Clone()
        $withoutGroup.Remove('Group')
        try {
            New-NetFirewallRule @withoutGroup | Out-Null
        } catch {
            throw "Failed to create firewall rule for $Domain ($canonicalIP): $($_.Exception.Message)"
        }
    }

    return New-DomainBlockEntry -Domain $Domain -Method Firewall -Status Blocked -Target $canonicalIP -Detail $ruleName
}

function Remove-DomainBlockFirewallRule {
    param(
        [string]$Domain,
        [switch]$All
    )

    $rules = @(Get-DomainBlockFirewallRule -Domain $(if ($All) { $null } else { $Domain }) | Where-Object { $_ })
    if (-not $All -and $Domain) {
        $normalized = ConvertTo-NormalizedDomainName -Name $Domain
        $rules = @($rules | Where-Object { $_.Domain -eq $normalized })
    }

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $rules) {
        Remove-NetFirewallRule -Name $rule.RuleName -ErrorAction Stop
        [void]$results.Add((
                New-DomainBlockEntry -Domain $rule.Domain -Method Firewall -Status Unblocked -Target $rule.IPAddress -Detail $rule.RuleName
            ))
    }
    foreach ($item in $results) {
        $item
    }
}
