function Test-IPAddressInCidr {
    param(
        [Parameter(Mandatory)]
        [Net.IPAddress]$IPAddress,
        [Parameter(Mandatory)]
        [Net.IPAddress]$Network,
        [Parameter(Mandatory)]
        [int]$PrefixLength
    )

    $ipBytes = $IPAddress.GetAddressBytes()
    $netBytes = $Network.GetAddressBytes()
    if ($ipBytes.Length -ne $netBytes.Length) {
        return $false
    }

    $maxBits = $ipBytes.Length * 8
    if ($PrefixLength -lt 0 -or $PrefixLength -gt $maxBits) {
        return $false
    }

    $remaining = $PrefixLength
    for ($i = 0; $i -lt $ipBytes.Length; $i++) {
        if ($remaining -ge 8) {
            if ($ipBytes[$i] -ne $netBytes[$i]) {
                return $false
            }
            $remaining -= 8
        } elseif ($remaining -gt 0) {
            $mask = [byte]((0xFF -shl (8 - $remaining)) -band 0xFF)
            if (($ipBytes[$i] -band $mask) -ne ($netBytes[$i] -band $mask)) {
                return $false
            }
            $remaining = 0
        } else {
            break
        }
    }

    return $true
}

function Convert-IPAddressToUInt32 {
    param(
        [Parameter(Mandatory)]
        [Net.IPAddress]$IPAddress
    )

    if ($IPAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        throw 'Only IPv4 addresses can be converted to UInt32.'
    }

    $bytes = $IPAddress.GetAddressBytes()
    if ([BitConverter]::IsLittleEndian) {
        [Array]::Reverse($bytes)
    }
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Test-IPAddressInRange {
    param(
        [Parameter(Mandatory)]
        [Net.IPAddress]$IPAddress,
        [Parameter(Mandatory)]
        [Net.IPAddress]$Start,
        [Parameter(Mandatory)]
        [Net.IPAddress]$End
    )

    if ($IPAddress.AddressFamily -ne $Start.AddressFamily -or $Start.AddressFamily -ne $End.AddressFamily) {
        return $false
    }

    if ($IPAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        $value = Convert-IPAddressToUInt32 -IPAddress $IPAddress
        $low = Convert-IPAddressToUInt32 -IPAddress $Start
        $high = Convert-IPAddressToUInt32 -IPAddress $End
        if ($low -gt $high) {
            $tmp = $low
            $low = $high
            $high = $tmp
        }
        return ($value -ge $low -and $value -le $high)
    }

    $ipBytes = $IPAddress.GetAddressBytes()
    $startBytes = $Start.GetAddressBytes()
    $endBytes = $End.GetAddressBytes()
    $startCmp = 0
    $endCmp = 0
    for ($i = 0; $i -lt $ipBytes.Length; $i++) {
        if ($startCmp -eq 0) {
            $startCmp = $ipBytes[$i].CompareTo($startBytes[$i])
        }
        if ($endCmp -eq 0) {
            $endCmp = $ipBytes[$i].CompareTo($endBytes[$i])
        }
    }
    return ($startCmp -ge 0 -and $endCmp -le 0)
}

function Test-IPAddressInSpec {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Spec
    )

    if ([string]::IsNullOrWhiteSpace($Spec)) {
        return [PSCustomObject]@{ Matches = $false; MatchedBy = 'None' }
    }

    $specTrim = $Spec.Trim()
    $parsedIP = $null
    if (-not [Net.IPAddress]::TryParse($IPAddress, [ref]$parsedIP)) {
        return [PSCustomObject]@{ Matches = $false; MatchedBy = 'None' }
    }

    $specialAny = @('Any', '*')
    if ($specialAny -contains $specTrim) {
        return [PSCustomObject]@{ Matches = $true; MatchedBy = 'Any' }
    }

    $unevaluated = @(
        'LocalSubnet', 'Internet', 'Intranet', 'DNS', 'DHCP', 'WINS',
        'DefaultGateway', 'PlayToDiscovery', 'CaptivePortal',
        'IPv6Loopback', 'IPv6LocalSubnet', 'IPv6Internet', 'IPv6Intranet'
    )
    if ($unevaluated -contains $specTrim) {
        return [PSCustomObject]@{ Matches = $false; MatchedBy = 'Unevaluated' }
    }

    $parsedSpec = $null
    if ([Net.IPAddress]::TryParse($specTrim, [ref]$parsedSpec)) {
        $matchesExact = $parsedIP.Equals($parsedSpec)
        return [PSCustomObject]@{
            Matches   = $matchesExact
            MatchedBy = $(if ($matchesExact) { 'Exact' } else { 'None' })
        }
    }

    if ($specTrim -match '^(?<net>.+)/(?<prefix>\d+)$') {
        $network = $null
        if (-not [Net.IPAddress]::TryParse($Matches['net'], [ref]$network)) {
            return [PSCustomObject]@{ Matches = $false; MatchedBy = 'None' }
        }
        $prefix = [int]$Matches['prefix']
        $inCidr = Test-IPAddressInCidr -IPAddress $parsedIP -Network $network -PrefixLength $prefix
        return [PSCustomObject]@{
            Matches   = $inCidr
            MatchedBy = $(if ($inCidr) { 'Cidr' } else { 'None' })
        }
    }

    if ($specTrim -match '^(?<start>.+)-(?<end>.+)$') {
        $start = $null
        $end = $null
        if (
            [Net.IPAddress]::TryParse($Matches['start'], [ref]$start) -and
            [Net.IPAddress]::TryParse($Matches['end'], [ref]$end)
        ) {
            $inRange = Test-IPAddressInRange -IPAddress $parsedIP -Start $start -End $end
            return [PSCustomObject]@{
                Matches   = $inRange
                MatchedBy = $(if ($inRange) { 'Range' } else { 'None' })
            }
        }
    }

    return [PSCustomObject]@{ Matches = $false; MatchedBy = 'None' }
}

function Test-IPAddressInFirewallRemoteAddress {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,
        $RemoteAddress
    )

    $specs = @()
    if ($null -eq $RemoteAddress) {
        return [PSCustomObject]@{ Matches = $false; MatchedBy = 'None'; Spec = $null }
    }

    foreach ($item in @($RemoteAddress)) {
        if ($null -eq $item) {
            continue
        }
        $specs += [string]$item
    }

    foreach ($spec in $specs) {
        $result = Test-IPAddressInSpec -IPAddress $IPAddress -Spec $spec
        if ($result.Matches) {
            return [PSCustomObject]@{
                Matches   = $true
                MatchedBy = $result.MatchedBy
                Spec      = $spec
            }
        }
    }

    return [PSCustomObject]@{ Matches = $false; MatchedBy = 'None'; Spec = ($specs -join ', ') }
}
