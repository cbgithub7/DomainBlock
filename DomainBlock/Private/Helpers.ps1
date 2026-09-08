function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw 'This command requires an elevated PowerShell session (Run as administrator).'
    }
}

function Assert-NetSecurityModule {
    if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        Import-Module NetSecurity -ErrorAction Stop
    }
    if (-not (Get-Command -Name Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        throw 'The NetSecurity module is required for firewall operations.'
    }
}

function Get-DefaultHostsFilePath {
    return (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts')
}

function Test-IsSystemHostsFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $default = Get-DefaultHostsFilePath
    try {
        $left = [IO.Path]::GetFullPath($Path)
        $right = [IO.Path]::GetFullPath($default)
        return [string]::Equals($left, $right, [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Get-DefaultHostsBackupDirectory {
    $dir = Join-Path (Join-Path $env:USERPROFILE 'Documents') 'DomainBlock'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function ConvertTo-NormalizedDomainName {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $n = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($n)) {
        throw 'Domain name is empty.'
    }

    $n = $n -replace '^https?://', ''
    $at = $n.LastIndexOf('@')
    if ($at -ge 0) {
        $n = $n.Substring($at + 1)
    }

    $n = ($n -split '[/?#]', 2)[0]
    if ($n.StartsWith('[')) {
        throw "IP addresses are not valid domain names: $Name"
    }

    if ($n -match '^(?<host>.+):(?<port>\d+)$') {
        $n = $Matches['host']
    }

    $n = $n.Trim().TrimEnd('.').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($n)) {
        throw "Invalid domain name: $Name"
    }

    $parsedIP = $null
    if ([Net.IPAddress]::TryParse($n, [ref]$parsedIP)) {
        throw "IP addresses are not valid domain names: $Name"
    }

    try {
        $idn = New-Object System.Globalization.IdnMapping
        $n = $idn.GetAscii($n)
    } catch {
        throw "Invalid domain name: $Name"
    }

    if ($n.Length -gt 253) {
        throw "Domain name is too long: $Name"
    }

    if ($n -notmatch '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$') {
        throw "Invalid domain name: $Name"
    }

    return $n
}

function Get-RelatedDomainName {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [switch]$NoWww
    )

    $normalized = ConvertTo-NormalizedDomainName -Name $Name
    $names = New-Object System.Collections.Generic.List[string]
    [void]$names.Add($normalized)
    if (-not $NoWww -and $normalized -notlike 'www.*') {
        [void]$names.Add("www.$normalized")
    }
    foreach ($item in $names) {
        $item
    }
}

function Read-DomainListFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Domain list file not found: $Path"
    }

    $text = [IO.File]::ReadAllText($Path)
    $trim = $text.Trim()
    if ($trim.StartsWith('{') -or $trim.StartsWith('[')) {
        $json = $trim | ConvertFrom-Json
        if ($null -ne $json.Domains) {
            return @($json.Domains | ForEach-Object { [string]$_ })
        }
        if ($json -is [System.Collections.IEnumerable] -and -not ($json -is [string])) {
            return @($json | ForEach-Object { [string]$_ })
        }
    }

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $item = $line.Trim()
        if ($item -and -not $item.StartsWith('#')) {
            [void]$names.Add($item)
        }
    }
    foreach ($item in $names) {
        $item
    }
}

function ConvertTo-CanonicalIPAddress {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress
    )

    $parsed = $null
    if ([Net.IPAddress]::TryParse($IPAddress, [ref]$parsed)) {
        return $parsed.ToString()
    }
    return $IPAddress
}

function Test-IsLoopbackAddress {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress
    )

    $canonical = ConvertTo-CanonicalIPAddress -IPAddress $IPAddress
    if ($canonical -eq $script:LoopbackIPv4 -or $canonical -eq $script:LoopbackIPv6 -or $canonical -eq $script:UnspecifiedIPv4) {
        return $true
    }

    $parsed = $null
    if ([Net.IPAddress]::TryParse($canonical, [ref]$parsed)) {
        return $parsed.Equals([Net.IPAddress]::Loopback) -or $parsed.Equals([Net.IPAddress]::IPv6Loopback)
    }
    return $false
}

function Get-FirewallDirectionList {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Outbound', 'Inbound', 'Both')]
        [string]$Direction
    )

    if ($Direction -eq 'Both') {
        'Outbound'
        'Inbound'
    } else {
        $Direction
    }
}

function ConvertTo-FirewallRuleDescription {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [Parameter(Mandatory)]
        [string]$Direction
    )

    return ('{0}; Domain={1}; IP={2}; Direction={3}' -f $script:DescriptionMarker, $Domain, $IPAddress, $Direction)
}

function ConvertFrom-FirewallRuleDescription {
    param(
        [string]$Description
    )

    if ([string]::IsNullOrWhiteSpace($Description)) {
        return $null
    }
    if ($Description -notlike "$($script:DescriptionMarker)*") {
        return $null
    }

    $map = @{}
    foreach ($part in $Description.Split(';')) {
        $kv = $part.Trim() -split '=', 2
        if ($kv.Count -eq 2) {
            $map[$kv[0].Trim()] = $kv[1].Trim()
        }
    }

    if (-not $map.ContainsKey('Domain') -or -not $map.ContainsKey('IP')) {
        return $null
    }

    $direction = 'Outbound'
    if ($map.ContainsKey('Direction') -and $map['Direction']) {
        $direction = $map['Direction']
    }

    return [PSCustomObject]@{
        Domain    = $map['Domain']
        IP        = $map['IP']
        Direction = $direction
    }
}

function Get-DomainFirewallRuleName {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [Parameter(Mandatory)]
        [string]$Direction
    )

    $safeIp = $IPAddress -replace ':', '~'
    $name = '{0}|{1}|{2}|{3}' -f $script:RuleNamePrefix, $Domain, $safeIp, $Direction
    if ($name.Length -gt 255) {
        $name = $name.Substring(0, 255)
    }
    return $name
}

function Get-DomainFirewallDisplayName {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [Parameter(Mandatory)]
        [string]$Direction
    )

    return ('DomainBlock: {0} ({1}, {2})' -f $Domain, $IPAddress, $Direction)
}

function New-DomainBlockEntry {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [ValidateSet('Hosts', 'Firewall')]
        [string]$Method,
        [Parameter(Mandatory)]
        [string]$Status,
        [string]$Target = '',
        [string]$Detail = ''
    )

    return [PSCustomObject]@{
        PSTypeName = 'DomainBlock.Entry'
        Domain     = $Domain
        Method     = $Method
        Status     = $Status
        Target     = $Target
        Detail     = $Detail
    }
}

function Clear-DomainBlockDnsCache {
    try {
        if (Get-Command -Name Clear-DnsClientCache -ErrorAction SilentlyContinue) {
            Clear-DnsClientCache -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Verbose "Clear-DnsClientCache failed: $($_.Exception.Message)"
    }

    $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
    if (Test-Path -LiteralPath $ipconfig) {
        try {
            Start-Process -FilePath $ipconfig -ArgumentList '/flushdns' -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        } catch {
            Write-Verbose "ipconfig /flushdns failed: $($_.Exception.Message)"
        }
    }
}

function ConvertTo-UniqueNormalizedDomain {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$Name
    )

    $unique = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($item in $Name) {
        if ([string]::IsNullOrWhiteSpace($item)) {
            continue
        }
        try {
            $normalized = ConvertTo-NormalizedDomainName -Name $item
        } catch {
            Write-Error -Message $_.Exception.Message -TargetObject $item
            continue
        }
        if (-not $seen.ContainsKey($normalized)) {
            $seen[$normalized] = $true
            [void]$unique.Add($normalized)
        }
    }
    foreach ($item in $unique) {
        $item
    }
}
