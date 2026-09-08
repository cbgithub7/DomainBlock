#Requires -Version 5.1
<#
.SYNOPSIS
    Lists neighbor IP and MAC entries from the local ARP/neighbor cache.

.DESCRIPTION
    Prefers Get-NetNeighbor, with a parsed arp.exe fallback. Local adapter
    addresses, loopback, and incomplete entries are omitted unless
    -IncludeLocal is specified. Multicast/broadcast rows are omitted unless
    -IncludeMulticast is specified.

    -VendorLookup queries api.macvendors.com (one request per second on the
    free tier) and sends MAC addresses to that public API.

.PARAMETER VendorLookup
    Look up unicast MAC vendors via api.macvendors.com.

.PARAMETER IncludeMulticast
    Include multicast and broadcast MAC addresses.

.PARAMETER IncludeLocal
    Include this computer's own adapter addresses.

.PARAMETER VendorDelayMs
    Delay between vendor API calls. Default 1000.

.EXAMPLE
    .\Get-DeviceMacInfo.ps1

    Lists unicast neighbors on the local links.

.EXAMPLE
    .\Get-DeviceMacInfo.ps1 -VendorLookup

    Adds a Vendor column using macvendors.com.

.NOTES
    Former name: Get-DeviceMACInfo.ps1
#>
[CmdletBinding()]
param(
    [switch]$VendorLookup,

    [switch]$IncludeMulticast,

    [switch]$IncludeLocal,

    [ValidateRange(0, 60000)]
    [int]$VendorDelayMs = 1000
)

$ErrorActionPreference = 'Stop'

function Get-MacAddressType {
    param([string]$MacAddress)

    $normalized = ($MacAddress -replace '[^0-9a-fA-F]', '').ToLowerInvariant()
    if ($normalized.Length -lt 2) {
        return 'Invalid'
    }
    if ($normalized -eq 'ffffffffffff') {
        return 'Broadcast'
    }

    try {
        $firstByte = [Convert]::ToByte($normalized.Substring(0, 2), 16)
        if (($firstByte -band 1) -eq 1) {
            return 'Multicast'
        }
    } catch {
        return 'Invalid'
    }
    return 'Unicast'
}

function ConvertTo-MacDashed {
    param([string]$MacAddress)

    $hex = ($MacAddress -replace '[^0-9a-fA-F]', '').ToLowerInvariant()
    if ($hex.Length -ne 12) {
        return $MacAddress
    }
    $parts = for ($i = 0; $i -lt 12; $i += 2) {
        $hex.Substring($i, 2)
    }
    return ($parts -join '-')
}

function Get-NeighborFromNetNeighbor {
    $rows = Get-NetNeighbor -ErrorAction Stop | Where-Object {
        $_.LinkLayerAddress -and
        $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
        $_.State -ne 'Incomplete'
    }

    foreach ($row in $rows) {
        [PSCustomObject]@{
            IPAddress      = $row.IPAddress
            MacAddress     = ConvertTo-MacDashed -MacAddress $row.LinkLayerAddress
            State          = [string]$row.State
            InterfaceAlias = $row.InterfaceAlias
            Source         = 'Get-NetNeighbor'
        }
    }
}

function Get-NeighborFromArp {
    $output = & arp.exe -a 2>$null
    foreach ($line in $output) {
        if ($line -match '^\s*Interface:') {
            continue
        }
        if ($line -match '^\s*Internet Address') {
            continue
        }
        if ($line -match '^\s*(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>[0-9a-fA-F\-:]{11,17})\s+(?<type>\w+)') {
            [PSCustomObject]@{
                IPAddress      = $Matches['ip']
                MacAddress     = ConvertTo-MacDashed -MacAddress $Matches['mac']
                State          = $Matches['type']
                InterfaceAlias = $null
                Source         = 'arp.exe'
            }
        }
    }
}

function Test-IsOwnAddress {
    param(
        [string]$IPAddress,
        [string[]]$OwnAddresses
    )
    return $OwnAddresses -contains $IPAddress
}

function Test-IsLoopbackIP {
    param([string]$IPAddress)
    return $IPAddress -match '^127\.' -or $IPAddress -eq '::1'
}

function Get-MacVendor {
    param(
        [string]$MacAddress,
        [int]$DelayMs
    )

    $hex = ($MacAddress -replace '[^0-9a-fA-F]', '')
    if ($hex.Length -lt 6) {
        return $null
    }
    $colon = ($hex -replace '(.{2})', '$1:').TrimEnd(':')
    $uri = "https://api.macvendors.com/$colon"

    $attempt = 0
    while ($attempt -lt 2) {
        $attempt++
        try {
            $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 15 -ErrorAction Stop
            if ($DelayMs -gt 0) {
                Start-Sleep -Milliseconds $DelayMs
            }
            return [string]$response
        } catch {
            $status = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $status = [int]$_.Exception.Response.StatusCode
            }
            if ($status -eq 404) {
                if ($DelayMs -gt 0) {
                    Start-Sleep -Milliseconds $DelayMs
                }
                return $null
            }
            if ($status -eq 429 -and $attempt -lt 2) {
                Start-Sleep -Seconds 2
                continue
            }
            Write-Warning "Vendor lookup failed for $MacAddress : $($_.Exception.Message)"
            return $null
        }
    }
    return $null
}

$own = @('127.0.0.1', '::1')
try {
    $own += @(Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
} catch {
    Write-Verbose 'Get-NetIPAddress is unavailable; own-address filter is limited to loopback.'
}

$neighbors = @()
try {
    $neighbors = @(Get-NeighborFromNetNeighbor)
} catch {
    Write-Verbose "Get-NetNeighbor failed, using arp.exe: $($_.Exception.Message)"
    $neighbors = @(Get-NeighborFromArp)
}

$results = New-Object System.Collections.Generic.List[object]
foreach ($item in $neighbors) {
    if (Test-IsLoopbackIP -IPAddress $item.IPAddress) {
        continue
    }
    if (-not $IncludeLocal -and (Test-IsOwnAddress -IPAddress $item.IPAddress -OwnAddresses $own)) {
        continue
    }

    $macType = Get-MacAddressType -MacAddress $item.MacAddress
    if ($macType -eq 'Invalid') {
        continue
    }
    if (-not $IncludeMulticast -and $macType -ne 'Unicast') {
        continue
    }

    $vendor = $null
    if ($VendorLookup -and $macType -eq 'Unicast') {
        $vendor = Get-MacVendor -MacAddress $item.MacAddress -DelayMs $VendorDelayMs
    }

    [void]$results.Add([PSCustomObject]@{
            IPAddress      = $item.IPAddress
            MacAddress     = $item.MacAddress
            MacAddressType = $macType
            State          = $item.State
            InterfaceAlias = $item.InterfaceAlias
            Vendor         = $vendor
            Source         = $item.Source
        })
}

$results | Sort-Object IPAddress
