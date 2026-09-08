#Requires -Version 5.1
<#
.SYNOPSIS
    Runs ping, DNS lookup, and traceroute for a host.

.DESCRIPTION
    Collects ICMP echo results, DNS records, and an optional traceroute into a
    single object. Traceroute uses tracert.exe. DNS failures do not skip ping.

.PARAMETER ComputerName
    Hostname or IP address to test.

.PARAMETER PingCount
    ICMP echo count. Default 4.

.PARAMETER MaxHops
    Traceroute hop limit. Default 30.

.PARAMETER SkipTraceRoute
    Do not run traceroute.

.EXAMPLE
    .\Invoke-NetworkDiagnostics.ps1 -ComputerName example.com

    Pings example.com, resolves DNS, and traces the route.

.EXAMPLE
    .\Invoke-NetworkDiagnostics.ps1 -ComputerName 1.1.1.1 -SkipTraceRoute
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [Alias('TargetHost', 'HostToTest', 'Name')]
    [string]$ComputerName,

    [ValidateRange(1, 20)]
    [int]$PingCount = 4,

    [ValidateRange(1, 255)]
    [int]$MaxHops = 30,

    [switch]$SkipTraceRoute
)

$ErrorActionPreference = 'Continue'

function Get-PingStatistic {
    param(
        [string]$Target,
        [int]$Count
    )

    $replies = @(Test-Connection -ComputerName $Target -Count $Count -ErrorAction SilentlyContinue)
    $times = New-Object System.Collections.Generic.List[int]
    foreach ($reply in $replies) {
        $value = $null
        $responseTime = $reply.PSObject.Properties['ResponseTime']
        $latency = $reply.PSObject.Properties['Latency']
        if ($null -ne $responseTime -and $null -ne $responseTime.Value) {
            $value = [int]$responseTime.Value
        } elseif ($null -ne $latency -and $null -ne $latency.Value) {
            if ($latency.Value -is [TimeSpan]) {
                $value = [int]$latency.Value.TotalMilliseconds
            } else {
                $value = [int]$latency.Value
            }
        }
        if ($null -ne $value) {
            [void]$times.Add($value)
        }
    }

    $lost = [Math]::Max(0, $Count - $times.Count)
    $average = $null
    if ($times.Count -gt 0) {
        $average = [Math]::Round((($times | Measure-Object -Average).Average), 2)
    }

    [PSCustomObject]@{
        Succeeded    = ($times.Count -gt 0)
        Sent         = $Count
        Received     = $times.Count
        Lost         = $lost
        LossPercent  = [Math]::Round(($lost / $Count) * 100, 1)
        AverageMs    = $average
        ResponseMs   = $times.ToArray()
    }
}

function Get-DnsRecordSet {
    param([string]$Target)

    try {
        $records = @(Resolve-DnsName -Name $Target -ErrorAction Stop)
        return [PSCustomObject]@{
            Succeeded = $true
            Records   = $records
            Error     = $null
        }
    } catch {
        return [PSCustomObject]@{
            Succeeded = $false
            Records   = @()
            Error     = $_.Exception.Message
        }
    }
}

function Get-TraceRouteHop {
    param(
        [string]$Target,
        [int]$Hops
    )

    $tracert = Join-Path $env:SystemRoot 'System32\tracert.exe'
    if (-not (Test-Path -LiteralPath $tracert)) {
        return [PSCustomObject]@{
            Succeeded = $false
            Output    = @()
            Error     = 'tracert.exe was not found.'
        }
    }

    try {
        $output = & $tracert -d -h $Hops $Target 2>&1 | ForEach-Object { [string]$_ }
        return [PSCustomObject]@{
            Succeeded = $true
            Output    = @($output)
            Error     = $null
        }
    } catch {
        return [PSCustomObject]@{
            Succeeded = $false
            Output    = @()
            Error     = $_.Exception.Message
        }
    }
}

$ping = Get-PingStatistic -Target $ComputerName -Count $PingCount
$dns = Get-DnsRecordSet -Target $ComputerName
$trace = $null
if (-not $SkipTraceRoute) {
    $trace = Get-TraceRouteHop -Target $ComputerName -Hops $MaxHops
}

[PSCustomObject]@{
    ComputerName     = $ComputerName
    PingSucceeded    = $ping.Succeeded
    PingSent         = $ping.Sent
    PingReceived     = $ping.Received
    PingLostPercent  = $ping.LossPercent
    PingAverageMs    = $ping.AverageMs
    PingResponseMs   = $ping.ResponseMs
    DnsSucceeded     = $dns.Succeeded
    DnsError         = $dns.Error
    DnsRecords       = $dns.Records
    TraceRouteRan    = (-not $SkipTraceRoute)
    TraceRouteOutput = $(if ($trace) { $trace.Output } else { @() })
    TraceRouteError  = $(if ($trace) { $trace.Error } else { $null })
}
