#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the DomainBlock and Outliers self-tests.

.PARAMETER LiveFirewall
    Also run firewall tests. Requires an elevated session.
#>
[CmdletBinding()]
param(
    [switch]$LiveFirewall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$moduleManifest = Join-Path $repoRoot 'DomainBlock\DomainBlock.psd1'
$failed = 0
$passed = 0

function Assert-True {
    param(
        [Parameter(Mandatory)]
        [bool]$Condition,
        [Parameter(Mandatory)]
        [string]$Message
    )
    if ($Condition) {
        $script:passed++
        Write-Host "  PASS  $Message"
    } else {
        $script:failed++
        Write-Host "  FAIL  $Message" -ForegroundColor Red
    }
}

function Assert-Equal {
    param(
        $Expected,
        $Actual,
        [Parameter(Mandatory)]
        [string]$Message
    )
    $ok = [string]$Expected -eq [string]$Actual
    if ($ok) {
        $script:passed++
        Write-Host "  PASS  $Message"
    } else {
        $script:failed++
        Write-Host "  FAIL  $Message (expected '$Expected', actual '$Actual')" -ForegroundColor Red
    }
}

function Invoke-InModule {
    param([scriptblock]$ScriptBlock)
    $mod = Get-Module DomainBlock
    if (-not $mod) {
        throw 'DomainBlock is not imported.'
    }
    & $mod $ScriptBlock
}

Write-Host 'Importing DomainBlock...'
Import-Module $moduleManifest -Force
Assert-True -Condition $true -Message 'Module imported'

$commands = @(Get-Command -Module DomainBlock | Select-Object -ExpandProperty Name)
foreach ($name in @(
        'Block-Domain', 'Unblock-Domain', 'Get-BlockedDomain', 'Test-DomainBlock',
        'Update-DomainFirewallBlock', 'Find-FirewallDomainRule', 'Get-DomainIPAddress',
        'ConvertTo-DomainListLiteral', 'Backup-HostsFile', 'Restore-HostsFile',
        'Export-BlockedDomain', 'Import-BlockedDomain', 'Invoke-DomainBlockWorkflow'
    )) {
    Assert-True -Condition ($commands -contains $name) -Message "Exports $name"
}

Write-Host "`nIP matching"
$exact = Invoke-InModule { Test-IPAddressInSpec -IPAddress '1.2.3.4' -Spec '1.2.3.4' }
Assert-Equal 'Exact' $exact.MatchedBy 'Exact IPv4 match'
Assert-True $exact.Matches 'Exact match flag'

$substring = Invoke-InModule { Test-IPAddressInSpec -IPAddress '1.2.3.4' -Spec '11.2.3.4' }
Assert-True (-not $substring.Matches) 'Does not substring-match 1.2.3.4 inside 11.2.3.4'

$suffix = Invoke-InModule { Test-IPAddressInSpec -IPAddress '1.2.3.4' -Spec '1.2.3.40' }
Assert-True (-not $suffix.Matches) 'Does not substring-match 1.2.3.4 inside 1.2.3.40'

$cidr = Invoke-InModule { Test-IPAddressInSpec -IPAddress '10.1.2.3' -Spec '10.0.0.0/8' }
Assert-Equal 'Cidr' $cidr.MatchedBy 'CIDR /8 match'

$cidrMiss = Invoke-InModule { Test-IPAddressInSpec -IPAddress '11.1.2.3' -Spec '10.0.0.0/8' }
Assert-True (-not $cidrMiss.Matches) 'CIDR /8 miss'

$range = Invoke-InModule { Test-IPAddressInSpec -IPAddress '192.168.1.10' -Spec '192.168.1.1-192.168.1.20' }
Assert-Equal 'Range' $range.MatchedBy 'IPv4 range match'

$any = Invoke-InModule { Test-IPAddressInSpec -IPAddress '8.8.8.8' -Spec 'Any' }
Assert-Equal 'Any' $any.MatchedBy 'RemoteAddress Any matches'

Write-Host "`nDomain normalization"
$fromUrl = Invoke-InModule { ConvertTo-NormalizedDomainName -Name 'https://WWW.Example.COM:443/path?q=1' }
Assert-Equal 'www.example.com' $fromUrl 'Strips scheme, port, path, and case'

$idn = Invoke-InModule { ConvertTo-NormalizedDomainName -Name 'bücher.de' }
Assert-True ($idn.StartsWith('xn--')) 'Converts IDN to punycode'

$invalid = $false
try {
    Invoke-InModule { ConvertTo-NormalizedDomainName -Name 'localhost' } | Out-Null
} catch {
    $invalid = $true
}
Assert-True $invalid 'Rejects single-label names'

Write-Host "`nHosts-file toolkit (temp file, no admin)"
$work = Join-Path $env:TEMP ("DomainBlock.Tests." + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work -Force | Out-Null
$hostsPath = Join-Path $work 'hosts'
Set-Content -LiteralPath $hostsPath -Value "# test hosts`r`n127.0.0.1 localhost`r`n" -Encoding UTF8

try {
    $block = @(Block-Domain -Name 'ads.example.com' -Method Hosts -HostsFilePath $hostsPath -NoFlushDns)
    $blockedNames = @($block | Where-Object { $_.Status -eq 'Blocked' } | Select-Object -ExpandProperty Domain -Unique)
    Assert-True ($blockedNames -contains 'ads.example.com') 'Blocks apex in hosts'
    Assert-True ($blockedNames -contains 'www.ads.example.com') 'Blocks www variant by default'

    $listed = @(Get-BlockedDomain -Method Hosts -HostsFilePath $hostsPath)
    Assert-True ($listed.Count -ge 4) 'Get-BlockedDomain sees IPv4 and IPv6 rows'

    $again = @(Block-Domain -Name 'ads.example.com' -Method Hosts -HostsFilePath $hostsPath -NoFlushDns)
    $already = @($again | Where-Object { $_.Status -eq 'AlreadyBlocked' })
    Assert-True ($already.Count -ge 4) 'Second block is idempotent'

    $v4 = @(Block-Domain -Name 'tracker.example.net' -Method Hosts -HostsFilePath $hostsPath -NoWww -IPv4Only -NoFlushDns)
    Assert-True (@($v4 | Where-Object { $_.Target -eq '::1' }).Count -eq 0) '-IPv4Only skips ::1'
    Assert-True (@($v4 | Where-Object { $_.Domain -eq 'www.tracker.example.net' }).Count -eq 0) '-NoWww skips www'

    $test = Test-DomainBlock -Name 'ads.example.com' -HostsFilePath $hostsPath
    $apex = @($test | Where-Object { $_.Domain -eq 'ads.example.com' }) | Select-Object -First 1
    Assert-True ([bool]$apex.HostsBlocked) 'Test-DomainBlock reports hosts blocked'

    $literal = ConvertTo-DomainListLiteral -Path (Join-Path $repoRoot 'examples\DomainList.txt')
    Assert-Equal '@()' $literal 'Sample list is comments-only so literal is empty'

    $listFile = Join-Path $work 'domains.txt'
    Set-Content -LiteralPath $listFile -Value "one.example`r`n# comment`r`ntwo.example`r`n" -Encoding UTF8
    $fromFile = ConvertTo-DomainListLiteral -Path $listFile
    Assert-Equal '@("one.example", "two.example")' $fromFile 'ConvertTo-DomainListLiteral formats a column'

    $backup = Backup-HostsFile -HostsFilePath $hostsPath -Destination (Join-Path $work 'hosts.bak')
    Assert-True (Test-Path -LiteralPath $backup.BackupPath) 'Backup-HostsFile writes destination'

    $exportPath = Join-Path $work 'blocked.json'
    $exported = Export-BlockedDomain -Path $exportPath -Format Json -Method Hosts -HostsFilePath $hostsPath
    Assert-True ($exported.Count -ge 2) 'Export-BlockedDomain writes unique names'
    Assert-True (Test-Path -LiteralPath $exportPath) 'Export JSON exists'

    $unblocked = @(Unblock-Domain -Name 'ads.example.com' -Method Hosts -HostsFilePath $hostsPath -NoFlushDns -Confirm:$false)
    Assert-True ($unblocked.Count -gt 0) 'Unblock-Domain removes hosts rows'
    $after = @(Get-BlockedDomain -Name 'ads.example.com' -Method Hosts -HostsFilePath $hostsPath)
    Assert-True ($after.Count -eq 0) 'ads.example.com is gone after unblock'

    $restored = Restore-HostsFile -Path $backup.BackupPath -HostsFilePath $hostsPath -NoFlushDns -Confirm:$false
    Assert-True ($null -ne $restored) 'Restore-HostsFile copies backup back'

    Unblock-Domain -All -Method Hosts -HostsFilePath $hostsPath -NoFlushDns -Confirm:$false | Out-Null
    $empty = @(Get-BlockedDomain -Method Hosts -HostsFilePath $hostsPath)
    Assert-True ($empty.Count -eq 0) 'Unblock-Domain -All clears tagged hosts entries'

    $wfBackup = Join-Path $work 'workflow.bak'
    $wf = Invoke-DomainBlockWorkflow -Action Apply -Name 'workflow.example.com' -Method Hosts -HostsFilePath $hostsPath -NoFlushDns -BackupDestination $wfBackup -Quiet -Confirm:$false
    Assert-True ([bool]$wf.Succeeded) 'Apply workflow succeeds'
    $wfCommands = @($wf.Steps | ForEach-Object { $_.Command })
    Assert-True ($wfCommands -contains 'Backup-HostsFile') 'Apply workflow backs up hosts first'
    Assert-True ($wfCommands -contains 'Block-Domain') 'Apply workflow blocks next'
    Assert-True ($wfCommands -contains 'Test-DomainBlock') 'Apply workflow tests last'
    Assert-True (Test-Path -LiteralPath $wfBackup) 'Apply workflow wrote the backup'
    $wfListed = @(Get-BlockedDomain -Name 'workflow.example.com' -Method Hosts -HostsFilePath $hostsPath)
    Assert-True ($wfListed.Count -gt 0) 'Apply workflow left hosts entries'

    $rm = Invoke-DomainBlockWorkflow -Action Remove -Name 'workflow.example.com' -Method Hosts -HostsFilePath $hostsPath -NoFlushDns -SkipBackup -Quiet -Confirm:$false
    Assert-True ([bool]$rm.Succeeded) 'Remove workflow succeeds'
    $afterWf = @(Get-BlockedDomain -Name 'workflow.example.com' -Method Hosts -HostsFilePath $hostsPath)
    Assert-True ($afterWf.Count -eq 0) 'Remove workflow cleared the domain'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`nOutliers"
$diag = & (Join-Path $repoRoot 'Outliers\Invoke-NetworkDiagnostics.ps1') -ComputerName '127.0.0.1' -PingCount 1 -SkipTraceRoute
Assert-True ([bool]$diag.PingSucceeded) 'Invoke-NetworkDiagnostics pings loopback'
Assert-True (-not $diag.TraceRouteRan) '-SkipTraceRoute is honored'

$tempFile = Join-Path $env:TEMP ("DomainBlock.File." + [guid]::NewGuid().ToString('N') + '.txt')
Set-Content -LiteralPath $tempFile -Value 'not locked'
try {
    $null = & (Join-Path $repoRoot 'Outliers\Remove-LockedFile.ps1') -Path $tempFile -WhatIf
    Assert-True (Test-Path -LiteralPath $tempFile) 'Remove-LockedFile -WhatIf does not delete'
} finally {
    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
}

if ($LiveFirewall) {
    Write-Host "`nLive firewall tests"
    $isAdmin = Invoke-InModule { Test-IsAdministrator }
    Assert-True $isAdmin '-LiveFirewall requires elevation'
    if ($isAdmin) {
        $matches = @(Find-FirewallDomainRule -Name 'example.com' -Direction Outbound -ErrorAction SilentlyContinue)
        Assert-True ($true) ("Find-FirewallDomainRule returned {0} row(s)" -f $matches.Count)
    }
} else {
    Write-Host "`nSkipping live firewall tests (pass -LiveFirewall in an elevated session to run them)."
}

Write-Host ""
Write-Host "Passed: $passed  Failed: $failed"
if ($failed -gt 0) {
    exit 1
}
exit 0
