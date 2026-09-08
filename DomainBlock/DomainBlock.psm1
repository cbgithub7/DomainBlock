$script:ModuleName = 'DomainBlock'
$script:FirewallGroup = 'DomainBlock'
$script:DescriptionMarker = 'ManagedBy=DomainBlock'
$script:HostsCommentTag = 'DomainBlock'
$script:RuleNamePrefix = 'DomainBlock'
$script:LoopbackIPv4 = '127.0.0.1'
$script:LoopbackIPv6 = '::1'
$script:UnspecifiedIPv4 = '0.0.0.0'

$privateDir = Join-Path $PSScriptRoot 'Private'
$publicDir = Join-Path $PSScriptRoot 'Public'

Get-ChildItem -Path $privateDir -Filter '*.ps1' -ErrorAction Stop |
    ForEach-Object { . $_.FullName }

Get-ChildItem -Path $publicDir -Filter '*.ps1' -ErrorAction Stop |
    ForEach-Object { . $_.FullName }

New-Alias -Name Search-FirewallDomainRule -Value Find-FirewallDomainRule -Force

$displaySets = @{
    'DomainBlock.Entry'          = 'Domain', 'Method', 'Status', 'Target', 'Detail'
    'DomainBlock.TestResult'     = 'Domain', 'IsBlocked', 'HostsBlocked', 'FirewallBlocked', 'ResolvesToLoopback'
    'DomainBlock.IPAddress'      = 'Domain', 'IPAddress', 'AddressFamily'
    'DomainBlock.FirewallMatch'  = 'Domain', 'IPAddress', 'DisplayName', 'Direction', 'Action', 'MatchedBy'
    'DomainBlock.HostsBackup'    = 'SourcePath', 'BackupPath', 'Created'
    'DomainBlock.WorkflowResult' = 'Action', 'Succeeded', 'Method', 'BackupPath'
    'DomainBlock.WorkflowStep'   = 'Index', 'Command', 'Status', 'Detail'
}

foreach ($typeName in $displaySets.Keys) {
    $params = @{
        TypeName                  = $typeName
        DefaultDisplayPropertySet = $displaySets[$typeName]
        ErrorAction               = 'SilentlyContinue'
        Force                     = $true
    }
    Update-TypeData @params
}

Export-ModuleMember -Function @(
    'Backup-HostsFile',
    'Block-Domain',
    'ConvertTo-DomainListLiteral',
    'Export-BlockedDomain',
    'Find-FirewallDomainRule',
    'Get-BlockedDomain',
    'Get-DomainIPAddress',
    'Import-BlockedDomain',
    'Invoke-DomainBlockWorkflow',
    'Restore-HostsFile',
    'Test-DomainBlock',
    'Unblock-Domain',
    'Update-DomainFirewallBlock'
) -Alias 'Search-FirewallDomainRule'
