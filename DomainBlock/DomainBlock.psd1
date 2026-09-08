@{
    RootModule           = 'DomainBlock.psm1'
    ModuleVersion        = '1.0.1'
    GUID                 = '9a29d6ef-eca1-461d-96fd-6284a381f01c'
    Author               = 'Cody'
    CompanyName          = 'cbgithub7'
    Copyright            = '(c) 2024-2026 Cody. MIT License.'
    Description          = 'Windows toolkit for blocking, unblocking, and inspecting domains via the hosts file and Windows Firewall.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
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
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @('Search-FirewallDomainRule')
    PrivateData          = @{
        PSData = @{
            Tags         = @('Windows', 'Firewall', 'Hosts', 'Networking', 'DomainBlock', 'Security')
            LicenseUri   = 'https://opensource.org/licenses/MIT'
            ProjectUri   = 'https://github.com/cbgithub7/DomainBlock'
            ReleaseNotes = 'DomainBlock 1.0.1: public tree is the DomainBlock module only.'
        }
    }
}
