function Test-DomainBlock {
    <#
    .SYNOPSIS
        Reports whether a domain is blocked by hosts file and/or firewall rules.

    .DESCRIPTION
        Combines toolkit-managed state with a live DNS lookup. If the hosts file
        is in effect, the name typically resolves to 127.0.0.1 or ::1 on this
        machine.

    .PARAMETER Name
        Domain names to test.

    .PARAMETER NoWww
        Do not also test the www. variant.

    .PARAMETER IncludeUnmanaged
        Count untagged loopback hosts entries as blocked.

    .PARAMETER HostsFilePath
        Hosts file to read. Defaults to the system hosts file.

    .EXAMPLE
        Test-DomainBlock -Name ads.example.com

        Shows hosts, firewall, and loopback-resolution status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [switch]$NoWww,

        [switch]$IncludeUnmanaged,

        [string]$HostsFilePath
    )

    begin {
        if (-not $HostsFilePath) {
            $HostsFilePath = Get-DefaultHostsFilePath
        }
        $hostsEntries = @(Get-HostsFileDomainBlock -Path $HostsFilePath -IncludeUnmanaged:$IncludeUnmanaged | Where-Object { $_ })
        $fwRules = @()
        try {
            Assert-NetSecurityModule
            $fwRules = @(Get-DomainBlockFirewallRule | Where-Object { $_ })
        } catch {
            Write-Verbose "Firewall rules could not be read: $($_.Exception.Message)"
        }
    }

    process {
        $domains = @(ConvertTo-UniqueNormalizedDomain -Name $Name)
        foreach ($domain in $domains) {
            $domainName = [string]$domain
            foreach ($variant in @(Get-RelatedDomainName -Name $domainName -NoWww:$NoWww)) {
                $hMatch = @($hostsEntries | Where-Object { $_.Domain -eq $variant })
                $fMatch = @($fwRules | Where-Object { $_.Domain -eq $variant })

                $resolved = @()
                $resolvesLoopback = $false
                try {
                    $resolved = @([Net.Dns]::GetHostAddresses($variant) | ForEach-Object { $_.ToString() })
                    foreach ($ip in $resolved) {
                        if (Test-IsLoopbackAddress -IPAddress $ip) {
                            $resolvesLoopback = $true
                            break
                        }
                    }
                } catch {
                    Write-Verbose "DNS lookup failed for $variant : $($_.Exception.Message)"
                }

                [PSCustomObject]@{
                    PSTypeName         = 'DomainBlock.TestResult'
                    Domain             = $variant
                    HostsBlocked       = ($hMatch.Count -gt 0)
                    FirewallBlocked    = ($fMatch.Count -gt 0)
                    HostsEntryCount    = $hMatch.Count
                    FirewallRuleCount  = $fMatch.Count
                    ResolvesToLoopback = $resolvesLoopback
                    ResolvedAddress    = ($resolved -join ', ')
                    IsBlocked          = ($hMatch.Count -gt 0) -or ($fMatch.Count -gt 0)
                }
            }
        }
    }
}
