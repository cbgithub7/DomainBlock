function Get-DomainIPAddress {
    <#
    .SYNOPSIS
        Resolves a domain name to its current A and AAAA addresses.

    .DESCRIPTION
        Looks up IP addresses for one or more domain names. Used by the firewall
        blocking commands and available for diagnostics.

    .PARAMETER Name
        Domain name to resolve. Accepts pipeline input and http(s) URLs.

    .PARAMETER AddressFamily
        Limit results to IPv4, IPv6, or both. Default is All.

    .EXAMPLE
        Get-DomainIPAddress -Name example.com

        Resolves example.com to IPv4 and IPv6 addresses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [ValidateSet('All', 'IPv4', 'IPv6')]
        [string]$AddressFamily = 'All'
    )

    process {
        foreach ($item in $Name) {
            try {
                $normalized = ConvertTo-NormalizedDomainName -Name $item
            } catch {
                Write-Error $_
                continue
            }

            try {
                $addresses = [Net.Dns]::GetHostAddresses($normalized)
            } catch {
                $record = New-Object System.Management.Automation.ErrorRecord(
                    $_.Exception,
                    'DomainResolutionFailed',
                    [System.Management.Automation.ErrorCategory]::ResourceUnavailable,
                    $normalized
                )
                $PSCmdlet.WriteError($record)
                continue
            }

            foreach ($address in $addresses) {
                if ($AddressFamily -eq 'IPv4' -and $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
                    continue
                }
                if ($AddressFamily -eq 'IPv6' -and $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetworkV6) {
                    continue
                }

                [PSCustomObject]@{
                    PSTypeName    = 'DomainBlock.IPAddress'
                    Domain        = $normalized
                    IPAddress     = $address.ToString()
                    AddressFamily = $address.AddressFamily.ToString()
                }
            }
        }
    }
}
