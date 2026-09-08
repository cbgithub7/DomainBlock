function Export-BlockedDomain {
    <#
    .SYNOPSIS
        Writes the unique blocked domain names to a file.

    .DESCRIPTION
        Exports names currently returned by Get-BlockedDomain. JSON includes a
        timestamp; TXT is one domain per line.

    .PARAMETER Path
        Output file path.

    .PARAMETER Format
        Txt or Json. Default Txt. Json is inferred from a .json extension.

    .PARAMETER Method
        Limit the export to Hosts, Firewall, or Both.

    .PARAMETER HostsFilePath
        Hosts file to read. Defaults to the system hosts file.

    .EXAMPLE
        Export-BlockedDomain -Path .\blocked.json -Format Json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet('Txt', 'Json')]
        [string]$Format,

        [ValidateSet('Hosts', 'Firewall', 'Both')]
        [string]$Method = 'Both',

        [string]$HostsFilePath
    )

    if (-not $Format) {
        if ([IO.Path]::GetExtension($Path) -eq '.json') {
            $Format = 'Json'
        } else {
            $Format = 'Txt'
        }
    }

    $getParams = @{ Method = $Method }
    if ($HostsFilePath) {
        $getParams['HostsFilePath'] = $HostsFilePath
    }

    $domains = @(
        Get-BlockedDomain @getParams |
            Where-Object { $_.Domain } |
            Select-Object -ExpandProperty Domain -Unique |
            Sort-Object
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    if ($Format -eq 'Json') {
        $payload = [PSCustomObject]@{
            ExportedAt = (Get-Date).ToString('o')
            Method     = $Method
            Domains    = @($domains)
        }
        $payload | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8
    } else {
        $domains | Set-Content -LiteralPath $Path -Encoding UTF8
    }

    [PSCustomObject]@{
        Path    = $Path
        Format  = $Format
        Count   = $domains.Count
        Domains = $domains
    }
}
