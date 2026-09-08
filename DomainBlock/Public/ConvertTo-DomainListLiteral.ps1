function ConvertTo-DomainListLiteral {
    <#
    .SYNOPSIS
        Converts a column of domain names into a PowerShell array literal.

    .DESCRIPTION
        Reads names from the pipeline, a file, or an interactive prompt and
        writes a single-line @("example.com", "ads.example.net") literal.
        Comment lines and blanks are skipped. This is for pasting into scripts,
        not for the hosts file format.

    .PARAMETER InputObject
        Domain names from the pipeline.

    .PARAMETER Path
        Text file with one domain per line.

    .EXAMPLE
        Get-Content .\list.txt | ConvertTo-DomainListLiteral

        Prints @("ads.example.com", "tracker.example.net")
    #>
    [CmdletBinding(DefaultParameterSetName = 'Pipeline')]
    param(
        [Parameter(ValueFromPipeline, ParameterSetName = 'Pipeline')]
        [AllowEmptyString()]
        [string]$InputObject,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [Alias('File')]
        [string]$Path
    )

    begin {
        $names = New-Object System.Collections.Generic.List[string]
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            return
        }
        if ($null -ne $InputObject -and $InputObject.Trim() -ne '' -and -not $InputObject.Trim().StartsWith('#')) {
            [void]$names.Add($InputObject.Trim())
        }
    }

    end {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            foreach ($item in (Read-DomainListFile -Path $Path)) {
                if ($item.Trim() -ne '') {
                    [void]$names.Add($item.Trim())
                }
            }
        } elseif ($names.Count -eq 0 -and -not $MyInvocation.ExpectingInput) {
            Write-Host "Enter domain names, one per line. Press Enter on an empty line when finished."
            while ($true) {
                $line = Read-Host
                if ([string]::IsNullOrWhiteSpace($line)) {
                    break
                }
                if (-not $line.Trim().StartsWith('#')) {
                    [void]$names.Add($line.Trim())
                }
            }
        }

        $quoted = foreach ($item in $names) {
            '"' + ($item -replace '"', '`"') + '"'
        }
        '@(' + ($quoted -join ', ') + ')'
    }
}
