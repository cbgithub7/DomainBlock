function ConvertFrom-HostsEntryLine {
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Line
    )

    $trim = $Line.Trim()
    if ($trim -eq '' -or $trim.StartsWith('#')) {
        return
    }

    $comment = ''
    $hash = $trim.IndexOf('#')
    $body = $trim
    if ($hash -ge 0) {
        $comment = $trim.Substring($hash + 1).Trim()
        $body = $trim.Substring(0, $hash).Trim()
    }

    $tokens = @($body -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -lt 2) {
        return
    }

    $ip = $tokens[0]
    $names = @($tokens[1..($tokens.Count - 1)])
    $managed = $comment -match ('\b{0}\b' -f [regex]::Escape($script:HostsCommentTag))

    foreach ($hostname in $names) {
        [PSCustomObject]@{
            IPAddress = $ip
            Domain    = $hostname.TrimEnd('.').ToLowerInvariant()
            Managed   = [bool]$managed
            Comment   = $comment
            Line      = $Line
        }
    }
}

function Test-IsBlockingHostsAddress {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress
    )

    return (Test-IsLoopbackAddress -IPAddress $IPAddress)
}

function Read-HostsFileLine {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $line
    }
}

function Write-HostsFileLine {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        $Lines
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $content = ($Lines -join "`r`n")
    if ($content.Length -gt 0 -and -not $content.EndsWith("`r`n")) {
        $content += "`r`n"
    }

    $encoding = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllText($Path, $content, $encoding)
}

function Get-HostsFileDomainBlock {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [string]$Domain,
        [switch]$IncludeUnmanaged
    )

    $results = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    $normalized = $null
    if ($Domain) {
        $normalized = ConvertTo-NormalizedDomainName -Name $Domain
    }

    foreach ($line in @(Read-HostsFileLine -Path $Path)) {
        foreach ($entry in @(ConvertFrom-HostsEntryLine -Line $line | Where-Object { $_ })) {
            if (-not (Test-IsBlockingHostsAddress -IPAddress $entry.IPAddress)) {
                continue
            }
            if (-not $entry.Managed -and -not $IncludeUnmanaged) {
                continue
            }
            if ($normalized -and $entry.Domain -ne $normalized) {
                continue
            }
            [void]$results.Add($entry)
        }
    }

    foreach ($item in $results) {
        $item
    }
}

function Add-HostsFileDomainBlock {
    param(
        [Parameter(Mandatory)]
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$IPv4Only
    )

    $normalized = ConvertTo-NormalizedDomainName -Name $Domain
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($line in @(Read-HostsFileLine -Path $Path)) {
        [void]$lines.Add([string]$line)
    }
    $existing = @(Get-HostsFileDomainBlock -Path $Path -Domain $normalized -IncludeUnmanaged | Where-Object { $_ })

    $want = New-Object System.Collections.Generic.List[string]
    [void]$want.Add($script:LoopbackIPv4)
    if (-not $IPv4Only) {
        [void]$want.Add($script:LoopbackIPv6)
    }

    $results = New-Object System.Collections.Generic.List[object]
    $changed = $false

    foreach ($ip in $want) {
        $already = @(
            $existing |
                Where-Object {
                    $_.IPAddress -and (
                        $_.IPAddress -eq $ip -or
                        (ConvertTo-CanonicalIPAddress -IPAddress $_.IPAddress) -eq $ip
                    )
                }
        )
        if ($already.Count -gt 0) {
            [void]$results.Add((
                    New-DomainBlockEntry -Domain $normalized -Method Hosts -Status AlreadyBlocked -Target $ip -Detail $Path
                ))
            continue
        }

        [void]$lines.Add(('{0} {1} # {2}' -f $ip, $normalized, $script:HostsCommentTag))
        $changed = $true
        [void]$results.Add((
                New-DomainBlockEntry -Domain $normalized -Method Hosts -Status Blocked -Target $ip -Detail $Path
            ))
    }

    if ($changed) {
        Write-HostsFileLine -Path $Path -Lines $lines
    }

    foreach ($item in $results) {
        $item
    }
}

function Remove-HostsFileDomainBlock {
    param(
        [string]$Domain,
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$All,
        [switch]$IncludeUnmanaged
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    $normalized = $null
    if (-not $All) {
        if (-not $Domain) {
            throw 'Domain is required unless -All is specified.'
        }
        $normalized = ConvertTo-NormalizedDomainName -Name $Domain
    }

    $original = @(Read-HostsFileLine -Path $Path)
    $kept = New-Object System.Collections.Generic.List[string]
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($line in $original) {
        $entries = @(ConvertFrom-HostsEntryLine -Line $line)
        if ($entries.Count -eq 0) {
            [void]$kept.Add($line)
            continue
        }

        $remainingNames = New-Object System.Collections.Generic.List[string]
        $ip = $entries[0].IPAddress
        $managed = [bool]($entries | Where-Object { $_.Managed } | Select-Object -First 1)
        $removedHere = New-Object System.Collections.Generic.List[object]

        foreach ($entry in $entries) {
            $isTargetDomain = $All -or ($entry.Domain -eq $normalized)
            $isManagedOk = $entry.Managed -or $IncludeUnmanaged -or (-not $All)
            if ($All) {
                $isManagedOk = $entry.Managed -or $IncludeUnmanaged
            }

            $shouldRemove = $isTargetDomain -and $isManagedOk -and (Test-IsBlockingHostsAddress -IPAddress $entry.IPAddress)
            if ($shouldRemove) {
                [void]$removedHere.Add($entry)
            } else {
                [void]$remainingNames.Add($entry.Domain)
            }
        }

        if ($removedHere.Count -eq 0) {
            [void]$kept.Add($line)
            continue
        }

        foreach ($removed in $removedHere) {
            [void]$results.Add((
                    New-DomainBlockEntry -Domain $removed.Domain -Method Hosts -Status Unblocked -Target $removed.IPAddress -Detail $Path
                ))
        }

        if ($remainingNames.Count -gt 0) {
            $suffix = ''
            if ($managed -and -not $All) {
                $suffix = ' # ' + $script:HostsCommentTag
            }
            [void]$kept.Add(('{0} {1}{2}' -f $ip, ($remainingNames -join ' '), $suffix).TrimEnd())
        }
    }

    if ($results.Count -gt 0) {
        Write-HostsFileLine -Path $Path -Lines $kept
    }

    foreach ($item in $results) {
        $item
    }
}
