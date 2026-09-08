function Invoke-DomainBlockWorkflow {
    <#
    .SYNOPSIS
        Runs the advised DomainBlock command sequence and waits for each step.

    .DESCRIPTION
        Do not run every toolkit command in one pass. Block and Unblock cancel
        each other, Restore undoes Backup, and the Outliers scripts are unrelated.

        These three sequences are the useful ones:

        Apply   Backup-HostsFile (if hosts) -> Block-Domain -> Test-DomainBlock
        Refresh Update-DomainFirewallBlock -> Test-DomainBlock
        Remove  Backup-HostsFile (if hosts) -> Unblock-Domain -> Test-DomainBlock

        Each step starts only after the previous step has finished. A failing
        step stops the workflow.

    .PARAMETER Action
        Apply, Refresh, or Remove.

    .PARAMETER Name
        Domain names for Apply or Remove. Optional for Refresh (all managed
        firewall domains when omitted).

    .PARAMETER Path
        Domain list file for Apply (same format as Block-Domain -Path).

    .PARAMETER All
        With -Action Remove, unblock every toolkit-managed entry.

    .PARAMETER Method
        Hosts, Firewall, or Both. Default is Both. Ignored by Refresh.

    .PARAMETER Direction
        Firewall direction for Apply/Refresh. Default is Outbound.

    .PARAMETER NoWww
        Do not also process www. variants.

    .PARAMETER IPv4Only
        IPv4 only for Apply/Refresh.

    .PARAMETER SkipBackup
        Do not back up the hosts file before Apply or Remove.

    .PARAMETER SkipTest
        Do not run Test-DomainBlock after the change.

    .PARAMETER BackupDestination
        Optional path for the hosts backup.

    .PARAMETER RemoveIfUnresolved
        Passed to Update-DomainFirewallBlock during Refresh.

    .PARAMETER IncludeUnmanaged
        Passed to Unblock-Domain during Remove.

    .PARAMETER NoFlushDns
        Skip DNS cache flush after hosts-file changes.

    .PARAMETER HostsFilePath
        Hosts file to use. Defaults to the system hosts file.

    .PARAMETER Quiet
        Do not print step progress to the host. The result object is still returned.

    .EXAMPLE
        Invoke-DomainBlockWorkflow -Action Apply -Name ads.example.com -Method Hosts

        Backs up hosts, blocks the domain, then tests the result.

    .EXAMPLE
        Invoke-DomainBlockWorkflow -Action Refresh

        Re-resolves DNS for every DomainBlock firewall rule, then tests.

    .EXAMPLE
        Invoke-DomainBlockWorkflow -Action Remove -Name ads.example.com

        Backs up hosts, unblocks the domain, then tests.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Apply', 'Refresh', 'Remove')]
        [string]$Action,

        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByName')]
        [Alias('Domain', 'HostName')]
        [string[]]$Name,

        [Parameter(ParameterSetName = 'ByPath')]
        [Alias('File', 'ListPath')]
        [string]$Path,

        [Parameter(ParameterSetName = 'All')]
        [switch]$All,

        [ValidateSet('Hosts', 'Firewall', 'Both')]
        [string]$Method = 'Both',

        [ValidateSet('Outbound', 'Inbound', 'Both')]
        [string]$Direction = 'Outbound',

        [switch]$NoWww,

        [switch]$IPv4Only,

        [switch]$SkipBackup,

        [switch]$SkipTest,

        [string]$BackupDestination,

        [switch]$RemoveIfUnresolved,

        [switch]$IncludeUnmanaged,

        [switch]$NoFlushDns,

        [string]$HostsFilePath,

        [switch]$Quiet
    )

    begin {
        $pending = New-Object System.Collections.Generic.List[string]
        if (-not $HostsFilePath) {
            $HostsFilePath = Get-DefaultHostsFilePath
        }
        $needHosts = $Method -in @('Hosts', 'Both')
        $steps = New-Object System.Collections.Generic.List[object]
        $state = @{
            Index  = 0
            Failed = $false
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ByName' -and $Name) {
            foreach ($item in $Name) {
                [void]$pending.Add($item)
            }
        }
    }

    end {
        if ($Action -eq 'Apply' -and $PSCmdlet.ParameterSetName -eq 'All') {
            throw '-All is only valid with -Action Remove.'
        }
        if ($Action -eq 'Refresh' -and $PSCmdlet.ParameterSetName -eq 'All') {
            throw '-All is only valid with -Action Remove. Omit -Name to refresh every managed firewall domain.'
        }
        if ($Action -ne 'Apply' -and $PSCmdlet.ParameterSetName -eq 'ByPath') {
            throw '-Path is only valid with -Action Apply.'
        }

        $resolvedNames = @()
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $resolvedNames = @(Read-DomainListFile -Path $Path | Where-Object { $_ })
        } elseif ($pending.Count -gt 0) {
            $resolvedNames = @(ConvertTo-UniqueNormalizedDomain -Name @($pending.ToArray()))
        }

        if ($Action -eq 'Apply' -and $resolvedNames.Count -eq 0) {
            throw 'Apply requires -Name or -Path with at least one domain.'
        }
        if ($Action -eq 'Remove' -and -not $All -and $resolvedNames.Count -eq 0) {
            throw 'Remove requires -Name or -All.'
        }

        $plan = New-Object System.Collections.Generic.List[string]
        $backupNow = $needHosts -and -not $SkipBackup -and $Action -in @('Apply', 'Remove')
        if ($backupNow) {
            [void]$plan.Add('Backup-HostsFile')
        }
        switch ($Action) {
            'Apply' { [void]$plan.Add('Block-Domain') }
            'Refresh' { [void]$plan.Add('Update-DomainFirewallBlock') }
            'Remove' { [void]$plan.Add('Unblock-Domain') }
        }
        if (-not $SkipTest) {
            [void]$plan.Add('Test-DomainBlock')
        }
        $total = $plan.Count

        $writeProgress = {
            param([string]$Message)
            if (-not $Quiet) {
                Write-Host $Message
            }
        }

        $invokeStep = {
            param(
                [string]$Command,
                [scriptblock]$Work
            )
            $state.Index++
            & $writeProgress ("[{0}/{1}] {2}..." -f $state.Index, $total, $Command)
            try {
                $output = @( & $Work | Where-Object { $_ } )
                $detail = '{0} object(s)' -f $output.Count
                & $writeProgress ("[{0}/{1}] {2} finished ({3})" -f $state.Index, $total, $Command, $detail)
                [void]$steps.Add([PSCustomObject]@{
                        PSTypeName = 'DomainBlock.WorkflowStep'
                        Index      = $state.Index
                        Command    = $Command
                        Status     = 'Finished'
                        Detail     = $detail
                        Output     = $output
                    })
                return $output
            } catch {
                $state.Failed = $true
                $message = $_.Exception.Message
                & $writeProgress ("[{0}/{1}] {2} failed: {3}" -f $state.Index, $total, $Command, $message)
                [void]$steps.Add([PSCustomObject]@{
                        PSTypeName = 'DomainBlock.WorkflowStep'
                        Index      = $state.Index
                        Command    = $Command
                        Status     = 'Failed'
                        Detail     = $message
                        Output     = @()
                    })
                throw
            }
        }

        $backupResult = $null
        $changeResult = @()
        $testResult = @()
        $testNames = @($resolvedNames)

        try {
        foreach ($command in $plan) {
            switch ($command) {
                'Backup-HostsFile' {
                    $backupResult = & $invokeStep $command {
                        $backupParams = @{ HostsFilePath = $HostsFilePath }
                        if ($BackupDestination) {
                            $backupParams['Destination'] = $BackupDestination
                        }
                        Backup-HostsFile @backupParams
                    } | Select-Object -Last 1
                }
                'Block-Domain' {
                    $changeResult = & $invokeStep $command {
                        $blockParams = @{
                            Method      = $Method
                            Direction   = $Direction
                            NoWww       = $NoWww
                            IPv4Only    = $IPv4Only
                            NoFlushDns  = $NoFlushDns
                            HostsFilePath = $HostsFilePath
                        }
                        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
                            $blockParams['Path'] = $Path
                        } else {
                            $blockParams['Name'] = $resolvedNames
                        }
                        Block-Domain @blockParams
                    }
                }
                'Update-DomainFirewallBlock' {
                    $changeResult = & $invokeStep $command {
                        $updateParams = @{
                            IPv4Only            = $IPv4Only
                            Direction           = $Direction
                            RemoveIfUnresolved  = $RemoveIfUnresolved
                            NoWww               = $NoWww
                        }
                        if ($resolvedNames.Count -gt 0) {
                            $updateParams['Name'] = $resolvedNames
                        }
                        Update-DomainFirewallBlock @updateParams
                    }
                    if ($testNames.Count -eq 0) {
                        $testNames = @(
                            Get-BlockedDomain -Method Firewall |
                                Where-Object { $_.Domain } |
                                Select-Object -ExpandProperty Domain -Unique
                        )
                    }
                }
                'Unblock-Domain' {
                    $changeResult = & $invokeStep $command {
                        $unblockParams = @{
                            Method            = $Method
                            NoWww             = $NoWww
                            IncludeUnmanaged  = $IncludeUnmanaged
                            NoFlushDns        = $NoFlushDns
                            HostsFilePath     = $HostsFilePath
                            Confirm           = $false
                        }
                        if ($All) {
                            $unblockParams['All'] = $true
                        } else {
                            $unblockParams['Name'] = $resolvedNames
                        }
                        Unblock-Domain @unblockParams
                    }
                    if ($All -and $testNames.Count -eq 0) {
                        $testNames = @(
                            $changeResult |
                                Where-Object { $_.Domain } |
                                Select-Object -ExpandProperty Domain -Unique
                        )
                    }
                }
                'Test-DomainBlock' {
                    if ($testNames.Count -eq 0) {
                        $state.Index++
                        & $writeProgress ("[{0}/{1}] Test-DomainBlock skipped (no domain names to test)." -f $state.Index, $total)
                        [void]$steps.Add([PSCustomObject]@{
                                PSTypeName = 'DomainBlock.WorkflowStep'
                                Index      = $state.Index
                                Command    = 'Test-DomainBlock'
                                Status     = 'Skipped'
                                Detail     = 'No domain names to test'
                                Output     = @()
                            })
                    } else {
                        $testParams = @{
                            Name          = $testNames
                            NoWww         = $NoWww
                            HostsFilePath = $HostsFilePath
                        }
                        $testResult = & $invokeStep $command {
                            Test-DomainBlock @testParams
                        }
                    }
                }
            }
        }
        } catch {
            $state.Failed = $true
        }

        $succeeded = -not $state.Failed
        if ($Action -eq 'Apply' -and $testResult.Count -gt 0) {
            $unblocked = @($testResult | Where-Object { -not $_.IsBlocked })
            if ($unblocked.Count -gt 0) {
                $succeeded = $false
                Write-Warning ("Workflow finished but {0} name(s) are not reported as blocked: {1}" -f $unblocked.Count, (($unblocked.Domain | Select-Object -Unique) -join ', '))
            }
        }

        [PSCustomObject]@{
            PSTypeName = 'DomainBlock.WorkflowResult'
            Action     = $Action
            Succeeded  = $succeeded
            Method     = $Method
            BackupPath = $(if ($backupResult) { $backupResult.BackupPath } else { $null })
            Steps      = $steps.ToArray()
            Changes    = $changeResult
            Tests      = $testResult
        }
    }
}
