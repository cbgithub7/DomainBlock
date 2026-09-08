#Requires -Version 5.1
<#
.SYNOPSIS
    Shows which processes hold a file, optionally ends them, and deletes the file.

.DESCRIPTION
    Uses the Windows Restart Manager API to find processes that have the file
    open. A command-line search is only a fallback hint; it is not proof that
    the file is locked.

    By default the file is sent to the Recycle Bin. Pass -Permanent for a
    hard delete. -KillLockingProcess stops the locking processes (except a
    small set of system processes) before deleting.

.PARAMETER Path
    File to inspect and optionally delete.

.PARAMETER KillLockingProcess
    Stop processes Restart Manager reports as locking the file.

.PARAMETER Permanent
    Delete permanently instead of sending to the Recycle Bin.

.PARAMETER Force
    Skip the ShouldProcess confirmation prompt.

.EXAMPLE
    .\Remove-LockedFile.ps1 -Path C:\Temp\report.docx

    Lists locking processes and asks before recycling the file if it is free.

.EXAMPLE
    .\Remove-LockedFile.ps1 -Path C:\Temp\report.docx -KillLockingProcess -Force

    Ends locking processes and recycles the file without a confirmation prompt.

.NOTES
    Former name: Check-FileUsageAndDelete.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, Position = 0)]
    [Alias('FilePath', 'LiteralPath')]
    [string]$Path,

    [switch]$KillLockingProcess,

    [switch]$Permanent,

    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Test-FileLocked {
    param([string]$LiteralPath)
    try {
        $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        $stream.Dispose()
        return $false
    } catch [IO.IOException] {
        return $true
    } catch [UnauthorizedAccessException] {
        return $true
    }
}

function Initialize-RestartManagerType {
    if ('NativeRestartManager' -as [type]) {
        return
    }

    $code = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class NativeRestartManager
{
    private const int ERROR_MORE_DATA = 234;
    private const int CCH_RM_MAX_APP_NAME = 255;
    private const int CCH_RM_MAX_SVC_NAME = 63;

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    private enum RM_APP_TYPE
    {
        RmUnknownApp = 0,
        RmMainWindow = 1,
        RmOtherWindow = 2,
        RmService = 3,
        RmExplorer = 4,
        RmConsole = 5,
        RmCritical = 1000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_APP_NAME + 1)]
        public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = CCH_RM_MAX_SVC_NAME + 1)]
        public string strServiceShortName;
        public RM_APP_TYPE ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint pSessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(
        uint pSessionHandle,
        uint nFiles,
        string[] rgsFilenames,
        uint nApplications,
        IntPtr rgApplications,
        uint nServices,
        string[] rgsServiceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(
        uint dwSessionHandle,
        out uint pnProcInfoNeeded,
        ref uint pnProcInfo,
        [In, Out] RM_PROCESS_INFO[] rgAffectedApps,
        ref uint lpdwRebootReasons);

    public static int[] GetLockingProcessIds(string path)
    {
        uint handle;
        string key = Guid.NewGuid().ToString("N");
        int result = RmStartSession(out handle, 0, key);
        if (result != 0)
        {
            throw new InvalidOperationException("RmStartSession failed with " + result);
        }

        try
        {
            result = RmRegisterResources(handle, 1, new string[] { path }, 0, IntPtr.Zero, 0, null);
            if (result != 0)
            {
                throw new InvalidOperationException("RmRegisterResources failed with " + result);
            }

            uint needed = 0;
            uint count = 0;
            uint reboot = 0;
            result = RmGetList(handle, out needed, ref count, null, ref reboot);
            if (result == ERROR_MORE_DATA)
            {
                RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed];
                count = needed;
                result = RmGetList(handle, out needed, ref count, info, ref reboot);
                if (result != 0)
                {
                    throw new InvalidOperationException("RmGetList failed with " + result);
                }

                List<int> ids = new List<int>();
                for (int i = 0; i < (int)count; i++)
                {
                    ids.Add(info[i].Process.dwProcessId);
                }
                return ids.ToArray();
            }

            if (result != 0)
            {
                throw new InvalidOperationException("RmGetList failed with " + result);
            }

            return new int[0];
        }
        finally
        {
            RmEndSession(handle);
        }
    }
}
'@

    Add-Type -TypeDefinition $code -Language CSharp
}

function Get-LockingProcess {
    param([string]$LiteralPath)

    $processes = @()
    try {
        Initialize-RestartManagerType
        $ids = [NativeRestartManager]::GetLockingProcessIds($LiteralPath)
        foreach ($id in @($ids)) {
            $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
            if ($proc) {
                $processes += $proc
            }
        }
    } catch {
        Write-Verbose "Restart Manager lookup failed: $($_.Exception.Message)"
    }

    if ($processes.Count -eq 0) {
        $escaped = [regex]::Escape($LiteralPath)
        try {
            $cim = Get-CimInstance -ClassName Win32_Process -ErrorAction Stop
            foreach ($item in $cim) {
                if ($item.CommandLine -and $item.CommandLine -match $escaped) {
                    $proc = Get-Process -Id $item.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {
                        $processes += $proc
                    }
                }
            }
        } catch {
            Write-Verbose "Win32_Process fallback failed: $($_.Exception.Message)"
        }
    }

    $processes | Sort-Object Id -Unique
}

function Send-FileToRecycleBin {
    param([string]$LiteralPath)

    Add-Type -AssemblyName Microsoft.VisualBasic
    [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(
        $LiteralPath,
        [Microsoft.VisualBasic.FileIO.UIOption]::OnlyErrorDialogs,
        [Microsoft.VisualBasic.FileIO.RecycleOption]::SendToRecycleBin,
        [Microsoft.VisualBasic.FileIO.UICancelOption]::ThrowException
    )
}

$resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
    throw "File not found: $resolved"
}

$locking = @(Get-LockingProcess -LiteralPath $resolved)
$locked = Test-FileLocked -LiteralPath $resolved

[PSCustomObject]@{
    Path             = $resolved
    Exists           = $true
    Locked           = $locked
    LockingProcessId = @($locking | ForEach-Object { $_.Id })
    LockingProcess   = @($locking | ForEach-Object { '{0} ({1})' -f $_.ProcessName, $_.Id })
}

if ($locking.Count -gt 0) {
    $locking | Select-Object Id, ProcessName, Path | Format-Table | Out-Host
}

$protected = @('csrss', 'winlogon', 'services', 'lsass', 'smss', 'System', 'Idle')

if ($locked -and $KillLockingProcess) {
    if ($locking.Count -eq 0) {
        Write-Warning "The file is locked, but no locking process could be identified."
    }
    foreach ($proc in $locking) {
        if ($protected -contains $proc.ProcessName) {
            Write-Warning "Refusing to stop protected process $($proc.ProcessName) (PID $($proc.Id))."
            continue
        }
        if ($proc.Id -eq $PID) {
            Write-Warning 'Refusing to stop the current PowerShell process.'
            continue
        }
        if ($Force -or $PSCmdlet.ShouldProcess(('{0} ({1})' -f $proc.ProcessName, $proc.Id), 'Stop process')) {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            try {
                $null = $proc.WaitForExit(10000)
            } catch {
                Start-Sleep -Seconds 1
            }
        }
    }
    $locked = Test-FileLocked -LiteralPath $resolved
}

if ($locked) {
    throw "File is still in use: $resolved"
}

$action = if ($Permanent) { 'Delete permanently' } else { 'Send to Recycle Bin' }
if (-not ($Force -or $PSCmdlet.ShouldProcess($resolved, $action))) {
    return
}

if ($Permanent) {
    Remove-Item -LiteralPath $resolved -Force
} else {
    Send-FileToRecycleBin -LiteralPath $resolved
}

Write-Verbose "Removed $resolved ($action)."
