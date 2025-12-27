<#
.SYNOPSIS
Identifies file locks / open handles (best-effort) locally or remotely.

.DESCRIPTION
Determining "who has this file open" is platform-dependent. This script provides a
practical, ops-focused approach by querying the best available sources:

1) SMB open files (file server view): Get-SmbOpenFile
   - Most reliable for shared files.
   - Provides client user, client computer, share path, and file id.

2) Sysinternals handle.exe (local view)
   - Best-effort to map local process -> locked file.
   - Optional and only used if handle.exe is available or explicitly specified.
   - Does not require enabling openfiles tracking.

3) openfiles.exe (local view)
   - Optional. Requires "Maintain Objects List" to be enabled (openfiles /local on).
   - Can show local open files, but often not enabled by default.

Outputs structured objects suitable for reporting and troubleshooting.

.PARAMETER Path
File or folder path to search for locks. Wildcards supported.
For folder paths, matching is performed by prefix ("starts with") when possible.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER IncludeSmb
Include SMB open file locks (recommended on file servers). Default True.

.PARAMETER IncludeHandleExe
Include local handle enumeration via Sysinternals handle.exe (optional).

.PARAMETER HandleExePath
Path to handle.exe. If not provided, attempts to find it in PATH.

.PARAMETER IncludeOpenFiles
Include local open files via openfiles.exe (optional; requires /local on).

.PARAMETER EnableOpenFilesLocal
Attempts to enable local open file tracking (openfiles /local on). Requires elevation and reboot.
This switch does NOT reboot the machine; it only runs the enable command.

.PARAMETER MaxResults
Limit results returned per computer (defensive). Default 5000.

.EXAMPLE
# Find who has a shared file open (server-side)
.\Get-FileLockStatus.ps1 -Path "D:\Shares\Accounting\FileCabinet.db" -IncludeSmb | Format-Table -Auto

.EXAMPLE
# Search all locks under a folder on a file server
.\Get-FileLockStatus.ps1 -ComputerName FS01 -Path "D:\Shares\Accounting\" -IncludeSmb |
  Sort-Object LockSource,UserName | Format-Table -Auto

.EXAMPLE
# Local handle lookup (requires handle.exe)
.\Get-FileLockStatus.ps1 -Path "C:\Temp\locked.xlsx" -IncludeHandleExe -HandleExePath "C:\Tools\Sysinternals\handle.exe" |
  Format-Table -Auto

.EXAMPLE
# Local openfiles (only works if /local on)
.\Get-FileLockStatus.ps1 -Path "C:\Temp\" -IncludeOpenFiles | Format-Table -Auto

.NOTES
Author: Cheri
Safe by default (read-only). Lock detection is best-effort by design.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeSmb = $true,

    [Parameter()]
    [switch]$IncludeHandleExe,

    [Parameter()]
    [string]$HandleExePath,

    [Parameter()]
    [switch]$IncludeOpenFiles,

    [Parameter()]
    [switch]$EnableOpenFilesLocal,

    [Parameter()]
    [ValidateRange(1,200000)]
    [int]$MaxResults = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-HandleExe {
    param([string]$HandleExePath)

    if ($HandleExePath) {
        if (Test-Path -LiteralPath $HandleExePath) { return $HandleExePath }
        throw "handle.exe not found at specified path: $HandleExePath"
    }

    $cmd = Get-Command handle.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    return $null
}

function Normalize-SearchPath {
    param([string]$Path)

    # Expand relative paths; keep wildcards as-is
    try {
        if ($Path -like '*[*?]*') { return $Path } # wildcard
        return [System.IO.Path]::GetFullPath($Path)
    } catch {
        return $Path
    }
}

function Path-Matches {
    param(
        [string]$Candidate,
        [string]$SearchPath
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    if ([string]::IsNullOrWhiteSpace($SearchPath)) { return $false }

    # Wildcard match
    if ($SearchPath -like '*[*?]*') {
        return ($Candidate -like $SearchPath)
    }

    # Prefix match for folder paths
    $sp = $SearchPath.TrimEnd('\')
    if ($Candidate.StartsWith($sp, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }

    # Exact file match
    return ($Candidate -ieq $SearchPath)
}

function Get-SmbLocks {
    param(
        [string]$SearchPath,
        [int]$MaxResults
    )

    $out = New-Object System.Collections.Generic.List[object]

    try {
        $open = Get-SmbOpenFile -ErrorAction Stop
        foreach ($o in @($open)) {
            # Some environments show paths like \Device\HarddiskVolumeX\... or fully qualified local paths
            $candidate = $o.Path

            if (-not (Path-Matches -Candidate $candidate -SearchPath $SearchPath)) { continue }

            $out.Add([PSCustomObject]@{
                ComputerName   = $env:COMPUTERNAME
                LockSource     = 'SMB'
                Path           = $candidate
                UserName       = $o.ClientUserName
                ClientComputer = $o.ClientComputerName
                SessionId      = $o.SessionId
                FileId         = $o.FileId
                ShareRelative  = $o.ShareRelativePath
                ProcessId      = $null
                ProcessName    = $null
                HandleId       = $null
                Notes          = $null
            })

            if ($out.Count -ge $MaxResults) { break }
        }
    } catch {
        $out.Add([PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            LockSource     = 'SMB'
            Path           = $null
            UserName       = $null
            ClientComputer = $null
            SessionId      = $null
            FileId         = $null
            ShareRelative  = $null
            ProcessId      = $null
            ProcessName    = $null
            HandleId       = $null
            Notes          = "SMB query failed: $($_.Exception.Message)"
        })
    }

    $out
}

function Get-HandleExeLocks {
    param(
        [string]$SearchPath,
        [string]$HandleExe,
        [int]$MaxResults
    )

    $out = New-Object System.Collections.Generic.List[object]

    if (-not $HandleExe) {
        $out.Add([PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            LockSource     = 'HandleExe'
            Path           = $null
            UserName       = $null
            ClientComputer = $null
            SessionId      = $null
            FileId         = $null
            ShareRelative  = $null
            ProcessId      = $null
            ProcessName    = $null
            HandleId       = $null
            Notes          = "handle.exe not found. Provide -HandleExePath or install Sysinternals and ensure handle.exe is in PATH."
        })
        return $out
    }

    # handle.exe parsing strategy:
    # - Use -nobanner
    # - Query by leaf name when possible to reduce output volume
    $leaf = $SearchPath
    if ($SearchPath -notlike '*[*?]*') {
        try { $leaf = [System.IO.Path]::GetFileName($SearchPath.TrimEnd('\')) } catch { $leaf = $SearchPath }
        if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = $SearchPath }
    }

    # handle.exe supports searching by substring; provide leaf to avoid massive output where possible
    $args = @('-nobanner', $leaf)

    try {
        $raw = & $HandleExe @args 2>$null
        if (-not $raw) { return $out }

        # Typical blocks:
        # "proc.exe pid: 1234 ..."
        # "  1A4: File  (RW-)   C:\Path\file.txt"
        $currentProc = $null
        $currentPid  = $null

        foreach ($line in $raw) {
            if ($line -match '^(?<proc>.+?)\s+pid:\s+(?<pid>\d+)\s+') {
                $currentProc = $matches['proc'].Trim()
                $currentPid  = [int]$matches['pid']
                continue
            }

            if ($line -match '^\s*(?<handle>[0-9A-F]+):\s+File\s+.*\s+(?<path>[A-Za-z]:\\.+)$') {
                $candidate = $matches['path'].Trim()
                if (-not (Path-Matches -Candidate $candidate -SearchPath $SearchPath)) { continue }

                $out.Add([PSCustomObject]@{
                    ComputerName   = $env:COMPUTERNAME
                    LockSource     = 'HandleExe'
                    Path           = $candidate
                    UserName       = $null
                    ClientComputer = $null
                    SessionId      = $null
                    FileId         = $null
                    ShareRelative  = $null
                    ProcessId      = $currentPid
                    ProcessName    = $currentProc
                    HandleId       = $matches['handle']
                    Notes          = $null
                })

                if ($out.Count -ge $MaxResults) { break }
            }
        }
    } catch {
        $out.Add([PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            LockSource     = 'HandleExe'
            Path           = $null
            UserName       = $null
            ClientComputer = $null
            SessionId      = $null
            FileId         = $null
            ShareRelative  = $null
            ProcessId      = $null
            ProcessName    = $null
            HandleId       = $null
            Notes          = "handle.exe query failed: $($_.Exception.Message)"
        })
    }

    $out
}

function Get-OpenFilesLocks {
    param(
        [string]$SearchPath,
        [int]$MaxResults
    )

    $out = New-Object System.Collections.Generic.List[object]

    try {
        # /query output is CSV when using /fo csv
        $csv = & openfiles.exe /query /fo csv /nh 2>$null
        if (-not $csv) { return $out }

        foreach ($line in $csv) {
            # CSV columns: "ID","Accessed By","Type","Open File (Path\executable)"
            # Not perfectly consistent across OS versions, so parse with ConvertFrom-Csv using headers.
            # However, output is already "no headers", so we provide them.
            $row = $line | ConvertFrom-Csv -Header @('Id','AccessedBy','Type','OpenFile')
            $candidate = $row.OpenFile

            if (-not (Path-Matches -Candidate $candidate -SearchPath $SearchPath)) { continue }

            $out.Add([PSCustomObject]@{
                ComputerName   = $env:COMPUTERNAME
                LockSource     = 'OpenFiles'
                Path           = $candidate
                UserName       = $row.AccessedBy
                ClientComputer = $null
                SessionId      = $null
                FileId         = $row.Id
                ShareRelative  = $null
                ProcessId      = $null
                ProcessName    = $null
                HandleId       = $null
                Notes          = $null
            })

            if ($out.Count -ge $MaxResults) { break }
        }
    } catch {
        $out.Add([PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            LockSource     = 'OpenFiles'
            Path           = $null
            UserName       = $null
            ClientComputer = $null
            SessionId      = $null
            FileId         = $null
            ShareRelative  = $null
            ProcessId      = $null
            ProcessName    = $null
            HandleId       = $null
            Notes          = "openfiles query failed (likely not enabled): $($_.Exception.Message)"
        })
    }

    $out
}

function Enable-OpenFilesLocalTracking {
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Enable local open files tracking (openfiles /local on). Reboot required.")) {
        & openfiles.exe /local on | Out-Null
    }
}

function Get-FileLockStatusLocal {
    param(
        [string]$SearchPath,
        [bool]$IncludeSmb,
        [bool]$IncludeHandleExe,
        [string]$HandleExePath,
        [bool]$IncludeOpenFiles,
        [bool]$EnableOpenFilesLocal,
        [int]$MaxResults
    )

    $result = New-Object System.Collections.Generic.List[object]

    if ($EnableOpenFilesLocal) {
        Enable-OpenFilesLocalTracking
    }

    if ($IncludeSmb) {
        foreach ($r in (Get-SmbLocks -SearchPath $SearchPath -MaxResults $MaxResults)) { $result.Add($r) }
    }

    if ($IncludeHandleExe) {
        $handleExe = Resolve-HandleExe -HandleExePath $HandleExePath
        foreach ($r in (Get-HandleExeLocks -SearchPath $SearchPath -HandleExe $handleExe -MaxResults $MaxResults)) { $result.Add($r) }
    }

    if ($IncludeOpenFiles) {
        foreach ($r in (Get-OpenFilesLocks -SearchPath $SearchPath -MaxResults $MaxResults)) { $result.Add($r) }
    }

    $result
}

$searchPath = Normalize-SearchPath -Path $Path

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-FileLockStatusLocal -SearchPath $searchPath `
                -IncludeSmb:$IncludeSmb `
                -IncludeHandleExe:$IncludeHandleExe `
                -HandleExePath $HandleExePath `
                -IncludeOpenFiles:$IncludeOpenFiles `
                -EnableOpenFilesLocal:$EnableOpenFilesLocal `
                -MaxResults $MaxResults
        } else {
            $sb = ${function:Get-FileLockStatusLocal}
            $rows = Invoke-Command -ComputerName $target -ScriptBlock $sb -ArgumentList @(
                $searchPath,
                [bool]$IncludeSmb,
                [bool]$IncludeHandleExe,
                $HandleExePath,
                [bool]$IncludeOpenFiles,
                [bool]$EnableOpenFilesLocal,
                [int]$MaxResults
            ) -ErrorAction Stop
        }

        foreach ($r in @($rows)) { $all.Add($r) }
    } catch {
        $all.Add([PSCustomObject]@{
            ComputerName   = $target
            LockSource     = 'Error'
            Path           = $null
            UserName       = $null
            ClientComputer = $null
            SessionId      = $null
            FileId         = $null
            ShareRelative  = $null
            ProcessId      = $null
            ProcessName    = $null
            HandleId       = $null
            Notes          = $_.Exception.Message
        })
    }
}

# Prefer actionable results first
$all | Sort-Object LockSource, UserName, ClientComputer, ProcessName, Path
