<#
.SYNOPSIS
Safely cleans common temporary directories and reports reclaimed space.

.DESCRIPTION
Deletes temp files older than a threshold from one or more target directories.
Designed for endpoint hygiene and disk pressure remediation.

Safe defaults:
- Only deletes files older than -OlderThanDays (default 7)
- Does not delete system-critical folders
- Supports -WhatIf and -Confirm (ShouldProcess)
- Can run locally or via remoting (-ComputerName)

Targets supported:
- Custom paths via -Path
- Preset sets via -Target (UserTemp, WindowsTemp, Prefetch, BrowserCaches, AllCommon)

Reports:
- FilesDeleted, DirsDeleted, BytesFreed, MBFreed, GBFreed
- Per-path and per-computer summary

.PARAMETER Path
One or more custom paths to clean.

.PARAMETER Target
Preset targets to clean. Default: UserTemp,WindowsTemp

.PARAMETER OlderThanDays
Only remove items with LastWriteTime older than this many days. Default 7.

.PARAMETER IncludeExtensions
Only delete files with these extensions (e.g., .tmp,.log). If omitted, all files are eligible.

.PARAMETER ExcludeExtensions
Exclude file extensions from deletion.

.PARAMETER IncludePattern
Only delete files matching wildcard patterns (Name match). Example: "*.tmp","~*"

.PARAMETER ExcludePattern
Exclude files matching wildcard patterns.

.PARAMETER IncludeDirectories
Also delete empty directories (after file cleanup) older than threshold.

.PARAMETER RemoveEmptyRoot
If specified, allows deleting the root path itself if it becomes empty (not recommended). Default: off.

.PARAMETER Force
Deletes read-only files and continues best-effort.

.PARAMETER ComputerName
Optional remote computer(s). Defaults to local computer.

.PARAMETER ThrottleLimit
Throttle for remote operations. Default 16.

.PARAMETER PassThru
Return detailed per-item deletion output instead of summary.

.EXAMPLE
# Default: clean user + windows temp older than 7 days (preview)
.\Clear-TempDirectories.ps1 -WhatIf

.EXAMPLE
# Aggressive cleanup on endpoint temp older than 14 days
.\Clear-TempDirectories.ps1 -Target AllCommon -OlderThanDays 14 -Force -Confirm:$false

.EXAMPLE
# Clean only .tmp and .log in user temp older than 30 days
.\Clear-TempDirectories.ps1 -Target UserTemp -OlderThanDays 30 -IncludeExtensions .tmp,.log -Force

.EXAMPLE
# Run on multiple machines (requires remoting)
.\Clear-TempDirectories.ps1 -ComputerName PC01,PC02 -Target WindowsTemp -OlderThanDays 7 -Force |
  Export-Csv C:\Reports\TempCleanup.csv -NoTypeInformation

.NOTES
Author: Cheri
Use -WhatIf first in client environments. For RMM, pair with -Force -Confirm:$false.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter()]
    [string[]]$Path,

    [Parameter()]
    [ValidateSet('UserTemp','WindowsTemp','Prefetch','BrowserCaches','AllCommon')]
    [string[]]$Target = @('UserTemp','WindowsTemp'),

    [Parameter()]
    [ValidateRange(0,36500)]
    [int]$OlderThanDays = 7,

    [Parameter()]
    [string[]]$IncludeExtensions,

    [Parameter()]
    [string[]]$ExcludeExtensions,

    [Parameter()]
    [string[]]$IncludePattern,

    [Parameter()]
    [string[]]$ExcludePattern,

    [Parameter()]
    [switch]$IncludeDirectories,

    [Parameter()]
    [switch]$RemoveEmptyRoot,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Extension {
    param([string]$Ext)
    if ([string]::IsNullOrWhiteSpace($Ext)) { return $null }
    if ($Ext.StartsWith('.')) { return $Ext.ToLowerInvariant() }
    return ('.' + $Ext).ToLowerInvariant()
}

function Match-AnyPattern {
    param(
        [string]$Value,
        [string[]]$Patterns
    )
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
    return $false
}

function Match-NoPattern {
    param(
        [string]$Value,
        [string[]]$Patterns
    )
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $false }
    }
    return $true
}

function Get-DefaultTargets {
    param([string[]]$Target)

    $targets = New-Object System.Collections.Generic.List[string]

    foreach ($t in $Target) {
        switch ($t) {
            'UserTemp' {
                # Covers both %TEMP% and typical user temp patterns
                $targets.Add($env:TEMP)
                $targets.Add((Join-Path $env:USERPROFILE 'AppData\Local\Temp'))
            }
            'WindowsTemp' {
                $targets.Add((Join-Path $env:WINDIR 'Temp'))
            }
            'Prefetch' {
                $targets.Add((Join-Path $env:WINDIR 'Prefetch'))
            }
            'BrowserCaches' {
                # Best-effort locations (safe to clean older items; browsers may hold open files)
                $targets.Add((Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Cache'))
                $targets.Add((Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Cache'))
                $targets.Add((Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'))
            }
            'AllCommon' {
                # Expand to common set
                foreach ($x in (Get-DefaultTargets -Target @('UserTemp','WindowsTemp','Prefetch','BrowserCaches'))) {
                    $targets.Add($x)
                }
            }
        }
    }

    # Remove null/empty + de-dupe
    $targets |
        Where-Object { $_ -and $_.Trim() } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
}

function Safe-RootAllowed {
    param([string]$Root)

    # Guardrail: avoid cleaning drive roots or critical folders unintentionally.
    $r = $Root.TrimEnd('\')
    if ($r -match '^[A-Za-z]:$') { return $false }         # C:
    if ($r -ieq $env:SystemDrive) { return $false }        # C:\ (after trim may be C:)
    if ($r -ieq "$($env:SystemDrive)\") { return $false }  # C:\ exact
    return $true
}

function Get-Candidates {
    param(
        [string]$Root,
        [datetime]$Cutoff,
        [string[]]$IncExt,
        [string[]]$ExcExt,
        [string[]]$IncludePattern,
        [string[]]$ExcludePattern,
        [bool]$IncludeDirectories
    )

    $items = @()

    # Files first
    try {
        $files = Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue
        foreach ($f in @($files)) {
            if ($f.LastWriteTime -gt $Cutoff) { continue }

            $ext = ([System.IO.Path]::GetExtension($f.FullName)).ToLowerInvariant()
            if ($IncExt -and $IncExt.Count -gt 0) {
                if ($IncExt -notcontains $ext) { continue }
            }
            if ($ExcExt -and $ExcExt.Count -gt 0) {
                if ($ExcExt -contains $ext) { continue }
            }

            if (-not (Match-AnyPattern -Value $f.Name -Patterns $IncludePattern)) { continue }
            if (-not (Match-NoPattern -Value $f.Name -Patterns $ExcludePattern)) { continue }

            $items += $f
        }
    } catch {}

    if ($IncludeDirectories) {
        try {
            # We only delete directories if empty, and only after file deletion pass.
            $dirs = Get-ChildItem -LiteralPath $Root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
                    Sort-Object FullName -Descending
            foreach ($d in @($dirs)) {
                if ($d.LastWriteTime -gt $Cutoff) { continue }
                $items += $d
            }
        } catch {}
    }

    $items
}

function Clear-TempDirectoriesLocal {
    param(
        [string[]]$Roots,
        [int]$OlderThanDays,
        [string[]]$IncludeExtensions,
        [string[]]$ExcludeExtensions,
        [string[]]$IncludePattern,
        [string[]]$ExcludePattern,
        [bool]$IncludeDirectories,
        [bool]$RemoveEmptyRoot,
        [bool]$Force,
        [bool]$PassThru
    )

    $cutoff = (Get-Date).AddDays(-$OlderThanDays)

    $incExt = @()
    if ($IncludeExtensions) { $incExt = @($IncludeExtensions | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }) }

    $excExt = @()
    if ($ExcludeExtensions) { $excExt = @($ExcludeExtensions | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }) }

    $detail = New-Object System.Collections.Generic.List[object]
    $summary = New-Object System.Collections.Generic.List[object]

    foreach ($root in $Roots) {
        if (-not $root) { continue }
        $rootPath = $root.Trim()

        if (-not (Test-Path -LiteralPath $rootPath)) {
            $summary.Add([PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                RootPath     = $rootPath
                Status       = 'NotFound'
                FilesDeleted = 0
                DirsDeleted  = 0
                BytesFreed   = 0
                MBFreed      = 0
                GBFreed      = 0
                Notes        = 'Path not found'
            })
            continue
        }

        if (-not (Safe-RootAllowed -Root $rootPath)) {
            $summary.Add([PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                RootPath     = $rootPath
                Status       = 'Skipped'
                FilesDeleted = 0
                DirsDeleted  = 0
                BytesFreed   = 0
                MBFreed      = 0
                GBFreed      = 0
                Notes        = 'Guardrail: root path not allowed'
            })
            continue
        }

        $filesDeleted = 0
        $dirsDeleted  = 0
        $bytesFreed   = 0

        $candidates = Get-Candidates -Root $rootPath -Cutoff $cutoff -IncExt $incExt -ExcExt $excExt `
            -IncludePattern $IncludePattern -ExcludePattern $ExcludePattern -IncludeDirectories:$IncludeDirectories

        foreach ($item in @($candidates)) {

            try {
                if ($item.PSIsContainer) {
                    # Only delete directories if empty
                    $hasChildren = @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue).Count -gt 0
                    if ($hasChildren) { continue }

                    if ($PSCmdlet.ShouldProcess($item.FullName, "Remove empty directory")) {
                        Remove-Item -LiteralPath $item.FullName -Force:$Force -ErrorAction Stop
                        $dirsDeleted++

                        if ($PassThru) {
                            $detail.Add([PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                RootPath     = $rootPath
                                ItemType     = 'Directory'
                                FullName     = $item.FullName
                                BytesFreed   = 0
                                Action       = 'Removed'
                                Notes        = $null
                            })
                        }
                    }
                }
                else {
                    $len = [long]$item.Length

                    if ($PSCmdlet.ShouldProcess($item.FullName, "Remove file")) {
                        Remove-Item -LiteralPath $item.FullName -Force:$Force -ErrorAction Stop
                        $filesDeleted++
                        $bytesFreed += $len

                        if ($PassThru) {
                            $detail.Add([PSCustomObject]@{
                                ComputerName = $env:COMPUTERNAME
                                RootPath     = $rootPath
                                ItemType     = 'File'
                                FullName     = $item.FullName
                                BytesFreed   = $len
                                Action       = 'Removed'
                                Notes        = $null
                            })
                        }
                    }
                }
            }
            catch {
                if ($PassThru) {
                    $detail.Add([PSCustomObject]@{
                        ComputerName = $env:COMPUTERNAME
                        RootPath     = $rootPath
                        ItemType     = if ($item.PSIsContainer) { 'Directory' } else { 'File' }
                        FullName     = $item.FullName
                        BytesFreed   = 0
                        Action       = 'Failed'
                        Notes        = $_.Exception.Message
                    })
                }
            }
        }

        if ($RemoveEmptyRoot) {
            try {
                $rootChildren = @(Get-ChildItem -LiteralPath $rootPath -Force -ErrorAction SilentlyContinue).Count
                if ($rootChildren -eq 0) {
                    if ($PSCmdlet.ShouldProcess($rootPath, "Remove empty root directory")) {
                        Remove-Item -LiteralPath $rootPath -Force:$Force -ErrorAction Stop
                        $dirsDeleted++
                    }
                }
            } catch {}
        }

        $summary.Add([PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            RootPath     = $rootPath
            Status       = 'Completed'
            FilesDeleted = $filesDeleted
            DirsDeleted  = $dirsDeleted
            BytesFreed   = $bytesFreed
            MBFreed      = [math]::Round($bytesFreed / 1MB, 2)
            GBFreed      = [math]::Round($bytesFreed / 1GB, 2)
            Notes        = "Cutoff: older than $OlderThanDays days"
        })
    }

    if ($PassThru) { return $detail }
    return $summary
}

# Build root list from presets + custom paths
$roots = New-Object System.Collections.Generic.List[string]

foreach ($r in (Get-DefaultTargets -Target $Target)) { $roots.Add($r) }
if ($Path) { foreach ($p in $Path) { if ($p) { $roots.Add($p) } } }

$roots = $roots | Where-Object { $_ -and $_.Trim() } | Sort-Object -Unique

$results = New-Object System.Collections.Generic.List[object]

# Remote execution fan-out
if ($ComputerName -and $ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit -ErrorAction Stop
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Clear-TempDirectoriesLocal} -ArgumentList @(
            $roots,
            $OlderThanDays,
            $IncludeExtensions,
            $ExcludeExtensions,
            $IncludePattern,
            $ExcludePattern,
            [bool]$IncludeDirectories,
            [bool]$RemoveEmptyRoot,
            [bool]$Force,
            [bool]$PassThru
        ) -ErrorAction Stop

        foreach ($r in @($rows)) { $results.Add($r) }
    }
    finally {
        if ($sessions) { $sessions | Remove-PSSession -ErrorAction SilentlyContinue }
    }
}
else {
    foreach ($c in $ComputerName) {
        $target = $c.Trim()
        if ([string]::IsNullOrWhiteSpace($target)) { continue }

        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Clear-TempDirectoriesLocal -Roots $roots `
                -OlderThanDays $OlderThanDays `
                -IncludeExtensions $IncludeExtensions `
                -ExcludeExtensions $ExcludeExtensions `
                -IncludePattern $IncludePattern `
                -ExcludePattern $ExcludePattern `
                -IncludeDirectories:$IncludeDirectories `
                -RemoveEmptyRoot:$RemoveEmptyRoot `
                -Force:$Force `
                -PassThru:$PassThru
        }
        else {
            $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Clear-TempDirectoriesLocal} -ArgumentList @(
                $roots,
                $OlderThanDays,
                $IncludeExtensions,
                $ExcludeExtensions,
                $IncludePattern,
                $ExcludePattern,
                [bool]$IncludeDirectories,
                [bool]$RemoveEmptyRoot,
                [bool]$Force,
                [bool]$PassThru
            ) -ErrorAction Stop
        }

        foreach ($r in @($rows)) { $results.Add($r) }
    }
}

$results
