<#
.SYNOPSIS
Calculates folder size and file counts with optional depth and exclusions.

.DESCRIPTION
Recursively calculates folder sizes for one or more paths.
Designed for operational use: migration sizing, disk growth analysis,
profile audits, and cleanup planning.

Features:
- Safe read-only by default
- Optional depth limiting
- Path exclusions (wildcards supported)
- Local and remote execution
- Object-based output suitable for reporting

.PARAMETER Path
One or more root paths to analyze.

.PARAMETER ComputerName
Optional remote computer(s). Defaults to local.

.PARAMETER Depth
Limit recursion depth. 0 = root only. Default: unlimited.

.PARAMETER ExcludePath
Exclude paths matching these patterns (wildcards allowed).

.PARAMETER IncludeFiles
Include per-file counts and total file size metrics.

.PARAMETER MinSizeMB
Only return folders larger than this size (MB).

.PARAMETER IncludeHidden
Include hidden and system files.

.EXAMPLE
.\Get-FolderSize.ps1 -Path C:\Data | Format-Table -Auto

.EXAMPLE
.\Get-FolderSize.ps1 -Path C:\Users -Depth 1 |
  Sort-Object SizeGB -Descending |
  Format-Table -Auto

.EXAMPLE
.\Get-FolderSize.ps1 -Path D:\Shares -ExcludePath '*\Temp*','*\Cache*' |
  Export-Csv C:\Reports\FolderSizes.csv -NoTypeInformation

.EXAMPLE
.\Get-FolderSize.ps1 -Path C:\Profiles -MinSizeMB 500 | Format-Table -Auto

.NOTES
Author: Cheri
Safe to run in production (read-only).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,

    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(0,100)]
    [int]$Depth = -1,

    [Parameter()]
    [string[]]$ExcludePath,

    [Parameter()]
    [switch]$IncludeFiles,

    [Parameter()]
    [ValidateRange(0,1048576)]
    [int]$MinSizeMB = 0,

    [Parameter()]
    [switch]$IncludeHidden
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Should-ExcludePath {
    param(
        [string]$CurrentPath,
        [string[]]$ExcludePath
    )
    if (-not $ExcludePath) { return $false }

    foreach ($pattern in $ExcludePath) {
        if ($CurrentPath -like $pattern) { return $true }
    }
    return $false
}

function Get-FolderSizeInternal {
    param(
        [string]$RootPath,
        [int]$Depth,
        [string[]]$ExcludePath,
        [bool]$IncludeFiles,
        [bool]$IncludeHidden
    )

    $items = Get-ChildItem -Path $RootPath -Directory -Force:$IncludeHidden -ErrorAction SilentlyContinue

    if ($Depth -eq 0) {
        $items = Get-Item -Path $RootPath -Force:$IncludeHidden -ErrorAction Stop
    }

    foreach ($item in $items) {
        if (Should-ExcludePath -CurrentPath $item.FullName -ExcludePath $ExcludePath) {
            continue
        }

        $fileParams = @{
            Path        = $item.FullName
            Recurse     = $true
            Force       = $IncludeHidden
            ErrorAction = 'SilentlyContinue'
        }

        $files = Get-ChildItem @fileParams -File

        $totalBytes = ($files | Measure-Object Length -Sum).Sum
        $fileCount  = $files.Count

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Path         = $item.FullName
            SizeBytes    = $totalBytes
            SizeMB       = [math]::Round($totalBytes / 1MB, 2)
            SizeGB       = [math]::Round($totalBytes / 1GB, 2)
            FileCount    = if ($IncludeFiles) { $fileCount } else { $null }
            LastWrite    = $item.LastWriteTime
        }

        if ($Depth -gt 0 -or $Depth -eq -1) {
            $nextDepth = if ($Depth -gt 0) { $Depth - 1 } else { -1 }
            Get-FolderSizeInternal -RootPath $item.FullName `
                -Depth $nextDepth `
                -ExcludePath $ExcludePath `
                -IncludeFiles $IncludeFiles `
                -IncludeHidden $IncludeHidden
        }
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($computer in $ComputerName) {
    foreach ($p in $Path) {
        try {
            if ($computer -eq $env:COMPUTERNAME -or $computer -eq 'localhost') {
                $rows = Get-FolderSizeInternal -RootPath $p `
                    -Depth $Depth `
                    -ExcludePath $ExcludePath `
                    -IncludeFiles:$IncludeFiles `
                    -IncludeHidden:$IncludeHidden
            }
            else {
                $rows = Invoke-Command -ComputerName $computer -ScriptBlock ${function:Get-FolderSizeInternal} `
                    -ArgumentList $p, $Depth, $ExcludePath, $IncludeFiles.IsPresent, $IncludeHidden.IsPresent
            }

            foreach ($r in $rows) {
                if ($r.SizeMB -ge $MinSizeMB) {
                    $results.Add($r)
                }
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                ComputerName = $computer
                Path         = $p
                SizeBytes    = $null
                SizeMB       = $null
                SizeGB       = $null
                FileCount    = $null
                LastWrite    = $null
                Error        = $_.Exception.Message
            })
        }
    }
}

$results
