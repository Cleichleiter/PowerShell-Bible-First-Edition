<#
.SYNOPSIS
Finds large files under one or more paths with optional filters and reporting output.

.DESCRIPTION
Recursively scans one or more paths and returns files exceeding a size threshold.
Designed for ops use-cases: cleanup planning, migration prep, storage audits, and
identifying files that negatively impact backups (ISOs, PSTs, DB backups, etc.).

Features:
- Minimum size threshold in MB (or bytes via -MinSizeBytes)
- Optional file extension filter (Include/Exclude)
- Optional last write age filters (older/newer than N days)
- Optional hashing (can be slow)
- Local and remote execution support
- Structured object output suitable for Export-Csv

.PARAMETER Path
One or more root paths to scan.

.PARAMETER ComputerName
Optional remote computer(s). Defaults to local.

.PARAMETER MinSizeMB
Return files at or above this size in MB. Default: 500 MB.

.PARAMETER MinSizeBytes
Optional override size threshold in bytes (takes precedence over MinSizeMB).

.PARAMETER IncludeExtension
Only include files with these extensions (e.g. ".pst",".iso"). Case-insensitive.

.PARAMETER ExcludeExtension
Exclude files with these extensions.

.PARAMETER OlderThanDays
Only include files with LastWriteTime older than this many days.

.PARAMETER NewerThanDays
Only include files with LastWriteTime newer than this many days.

.PARAMETER ExcludePath
Exclude files whose full path matches these wildcard patterns.

.PARAMETER Top
Return only the top N largest files per target/path scope after filtering.

.PARAMETER IncludeHash
Include SHA256 hash for each file (slow; use for targeted validation only).

.PARAMETER IncludeHidden
Include hidden/system files.

.EXAMPLE
.\Get-LargeFiles.ps1 -Path C:\Data | Format-Table -Auto

.EXAMPLE
.\Get-LargeFiles.ps1 -Path D:\Shares -MinSizeMB 1024 -Top 50 |
  Sort-Object SizeGB -Descending |
  Format-Table -Auto

.EXAMPLE
.\Get-LargeFiles.ps1 -Path C:\Users -IncludeExtension .pst -MinSizeMB 250 |
  Export-Csv C:\Reports\LargePSTs.csv -NoTypeInformation

.EXAMPLE
.\Get-LargeFiles.ps1 -Path D:\ -ExcludePath 'D:\Shares\Temp*','D:\Shares\Cache*' -OlderThanDays 180 -MinSizeMB 500 |
  Export-Csv C:\Reports\LargeOldFiles.csv -NoTypeInformation

.EXAMPLE
.\Get-LargeFiles.ps1 -ComputerName FS01,FS02 -Path D:\Shares -MinSizeMB 2048 -Top 25 |
  Export-Csv C:\Reports\TopLargeFiles.csv -NoTypeInformation

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
    [ValidateRange(1,1048576)]
    [int]$MinSizeMB = 500,

    [Parameter()]
    [ValidateRange(1,[long]::MaxValue)]
    [long]$MinSizeBytes,

    [Parameter()]
    [string[]]$IncludeExtension,

    [Parameter()]
    [string[]]$ExcludeExtension,

    [Parameter()]
    [ValidateRange(0,36500)]
    [int]$OlderThanDays,

    [Parameter()]
    [ValidateRange(0,36500)]
    [int]$NewerThanDays,

    [Parameter()]
    [string[]]$ExcludePath,

    [Parameter()]
    [ValidateRange(1,1000000)]
    [int]$Top,

    [Parameter()]
    [switch]$IncludeHash,

    [Parameter()]
    [switch]$IncludeHidden
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Extension {
    param([string]$Ext)
    if ([string]::IsNullOrWhiteSpace($Ext)) { return $null }
    if ($Ext.StartsWith('.')) { return $Ext.ToLowerInvariant() }
    return ('.' + $Ext).ToLowerInvariant()
}

function Should-ExcludeByPath {
    param([string]$FullName,[string[]]$ExcludePath)
    if (-not $ExcludePath) { return $false }
    foreach ($pattern in $ExcludePath) {
        if ($FullName -like $pattern) { return $true }
    }
    return $false
}

function Should-IncludeByExtension {
    param(
        [string]$FullName,
        [string[]]$IncludeExtension,
        [string[]]$ExcludeExtension
    )

    $ext = [System.IO.Path]::GetExtension($FullName).ToLowerInvariant()

    if ($IncludeExtension -and $IncludeExtension.Count -gt 0) {
        if ($IncludeExtension -notcontains $ext) { return $false }
    }

    if ($ExcludeExtension -and $ExcludeExtension.Count -gt 0) {
        if ($ExcludeExtension -contains $ext) { return $false }
    }

    return $true
}

function Should-IncludeByAge {
    param(
        [datetime]$LastWriteTime,
        [int]$OlderThanDays,
        [int]$NewerThanDays
    )

    $now = Get-Date

    if ($PSBoundParameters.ContainsKey('OlderThanDays')) {
        if ($LastWriteTime -gt $now.AddDays(-$OlderThanDays)) { return $false }
    }

    if ($PSBoundParameters.ContainsKey('NewerThanDays')) {
        if ($LastWriteTime -lt $now.AddDays(-$NewerThanDays)) { return $false }
    }

    return $true
}

function Get-LargeFilesInternal {
    param(
        [string]$RootPath,
        [long]$MinSizeBytes,
        [string[]]$IncludeExtension,
        [string[]]$ExcludeExtension,
        [int]$OlderThanDays,
        [int]$NewerThanDays,
        [string[]]$ExcludePath,
        [int]$Top,
        [bool]$IncludeHash,
        [bool]$IncludeHidden
    )

    $gciParams = @{
        Path        = $RootPath
        Recurse     = $true
        File        = $true
        Force       = $IncludeHidden
        ErrorAction = 'SilentlyContinue'
    }

    $files = Get-ChildItem @gciParams

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($f in @($files)) {

        if (Should-ExcludeByPath -FullName $f.FullName -ExcludePath $ExcludePath) { continue }
        if (-not (Should-IncludeByExtension -FullName $f.FullName -IncludeExtension $IncludeExtension -ExcludeExtension $ExcludeExtension)) { continue }
        if (-not (Should-IncludeByAge -LastWriteTime $f.LastWriteTime -OlderThanDays $OlderThanDays -NewerThanDays $NewerThanDays)) { continue }
        if ($f.Length -lt $MinSizeBytes) { continue }

        $hash = $null
        if ($IncludeHash) {
            try {
                $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
            } catch {
                $hash = $null
            }
        }

        $rows.Add([PSCustomObject]@{
            ComputerName   = $env:COMPUTERNAME
            Path           = $f.DirectoryName
            FullName       = $f.FullName
            Name           = $f.Name
            Extension      = $f.Extension.ToLowerInvariant()
            SizeBytes      = [long]$f.Length
            SizeMB         = [math]::Round($f.Length / 1MB, 2)
            SizeGB         = [math]::Round($f.Length / 1GB, 2)
            LastWriteTime  = $f.LastWriteTime
            CreatedTime    = $f.CreationTime
            Attributes     = $f.Attributes.ToString()
            Sha256         = $hash
        })
    }

    $sorted = $rows | Sort-Object SizeBytes -Descending
    if ($Top -gt 0) {
        $sorted | Select-Object -First $Top
    } else {
        $sorted
    }
}

# Normalize extensions once
$incExt = @()
if ($IncludeExtension) { $incExt = @($IncludeExtension | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }) }

$excExt = @()
if ($ExcludeExtension) { $excExt = @($ExcludeExtension | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }) }

$thresholdBytes = if ($PSBoundParameters.ContainsKey('MinSizeBytes')) { $MinSizeBytes } else { [long]$MinSizeMB * 1MB }

$results = New-Object System.Collections.Generic.List[object]

foreach ($computer in $ComputerName) {
    foreach ($p in $Path) {
        $target = $computer.Trim()
        if ([string]::IsNullOrWhiteSpace($target)) { continue }

        try {
            if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
                $rows = Get-LargeFilesInternal -RootPath $p -MinSizeBytes $thresholdBytes `
                    -IncludeExtension $incExt -ExcludeExtension $excExt `
                    -OlderThanDays $OlderThanDays -NewerThanDays $NewerThanDays `
                    -ExcludePath $ExcludePath -Top $Top `
                    -IncludeHash:$IncludeHash -IncludeHidden:$IncludeHidden
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-LargeFilesInternal} -ArgumentList @(
                    $p, $thresholdBytes, $incExt, $excExt, $OlderThanDays, $NewerThanDays, $ExcludePath, $Top,
                    [bool]$IncludeHash, [bool]$IncludeHidden
                ) -ErrorAction Stop
            }

            foreach ($r in @($rows)) { $results.Add($r) }
        }
        catch {
            $results.Add([PSCustomObject]@{
                ComputerName  = $target
                Path          = $p
                FullName      = $null
                Name          = $null
                Extension     = $null
                SizeBytes     = $null
                SizeMB        = $null
                SizeGB        = $null
                LastWriteTime = $null
                CreatedTime   = $null
                Attributes    = $null
                Sha256        = $null
                Error         = $_.Exception.Message
            })
        }
    }
}

$results
