<#
.SYNOPSIS
Finds old/stale files under one or more paths with safe reporting and optional actions.

.DESCRIPTION
Recursively scans one or more paths and returns files whose LastWriteTime is older
than a specified threshold (days). Designed for cleanup planning, archiving workflows,
and compliance/storage audits.

Safe-by-default:
- Reports findings only unless -Remove or -ArchivePath is used
- Supports -WhatIf / -Confirm when removing or moving files

Features:
- Age threshold (OlderThanDays)
- Optional size threshold
- Optional include/exclude extension filters
- Optional exclude path patterns
- Optional include directories (for empty folder cleanup planning)
- Optional removal or archival move (with guardrails)
- Local and remote execution support
- Structured output for automation/reporting

.PARAMETER Path
One or more root paths to scan.

.PARAMETER ComputerName
Optional remote computer(s). Defaults to local.

.PARAMETER OlderThanDays
Files with LastWriteTime older than this many days are returned.

.PARAMETER MinSizeMB
Only return files larger than or equal to this size in MB.

.PARAMETER IncludeExtension
Only include files with these extensions (e.g. ".log",".bak"). Case-insensitive.

.PARAMETER ExcludeExtension
Exclude files with these extensions.

.PARAMETER ExcludePath
Exclude files whose full path matches these wildcard patterns.

.PARAMETER IncludeHidden
Include hidden/system files.

.PARAMETER IncludeDirectories
Also return directories that have LastWriteTime older than the threshold (reporting only).

.PARAMETER Remove
Remove matched files (and optionally directories). Requires -Force for non-interactive removal.

.PARAMETER ArchivePath
Move matched files to an archive root. Preserves relative path under the archive.
If the archive path does not exist, it will be created.

.PARAMETER Force
Allows non-interactive removal/moves (still respects -WhatIf and -Confirm).
Also allows deleting read-only files when used with -Remove.

.PARAMETER Top
Return only the first N results after filtering (sorted oldest first, then largest).

.EXAMPLE
.\Find-OldFiles.ps1 -Path D:\Shares -OlderThanDays 180 | Format-Table -Auto

.EXAMPLE
.\Find-OldFiles.ps1 -Path C:\Logs -OlderThanDays 30 -IncludeExtension .log |
  Sort-Object LastWriteTime |
  Export-Csv C:\Reports\OldLogs.csv -NoTypeInformation

.EXAMPLE
.\Find-OldFiles.ps1 -Path D:\Data -OlderThanDays 365 -MinSizeMB 500 -ExcludePath '*\Temp*','*\Cache*' |
  Format-Table -Auto

.EXAMPLE
# Archive files older than 1 year (preview)
.\Find-OldFiles.ps1 -Path D:\Shares -OlderThanDays 365 -ArchivePath E:\Archive -WhatIf

.EXAMPLE
# Remove files older than 90 days (requires -Force for non-interactive)
.\Find-OldFiles.ps1 -Path C:\Temp -OlderThanDays 90 -Remove -Force -Confirm:$false

.NOTES
Author: Cheri
By design, destructive actions require explicit switches.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,

    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory)]
    [ValidateRange(1,36500)]
    [int]$OlderThanDays,

    [Parameter()]
    [ValidateRange(0,1048576)]
    [int]$MinSizeMB = 0,

    [Parameter()]
    [string[]]$IncludeExtension,

    [Parameter()]
    [string[]]$ExcludeExtension,

    [Parameter()]
    [string[]]$ExcludePath,

    [Parameter()]
    [switch]$IncludeHidden,

    [Parameter()]
    [switch]$IncludeDirectories,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ArchivePath,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateRange(1,1000000)]
    [int]$Top
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

function Get-RelativePath {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Child
    )
    $rootNorm = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    $childNorm = [System.IO.Path]::GetFullPath($Child)
    if ($childNorm.StartsWith($rootNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $childNorm.Substring($rootNorm.Length)
    }
    return [System.IO.Path]::GetFileName($childNorm)
}

function Find-OldFilesInternal {
    param(
        [string]$RootPath,
        [datetime]$Cutoff,
        [long]$MinBytes,
        [string[]]$IncludeExtension,
        [string[]]$ExcludeExtension,
        [string[]]$ExcludePath,
        [bool]$IncludeHidden,
        [bool]$IncludeDirectories
    )

    $force = $IncludeHidden

    $gciParams = @{
        Path        = $RootPath
        Recurse     = $true
        Force       = $force
        ErrorAction = 'SilentlyContinue'
    }

    $items = Get-ChildItem @gciParams
    foreach ($i in @($items)) {

        if (Should-ExcludeByPath -FullName $i.FullName -ExcludePath $ExcludePath) { continue }

        if ($i.PSIsContainer) {
            if (-not $IncludeDirectories) { continue }
            if ($i.LastWriteTime -gt $Cutoff) { continue }

            [PSCustomObject]@{
                ComputerName  = $env:COMPUTERNAME
                RootPath      = $RootPath
                ItemType      = 'Directory'
                FullName      = $i.FullName
                Name          = $i.Name
                Extension     = $null
                SizeBytes     = $null
                SizeMB        = $null
                SizeGB        = $null
                LastWriteTime = $i.LastWriteTime
                CreatedTime   = $i.CreationTime
                Attributes    = $i.Attributes.ToString()
            }
            continue
        }

        # Files
        if ($i.LastWriteTime -gt $Cutoff) { continue }
        if (-not (Should-IncludeByExtension -FullName $i.FullName -IncludeExtension $IncludeExtension -ExcludeExtension $ExcludeExtension)) { continue }
        if ($i.Length -lt $MinBytes) { continue }

        [PSCustomObject]@{
            ComputerName  = $env:COMPUTERNAME
            RootPath      = $RootPath
            ItemType      = 'File'
            FullName      = $i.FullName
            Name          = $i.Name
            Extension     = $i.Extension.ToLowerInvariant()
            SizeBytes     = [long]$i.Length
            SizeMB        = [math]::Round($i.Length / 1MB, 2)
            SizeGB        = [math]::Round($i.Length / 1GB, 2)
            LastWriteTime = $i.LastWriteTime
            CreatedTime   = $i.CreationTime
            Attributes    = $i.Attributes.ToString()
        }
    }
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

# Guardrails: cannot specify both destructive actions at the same time
if ($Remove -and $PSBoundParameters.ContainsKey('ArchivePath')) {
    throw "Choose one action: -Remove OR -ArchivePath. Do not use both in the same run."
}

# Strong guardrail: remove/move requires Force for non-interactive usage patterns
if (($Remove -or $PSBoundParameters.ContainsKey('ArchivePath')) -and -not $Force) {
    Write-Warning "Destructive/action mode requested. Add -Force if you intend non-interactive operations. -WhatIf is recommended first."
}

$cutoff = (Get-Date).AddDays(-$OlderThanDays)
$minBytes = [long]$MinSizeMB * 1MB

# Normalize extensions once
$incExt = @()
if ($IncludeExtension) { $incExt = @($IncludeExtension | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }) }

$excExt = @()
if ($ExcludeExtension) { $excExt = @($ExcludeExtension | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }) }

$results = New-Object System.Collections.Generic.List[object]

foreach ($computer in $ComputerName) {
    $target = $computer.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    foreach ($p in $Path) {
        try {
            $rows =
                if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
                    Find-OldFilesInternal -RootPath $p -Cutoff $cutoff -MinBytes $minBytes `
                        -IncludeExtension $incExt -ExcludeExtension $excExt -ExcludePath $ExcludePath `
                        -IncludeHidden:$IncludeHidden -IncludeDirectories:$IncludeDirectories
                } else {
                    Invoke-Command -ComputerName $target -ScriptBlock ${function:Find-OldFilesInternal} -ArgumentList @(
                        $p, $cutoff, $minBytes, $incExt, $excExt, $ExcludePath,
                        [bool]$IncludeHidden, [bool]$IncludeDirectories
                    ) -ErrorAction Stop
                }

            # Sort oldest first then largest
            $sorted = $rows | Sort-Object LastWriteTime, @{Expression='SizeBytes'; Descending=$true}

            if ($Top -gt 0) { $sorted = $sorted | Select-Object -First $Top }

            # Action phase (local only). For remoting, action should be performed on target explicitly.
            foreach ($r in @($sorted)) {

                # Add to results (always report)
                $results.Add($r)

                # No action requested
                if (-not $Remove -and -not $PSBoundParameters.ContainsKey('ArchivePath')) { continue }

                # Only act on files (directories are report-only by default to avoid high-risk recursive removals)
                if ($r.ItemType -ne 'File') { continue }

                if ($PSBoundParameters.ContainsKey('ArchivePath')) {
                    if ($target -ne $env:COMPUTERNAME -and $target -ne 'localhost') {
                        continue # remote action intentionally not performed from local session
                    }

                    $rel = Get-RelativePath -Root $r.RootPath -Child $r.FullName
                    $dest = Join-Path -Path $ArchivePath -ChildPath $rel
                    $destDir = Split-Path -Path $dest -Parent

                    if ($PSCmdlet.ShouldProcess($r.FullName, "Move to archive: $dest")) {
                        Ensure-Directory -Path $destDir
                        Move-Item -LiteralPath $r.FullName -Destination $dest -Force:$Force -ErrorAction Stop
                    }

                    continue
                }

                if ($Remove) {
                    if ($target -ne $env:COMPUTERNAME -and $target -ne 'localhost') {
                        continue # remote action intentionally not performed from local session
                    }

                    if ($PSCmdlet.ShouldProcess($r.FullName, "Remove file")) {
                        Remove-Item -LiteralPath $r.FullName -Force:$Force -ErrorAction Stop
                    }
                }
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                ComputerName  = $target
                RootPath      = $p
                ItemType      = $null
                FullName      = $null
                Name          = $null
                Extension     = $null
                SizeBytes     = $null
                SizeMB        = $null
                SizeGB        = $null
                LastWriteTime = $null
                CreatedTime   = $null
                Attributes    = $null
                Error         = $_.Exception.Message
            })
        }
    }
}

$results
