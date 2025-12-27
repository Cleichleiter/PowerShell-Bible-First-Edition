<#
.SYNOPSIS
Captures disk free-space snapshots for trend tracking and capacity planning.

.DESCRIPTION
Returns one row per logical disk (fixed by default) including:
- Size, Free, Used (Bytes/GB), PercentFree
- Timestamp
- Optional baseline comparison using an existing CSV (delta since most recent prior snapshot)

Designed for:
- Scheduled tasks / RMM recurring execution
- Capacity planning
- Detecting disks that consistently trend downward

Supports local and remote execution via PowerShell remoting.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER DriveType
Filter drive type(s). Default: Fixed. Options: Fixed, Removable, Network, CDROM, RAMDisk, Unknown, All.

.PARAMETER IncludeSystemDriveOnly
Only return the system drive (e.g., C:).

.PARAMETER IncludeAllVolumes
Include volumes without drive letters (requires CIM association query). Default: off.

.PARAMETER MinimumSizeGB
Exclude volumes smaller than this size (GB).

.PARAMETER ExportCsv
If provided, exports the snapshot to CSV.

.PARAMETER Append
When used with -ExportCsv, appends instead of overwriting.

.PARAMETER CompareToCsv
Path to an existing CSV to compare against. Uses the most recent prior snapshot per ComputerName+Drive.
Adds delta fields: FreeBytesDelta, FreeGBDelta, PercentFreeDelta.

.PARAMETER AsOf
Override timestamp. Default: current time.

.PARAMETER ThrottleLimit
Throttle for remoting sessions. Default 16.

.EXAMPLE
.\Get-DiskFreeSpaceTrend.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-DiskFreeSpaceTrend.ps1 -ComputerName FS01,FS02 |
  Export-Csv C:\Reports\DiskSnapshots.csv -NoTypeInformation

.EXAMPLE
# Append a daily snapshot for trending
.\Get-DiskFreeSpaceTrend.ps1 -ExportCsv C:\Reports\DiskTrend.csv -Append

.EXAMPLE
# Compare current snapshot to last stored snapshot in the trend file
.\Get-DiskFreeSpaceTrend.ps1 -CompareToCsv C:\Reports\DiskTrend.csv | Format-Table -Auto

.NOTES
Author: Cheri
Safe to run in production (read-only).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateSet('Fixed','Removable','Network','CDROM','RAMDisk','Unknown','All')]
    [string]$DriveType = 'Fixed',

    [Parameter()]
    [switch]$IncludeSystemDriveOnly,

    [Parameter()]
    [switch]$IncludeAllVolumes,

    [Parameter()]
    [ValidateRange(0,1048576)]
    [int]$MinimumSizeGB = 0,

    [Parameter()]
    [string]$ExportCsv,

    [Parameter()]
    [switch]$Append,

    [Parameter()]
    [string]$CompareToCsv,

    [Parameter()]
    [datetime]$AsOf = (Get-Date),

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Map-DriveType {
    param([string]$DriveType)
    switch ($DriveType) {
        'Unknown'   { return 0 }
        'Removable' { return 2 }
        'Fixed'     { return 3 }
        'Network'   { return 4 }
        'CDROM'     { return 5 }
        'RAMDisk'   { return 6 }
        'All'       { return $null }
    }
}

function Get-DiskSnapshotLocal {
    param(
        [string]$Computer,
        [string]$DriveType,
        [bool]$IncludeSystemDriveOnly,
        [bool]$IncludeAllVolumes,
        [int]$MinimumSizeGB,
        [datetime]$AsOf
    )

    $rows = New-Object System.Collections.Generic.List[object]

    try {
        $driveTypeInt = Map-DriveType -DriveType $DriveType

        if (-not $IncludeAllVolumes) {
            # Win32_LogicalDisk includes drive-letter volumes (fast)
            $filter = @()
            if ($driveTypeInt -ne $null) { $filter += "DriveType = $driveTypeInt" }
            $filterStr = if ($filter.Count -gt 0) { $filter -join ' AND ' } else { $null }

            $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter $filterStr -ErrorAction Stop

            foreach ($d in @($disks)) {
                if ($IncludeSystemDriveOnly -and ($d.DeviceID -ne "$($env:SystemDrive.TrimEnd('\'))")) { continue }

                $sizeBytes = [long]$d.Size
                $freeBytes = [long]$d.FreeSpace

                if ($MinimumSizeGB -gt 0 -and ($sizeBytes -lt ([long]$MinimumSizeGB * 1GB))) { continue }
                if ($sizeBytes -le 0) { continue }

                $usedBytes = $sizeBytes - $freeBytes
                $pctFree = [math]::Round(($freeBytes / $sizeBytes) * 100, 2)

                $rows.Add([PSCustomObject]@{
                    Timestamp      = $AsOf
                    ComputerName   = $env:COMPUTERNAME
                    Drive          = $d.DeviceID
                    VolumeName     = $d.VolumeName
                    FileSystem     = $d.FileSystem
                    DriveType      = $DriveType
                    SizeBytes      = $sizeBytes
                    FreeBytes      = $freeBytes
                    UsedBytes      = $usedBytes
                    SizeGB         = [math]::Round($sizeBytes / 1GB, 2)
                    FreeGB         = [math]::Round($freeBytes / 1GB, 2)
                    UsedGB         = [math]::Round($usedBytes / 1GB, 2)
                    PercentFree    = $pctFree
                    PercentUsed    = [math]::Round(100 - $pctFree, 2)
                    Error          = $null
                })
            }
        }
        else {
            # Include volumes without letters: query Win32_Volume (can be slower)
            $vols = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop

            foreach ($v in @($vols)) {
                if ($driveTypeInt -ne $null -and $v.DriveType -ne $driveTypeInt) { continue }

                $driveLetter = $v.DriveLetter
                if ($IncludeSystemDriveOnly) {
                    if (-not $driveLetter) { continue }
                    if ($driveLetter -ne "$($env:SystemDrive.TrimEnd('\'))") { continue }
                }

                $sizeBytes = [long]$v.Capacity
                $freeBytes = [long]$v.FreeSpace

                if ($MinimumSizeGB -gt 0 -and ($sizeBytes -lt ([long]$MinimumSizeGB * 1GB))) { continue }
                if ($sizeBytes -le 0) { continue }

                $usedBytes = $sizeBytes - $freeBytes
                $pctFree = [math]::Round(($freeBytes / $sizeBytes) * 100, 2)

                $rows.Add([PSCustomObject]@{
                    Timestamp      = $AsOf
                    ComputerName   = $env:COMPUTERNAME
                    Drive          = if ($driveLetter) { $driveLetter } else { '(NoLetter)' }
                    VolumeName     = $v.Label
                    FileSystem     = $v.FileSystem
                    DriveType      = $DriveType
                    SizeBytes      = $sizeBytes
                    FreeBytes      = $freeBytes
                    UsedBytes      = $usedBytes
                    SizeGB         = [math]::Round($sizeBytes / 1GB, 2)
                    FreeGB         = [math]::Round($freeBytes / 1GB, 2)
                    UsedGB         = [math]::Round($usedBytes / 1GB, 2)
                    PercentFree    = $pctFree
                    PercentUsed    = [math]::Round(100 - $pctFree, 2)
                    Error          = $null
                })
            }
        }
    }
    catch {
        $rows.Add([PSCustomObject]@{
            Timestamp      = $AsOf
            ComputerName   = $Computer
            Drive          = $null
            VolumeName     = $null
            FileSystem     = $null
            DriveType      = $DriveType
            SizeBytes      = $null
            FreeBytes      = $null
            UsedBytes      = $null
            SizeGB         = $null
            FreeGB         = $null
            UsedGB         = $null
            PercentFree    = $null
            PercentUsed    = $null
            Error          = $_.Exception.Message
        })
    }

    $rows
}

function Add-ComparisonDeltas {
    param(
        [object[]]$CurrentRows,
        [string]$CompareToCsv
    )

    if (-not $CompareToCsv) { return $CurrentRows }
    if (-not (Test-Path -LiteralPath $CompareToCsv)) { return $CurrentRows }

    try {
        $history = Import-Csv -LiteralPath $CompareToCsv -ErrorAction Stop
        if (-not $history) { return $CurrentRows }

        # Build most recent prior snapshot per ComputerName+Drive
        $latest = @{}

        foreach ($h in $history) {
            if (-not $h.ComputerName -or -not $h.Drive -or -not $h.Timestamp) { continue }

            $key = "$($h.ComputerName)|$($h.Drive)"
            $ts  = $null
            try { $ts = [datetime]$h.Timestamp } catch { continue }

            if (-not $latest.ContainsKey($key) -or $ts -gt $latest[$key].Timestamp) {
                $latest[$key] = [PSCustomObject]@{
                    Timestamp   = $ts
                    FreeBytes   = [long]$h.FreeBytes
                    PercentFree = [double]$h.PercentFree
                }
            }
        }

        foreach ($r in $CurrentRows) {
            $key = "$($r.ComputerName)|$($r.Drive)"
            if ($latest.ContainsKey($key) -and $r.FreeBytes -ne $null -and $r.PercentFree -ne $null) {
                $prior = $latest[$key]

                $freeDelta = [long]$r.FreeBytes - [long]$prior.FreeBytes
                $pctDelta  = [double]$r.PercentFree - [double]$prior.PercentFree

                Add-Member -InputObject $r -NotePropertyName FreeBytesDelta -NotePropertyValue $freeDelta -Force
                Add-Member -InputObject $r -NotePropertyName FreeGBDelta -NotePropertyValue ([math]::Round($freeDelta / 1GB, 2)) -Force
                Add-Member -InputObject $r -NotePropertyName PercentFreeDelta -NotePropertyValue ([math]::Round($pctDelta, 2)) -Force
                Add-Member -InputObject $r -NotePropertyName ComparedToTimestamp -NotePropertyValue $prior.Timestamp -Force
            }
            else {
                Add-Member -InputObject $r -NotePropertyName FreeBytesDelta -NotePropertyValue $null -Force
                Add-Member -InputObject $r -NotePropertyName FreeGBDelta -NotePropertyValue $null -Force
                Add-Member -InputObject $r -NotePropertyName PercentFreeDelta -NotePropertyValue $null -Force
                Add-Member -InputObject $r -NotePropertyName ComparedToTimestamp -NotePropertyValue $null -Force
            }
        }
    }
    catch {
        # If compare fails, return current rows unchanged
    }

    $CurrentRows
}

$results = New-Object System.Collections.Generic.List[object]

# If multiple remote targets, use sessions for efficiency
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit -ErrorAction Stop
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-DiskSnapshotLocal} -ArgumentList @(
            $env:COMPUTERNAME, $DriveType, [bool]$IncludeSystemDriveOnly, [bool]$IncludeAllVolumes, [int]$MinimumSizeGB, [datetime]$AsOf
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
            $rows = Get-DiskSnapshotLocal -Computer $target -DriveType $DriveType `
                -IncludeSystemDriveOnly:$IncludeSystemDriveOnly -IncludeAllVolumes:$IncludeAllVolumes `
                -MinimumSizeGB $MinimumSizeGB -AsOf $AsOf
        }
        else {
            $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-DiskSnapshotLocal} -ArgumentList @(
                $target, $DriveType, [bool]$IncludeSystemDriveOnly, [bool]$IncludeAllVolumes, [int]$MinimumSizeGB, [datetime]$AsOf
            ) -ErrorAction Stop
        }

        foreach ($r in @($rows)) { $results.Add($r) }
    }
}

# Add comparison deltas if requested
$final = Add-ComparisonDeltas -CurrentRows @($results) -CompareToCsv $CompareToCsv

# Export if requested
if ($ExportCsv) {
    if ($Append -and (Test-Path -LiteralPath $ExportCsv)) {
        $final | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Append
    }
    else {
        $final | Export-Csv -LiteralPath $ExportCsv -NoTypeInformation
    }
}

$final
