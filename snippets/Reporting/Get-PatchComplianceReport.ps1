<#
.SYNOPSIS
Generates a patch compliance report using safe, read-only signals.

.DESCRIPTION
This script provides a practical patch compliance snapshot per computer by combining:
- Installed hotfix inventory (Win32_QuickFixEngineering)
- OS install date + build metadata (Win32_OperatingSystem)
- Reboot pending detection (common registry/component-based signals)
- "Recency" metrics (days since latest hotfix / days since last boot)

Important note:
This script does NOT query Windows Update to enumerate missing patches unless you add an update source.
In MSP environments, "compliance" often means: "recent patch installed + no pending reboot + patch cadence within SLA".

Outputs one object per computer, optionally including detailed hotfix rows.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER ComplianceDays
Defines the patch recency SLA: latest installed hotfix must be within this many days. Default 35.

.PARAMETER IncludeHotfixes
Include a Hotfixes property containing the installed hotfix list (can be large).

.PARAMETER TopHotfixes
When -IncludeHotfixes is used, limit to the most recent N hotfixes. Default 25.

.PARAMETER IncludePendingRebootSignals
Include which reboot signals were detected (helps troubleshooting).

.PARAMETER SkipHotfixQuery
Skips hotfix enumeration (faster). Compliance then uses OS install/boot signals only.

.EXAMPLE
.\Get-PatchComplianceReport.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-PatchComplianceReport.ps1 -ComputerName PC01,PC02 -ComplianceDays 30 |
  Export-Csv C:\Reports\PatchCompliance.csv -NoTypeInformation

.EXAMPLE
# Include most recent hotfix rows (for audit evidence)
.\Get-PatchComplianceReport.ps1 -IncludeHotfixes -TopHotfixes 15 | Format-List

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(1,365)]
    [int]$ComplianceDays = 35,

    [Parameter()]
    [switch]$IncludeHotfixes,

    [Parameter()]
    [ValidateRange(1,500)]
    [int]$TopHotfixes = 25,

    [Parameter()]
    [switch]$IncludePendingRebootSignals,

    [Parameter()]
    [switch]$SkipHotfixQuery
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-PendingRebootLocal {
    # Best-effort signals commonly used in enterprise patching workflows
    $signals = New-Object System.Collections.Generic.List[string]

    # 1) Component Based Servicing
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $signals.Add('CBS:RebootPending')
    }

    # 2) Windows Update
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $signals.Add('WU:RebootRequired')
    }

    # 3) PendingFileRenameOperations
    try {
        $p = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction Stop
        if ($p.PendingFileRenameOperations) { $signals.Add('SessionMgr:PendingFileRenameOperations') }
    } catch {}

    # 4) Domain join / computer rename signal
    try {
        $activeName  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction Stop).ComputerName
        $pendingName = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -ErrorAction Stop).ComputerName
        if ($activeName -and $pendingName -and ($activeName -ne $pendingName)) {
            $signals.Add('ComputerName:RenamePending')
        }
    } catch {}

    # 5) SCCM client signal (if present)
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM\RebootPending') {
        $signals.Add('SCCM:RebootPending')
    }

    [PSCustomObject]@{
        IsPendingReboot = ($signals.Count -gt 0)
        Signals         = @($signals)
    }
}

function Get-PatchComplianceLocal {
    param(
        [int]$ComplianceDays,
        [bool]$IncludeHotfixes,
        [int]$TopHotfixes,
        [bool]$IncludePendingRebootSignals,
        [bool]$SkipHotfixQuery
    )

    $now = Get-Date

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop

        $lastBoot = $os.LastBootUpTime
        $uptime = $now - $lastBoot

        $pending = Test-PendingRebootLocal

        $hotfixes = @()
        $latestHotfix = $null
        $latestHotfixDate = $null
        $daysSinceLatestHotfix = $null

        if (-not $SkipHotfixQuery) {
            try {
                $hotfixes = Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop |
                    Select-Object HotFixID, InstalledOn, Description, InstalledBy, Caption

                # Parse InstalledOn safely (varies by locale)
                $hotfixesWithDate = foreach ($h in @($hotfixes)) {
                    $dt = $null
                    if ($h.InstalledOn) {
                        try { $dt = [datetime]$h.InstalledOn } catch { $dt = $null }
                    }
                    [PSCustomObject]@{
                        HotFixID     = $h.HotFixID
                        InstalledOn  = $dt
                        Description  = $h.Description
                        InstalledBy  = $h.InstalledBy
                        Caption      = $h.Caption
                    }
                }

                $latest = $hotfixesWithDate |
                    Where-Object { $_.InstalledOn } |
                    Sort-Object InstalledOn -Descending |
                    Select-Object -First 1

                if ($latest) {
                    $latestHotfix = $latest.HotFixID
                    $latestHotfixDate = $latest.InstalledOn
                    $daysSinceLatestHotfix = [math]::Round(($now - $latestHotfixDate).TotalDays, 2)
                }

                if ($IncludeHotfixes) {
                    $hotfixes = $hotfixesWithDate |
                        Sort-Object InstalledOn -Descending |
                        Select-Object -First $TopHotfixes
                }
                else {
                    $hotfixes = $null
                }
            }
            catch {
                # Hotfix query failure should not break the whole report
                if ($IncludeHotfixes) { $hotfixes = @() } else { $hotfixes = $null }
            }
        }
        else {
            $hotfixes = $null
        }

        # Compliance logic:
        # - Pending reboot => NonCompliant (actionable)
        # - If we have a latest hotfix date: must be within ComplianceDays
        # - If we can't determine hotfix date: mark Unknown unless reboot pending
        $complianceState = 'Unknown'
        $complianceReason = $null

        if ($pending.IsPendingReboot) {
            $complianceState = 'NonCompliant'
            $complianceReason = 'Pending reboot detected'
        }
        elseif ($daysSinceLatestHotfix -ne $null) {
            if ($daysSinceLatestHotfix -le $ComplianceDays) {
                $complianceState = 'Compliant'
                $complianceReason = "Latest hotfix within $ComplianceDays days"
            }
            else {
                $complianceState = 'NonCompliant'
                $complianceReason = "Latest hotfix older than $ComplianceDays days"
            }
        }
        else {
            $complianceState = 'Unknown'
            $complianceReason = 'Latest hotfix date not determinable (hotfix query unavailable or returned no dates)'
        }

        $row = [ordered]@{
            Timestamp               = $now
            ComputerName            = $env:COMPUTERNAME
            OSName                  = $os.Caption
            OSVersion               = $os.Version
            OSBuild                 = $os.BuildNumber
            InstallDate             = $os.InstallDate
            LastBootTime            = $lastBoot
            UptimeDays              = [math]::Round($uptime.TotalDays, 2)

            LatestHotfixId          = $latestHotfix
            LatestHotfixInstalledOn = $latestHotfixDate
            DaysSinceLatestHotfix   = $daysSinceLatestHotfix

            ComplianceDays          = $ComplianceDays
            ComplianceState         = $complianceState
            ComplianceReason        = $complianceReason

            PendingReboot           = $pending.IsPendingReboot
            PendingRebootSignals    = $null

            Hotfixes                = $hotfixes
            Error                   = $null
        }

        if ($IncludePendingRebootSignals) {
            $row.PendingRebootSignals = ($pending.Signals -join '; ')
        }

        [PSCustomObject]$row
    }
    catch {
        [PSCustomObject]@{
            Timestamp               = $now
            ComputerName            = $env:COMPUTERNAME
            OSName                  = $null
            OSVersion               = $null
            OSBuild                 = $null
            InstallDate             = $null
            LastBootTime            = $null
            UptimeDays              = $null
            LatestHotfixId          = $null
            LatestHotfixInstalledOn = $null
            DaysSinceLatestHotfix   = $null
            ComplianceDays          = $ComplianceDays
            ComplianceState         = 'Error'
            ComplianceReason        = 'Failed to query system patch signals'
            PendingReboot           = $null
            PendingRebootSignals    = $null
            Hotfixes                = $null
            Error                   = $_.Exception.Message
        }
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $results.Add((Get-PatchComplianceLocal -ComplianceDays $ComplianceDays `
                -IncludeHotfixes:$IncludeHotfixes -TopHotfixes $TopHotfixes `
                -IncludePendingRebootSignals:$IncludePendingRebootSignals `
                -SkipHotfixQuery:$SkipHotfixQuery))
        }
        else {
            $r = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-PatchComplianceLocal} -ArgumentList @(
                [int]$ComplianceDays,
                [bool]$IncludeHotfixes,
                [int]$TopHotfixes,
                [bool]$IncludePendingRebootSignals,
                [bool]$SkipHotfixQuery
            ) -ErrorAction Stop
            $results.Add($r)
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp               = (Get-Date)
            ComputerName            = $target
            OSName                  = $null
            OSVersion               = $null
            OSBuild                 = $null
            InstallDate             = $null
            LastBootTime            = $null
            UptimeDays              = $null
            LatestHotfixId          = $null
            LatestHotfixInstalledOn = $null
            DaysSinceLatestHotfix   = $null
            ComplianceDays          = $ComplianceDays
            ComplianceState         = 'Error'
            ComplianceReason        = 'Remote query failed'
            PendingReboot           = $null
            PendingRebootSignals    = $null
            Hotfixes                = $null
            Error                   = $_.Exception.Message
        })
    }
}

$results
