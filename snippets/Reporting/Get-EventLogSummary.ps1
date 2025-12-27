<#
.SYNOPSIS
Summarizes Windows Event Logs over a time window (object output).

.DESCRIPTION
Collects events from one or more logs (System/Application/Security/etc.) over a time window
and returns a summary suitable for reporting and triage:

Per ComputerName + LogName:
- Total events
- Counts by Level (Critical/Error/Warning/Info/Verbose)
- Top Event IDs
- Top Providers
- Most recent event timestamp
- Optional sample rows (latest N events) with compact message preview

Designed for:
- Incident triage
- Daily/weekly health reporting
- Post-change validation
- RMM / scheduled reporting pipelines

Uses Get-WinEvent (recommended) and supports remote execution.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER LogName
Event log(s) to query. Default: System, Application.

.PARAMETER StartTime
Start of time window. If omitted, computed from -Hours.

.PARAMETER EndTime
End of time window. Default: now.

.PARAMETER Hours
Convenience window. If StartTime not specified, StartTime = now - Hours. Default 24.

.PARAMETER Level
Filter by level(s): Critical, Error, Warning, Information, Verbose. Default: all.

.PARAMETER ProviderName
Filter by provider name(s) (supports wildcards).

.PARAMETER Id
Filter by specific event IDs.

.PARAMETER MaxEvents
Maximum events to retrieve per log per computer. Default 5000 (guardrail).

.PARAMETER IncludeSamples
Include latest sample event rows per log (compact view).

.PARAMETER SampleCount
How many sample events to include (latest N). Default 10.

.PARAMETER MessagePreviewLength
Max characters to include for MessagePreview. Default 160.

.EXAMPLE
.\Get-EventLogSummary.ps1 | Format-Table -Auto

.EXAMPLE
# System/Application last 6 hours, only critical+error
.\Get-EventLogSummary.ps1 -Hours 6 -Level Critical,Error | Format-Table -Auto

.EXAMPLE
# RDS hosts - last 24 hours - export summary
.\Get-EventLogSummary.ps1 -ComputerName RDSH01,RDSH02 -Hours 24 |
  Export-Csv C:\Reports\EventLogSummary.csv -NoTypeInformation

.EXAMPLE
# Include sample events (latest 15 per log)
.\Get-EventLogSummary.ps1 -Hours 12 -IncludeSamples -SampleCount 15 | Format-List

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [string[]]$LogName = @('System','Application'),

    [Parameter()]
    [datetime]$StartTime,

    [Parameter()]
    [datetime]$EndTime = (Get-Date),

    [Parameter()]
    [ValidateRange(1,8760)]
    [int]$Hours = 24,

    [Parameter()]
    [ValidateSet('Critical','Error','Warning','Information','Verbose')]
    [string[]]$Level,

    [Parameter()]
    [string[]]$ProviderName,

    [Parameter()]
    [int[]]$Id,

    [Parameter()]
    [ValidateRange(1,200000)]
    [int]$MaxEvents = 5000,

    [Parameter()]
    [switch]$IncludeSamples,

    [Parameter()]
    [ValidateRange(1,200)]
    [int]$SampleCount = 10,

    [Parameter()]
    [ValidateRange(20,2000)]
    [int]$MessagePreviewLength = 160
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-LevelToInt {
    param([string]$LevelName)
    # Get-WinEvent Level values:
    # 1=Critical,2=Error,3=Warning,4=Information,5=Verbose
    switch ($LevelName) {
        'Critical'     { 1 }
        'Error'        { 2 }
        'Warning'      { 3 }
        'Information'  { 4 }
        'Verbose'      { 5 }
    }
}

function Match-AnyWildcard {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
    return $false
}

function Get-EventLogSummaryLocal {
    param(
        [string[]]$LogName,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [string[]]$Level,
        [string[]]$ProviderName,
        [int[]]$Id,
        [int]$MaxEvents,
        [bool]$IncludeSamples,
        [int]$SampleCount,
        [int]$MessagePreviewLength
    )

    $out = New-Object System.Collections.Generic.List[object]

    foreach ($log in $LogName) {
        try {
            $filter = @{
                LogName   = $log
                StartTime = $StartTime
                EndTime   = $EndTime
            }

            if ($Id -and $Id.Count -gt 0) {
                $filter.Id = $Id
            }

            if ($Level -and $Level.Count -gt 0) {
                $filter.Level = @($Level | ForEach-Object { Convert-LevelToInt $_ })
            }

            # Retrieve events with guardrail
            $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop

            # Provider filter (wildcards) must be applied post-query
            if ($ProviderName -and $ProviderName.Count -gt 0) {
                $events = $events | Where-Object { Match-AnyWildcard -Value $_.ProviderName -Patterns $ProviderName }
            }

            $eventsArr = @($events)

            $total = $eventsArr.Count
            $levelCounts = @{
                Critical     = 0
                Error        = 0
                Warning      = 0
                Information  = 0
                Verbose      = 0
            }

            foreach ($e in $eventsArr) {
                switch ($e.Level) {
                    1 { $levelCounts.Critical++ }
                    2 { $levelCounts.Error++ }
                    3 { $levelCounts.Warning++ }
                    4 { $levelCounts.Information++ }
                    5 { $levelCounts.Verbose++ }
                }
            }

            $topIds = $eventsArr |
                Group-Object Id |
                Sort-Object Count -Descending |
                Select-Object -First 10 |
                ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count } |
                -join '; '

            $topProviders = $eventsArr |
                Group-Object ProviderName |
                Sort-Object Count -Descending |
                Select-Object -First 10 |
                ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count } |
                -join '; '

            $mostRecent = $null
            if ($total -gt 0) {
                $mostRecent = ($eventsArr | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated
            }

            $samples = $null
            if ($IncludeSamples -and $total -gt 0) {
                $samples = $eventsArr |
                    Sort-Object TimeCreated -Descending |
                    Select-Object -First $SampleCount |
                    ForEach-Object {
                        $msg = $null
                        try { $msg = $_.Message } catch { $msg = $null }
                        if ($msg -and $msg.Length -gt $MessagePreviewLength) {
                            $msg = $msg.Substring(0, $MessagePreviewLength) + '…'
                        }

                        [PSCustomObject]@{
                            TimeCreated     = $_.TimeCreated
                            Level           = $_.LevelDisplayName
                            ProviderName    = $_.ProviderName
                            Id              = $_.Id
                            TaskDisplayName = $_.TaskDisplayName
                            MessagePreview  = $msg
                        }
                    }
            }

            $out.Add([PSCustomObject]@{
                Timestamp          = (Get-Date)
                ComputerName       = $env:COMPUTERNAME
                LogName            = $log
                StartTime          = $StartTime
                EndTime            = $EndTime
                TotalEvents        = $total
                CriticalCount      = $levelCounts.Critical
                ErrorCount         = $levelCounts.Error
                WarningCount       = $levelCounts.Warning
                InformationCount   = $levelCounts.Information
                VerboseCount       = $levelCounts.Verbose
                MostRecentEvent    = $mostRecent
                TopEventIds        = $topIds
                TopProviders       = $topProviders
                SampleEvents       = $samples
                Error              = $null
            })
        }
        catch {
            $out.Add([PSCustomObject]@{
                Timestamp          = (Get-Date)
                ComputerName       = $env:COMPUTERNAME
                LogName            = $log
                StartTime          = $StartTime
                EndTime            = $EndTime
                TotalEvents        = $null
                CriticalCount      = $null
                ErrorCount         = $null
                WarningCount       = $null
                InformationCount   = $null
                VerboseCount       = $null
                MostRecentEvent    = $null
                TopEventIds        = $null
                TopProviders       = $null
                SampleEvents       = $null
                Error              = $_.Exception.Message
            })
        }
    }

    $out
}

if (-not $PSBoundParameters.ContainsKey('StartTime')) {
    $StartTime = (Get-Date).AddHours(-$Hours)
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-EventLogSummaryLocal -LogName $LogName -StartTime $StartTime -EndTime $EndTime `
                -Level $Level -ProviderName $ProviderName -Id $Id -MaxEvents $MaxEvents `
                -IncludeSamples:$IncludeSamples -SampleCount $SampleCount -MessagePreviewLength $MessagePreviewLength
        }
        else {
            $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-EventLogSummaryLocal} -ArgumentList @(
                $LogName,
                [datetime]$StartTime,
                [datetime]$EndTime,
                $Level,
                $ProviderName,
                $Id,
                [int]$MaxEvents,
                [bool]$IncludeSamples,
                [int]$SampleCount,
                [int]$MessagePreviewLength
            ) -ErrorAction Stop
        }

        foreach ($r in @($rows)) { $results.Add($r) }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp          = (Get-Date)
            ComputerName       = $target
            LogName            = ($LogName -join ', ')
            StartTime          = $StartTime
            EndTime            = $EndTime
            TotalEvents        = $null
            CriticalCount      = $null
            ErrorCount         = $null
            WarningCount       = $null
            InformationCount   = $null
            VerboseCount       = $null
            MostRecentEvent    = $null
            TopEventIds        = $null
            TopProviders       = $null
            SampleEvents       = $null
            Error              = $_.Exception.Message
        })
    }
}

$results
