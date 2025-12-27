<#
.SYNOPSIS
Finds stale scheduled tasks (not run recently, never run, or repeatedly failing).

.DESCRIPTION
Enumerates scheduled tasks and flags "stale" tasks based on:
- InactiveDays: last run time older than N days (default 90)
- NeverRun: enabled tasks that have never run (optional include)
- Disabled: optionally include disabled tasks (informational or warn)
- NonSuccess: last task result not 0x0 (optional include)

Outputs structured objects suitable for CSV/HTML/JSON and triage.

Designed for:
- Post-migration cleanup (old automations, vendor installers, legacy tasks)
- Health checks and drift detection
- Audit prep and hardening reviews

Remote support via PowerShell remoting.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER InactiveDays
Tasks with LastRunTime older than this many days are considered stale. Default 90.
Set to 0 to disable the "older than" check.

.PARAMETER IncludeNeverRun
Include enabled tasks that have not yet run (LastRunTime missing/min value or result 0x41303).

.PARAMETER IncludeDisabled
Include disabled tasks in output (typically for cleanup review).

.PARAMETER IncludeFailing
Include tasks with non-success LastTaskResult (non-zero), regardless of recency.

.PARAMETER ExcludeMicrosoft
Exclude tasks under "\Microsoft\Windows\".

.PARAMETER TaskName
Filter by task name (supports wildcards).

.PARAMETER TaskPath
Filter by task path (supports wildcards).

.PARAMETER MinRuns
Only include tasks that have run at least this many times (applies to stale-by-age logic).
Useful to avoid flagging one-time tasks. Default 0 (no minimum).

.PARAMETER IncludeDefinition
Include simplified Actions/Triggers summaries for triage.

.PARAMETER MaxTasks
Guardrail for extremely large inventories. Default 5000.

.PARAMETER ThrottleLimit
Throttle limit for multi-host PSSession usage. Default 16.

.EXAMPLE
# Default: tasks inactive > 90 days (exclude Microsoft noise)
.\Find-StaleScheduledTasks.ps1 -ExcludeMicrosoft | Format-Table -Auto

.EXAMPLE
# Include tasks that never ran (enabled)
.\Find-StaleScheduledTasks.ps1 -ExcludeMicrosoft -IncludeNeverRun | Format-Table -Auto

.EXAMPLE
# Include disabled tasks too, export for cleanup review
.\Find-StaleScheduledTasks.ps1 -ExcludeMicrosoft -IncludeDisabled |
  Export-Csv C:\Reports\StaleTasks.csv -NoTypeInformation

.EXAMPLE
# Multi-host stale task sweep + include failures
.\Find-StaleScheduledTasks.ps1 -ComputerName RDSH01,RDSH02 -ExcludeMicrosoft -IncludeFailing |
  Export-Csv C:\Reports\StaleOrFailingTasks.csv -NoTypeInformation

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(0,36500)]
    [int]$InactiveDays = 90,

    [Parameter()]
    [switch]$IncludeNeverRun,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$IncludeFailing,

    [Parameter()]
    [switch]$ExcludeMicrosoft,

    [Parameter()]
    [string[]]$TaskName,

    [Parameter()]
    [string[]]$TaskPath,

    [Parameter()]
    [ValidateRange(0,1000000)]
    [int]$MinRuns = 0,

    [Parameter()]
    [switch]$IncludeDefinition,

    [Parameter()]
    [ValidateRange(1,200000)]
    [int]$MaxTasks = 5000,

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Match-AnyWildcard {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

function Normalize-ResultCode {
    param($Code)
    if ($null -eq $Code) { return $null }
    try {
        $i = [int]$Code
        if ($i -eq 0) { return '0x0' }
        return ('0x{0:X}' -f ($i -band 0xFFFFFFFF))
    }
    catch {
        return [string]$Code
    }
}

function Convert-ActionSummary {
    param($Task)
    try {
        return @($Task.Actions | ForEach-Object {
            $exe = $_.Execute
            $arg = $_.Arguments
            if ($exe) { if ($arg) { "$exe $arg" } else { "$exe" } } else { ($_ | Out-String).Trim() }
        }) -join ' | '
    } catch { return $null }
}

function Convert-TriggerSummary {
    param($Task)
    try {
        return @($Task.Triggers | ForEach-Object { $_.ToString() }) -join ' | '
    } catch { return $null }
}

function Get-StaleReason {
    param(
        [bool]$Enabled,
        [datetime]$LastRunTime,
        [string]$LastResultHex,
        [int]$InactiveDays,
        [bool]$IncludeNeverRun,
        [bool]$IncludeDisabled,
        [bool]$IncludeFailing,
        [int]$Runs,
        [int]$MinRuns
    )

    # Disabled tasks: only include if asked
    if (-not $Enabled) {
        if ($IncludeDisabled) { return 'Disabled task' }
        return $null
    }

    # Failing tasks: include if asked
    if ($IncludeFailing -and $LastResultHex -and $LastResultHex -ne '0x0') {
        # Exclude "still running" unless you explicitly want it later
        if ($LastResultHex -eq '0x41301') { }
        else { return "Non-success LastTaskResult $LastResultHex" }
    }

    # Never run: include if asked
    $neverRun = $false
    if (-not $LastRunTime -or $LastRunTime -lt [datetime]'1901-01-01') { $neverRun = $true }
    if ($LastResultHex -eq '0x41303') { $neverRun = $true }

    if ($neverRun) {
        if ($IncludeNeverRun) { return 'Enabled task has not yet run' }
        return $null
    }

    # Stale by age: optional
    if ($InactiveDays -gt 0) {
        # If MinRuns specified, require that to avoid flagging one-time/installer tasks
        if ($Runs -ne $null -and $Runs -lt $MinRuns) {
            return $null
        }

        $days = (New-TimeSpan -Start $LastRunTime -End (Get-Date)).TotalDays
        if ($days -ge $InactiveDays) {
            return "Last run older than $InactiveDays days"
        }
    }

    return $null
}

function Find-StaleScheduledTasksLocal {
    param(
        [int]$InactiveDays,
        [bool]$IncludeNeverRun,
        [bool]$IncludeDisabled,
        [bool]$IncludeFailing,
        [bool]$ExcludeMicrosoft,
        [string[]]$TaskName,
        [string[]]$TaskPath,
        [int]$MinRuns,
        [bool]$IncludeDefinition,
        [int]$MaxTasks
    )

    $now = Get-Date
    $out = New-Object System.Collections.Generic.List[object]

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop

        if (@($tasks).Count -gt $MaxTasks) {
            throw "Task enumeration exceeded MaxTasks ($MaxTasks). Found: $(@($tasks).Count). Use filters or increase MaxTasks."
        }

        foreach ($t in @($tasks)) {
            if ($ExcludeMicrosoft -and $t.TaskPath -like '\Microsoft\Windows\*') { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskName -Patterns $TaskName)) { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskPath -Patterns $TaskPath)) { continue }

            $enabled = $true
            $hidden  = $null
            try { $enabled = [bool]$t.Settings.Enabled } catch { $enabled = $true }
            try { $hidden  = [bool]$t.Settings.Hidden } catch {}

            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { $info = $null }

            $lastRun = $null
            $nextRun = $null
            $lastResultHex = $null
            $runs = $null
            $missed = $null

            if ($info) {
                $lastRun = $info.LastRunTime
                $nextRun = $info.NextRunTime
                $lastResultHex = Normalize-ResultCode $info.LastTaskResult
                $runs = $info.NumberOfRuns
                $missed = $info.NumberOfMissedRuns
            }

            $reason = Get-StaleReason -Enabled:$enabled -LastRunTime $lastRun -LastResultHex $lastResultHex `
                -InactiveDays $InactiveDays -IncludeNeverRun:$IncludeNeverRun -IncludeDisabled:$IncludeDisabled `
                -IncludeFailing:$IncludeFailing -Runs $runs -MinRuns $MinRuns

            if (-not $reason) { continue }

            $actions = $null
            $triggers = $null
            if ($IncludeDefinition) {
                $actions  = Convert-ActionSummary -Task $t
                $triggers = Convert-TriggerSummary -Task $t
            }

            $ageDays = $null
            if ($lastRun -and $lastRun -gt [datetime]'1901-01-01') {
                $ageDays = [math]::Round((New-TimeSpan -Start $lastRun -End (Get-Date)).TotalDays, 2)
            }

            $health = 'Warn'
            if ($reason -like 'Non-success*') { $health = 'Critical' }
            if ($reason -like 'Disabled*') { $health = 'Warn' }
            if ($reason -like '*has not yet run*') { $health = 'Warn' }

            $row = [ordered]@{
                Timestamp          = $now
                ComputerName       = $env:COMPUTERNAME

                TaskPath           = $t.TaskPath
                TaskName           = $t.TaskName
                FullName           = ($t.TaskPath + $t.TaskName)

                State              = $t.State
                Enabled            = $enabled
                Hidden             = $hidden

                Author             = $t.Author
                Description        = $t.Description

                PrincipalUserId    = $t.Principal.UserId
                PrincipalLogonType = $t.Principal.LogonType
                RunLevel           = $t.Principal.RunLevel

                LastRunTime        = $lastRun
                NextRunTime        = $nextRun
                LastTaskResult     = $lastResultHex
                NumberOfRuns       = $runs
                NumberOfMissedRuns = $missed
                LastRunAgeDays     = $ageDays

                Health             = $health
                Reason             = $reason

                Actions            = $actions
                Triggers           = $triggers

                Error              = $null
            }

            $out.Add([PSCustomObject]$row)
        }
    }
    catch {
        $out.Add([PSCustomObject]@{
            Timestamp          = $now
            ComputerName       = $env:COMPUTERNAME
            TaskPath           = $null
            TaskName           = $null
            FullName           = $null
            State              = $null
            Enabled            = $null
            Hidden             = $null
            Author             = $null
            Description        = $null
            PrincipalUserId    = $null
            PrincipalLogonType = $null
            RunLevel           = $null
            LastRunTime        = $null
            NextRunTime        = $null
            LastTaskResult     = $null
            NumberOfRuns       = $null
            NumberOfMissedRuns = $null
            LastRunAgeDays     = $null
            Health             = 'Error'
            Reason             = 'Stale task query failed'
            Actions            = $null
            Triggers           = $null
            Error              = $_.Exception.Message
        })
    }

    $out
}

$results = New-Object System.Collections.Generic.List[object]

# Multi-host via PSSession
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Find-StaleScheduledTasksLocal} -ArgumentList @(
            [int]$InactiveDays,
            [bool]$IncludeNeverRun,
            [bool]$IncludeDisabled,
            [bool]$IncludeFailing,
            [bool]$ExcludeMicrosoft,
            $TaskName,
            $TaskPath,
            [int]$MinRuns,
            [bool]$IncludeDefinition,
            [int]$MaxTasks
        )
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

        try {
            if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
                $rows = Find-StaleScheduledTasksLocal -InactiveDays $InactiveDays `
                    -IncludeNeverRun:$IncludeNeverRun -IncludeDisabled:$IncludeDisabled -IncludeFailing:$IncludeFailing `
                    -ExcludeMicrosoft:$ExcludeMicrosoft -TaskName $TaskName -TaskPath $TaskPath `
                    -MinRuns $MinRuns -IncludeDefinition:$IncludeDefinition -MaxTasks $MaxTasks
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Find-StaleScheduledTasksLocal} -ArgumentList @(
                    [int]$InactiveDays,
                    [bool]$IncludeNeverRun,
                    [bool]$IncludeDisabled,
                    [bool]$IncludeFailing,
                    [bool]$ExcludeMicrosoft,
                    $TaskName,
                    $TaskPath,
                    [int]$MinRuns,
                    [bool]$IncludeDefinition,
                    [int]$MaxTasks
                ) -ErrorAction Stop
            }

            foreach ($r in @($rows)) { $results.Add($r) }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Timestamp          = (Get-Date)
                ComputerName       = $target
                TaskPath           = $null
                TaskName           = $null
                FullName           = $null
                State              = $null
                Enabled            = $null
                Hidden             = $null
                Author             = $null
                Description        = $null
                PrincipalUserId    = $null
                PrincipalLogonType = $null
                RunLevel           = $null
                LastRunTime        = $null
                NextRunTime        = $null
                LastTaskResult     = $null
                NumberOfRuns       = $null
                NumberOfMissedRuns = $null
                LastRunAgeDays     = $null
                Health             = 'Error'
                Reason             = 'Remote query failed'
                Actions            = $null
                Triggers           = $null
                Error              = $_.Exception.Message
            })
        }
    }
}

$results
