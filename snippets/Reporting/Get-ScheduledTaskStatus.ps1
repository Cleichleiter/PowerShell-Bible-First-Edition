<#
.SYNOPSIS
Reports scheduled task status and last-run health (object output).

.DESCRIPTION
Returns one row per scheduled task (or filtered subset) including:
- Task name/path, state, author, principal/user
- Enabled/disabled, last run, next run, last result, run count
- Health classification (OK/Warn/Critical) with reason

Designed for:
- Daily/weekly health reporting
- RMM validation of automation tasks
- Detecting broken tasks after changes
- Export to CSV/HTML without reformatting

Uses Get-ScheduledTask + Get-ScheduledTaskInfo (built-in ScheduledTasks module).
Supports remote execution via PowerShell remoting.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER TaskName
Filter by task name (supports wildcards). Example: "Datto*", "Backup*"

.PARAMETER TaskPath
Filter by task path (supports wildcards). Example: "\Microsoft\Windows\*"

.PARAMETER State
Filter by task runtime state. Default: All.

.PARAMETER IncludeDisabled
Include disabled tasks (default includes them anyway if not filtering).

.PARAMETER OnlyProblems
Return only non-OK tasks (Warn/Critical/Error).

.PARAMETER FailureCodes
Treat these LastTaskResult codes as Critical. Default includes 0x1, 0x2, 0x41301, 0x8004131F, 0x80070005.

.PARAMETER WarnCodes
Treat these LastTaskResult codes as Warn. Default includes 0x41303 (not yet run), 0x0 (success) is OK.

.PARAMETER SuccessRecencyDays
If a task is enabled and has a last run older than this, mark Warn. Default 14.
Set to 0 to disable recency checks.

.PARAMETER IncludeDefinition
Include task actions/triggers/principal details (heavier). Default off.

.EXAMPLE
.\Get-ScheduledTaskStatus.ps1 | Format-Table -Auto

.EXAMPLE
# Show only tasks with failures or suspicious signals
.\Get-ScheduledTaskStatus.ps1 -OnlyProblems | Format-Table -Auto

.EXAMPLE
# Focus on Microsoft tasks in a subtree
.\Get-ScheduledTaskStatus.ps1 -TaskPath "\Microsoft\Windows\*" |
  Export-Csv C:\Reports\ScheduledTasks.csv -NoTypeInformation

.EXAMPLE
# Remote export
.\Get-ScheduledTaskStatus.ps1 -ComputerName PC01,PC02 -OnlyProblems |
  Export-Csv C:\Reports\ScheduledTaskProblems.csv -NoTypeInformation

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [string[]]$TaskName,

    [Parameter()]
    [string[]]$TaskPath,

    [Parameter()]
    [ValidateSet('All','Ready','Running','Disabled','Queued','Unknown')]
    [string]$State = 'All',

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$OnlyProblems,

    [Parameter()]
    [string[]]$FailureCodes = @(
        '0x1',          # Incorrect function / generic failure
        '0x2',          # File not found
        '0x41301',      # Task is currently running (warnable, but often means stuck)
        '0x8004131F',   # An instance of this task is already running
        '0x80070005'    # Access denied
    ),

    [Parameter()]
    [string[]]$WarnCodes = @(
        '0x41303'       # Task has not yet run
    ),

    [Parameter()]
    [ValidateRange(0,3650)]
    [int]$SuccessRecencyDays = 14,

    [Parameter()]
    [switch]$IncludeDefinition
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Match-AnyWildcard {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
    return $false
}

function Normalize-ResultCode {
    param($Code)
    if ($null -eq $Code) { return $null }

    # Get-ScheduledTaskInfo typically returns LastTaskResult as Int32
    # Normalize to hex string for consistent matching
    try {
        $i = [int]$Code
        if ($i -eq 0) { return '0x0' }
        return ('0x{0:X}' -f ($i -band 0xFFFFFFFF))
    }
    catch {
        return [string]$Code
    }
}

function Get-Health {
    param(
        [bool]$Enabled,
        [string]$TaskState,
        [datetime]$LastRunTime,
        [string]$LastResultHex,
        [int]$SuccessRecencyDays,
        [string[]]$FailureCodes,
        [string[]]$WarnCodes
    )

    # Disabled tasks are usually informational unless user wants to treat as problems
    if (-not $Enabled) {
        return [PSCustomObject]@{ Health='OK'; Reason=$null }
    }

    if ($TaskState -eq 'Running') {
        return [PSCustomObject]@{ Health='Warn'; Reason='Task is currently running' }
    }

    if ($LastResultHex -and ($FailureCodes -contains $LastResultHex)) {
        # Special-case "currently running" style codes: treat Warn by default unless user prefers Critical
        if ($LastResultHex -in @('0x41301','0x8004131F')) {
            return [PSCustomObject]@{ Health='Warn'; Reason="LastTaskResult $LastResultHex (possible overlap/stuck run)" }
        }
        return [PSCustomObject]@{ Health='Critical'; Reason="LastTaskResult $LastResultHex" }
    }

    if ($LastResultHex -and ($WarnCodes -contains $LastResultHex)) {
        return [PSCustomObject]@{ Health='Warn'; Reason="LastTaskResult $LastResultHex" }
    }

    if ($LastResultHex -and $LastResultHex -ne '0x0') {
        # Unknown non-success code: warn
        return [PSCustomObject]@{ Health='Warn'; Reason="Non-zero LastTaskResult $LastResultHex" }
    }

    if ($SuccessRecencyDays -gt 0) {
        if ($LastRunTime -and $LastRunTime -gt [datetime]'1900-01-01') {
            $days = (New-TimeSpan -Start $LastRunTime -End (Get-Date)).TotalDays
            if ($days -gt $SuccessRecencyDays) {
                return [PSCustomObject]@{ Health='Warn'; Reason="Last run older than $SuccessRecencyDays days" }
            }
        }
        else {
            return [PSCustomObject]@{ Health='Warn'; Reason='Enabled task has never run (or last run unavailable)' }
        }
    }

    return [PSCustomObject]@{ Health='OK'; Reason=$null }
}

function Get-ScheduledTaskStatusLocal {
    param(
        [string[]]$TaskName,
        [string[]]$TaskPath,
        [string]$State,
        [bool]$IncludeDisabled,
        [bool]$OnlyProblems,
        [string[]]$FailureCodes,
        [string[]]$WarnCodes,
        [int]$SuccessRecencyDays,
        [bool]$IncludeDefinition
    )

    $now = Get-Date
    $out = New-Object System.Collections.Generic.List[object]

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop

        foreach ($t in @($tasks)) {
            if (-not (Match-AnyWildcard -Value $t.TaskName -Patterns $TaskName)) { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskPath -Patterns $TaskPath)) { continue }

            # Filter state (runtime state from task object)
            if ($State -ne 'All') {
                if ($t.State -ne $State) { continue }
            }

            $enabled = $true
            try { $enabled = [bool]$t.Settings.Enabled } catch { $enabled = $true }

            if (-not $IncludeDisabled -and -not $enabled) { continue }

            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { $info = $null }

            $lastRun = $null
            $nextRun = $null
            $lastResultHex = $null
            $numberOfMissedRuns = $null
            $runCount = $null

            if ($info) {
                $lastRun = $info.LastRunTime
                $nextRun = $info.NextRunTime
                $lastResultHex = Normalize-ResultCode $info.LastTaskResult
                $numberOfMissedRuns = $info.NumberOfMissedRuns
                $runCount = $info.NumberOfRuns
            }

            $healthObj = Get-Health -Enabled:$enabled -TaskState $t.State -LastRunTime $lastRun -LastResultHex $lastResultHex `
                -SuccessRecencyDays $SuccessRecencyDays -FailureCodes $FailureCodes -WarnCodes $WarnCodes

            if ($OnlyProblems -and $healthObj.Health -eq 'OK') { continue }

            $row = [ordered]@{
                Timestamp           = $now
                ComputerName        = $env:COMPUTERNAME
                TaskPath            = $t.TaskPath
                TaskName            = $t.TaskName
                FullName            = ($t.TaskPath + $t.TaskName)
                State               = $t.State
                Enabled             = $enabled
                Author              = $t.Author
                Description         = $t.Description
                PrincipalUserId     = $t.Principal.UserId
                PrincipalLogonType  = $t.Principal.LogonType
                RunLevel            = $t.Principal.RunLevel

                LastRunTime         = $lastRun
                NextRunTime         = $nextRun
                LastTaskResult      = $lastResultHex
                NumberOfRuns        = $runCount
                NumberOfMissedRuns  = $numberOfMissedRuns

                Health              = $healthObj.Health
                Reason              = $healthObj.Reason

                Actions             = $null
                Triggers            = $null
            }

            if ($IncludeDefinition) {
                try {
                    $row.Actions = @($t.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | '
                } catch {}

                try {
                    $row.Triggers = @($t.Triggers | ForEach-Object { $_.ToString() }) -join ' | '
                } catch {}
            }

            $out.Add([PSCustomObject]$row)
        }
    }
    catch {
        $out.Add([PSCustomObject]@{
            Timestamp           = $now
            ComputerName        = $env:COMPUTERNAME
            TaskPath            = $null
            TaskName            = $null
            FullName            = $null
            State               = $null
            Enabled             = $null
            Author              = $null
            Description         = $null
            PrincipalUserId     = $null
            PrincipalLogonType  = $null
            RunLevel            = $null
            LastRunTime         = $null
            NextRunTime         = $null
            LastTaskResult      = $null
            NumberOfRuns        = $null
            NumberOfMissedRuns  = $null
            Health              = 'Error'
            Reason              = $_.Exception.Message
            Actions             = $null
            Triggers            = $null
        })
    }

    $out
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-ScheduledTaskStatusLocal -TaskName $TaskName -TaskPath $TaskPath -State $State `
                -IncludeDisabled:$IncludeDisabled -OnlyProblems:$OnlyProblems `
                -FailureCodes $FailureCodes -WarnCodes $WarnCodes `
                -SuccessRecencyDays $SuccessRecencyDays -IncludeDefinition:$IncludeDefinition
        }
        else {
            $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-ScheduledTaskStatusLocal} -ArgumentList @(
                $TaskName,
                $TaskPath,
                $State,
                [bool]$IncludeDisabled,
                [bool]$OnlyProblems,
                $FailureCodes,
                $WarnCodes,
                [int]$SuccessRecencyDays,
                [bool]$IncludeDefinition
            ) -ErrorAction Stop
        }

        foreach ($r in @($rows)) { $results.Add($r) }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp           = (Get-Date)
            ComputerName        = $target
            TaskPath            = $null
            TaskName            = $null
            FullName            = $null
            State               = $null
            Enabled             = $null
            Author              = $null
            Description         = $null
            PrincipalUserId     = $null
            PrincipalLogonType  = $null
            RunLevel            = $null
            LastRunTime         = $null
            NextRunTime         = $null
            LastTaskResult      = $null
            NumberOfRuns        = $null
            NumberOfMissedRuns  = $null
            Health              = 'Error'
            Reason              = $_.Exception.Message
            Actions             = $null
            Triggers            = $null
        })
    }
}

$results
