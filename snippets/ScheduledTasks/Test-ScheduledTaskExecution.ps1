<#
.SYNOPSIS
Safely tests scheduled task execution readiness and (optionally) triggers a controlled run.

.DESCRIPTION
Provides two modes:

1) Readiness check (default, no changes):
   - Confirms task exists, is enabled, and can be started in principle
   - Validates principal, last result, state, and action target path existence (best-effort)
   - Returns a structured object with Health/Reason and recommended next steps

2) Controlled start (optional, requires -Start):
   - Starts the task via Start-ScheduledTask
   - Waits for completion up to -WaitSeconds (optional)
   - Captures updated LastRunTime/LastTaskResult and state after start
   - Still does NOT modify task definition (no enable/disable/update)

Designed for:
- Change validation (before/after)
- Troubleshooting broken tasks
- RMM validation runs (with explicit opt-in)

Remote support via PowerShell remoting.

IMPORTANT
- Starting a task may have real side effects (backups, scripts, installers).
  Use -Start only when you intend to run the task.
- For tasks that take longer than WaitSeconds, results may remain "Running".

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER TaskName
Task name (supports wildcards only when used with TaskPath/FullName filters; for exact run use exact name).

.PARAMETER TaskPath
Task path. Default "\".

.PARAMETER FullName
Full task name (TaskPath + TaskName). Supports wildcards for discovery.
If FullName is used and resolves to multiple tasks, script returns results for each
unless -RequireSingle is set.

.PARAMETER RequireSingle
Fail if filters match more than one task (safety guard for -Start).

.PARAMETER Start
Actually start the task (opt-in). Without this switch, script is read-only.

.PARAMETER Wait
Wait for the task to complete (polls state).

.PARAMETER WaitSeconds
Maximum seconds to wait when -Wait is used. Default 60.

.PARAMETER PollSeconds
Polling interval while waiting. Default 3.

.PARAMETER IncludeDefinitionSignals
Include basic definition signals (principal, action summary) in output for triage.

.PARAMETER IgnoreRunning
If task is already running, treat as Warn instead of Error and do not attempt start.

.PARAMETER MaxTasks
Guardrail for discovery queries. Default 5000.

.PARAMETER ThrottleLimit
Throttle limit for multi-host PSSession usage. Default 16.

.EXAMPLE
# Readiness check (no start)
.\Test-ScheduledTaskExecution.ps1 -TaskName "MyTask" -TaskPath "\"

.EXAMPLE
# Discover tasks and check readiness for a subtree
.\Test-ScheduledTaskExecution.ps1 -FullName "\Vendor\*" -IncludeDefinitionSignals |
  Format-Table -Auto

.EXAMPLE
# Controlled start with safety guard
.\Test-ScheduledTaskExecution.ps1 -TaskName "NightlyBackup" -TaskPath "\Backups\" -Start -RequireSingle -Wait -WaitSeconds 300

.EXAMPLE
# Remote controlled start (explicit)
.\Test-ScheduledTaskExecution.ps1 -ComputerName RDSH01 -TaskName "Cleanup" -TaskPath "\Ops\" -Start -RequireSingle -Wait

.NOTES
Author: Cheri
Default mode is read-only. -Start is the only action.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [string]$TaskName,

    [Parameter()]
    [string]$TaskPath = '\',

    [Parameter()]
    [string]$FullName,

    [Parameter()]
    [switch]$RequireSingle,

    [Parameter()]
    [switch]$Start,

    [Parameter()]
    [switch]$Wait,

    [Parameter()]
    [ValidateRange(1,3600)]
    [int]$WaitSeconds = 60,

    [Parameter()]
    [ValidateRange(1,60)]
    [int]$PollSeconds = 3,

    [Parameter()]
    [switch]$IncludeDefinitionSignals,

    [Parameter()]
    [switch]$IgnoreRunning,

    [Parameter()]
    [ValidateRange(1,200000)]
    [int]$MaxTasks = 5000,

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Match-AnyWildcard {
    param([string]$Value, [string]$Patterns)
    if (-not $Patterns) { return $true }
    return ($Value -like $Patterns)
}

function Get-ActionSummary {
    param($Task)
    try {
        return @($Task.Actions | ForEach-Object {
            $exe = $_.Execute
            $arg = $_.Arguments
            if ($exe) { if ($arg) { "$exe $arg" } else { "$exe" } } else { ($_ | Out-String).Trim() }
        }) -join ' | '
    } catch { return $null }
}

function Test-ActionTargets {
    param($Task)

    # Best-effort: validate that Execute paths exist if they look like local file paths.
    # (This is not perfect: could be cmd.exe /c, powershell.exe, relative paths, etc.)
    $signals = New-Object System.Collections.Generic.List[string]

    foreach ($a in @($Task.Actions)) {
        $exe = $null
        try { $exe = [string]$a.Execute } catch { $exe = $null }
        if (-not $exe) { continue }

        # Skip obvious non-path executables that exist via PATH (cmd, powershell, wscript, etc.)
        $leaf = Split-Path -Path $exe -Leaf -ErrorAction SilentlyContinue
        $isRooted = $false
        try { $isRooted = [System.IO.Path]::IsPathRooted($exe) } catch { $isRooted = $false }

        if ($isRooted) {
            if (-not (Test-Path -LiteralPath $exe)) {
                $signals.Add("Action execute path missing: $exe")
            }
        }
        else {
            # best-effort: if it contains a slash/backslash or ends in .exe/.ps1/.bat treat as path-like
            if ($exe -match '[\\/]' -or $exe -match '\.(exe|ps1|cmd|bat|vbs)$') {
                if (-not (Test-Path -LiteralPath $exe)) {
                    $signals.Add("Action execute path not found (relative/path-like): $exe")
                }
            }
        }
    }

    $signals
}

function Resolve-Tasks {
    param([string]$TaskName, [string]$TaskPath, [string]$FullName, [int]$MaxTasks)

    $tasks = Get-ScheduledTask -ErrorAction Stop

    if (@($tasks).Count -gt $MaxTasks) {
        throw "Task enumeration exceeded MaxTasks ($MaxTasks). Found: $(@($tasks).Count). Use narrower filters or increase MaxTasks."
    }

    $filtered = $tasks

    if ($FullName) {
        $filtered = $filtered | Where-Object { ($_.TaskPath + $_.TaskName) -like $FullName }
    }
    else {
        if ($TaskName) { $filtered = $filtered | Where-Object { $_.TaskName -eq $TaskName -or $_.TaskName -like $TaskName } }
        if ($TaskPath) { $filtered = $filtered | Where-Object { $_.TaskPath -eq $TaskPath -or $_.TaskPath -like $TaskPath } }
    }

    $filtered
}

function Test-ScheduledTaskExecutionLocal {
    param(
        [string]$TaskName,
        [string]$TaskPath,
        [string]$FullName,
        [bool]$RequireSingle,
        [bool]$Start,
        [bool]$Wait,
        [int]$WaitSeconds,
        [int]$PollSeconds,
        [bool]$IncludeDefinitionSignals,
        [bool]$IgnoreRunning,
        [int]$MaxTasks
    )

    $now = Get-Date
    $rows = New-Object System.Collections.Generic.List[object]

    $tasks = Resolve-Tasks -TaskName $TaskName -TaskPath $TaskPath -FullName $FullName -MaxTasks $MaxTasks

    if (-not $tasks -or @($tasks).Count -eq 0) {
        $rows.Add([PSCustomObject]@{
            Timestamp         = $now
            ComputerName      = $env:COMPUTERNAME
            TaskPath          = $TaskPath
            TaskName          = $TaskName
            FullName          = $FullName
            Enabled           = $null
            State             = $null
            LastRunTime       = $null
            NextRunTime       = $null
            LastTaskResult    = $null
            PrincipalUserId   = $null
            RunLevel          = $null
            ActionSummary     = $null
            Health            = 'Error'
            Reason            = 'Task not found'
            Started           = $false
            Waited            = $false
            Completed         = $false
            PostState         = $null
            PostLastRunTime   = $null
            PostLastTaskResult= $null
            Signals           = @()
            Error             = $null
        })
        return $rows
    }

    if ($RequireSingle -and @($tasks).Count -ne 1) {
        throw "RequireSingle specified but filters matched $(@($tasks).Count) tasks. Narrow filters before running."
    }

    foreach ($t in @($tasks)) {
        $full = ($t.TaskPath + $t.TaskName)

        $enabled = $true
        try { $enabled = [bool]$t.Settings.Enabled } catch { $enabled = $true }

        $info = $null
        try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { $info = $null }

        $lastRun = $null
        $nextRun = $null
        $lastResultHex = $null
        if ($info) {
            $lastRun = $info.LastRunTime
            $nextRun = $info.NextRunTime
            $lastResultHex = Normalize-ResultCode $info.LastTaskResult
        }

        $signals = New-Object System.Collections.Generic.List[string]

        # Readiness rules
        $health = 'OK'
        $reason = $null

        if (-not $enabled) {
            $health = 'Warn'
            $reason = 'Task is disabled'
        }

        if ($t.State -eq 'Running') {
            if ($IgnoreRunning) {
                $health = 'Warn'
                $reason = 'Task is already running'
            }
            else {
                $health = 'Error'
                $reason = 'Task is already running'
            }
        }

        # Action target signals
        if ($IncludeDefinitionSignals) {
            foreach ($s in @(Test-ActionTargets -Task $t)) { $signals.Add($s) }
            if ($signals.Count -gt 0 -and $health -eq 'OK') {
                $health = 'Warn'
                $reason = 'Action target validation warnings'
            }
        }

        $started = $false
        $waited = $false
        $completed = $false
        $postState = $null
        $postLastRun = $null
        $postLastResult = $null

        if ($Start) {
            # Safety: do not start if multiple tasks matched unless RequireSingle, enforced above.
            if (-not $enabled) {
                if ($health -ne 'Error') {
                    $health = 'Error'
                    $reason = 'Cannot start disabled task (enable first)'
                }
            }
            elseif ($t.State -eq 'Running') {
                if (-not $IgnoreRunning) {
                    # already error
                }
                else {
                    # do not attempt start
                }
            }
            else {
                $actionLabel = "Start scheduled task $full"
                if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $actionLabel)) {
                    try {
                        Start-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                        $started = $true
                    }
                    catch {
                        $health = 'Error'
                        $reason = 'Start-ScheduledTask failed'
                        $signals.Add($_.Exception.Message)
                    }
                }
            }

            if ($started -and $Wait) {
                $waited = $true
                $deadline = (Get-Date).AddSeconds($WaitSeconds)

                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Seconds $PollSeconds

                    try {
                        $t2 = Get-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                        $postState = $t2.State
                        if ($postState -ne 'Running') { break }
                    }
                    catch {
                        $signals.Add("Re-query task state failed: $($_.Exception.Message)")
                        break
                    }
                }

                # Post snapshot
                try {
                    $t2 = Get-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                    $postState = $t2.State
                } catch {}

                try {
                    $i2 = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                    $postLastRun = $i2.LastRunTime
                    $postLastResult = Normalize-ResultCode $i2.LastTaskResult
                } catch {}

                if ($postState -and $postState -ne 'Running') {
                    $completed = $true
                }

                if ($completed -and $postLastResult -and $postLastResult -ne '0x0') {
                    $health = 'Critical'
                    $reason = "Task completed with non-success result $postLastResult"
                }
                elseif ($completed -and $postLastResult -eq '0x0') {
                    $health = 'OK'
                    $reason = $null
                }
                elseif (-not $completed) {
                    $health = 'Warn'
                    $reason = "Task did not complete within $WaitSeconds seconds"
                }
            }
        }

        $actionSummary = $null
        if ($IncludeDefinitionSignals) {
            $actionSummary = Get-ActionSummary -Task $t
        }

        $rows.Add([PSCustomObject]@{
            Timestamp          = $now
            ComputerName       = $env:COMPUTERNAME

            TaskPath           = $t.TaskPath
            TaskName           = $t.TaskName
            FullName           = $full

            Enabled            = $enabled
            State              = $t.State
            LastRunTime        = $lastRun
            NextRunTime        = $nextRun
            LastTaskResult     = $lastResultHex

            PrincipalUserId    = $t.Principal.UserId
            RunLevel           = $t.Principal.RunLevel
            ActionSummary      = $actionSummary

            Health             = $health
            Reason             = $reason

            Started            = $started
            Waited             = $waited
            Completed          = $completed
            PostState          = $postState
            PostLastRunTime    = $postLastRun
            PostLastTaskResult = $postLastResult

            Signals            = @($signals)
            Error              = $null
        })
    }

    $rows
}

$results = New-Object System.Collections.Generic.List[object]

# Multi-host via PSSession (NOTE: -Start runs on remote; be deliberate)
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Test-ScheduledTaskExecutionLocal} -ArgumentList @(
            $TaskName,
            $TaskPath,
            $FullName,
            [bool]$RequireSingle,
            [bool]$Start,
            [bool]$Wait,
            [int]$WaitSeconds,
            [int]$PollSeconds,
            [bool]$IncludeDefinitionSignals,
            [bool]$IgnoreRunning,
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
                $rows = Test-ScheduledTaskExecutionLocal -TaskName $TaskName -TaskPath $TaskPath -FullName $FullName `
                    -RequireSingle:$RequireSingle -Start:$Start -Wait:$Wait -WaitSeconds $WaitSeconds -PollSeconds $PollSeconds `
                    -IncludeDefinitionSignals:$IncludeDefinitionSignals -IgnoreRunning:$IgnoreRunning -MaxTasks $MaxTasks
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Test-ScheduledTaskExecutionLocal} -ArgumentList @(
                    $TaskName,
                    $TaskPath,
                    $FullName,
                    [bool]$RequireSingle,
                    [bool]$Start,
                    [bool]$Wait,
                    [int]$WaitSeconds,
                    [int]$PollSeconds,
                    [bool]$IncludeDefinitionSignals,
                    [bool]$IgnoreRunning,
                    [int]$MaxTasks
                ) -ErrorAction Stop
            }

            foreach ($r in @($rows)) { $results.Add($r) }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Timestamp          = (Get-Date)
                ComputerName       = $target
                TaskPath           = $TaskPath
                TaskName           = $TaskName
                FullName           = $FullName
                Enabled            = $null
                State              = $null
                LastRunTime        = $null
                NextRunTime        = $null
                LastTaskResult     = $null
                PrincipalUserId    = $null
                RunLevel           = $null
                ActionSummary      = $null
                Health             = 'Error'
                Reason             = 'Remote query failed'
                Started            = $false
                Waited             = $false
                Completed          = $false
                PostState          = $null
                PostLastRunTime    = $null
                PostLastTaskResult = $null
                Signals            = @()
                Error              = $_.Exception.Message
            })
        }
    }
}

$results
