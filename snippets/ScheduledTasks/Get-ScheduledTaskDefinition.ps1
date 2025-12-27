<#
.SYNOPSIS
Retrieves scheduled task definitions (actions/triggers/principal/settings) in a report-friendly format.

.DESCRIPTION
Expands a scheduled task into a structured definition object suitable for triage and audits:
- Identity: TaskPath, TaskName, FullName
- Principal: UserId, LogonType, RunLevel, GroupId
- Actions: Execute, Arguments, WorkingDirectory, action type
- Triggers: TriggerType, StartBoundary, Enabled, user/event details (best-effort)
- Settings: Hidden, Enabled, WakeToRun, DisallowStartIfOnBatteries, etc.
- Optional: Raw XML (heavier) for deep review or exports

Uses the ScheduledTasks module for rich objects and can optionally collect XML via schtasks.

Remote support via PowerShell remoting.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER TaskName
Filter by task name (supports wildcards). Example: "Backup*", "Datto*"

.PARAMETER TaskPath
Filter by task path (supports wildcards). Example: "\Microsoft\Windows\*"

.PARAMETER FullName
Filter by full task name (TaskPath + TaskName). Supports wildcards. Example: "\Microsoft\Windows\UpdateOrchestrator\*"

.PARAMETER ExcludeMicrosoft
Exclude tasks under "\Microsoft\Windows\".

.PARAMETER IncludeRawXml
Include raw task XML (heavier).

.PARAMETER MaxTasks
Guardrail to prevent runaway enumeration. Default 5000.

.PARAMETER ThrottleLimit
Throttle limit for multi-host PSSession usage. Default 16.

.EXAMPLE
.\Get-ScheduledTaskDefinition.ps1 -TaskName "Backup*" | Format-List

.EXAMPLE
.\Get-ScheduledTaskDefinition.ps1 -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" -IncludeRawXml |
  Export-Csv C:\Reports\TaskDefinitions.csv -NoTypeInformation

.EXAMPLE
.\Get-ScheduledTaskDefinition.ps1 -ComputerName RDSH01,RDSH02 -ExcludeMicrosoft |
  Export-Csv C:\Reports\TaskDefinitions.csv -NoTypeInformation

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
    [string[]]$FullName,

    [Parameter()]
    [switch]$ExcludeMicrosoft,

    [Parameter()]
    [switch]$IncludeRawXml,

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

function Get-TaskXml {
    param([string]$TaskPath, [string]$TaskName)

    $full = ($TaskPath + $TaskName)
    $escaped = $full.Replace('"','\"')
    $cmd = "schtasks /Query /TN `"$escaped`" /XML"
    try {
        $xml = cmd.exe /c $cmd 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        return ($xml -join "`n")
    }
    catch {
        return $null
    }
}

function Convert-ActionSummary {
    param($Action)

    # ScheduledTasks action types differ across PS versions; best-effort extraction
    $type = $null
    try { $type = $Action.CimClass.CimClassName } catch {}

    $execute = $null
    $args = $null
    $wd = $null

    try { $execute = $Action.Execute } catch {}
    try { $args = $Action.Arguments } catch {}
    try { $wd = $Action.WorkingDirectory } catch {}

    [PSCustomObject]@{
        ActionType        = $type
        Execute           = $execute
        Arguments         = $args
        WorkingDirectory  = $wd
        Summary           = if ($execute) { ($execute + ($(if ($args) { " $args" } else { "" }))) } else { ($Action | Out-String).Trim() }
    }
}

function Convert-TriggerSummary {
    param($Trigger)

    # Trigger objects vary by type; we capture a consistent baseline + best-effort fields
    $type = $null
    try { $type = $Trigger.CimClass.CimClassName } catch {}

    $start = $null
    $enabled = $null
    try { $start = $Trigger.StartBoundary } catch {}
    try { $enabled = $Trigger.Enabled } catch {}

    $userId = $null
    $delay  = $null
    $randomDelay = $null
    $interval = $null
    $duration = $null

    try { $userId = $Trigger.UserId } catch {}
    try { $delay = $Trigger.Delay } catch {}
    try { $randomDelay = $Trigger.RandomDelay } catch {}
    try { $interval = $Trigger.Repetition.Interval } catch {}
    try { $duration = $Trigger.Repetition.Duration } catch {}

    # Event trigger fields
    $subscription = $null
    try { $subscription = $Trigger.Subscription } catch {}

    [PSCustomObject]@{
        TriggerType        = $type
        Enabled            = $enabled
        StartBoundary      = $start
        UserId             = $userId
        Delay              = $delay
        RandomDelay        = $randomDelay
        RepetitionInterval = $interval
        RepetitionDuration = $duration
        EventSubscription  = $subscription
        Summary            = ($Trigger | Out-String).Trim()
    }
}

function Get-ScheduledTaskDefinitionLocal {
    param(
        [string[]]$TaskName,
        [string[]]$TaskPath,
        [string[]]$FullName,
        [bool]$ExcludeMicrosoft,
        [bool]$IncludeRawXml,
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
            $full = ($t.TaskPath + $t.TaskName)

            if ($ExcludeMicrosoft -and $t.TaskPath -like '\Microsoft\Windows\*') { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskName -Patterns $TaskName)) { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskPath -Patterns $TaskPath)) { continue }
            if (-not (Match-AnyWildcard -Value $full -Patterns $FullName)) { continue }

            $enabled = $true
            $hidden  = $null
            try { $enabled = [bool]$t.Settings.Enabled } catch { $enabled = $true }
            try { $hidden  = [bool]$t.Settings.Hidden } catch {}

            $principal = $t.Principal
            $actions = @()
            $triggers = @()

            try { $actions = @($t.Actions | ForEach-Object { Convert-ActionSummary $_ }) } catch {}
            try { $triggers = @($t.Triggers | ForEach-Object { Convert-TriggerSummary $_ }) } catch {}

            $rawXml = $null
            if ($IncludeRawXml) {
                $rawXml = Get-TaskXml -TaskPath $t.TaskPath -TaskName $t.TaskName
            }

            $settings = $null
            try {
                $s = $t.Settings
                $settings = [PSCustomObject]@{
                    Enabled                    = $enabled
                    Hidden                     = $hidden
                    AllowDemandStart           = $s.AllowDemandStart
                    DisallowStartIfOnBatteries = $s.DisallowStartIfOnBatteries
                    StopIfGoingOnBatteries     = $s.StopIfGoingOnBatteries
                    WakeToRun                  = $s.WakeToRun
                    RunOnlyIfIdle              = $s.RunOnlyIfIdle
                    IdleDuration               = $s.IdleSettings.IdleDuration
                    WaitTimeout                = $s.IdleSettings.WaitTimeout
                    RestartCount               = $s.RestartCount
                    RestartInterval            = $s.RestartInterval
                    ExecutionTimeLimit         = $s.ExecutionTimeLimit
                    MultipleInstances          = $s.MultipleInstances
                    StartWhenAvailable         = $s.StartWhenAvailable
                }
            } catch { $settings = $null }

            $row = [ordered]@{
                Timestamp          = $now
                ComputerName       = $env:COMPUTERNAME

                TaskPath           = $t.TaskPath
                TaskName           = $t.TaskName
                FullName           = $full

                State              = $t.State
                Enabled            = $enabled
                Hidden             = $hidden

                Author             = $t.Author
                Description        = $t.Description

                PrincipalUserId    = $principal.UserId
                PrincipalGroupId   = $principal.GroupId
                PrincipalLogonType = $principal.LogonType
                RunLevel           = $principal.RunLevel

                Actions            = $actions
                Triggers           = $triggers
                Settings           = $settings

                TaskXml            = $rawXml
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
            PrincipalGroupId   = $null
            PrincipalLogonType = $null
            RunLevel           = $null
            Actions            = $null
            Triggers           = $null
            Settings           = $null
            TaskXml            = $null
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
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-ScheduledTaskDefinitionLocal} -ArgumentList @(
            $TaskName,
            $TaskPath,
            $FullName,
            [bool]$ExcludeMicrosoft,
            [bool]$IncludeRawXml,
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
                $rows = Get-ScheduledTaskDefinitionLocal -TaskName $TaskName -TaskPath $TaskPath -FullName $FullName `
                    -ExcludeMicrosoft:$ExcludeMicrosoft -IncludeRawXml:$IncludeRawXml -MaxTasks $MaxTasks
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-ScheduledTaskDefinitionLocal} -ArgumentList @(
                    $TaskName,
                    $TaskPath,
                    $FullName,
                    [bool]$ExcludeMicrosoft,
                    [bool]$IncludeRawXml,
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
                PrincipalGroupId   = $null
                PrincipalLogonType = $null
                RunLevel           = $null
                Actions            = $null
                Triggers           = $null
                Settings           = $null
                TaskXml            = $null
                Error              = $_.Exception.Message
            })
        }
    }
}

$results
