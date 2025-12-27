<#
.SYNOPSIS
Collects scheduled task inventory (baseline discovery) with normalized, report-ready output.

.DESCRIPTION
Enumerates scheduled tasks and returns one row per task including:
- Identity: TaskPath, TaskName, FullName
- Runtime: State, Enabled, LastRunTime, NextRunTime, LastTaskResult, Runs/MissedRuns
- Security context: RunAs user, LogonType, RunLevel
- Metadata: Author, Description, Hidden
- Optional: Actions and Triggers (lightweight string summaries)

Designed for:
- Baseline snapshots before/after changes
- Audit preparation and documentation
- RMM-friendly inventory collection

Uses ScheduledTasks module: Get-ScheduledTask + Get-ScheduledTaskInfo.
Remote support via PowerShell remoting.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER TaskName
Filter by task name (supports wildcards). Example: "Backup*", "Datto*"

.PARAMETER TaskPath
Filter by task path (supports wildcards). Example: "\Microsoft\Windows\*"

.PARAMETER ExcludeMicrosoft
Exclude tasks under "\Microsoft\Windows\".

.PARAMETER IncludeDisabled
Include disabled tasks (default includes them unless explicitly filtered out).

.PARAMETER IncludeActions
Include a simplified action summary (Execute + Arguments).

.PARAMETER IncludeTriggers
Include a simplified trigger summary.

.PARAMETER IncludeRawXml
Include the raw task XML (heavier). Useful for deep auditing or exports.

.PARAMETER MaxTasks
Guardrail to prevent runaway enumeration in broken environments. Default 5000.

.PARAMETER ThrottleLimit
Throttle limit for multi-host PSSession usage. Default 16.

.EXAMPLE
.\Get-ScheduledTaskInventory.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-ScheduledTaskInventory.ps1 -ExcludeMicrosoft -IncludeActions -IncludeTriggers |
  Export-Csv C:\Reports\ScheduledTaskInventory.csv -NoTypeInformation

.EXAMPLE
.\Get-ScheduledTaskInventory.ps1 -TaskPath "\Microsoft\Windows\*" -TaskName "*Update*" |
  Format-Table -Auto

.EXAMPLE
.\Get-ScheduledTaskInventory.ps1 -ComputerName RDSH01,RDSH02 -ExcludeMicrosoft |
  Export-Csv C:\Reports\TaskInventory.csv -NoTypeInformation

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
    [switch]$ExcludeMicrosoft,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$IncludeActions,

    [Parameter()]
    [switch]$IncludeTriggers,

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
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
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

function Get-TaskXml {
    param([string]$TaskPath, [string]$TaskName)

    # schtasks is available almost everywhere and returns task XML reliably
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

function Get-ScheduledTaskInventoryLocal {
    param(
        [string[]]$TaskName,
        [string[]]$TaskPath,
        [bool]$ExcludeMicrosoft,
        [bool]$IncludeDisabled,
        [bool]$IncludeActions,
        [bool]$IncludeTriggers,
        [bool]$IncludeRawXml,
        [int]$MaxTasks
    )

    $now = Get-Date
    $out = New-Object System.Collections.Generic.List[object]

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop

        # Guardrail
        if (@($tasks).Count -gt $MaxTasks) {
            throw "Task inventory exceeded MaxTasks ($MaxTasks). Found: $(@($tasks).Count). Use filters or increase MaxTasks."
        }

        foreach ($t in @($tasks)) {
            if ($ExcludeMicrosoft -and $t.TaskPath -like '\Microsoft\Windows\*') { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskName -Patterns $TaskName)) { continue }
            if (-not (Match-AnyWildcard -Value $t.TaskPath -Patterns $TaskPath)) { continue }

            $enabled = $true
            try { $enabled = [bool]$t.Settings.Enabled } catch { $enabled = $true }
            if (-not $IncludeDisabled -and -not $enabled) { continue }

            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { $info = $null }

            $lastRun = $null
            $nextRun = $null
            $lastResultHex = $null
            $missed = $null
            $runs = $null
            if ($info) {
                $lastRun = $info.LastRunTime
                $nextRun = $info.NextRunTime
                $lastResultHex = Normalize-ResultCode $info.LastTaskResult
                $missed = $info.NumberOfMissedRuns
                $runs = $info.NumberOfRuns
            }

            $actions = $null
            if ($IncludeActions) {
                try {
                    $actions = @($t.Actions | ForEach-Object {
                        $exe = $_.Execute
                        $arg = $_.Arguments
                        if ($arg) { "$exe $arg" } else { "$exe" }
                    }) -join ' | '
                } catch { $actions = $null }
            }

            $triggers = $null
            if ($IncludeTriggers) {
                try {
                    $triggers = @($t.Triggers | ForEach-Object { $_.ToString() }) -join ' | '
                } catch { $triggers = $null }
            }

            $rawXml = $null
            if ($IncludeRawXml) {
                $rawXml = Get-TaskXml -TaskPath $t.TaskPath -TaskName $t.TaskName
            }

            $row = [ordered]@{
                Timestamp          = $now
                ComputerName       = $env:COMPUTERNAME

                TaskPath           = $t.TaskPath
                TaskName           = $t.TaskName
                FullName           = ($t.TaskPath + $t.TaskName)

                State              = $t.State
                Enabled            = $enabled
                Hidden             = $t.Settings.Hidden

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

                Actions            = $actions
                Triggers           = $triggers
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
            PrincipalLogonType = $null
            RunLevel           = $null
            LastRunTime        = $null
            NextRunTime        = $null
            LastTaskResult     = $null
            NumberOfRuns       = $null
            NumberOfMissedRuns = $null
            Actions            = $null
            Triggers           = $null
            TaskXml            = $null
            Error              = $_.Exception.Message
        })
    }

    $out
}

$results = New-Object System.Collections.Generic.List[object]

# If multiple computers, use PSSessions for efficiency/throttle control
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-ScheduledTaskInventoryLocal} -ArgumentList @(
            $TaskName,
            $TaskPath,
            [bool]$ExcludeMicrosoft,
            [bool]$IncludeDisabled,
            [bool]$IncludeActions,
            [bool]$IncludeTriggers,
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
                $rows = Get-ScheduledTaskInventoryLocal -TaskName $TaskName -TaskPath $TaskPath `
                    -ExcludeMicrosoft:$ExcludeMicrosoft -IncludeDisabled:$IncludeDisabled `
                    -IncludeActions:$IncludeActions -IncludeTriggers:$IncludeTriggers -IncludeRawXml:$IncludeRawXml `
                    -MaxTasks $MaxTasks
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-ScheduledTaskInventoryLocal} -ArgumentList @(
                    $TaskName,
                    $TaskPath,
                    [bool]$ExcludeMicrosoft,
                    [bool]$IncludeDisabled,
                    [bool]$IncludeActions,
                    [bool]$IncludeTriggers,
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
                PrincipalLogonType = $null
                RunLevel           = $null
                LastRunTime        = $null
                NextRunTime        = $null
                LastTaskResult     = $null
                NumberOfRuns       = $null
                NumberOfMissedRuns = $null
                Actions            = $null
                Triggers           = $null
                TaskXml            = $null
                Error              = $_.Exception.Message
            })
        }
    }
}

$results
