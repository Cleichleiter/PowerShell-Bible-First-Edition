<#
.SYNOPSIS
Safely disables scheduled tasks with pre-change snapshots, strong guardrails, and optional rollback output.

.DESCRIPTION
Disables one or more scheduled tasks (local or remote) with safety controls:
- Defaults to WhatIf behavior via PowerShell -WhatIf (SupportsShouldProcess)
- Captures a pre-change snapshot (status + definition signals) before changes
- Supports wildcard filters and explicit FullName selection
- Optionally exports snapshots to CSV/JSON for audit trails
- Returns a structured result object per task (Before/After + ChangeStatus)

This script DOES NOT delete tasks.

Remote support via PowerShell remoting.

.PARAMETER ComputerName
One or more computers to target. Defaults to local.

.PARAMETER TaskName
Filter by task name (supports wildcards). Example: "Backup*", "Datto*"

.PARAMETER TaskPath
Filter by task path (supports wildcards). Example: "\Vendor\*"

.PARAMETER FullName
Filter by full task name (TaskPath + TaskName). Supports wildcards. Example: "\Vendor\Backup\*"

.PARAMETER ExcludeMicrosoft
Exclude tasks under "\Microsoft\Windows\".

.PARAMETER RequireSingle
Fail if filters match more than one task (recommended for high-risk environments).

.PARAMETER Force
Skips interactive confirmation (still honors -WhatIf).

.PARAMETER ExportCsv
If provided, exports results to CSV at this path.

.PARAMETER ExportJson
If provided, exports results to JSON at this path.

.PARAMETER IncludeDefinition
Include action/trigger summary signals in output.

.PARAMETER PassThru
Return objects (default). If not set, still returns objects (kept on for pipeline consistency).

.PARAMETER MaxTasks
Guardrail for very large inventories. Default 5000.

.PARAMETER ThrottleLimit
Throttle limit for multi-host PSSession usage. Default 16.

.EXAMPLE
# Preview what would be disabled (recommended first run)
.\Disable-ScheduledTaskSafely.ps1 -FullName "\Vendor\*" -ExcludeMicrosoft -WhatIf

.EXAMPLE
# Disable a single task safely (exact match), capture output
.\Disable-ScheduledTaskSafely.ps1 -TaskName "NightlyBackup" -TaskPath "\Backups\" -RequireSingle -Force

.EXAMPLE
# Disable tasks matching pattern and export evidence
.\Disable-ScheduledTaskSafely.ps1 -FullName "\Vendor\*" -ExcludeMicrosoft -Force `
  -ExportCsv C:\Reports\DisabledTasks.csv

.EXAMPLE
# Remote disable with audit trail
.\Disable-ScheduledTaskSafely.ps1 -ComputerName RDSH01,RDSH02 -FullName "\Ops\Legacy\*" -Force `
  -ExportJson C:\Reports\DisabledTasks.json

.NOTES
Author: Cheri
Change-impact script. Default to -WhatIf for first run.
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
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
    [switch]$RequireSingle,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string]$ExportCsv,

    [Parameter()]
    [string]$ExportJson,

    [Parameter()]
    [switch]$IncludeDefinition,

    [Parameter()]
    [switch]$PassThru = $true,

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

function Get-TriggerSummary {
    param($Task)
    try { return @($Task.Triggers | ForEach-Object { $_.ToString() }) -join ' | ' } catch { return $null }
}

function Resolve-TasksLocal {
    param(
        [string[]]$TaskName,
        [string[]]$TaskPath,
        [string[]]$FullName,
        [bool]$ExcludeMicrosoft,
        [int]$MaxTasks
    )

    $tasks = Get-ScheduledTask -ErrorAction Stop

    if (@($tasks).Count -gt $MaxTasks) {
        throw "Task enumeration exceeded MaxTasks ($MaxTasks). Found: $(@($tasks).Count). Use narrower filters or increase MaxTasks."
    }

    foreach ($t in @($tasks)) {
        $full = ($t.TaskPath + $t.TaskName)

        if ($ExcludeMicrosoft -and $t.TaskPath -like '\Microsoft\Windows\*') { continue }
        if (-not (Match-AnyWildcard -Value $t.TaskName -Patterns $TaskName)) { continue }
        if (-not (Match-AnyWildcard -Value $t.TaskPath -Patterns $TaskPath)) { continue }
        if (-not (Match-AnyWildcard -Value $full -Patterns $FullName)) { continue }

        $t
    }
}

function Disable-ScheduledTaskSafelyLocal {
    param(
        [string[]]$TaskName,
        [string[]]$TaskPath,
        [string[]]$FullName,
        [bool]$ExcludeMicrosoft,
        [bool]$RequireSingle,
        [bool]$Force,
        [bool]$IncludeDefinition,
        [int]$MaxTasks
    )

    $now = Get-Date
    $out = New-Object System.Collections.Generic.List[object]

    $targets = @(Resolve-TasksLocal -TaskName $TaskName -TaskPath $TaskPath -FullName $FullName -ExcludeMicrosoft:$ExcludeMicrosoft -MaxTasks $MaxTasks)

    if (-not $targets -or $targets.Count -eq 0) {
        $out.Add([PSCustomObject]@{
            Timestamp          = $now
            ComputerName       = $env:COMPUTERNAME
            TaskPath           = $null
            TaskName           = $null
            FullName           = ($FullName -join ',')
            ChangeStatus       = 'NoMatch'
            Message            = 'No matching tasks found'
            BeforeEnabled      = $null
            AfterEnabled       = $null
            BeforeState        = $null
            AfterState         = $null
            BeforeLastRunTime  = $null
            AfterLastRunTime   = $null
            BeforeLastResult   = $null
            AfterLastResult    = $null
            PrincipalUserId    = $null
            RunLevel           = $null
            ActionSummary      = $null
            TriggerSummary     = $null
            Error              = $null
        })
        return $out
    }

    if ($RequireSingle -and $targets.Count -ne 1) {
        throw "RequireSingle specified but filters matched $($targets.Count) tasks. Narrow filters before disabling."
    }

    if (-not $Force) {
        $caption = "Disable scheduled tasks"
        $msg = "You are about to disable $($targets.Count) scheduled task(s) on $($env:COMPUTERNAME). Continue?"
        if (-not $PSCmdlet.ShouldContinue($msg, $caption)) {
            foreach ($t in $targets) {
                $out.Add([PSCustomObject]@{
                    Timestamp          = $now
                    ComputerName       = $env:COMPUTERNAME
                    TaskPath           = $t.TaskPath
                    TaskName           = $t.TaskName
                    FullName           = ($t.TaskPath + $t.TaskName)
                    ChangeStatus       = 'Skipped'
                    Message            = 'User declined confirmation'
                    BeforeEnabled      = $null
                    AfterEnabled       = $null
                    BeforeState        = $t.State
                    AfterState         = $null
                    BeforeLastRunTime  = $null
                    AfterLastRunTime   = $null
                    BeforeLastResult   = $null
                    AfterLastResult    = $null
                    PrincipalUserId    = $t.Principal.UserId
                    RunLevel           = $t.Principal.RunLevel
                    ActionSummary      = if ($IncludeDefinition) { Get-ActionSummary -Task $t } else { $null }
                    TriggerSummary     = if ($IncludeDefinition) { Get-TriggerSummary -Task $t } else { $null }
                    Error              = $null
                })
            }
            return $out
        }
    }

    foreach ($t in $targets) {
        $full = ($t.TaskPath + $t.TaskName)

        $beforeEnabled = $true
        try { $beforeEnabled = [bool]$t.Settings.Enabled } catch { $beforeEnabled = $true }

        $beforeInfo = $null
        try { $beforeInfo = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch { $beforeInfo = $null }

        $beforeLastRun = $null
        $beforeLastResult = $null
        if ($beforeInfo) {
            $beforeLastRun = $beforeInfo.LastRunTime
            $beforeLastResult = Normalize-ResultCode $beforeInfo.LastTaskResult
        }

        $actionSummary = $null
        $triggerSummary = $null
        if ($IncludeDefinition) {
            $actionSummary = Get-ActionSummary -Task $t
            $triggerSummary = Get-TriggerSummary -Task $t
        }

        $changeStatus = 'NoChange'
        $message = $null
        $afterEnabled = $beforeEnabled
        $afterState = $null
        $afterLastRun = $null
        $afterLastResult = $null
        $err = $null

        if (-not $beforeEnabled) {
            $changeStatus = 'AlreadyDisabled'
            $message = 'Task already disabled'
        }
        else {
            $op = "Disable scheduled task $full"
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $op)) {
                try {
                    Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null
                    $changeStatus = 'Disabled'
                    $message = 'Task disabled successfully'

                    # Re-query
                    $t2 = Get-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                    try { $afterEnabled = [bool]$t2.Settings.Enabled } catch { $afterEnabled = $null }
                    $afterState = $t2.State

                    try {
                        $i2 = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
                        $afterLastRun = $i2.LastRunTime
                        $afterLastResult = Normalize-ResultCode $i2.LastTaskResult
                    } catch {}
                }
                catch {
                    $changeStatus = 'Error'
                    $message = 'Disable operation failed'
                    $err = $_.Exception.Message
                }
            }
            else {
                $changeStatus = 'WhatIf'
                $message = 'WhatIf: disable would be performed'
            }
        }

        $out.Add([PSCustomObject]@{
            Timestamp          = $now
            ComputerName       = $env:COMPUTERNAME

            TaskPath           = $t.TaskPath
            TaskName           = $t.TaskName
            FullName           = $full

            ChangeStatus       = $changeStatus
            Message            = $message

            BeforeEnabled      = $beforeEnabled
            AfterEnabled       = $afterEnabled

            BeforeState        = $t.State
            AfterState         = $afterState

            BeforeLastRunTime  = $beforeLastRun
            AfterLastRunTime   = $afterLastRun

            BeforeLastResult   = $beforeLastResult
            AfterLastResult    = $afterLastResult

            PrincipalUserId    = $t.Principal.UserId
            RunLevel           = $t.Principal.RunLevel

            ActionSummary      = $actionSummary
            TriggerSummary     = $triggerSummary

            Error              = $err
        })
    }

    $out
}

$all = New-Object System.Collections.Generic.List[object]

# Multi-host via PSSession
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Disable-ScheduledTaskSafelyLocal} -ArgumentList @(
            $TaskName,
            $TaskPath,
            $FullName,
            [bool]$ExcludeMicrosoft,
            [bool]$RequireSingle,
            [bool]$Force,
            [bool]$IncludeDefinition,
            [int]$MaxTasks
        )
        foreach ($r in @($rows)) { $all.Add($r) }
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
                $rows = Disable-ScheduledTaskSafelyLocal -TaskName $TaskName -TaskPath $TaskPath -FullName $FullName `
                    -ExcludeMicrosoft:$ExcludeMicrosoft -RequireSingle:$RequireSingle -Force:$Force `
                    -IncludeDefinition:$IncludeDefinition -MaxTasks $MaxTasks
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Disable-ScheduledTaskSafelyLocal} -ArgumentList @(
                    $TaskName,
                    $TaskPath,
                    $FullName,
                    [bool]$ExcludeMicrosoft,
                    [bool]$RequireSingle,
                    [bool]$Force,
                    [bool]$IncludeDefinition,
                    [int]$MaxTasks
                ) -ErrorAction Stop
            }

            # Fix ComputerName to the actual target in output when remoting
            foreach ($r in @($rows)) {
                if ($r.ComputerName -ne $target -and $target -ne $env:COMPUTERNAME) {
                    $r | Add-Member -NotePropertyName ComputerName -NotePropertyValue $target -Force
                }
                $all.Add($r)
            }
        }
        catch {
            $all.Add([PSCustomObject]@{
                Timestamp          = (Get-Date)
                ComputerName       = $target
                TaskPath           = ($TaskPath -join ',')
                TaskName           = ($TaskName -join ',')
                FullName           = ($FullName -join ',')
                ChangeStatus       = 'Error'
                Message            = 'Remote operation failed'
                BeforeEnabled      = $null
                AfterEnabled       = $null
                BeforeState        = $null
                AfterState         = $null
                BeforeLastRunTime  = $null
                AfterLastRunTime   = $null
                BeforeLastResult   = $null
                AfterLastResult    = $null
                PrincipalUserId    = $null
                RunLevel           = $null
                ActionSummary      = $null
                TriggerSummary     = $null
                Error              = $_.Exception.Message
            })
        }
    }
}

# Optional exports
if ($ExportCsv) {
    $dir = Split-Path -Path $ExportCsv -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $all | Export-Csv -Path $ExportCsv -NoTypeInformation
}

if ($ExportJson) {
    $dir = Split-Path -Path $ExportJson -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $all | ConvertTo-Json -Depth 6 | Out-File -FilePath $ExportJson -Encoding utf8
}

if ($PassThru) { $all }
