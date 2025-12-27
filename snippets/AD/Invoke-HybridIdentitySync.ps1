<#
.SYNOPSIS
Hybrid identity sync utility for Entra Connect Sync (ADSync) and Entra Cloud Sync.

.DESCRIPTION
Single-script operational tool to:
- Trigger Entra Connect Sync cycles (Delta/Initial)
- Inspect and toggle Entra Connect scheduler state
- Stop a running sync cycle (where supported)
- Provide Cloud Sync quick triage actions (trace logs, tooling presence)

This script is intended to be run on the sync server(s) where the relevant modules exist.

.PARAMETER Mode
Selects the platform: EntraConnect (ADSync) or CloudSync.

.PARAMETER Action
Operation to perform for the selected Mode.

.PARAMETER OpenLogs
If specified, opens the relevant log folder (Cloud Sync trace folder, or Windows Event Viewer hint).

.EXAMPLE
.\Invoke-HybridIdentitySync.ps1 -Mode EntraConnect -Action DeltaSync

.EXAMPLE
.\Invoke-HybridIdentitySync.ps1 -Mode EntraConnect -Action GetScheduler

.EXAMPLE
.\Invoke-HybridIdentitySync.ps1 -Mode EntraConnect -Action DisableScheduler

.EXAMPLE
.\Invoke-HybridIdentitySync.ps1 -Mode CloudSync -Action ShowLogs -OpenLogs

.NOTES
Author: Cheri
Safe defaults: read-only unless action explicitly changes state.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('EntraConnect','CloudSync')]
    [string]$Mode,

    [Parameter(Mandatory)]
    [ValidateSet(
        # Entra Connect (ADSync)
        'GetScheduler','DeltaSync','FullSync','StopCurrentCycle','EnableScheduler','DisableScheduler',
        # Cloud Sync
        'ShowLogs','ListTools','ShowStatus'
    )]
    [string]$Action,

    [Parameter()]
    [switch]$OpenLogs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Result {
    param(
        [string]$Mode,
        [string]$Action,
        [string]$Result,
        [string]$Message,
        [hashtable]$Data
    )

    $obj = [ordered]@{
        Timestamp    = Get-Date
        ComputerName = $env:COMPUTERNAME
        Mode         = $Mode
        Action       = $Action
        Result       = $Result
        Message      = $Message
    }

    if ($Data) {
        foreach ($k in $Data.Keys) { $obj[$k] = $Data[$k] }
    }

    [PSCustomObject]$obj
}

function Test-ModuleAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
}

function Require-Module {
    param([Parameter(Mandatory)][string]$Name)
    if (-not (Test-ModuleAvailable -Name $Name)) {
        throw "Required module not found: $Name. Run this on the appropriate sync server."
    }
    Import-Module $Name -ErrorAction Stop
}

function Try-GetAdSyncScheduler {
    try {
        if (Get-Command -Name Get-ADSyncScheduler -ErrorAction SilentlyContinue) {
            return Get-ADSyncScheduler
        }
    } catch { }
    return $null
}

# ===========================
# Entra Connect Sync (ADSync)
# ===========================
if ($Mode -eq 'EntraConnect') {

    Require-Module -Name 'ADSync'

    switch ($Action) {

        'GetScheduler' {
            $sched = Try-GetAdSyncScheduler
            if (-not $sched) {
                return New-Result -Mode $Mode -Action $Action -Result 'Warning' -Message "Get-ADSyncScheduler not available on this host/build. ADSync module loaded, but scheduler cmdlet not found." -Data @{}
            }

            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Scheduler state retrieved.' -Data @{
                SyncCycleEnabled              = $sched.SyncCycleEnabled
                StagingModeEnabled           = $sched.StagingModeEnabled
                NextSyncCyclePolicyType      = $sched.NextSyncCyclePolicyType
                NextSyncCycleStartTimeInUTC  = $sched.NextSyncCycleStartTimeInUTC
                CustomizedSyncCycleInterval  = $sched.CustomizedSyncCycleInterval
                PurgeRunHistoryInterval      = $sched.PurgeRunHistoryInterval
            }
        }

        'DeltaSync' {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Start Entra Connect sync cycle: Delta")) {
                $r = Start-ADSyncSyncCycle -PolicyType Delta
            }
            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Delta sync requested.' -Data @{
                PolicyType = 'Delta'
                ReturnValue = ($r | Out-String).Trim()
            }
        }

        'FullSync' {
            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Start Entra Connect sync cycle: Initial (Full)")) {
                $r = Start-ADSyncSyncCycle -PolicyType Initial
            }
            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Full (Initial) sync requested.' -Data @{
                PolicyType = 'Initial'
                ReturnValue = ($r | Out-String).Trim()
            }
        }

        'StopCurrentCycle' {
            if (-not (Get-Command -Name Stop-ADSyncSyncCycle -ErrorAction SilentlyContinue)) {
                return New-Result -Mode $Mode -Action $Action -Result 'Warning' -Message "Stop-ADSyncSyncCycle not available on this host/build." -Data @{}
            }

            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Stop current Entra Connect sync cycle")) {
                Stop-ADSyncSyncCycle
            }

            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Stop current cycle requested.' -Data @{}
        }

        'EnableScheduler' {
            if (-not (Get-Command -Name Set-ADSyncScheduler -ErrorAction SilentlyContinue)) {
                return New-Result -Mode $Mode -Action $Action -Result 'Warning' -Message "Set-ADSyncScheduler not available on this host/build." -Data @{}
            }

            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Enable Entra Connect scheduler")) {
                Set-ADSyncScheduler -SyncCycleEnabled $true
            }

            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Scheduler enabled.' -Data @{}
        }

        'DisableScheduler' {
            if (-not (Get-Command -Name Set-ADSyncScheduler -ErrorAction SilentlyContinue)) {
                return New-Result -Mode $Mode -Action $Action -Result 'Warning' -Message "Set-ADSyncScheduler not available on this host/build." -Data @{}
            }

            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Disable Entra Connect scheduler")) {
                Set-ADSyncScheduler -SyncCycleEnabled $false
            }

            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Scheduler disabled.' -Data @{}
        }

        default {
            throw "Unsupported Action '$Action' for Mode '$Mode'."
        }
    }
}

# ======================
# Entra Cloud Sync
# ======================
if ($Mode -eq 'CloudSync') {

    $TracePath = "C:\ProgramData\Microsoft\Azure AD Connect Provisioning Agent\Trace"

    switch ($Action) {

        'ShowLogs' {
            $exists = Test-Path $TracePath
            if ($OpenLogs -and $exists) {
                Start-Process explorer.exe $TracePath | Out-Null
            }

            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Cloud Sync trace log location.' -Data @{
                TracePathExists = $exists
                TracePath       = $TracePath
            }
        }

        'ListTools' {
            $hasTools = Test-ModuleAvailable -Name 'AADCloudSyncTools'

            if ($hasTools) {
                Import-Module AADCloudSyncTools -ErrorAction Stop
                $cmds = Get-Command -Module AADCloudSyncTools | Sort-Object Name | Select-Object -ExpandProperty Name
                return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'AADCloudSyncTools module detected.' -Data @{
                    ModulePresent = $true
                    Cmdlets       = ($cmds -join ', ')
                }
            }

            return New-Result -Mode $Mode -Action $Action -Result 'Warning' -Message 'AADCloudSyncTools module not found on this host. Cloud Sync is primarily managed via Entra portal; install tools only on approved agent hosts.' -Data @{
                ModulePresent = $false
                TracePath     = $TracePath
            }
        }

        'ShowStatus' {
            # Cloud Sync status is primarily surfaced in Entra portal.
            # Locally, we can provide quick signals: trace folder existence and agent-related services presence.
            $services = Get-Service -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'AADConnectProvisioningAgent|Provisioning|AzureADConnect' } |
                Select-Object Name, DisplayName, Status, StartType

            return New-Result -Mode $Mode -Action $Action -Result 'Success' -Message 'Local Cloud Sync signals gathered (portal remains source of truth for job state).' -Data @{
                TracePathExists = (Test-Path $TracePath)
                TracePath       = $TracePath
                ServicesFound   = ($services.Count -gt 0)
                Services        = ($services | ConvertTo-Json -Depth 3)
            }
        }

        default {
            throw "Unsupported Action '$Action' for Mode '$Mode'."
        }
    }
}
