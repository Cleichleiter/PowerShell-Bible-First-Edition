<#
.SYNOPSIS
Generates an ops-friendly service health report (object output).

.DESCRIPTION
Queries Win32_Service and returns one row per service with:
- State (Running/Stopped/etc.)
- StartMode (Auto/Manual/Disabled)
- Health classification (OK/Warn/Critical)
- Reason and suggested action signals
- Service account, ProcessId, PathName (when available)

Designed for:
- Daily/weekly health checks
- Pre/post-change baselines
- Incident triage (why isn't X running?)
- CSV/HTML exports

Uses CIM (Win32_Service) for consistency and remote support.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER Name
Filter by service name (supports wildcards). Example: "w32time", "MSSQL*"

.PARAMETER DisplayName
Filter by display name (supports wildcards). Example: "*Print*", "*SQL*"

.PARAMETER State
Filter by current state. Default: All.

.PARAMETER StartMode
Filter by start mode. Default: All.

.PARAMETER OnlyProblems
Returns only services that appear unhealthy based on start mode and state.

.PARAMETER ExpectedRunning
Treat these services as critical if they are not running (regardless of StartMode).
Supports wildcards. Example: "Spooler","w32time","MSSQLSERVER"

.PARAMETER IncludePath
Include ImagePath/PathName from Win32_Service (can be noisy but useful for malware triage).

.PARAMETER IncludeDependencies
Include dependency counts (DependentServices / ServicesDependedOn).

.EXAMPLE
.\Get-ServiceHealthReport.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-ServiceHealthReport.ps1 -StartMode Auto -OnlyProblems |
  Sort-Object ComputerName,Name |
  Format-Table -Auto

.EXAMPLE
.\Get-ServiceHealthReport.ps1 -ComputerName RDSH01,RDSH02 -ExpectedRunning TermService,UmRdpService -OnlyProblems |
  Export-Csv C:\Reports\ServiceHealth-RDS.csv -NoTypeInformation

.EXAMPLE
.\Get-ServiceHealthReport.ps1 -Name "MSSQL*" -State Running -IncludePath |
  Format-Table -Auto

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [string[]]$Name,

    [Parameter()]
    [string[]]$DisplayName,

    [Parameter()]
    [ValidateSet('All','Running','Stopped','Paused','Start Pending','Stop Pending','Continue Pending','Pause Pending')]
    [string]$State = 'All',

    [Parameter()]
    [ValidateSet('All','Auto','Manual','Disabled')]
    [string]$StartMode = 'All',

    [Parameter()]
    [switch]$OnlyProblems,

    [Parameter()]
    [string[]]$ExpectedRunning,

    [Parameter()]
    [switch]$IncludePath,

    [Parameter()]
    [switch]$IncludeDependencies
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Match-AnyWildcard {
    param(
        [string]$Value,
        [string[]]$Patterns
    )
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
    return $false
}

function Get-Health {
    param(
        [string]$ServiceName,
        [string]$CurrentState,
        [string]$StartMode,
        [string[]]$ExpectedRunningPatterns
    )

    $isExpected = $false
    if ($ExpectedRunningPatterns -and $ExpectedRunningPatterns.Count -gt 0) {
        foreach ($p in $ExpectedRunningPatterns) {
            if ($ServiceName -like $p) { $isExpected = $true; break }
        }
    }

    # Critical: explicitly expected to run but isn't
    if ($isExpected -and $CurrentState -ne 'Running') {
        return [PSCustomObject]@{
            Health = 'Critical'
            Reason = 'ExpectedRunning but not Running'
        }
    }

    # General logic based on start mode:
    # - Auto + not Running => Critical
    # - Disabled + Running => Warn
    # - Manual => usually OK regardless of state (unless explicitly expected)
    if ($StartMode -eq 'Auto' -and $CurrentState -ne 'Running') {
        return [PSCustomObject]@{
            Health = 'Critical'
            Reason = 'Auto-start service not running'
        }
    }

    if ($StartMode -eq 'Disabled' -and $CurrentState -eq 'Running') {
        return [PSCustomObject]@{
            Health = 'Warn'
            Reason = 'Disabled service is running'
        }
    }

    if ($CurrentState -like '*Pending') {
        return [PSCustomObject]@{
            Health = 'Warn'
            Reason = 'Service in pending state'
        }
    }

    return [PSCustomObject]@{
        Health = 'OK'
        Reason = $null
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        $services = Get-CimInstance -ClassName Win32_Service -ComputerName $target -ErrorAction Stop

        foreach ($s in @($services)) {
            # Filters: Name / DisplayName
            if (-not (Match-AnyWildcard -Value $s.Name -Patterns $Name)) { continue }
            if (-not (Match-AnyWildcard -Value $s.DisplayName -Patterns $DisplayName)) { continue }

            # Filter: State
            if ($State -ne 'All' -and $s.State -ne $State) { continue }

            # Filter: StartMode
            # Win32_Service StartMode is typically: "Auto", "Manual", "Disabled"
            if ($StartMode -ne 'All' -and $s.StartMode -ne $StartMode) { continue }

            $healthObj = Get-Health -ServiceName $s.Name -CurrentState $s.State -StartMode $s.StartMode -ExpectedRunningPatterns $ExpectedRunning

            if ($OnlyProblems -and $healthObj.Health -eq 'OK') { continue }

            $row = [ordered]@{
                Timestamp     = (Get-Date)
                ComputerName  = $target
                Name          = $s.Name
                DisplayName   = $s.DisplayName
                State         = $s.State
                StartMode     = $s.StartMode
                StartName     = $s.StartName
                ProcessId     = $s.ProcessId
                ExitCode      = $s.ExitCode
                ServiceType   = $s.ServiceType
                Health        = $healthObj.Health
                Reason        = $healthObj.Reason
                CanStop       = $null
                DelayedAutoStart = $null
                PathName      = $null
                ServicesDependedOnCount = $null
                DependentServicesCount  = $null
            }

            # DelayedAutoStart exists on many modern Windows builds; best-effort
            try { $row.DelayedAutoStart = $s.DelayedAutoStart } catch {}

            # CanStop isn't directly on Win32_Service; derive best-effort
            # If AcceptStop property exists in CIM (not consistent), otherwise infer from state
            try { $row.CanStop = [bool]$s.AcceptStop } catch { $row.CanStop = ($s.State -eq 'Running') }

            if ($IncludePath) {
                $row.PathName = $s.PathName
            }

            if ($IncludeDependencies) {
                try { $row.ServicesDependedOnCount = @($s.ServicesDependedOn).Count } catch {}
                try { $row.DependentServicesCount  = @($s.DependentServices).Count } catch {}
            }

            $results.Add([PSCustomObject]$row)
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp    = (Get-Date)
            ComputerName = $target
            Name         = $null
            DisplayName  = $null
            State        = $null
            StartMode    = $null
            StartName    = $null
            ProcessId    = $null
            ExitCode     = $null
            ServiceType  = $null
            Health       = 'Error'
            Reason       = $_.Exception.Message
            CanStop      = $null
            DelayedAutoStart = $null
            PathName     = $null
            ServicesDependedOnCount = $null
            DependentServicesCount  = $null
        })
    }
}

$results
