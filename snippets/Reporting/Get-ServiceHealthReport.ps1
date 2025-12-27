<#
.SYNOPSIS
Generates an ops-friendly service health report (object output).

.DESCRIPTION
Queries services via CIM (Win32_Service) and returns one row per service with:
- State (Running/Stopped/etc.)
- StartMode (Auto/Manual/Disabled)
- Health classification (OK/Warn/Critical)
- Reason (why it’s flagged)
- Service account and PID
- Optional PathName and dependency counts

Designed for:
- Daily/weekly health reporting
- Pre/post-change baselines
- Incident triage
- CSV/HTML exports

All output is object-based and safe for automation.

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
Returns only services that are non-OK (Warn/Critical) plus query errors.

.PARAMETER ExpectedRunning
Treat these services as critical if they are not running (regardless of StartMode).
Supports wildcards.

.PARAMETER IncludePath
Include PathName from Win32_Service.

.PARAMETER IncludeDependencies
Include dependency counts (ServicesDependedOn / DependentServices).

.PARAMETER ThrottleLimit
Throttle limit when querying multiple remote hosts via PSSession. Default 16.

.EXAMPLE
.\Get-ServiceHealthReport.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-ServiceHealthReport.ps1 -StartMode Auto -OnlyProblems |
  Sort-Object ComputerName,Name |
  Format-Table -Auto

.EXAMPLE
.\Get-ServiceHealthReport.ps1 -ComputerName RDSH01,RDSH02 -ExpectedRunning TermService,UmRdpService -OnlyProblems |
  Export-Csv C:\Reports\ServiceHealth-RDS.csv -NoTypeInformation

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
    [switch]$IncludeDependencies,

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

function Get-Health {
    param(
        [string]$ServiceName,
        [string]$CurrentState,
        [string]$StartMode,
        [string[]]$ExpectedRunningPatterns
    )

    $isExpected = $false
    if ($ExpectedRunningPatterns) {
        foreach ($p in $ExpectedRunningPatterns) {
            if ($ServiceName -like $p) { $isExpected = $true; break }
        }
    }

    if ($isExpected -and $CurrentState -ne 'Running') {
        return [PSCustomObject]@{ Health='Critical'; Reason='ExpectedRunning but not Running' }
    }

    if ($StartMode -eq 'Auto' -and $CurrentState -ne 'Running') {
        return [PSCustomObject]@{ Health='Critical'; Reason='Auto-start service not running' }
    }

    if ($StartMode -eq 'Disabled' -and $CurrentState -eq 'Running') {
        return [PSCustomObject]@{ Health='Warn'; Reason='Disabled service is running' }
    }

    if ($CurrentState -like '*Pending') {
        return [PSCustomObject]@{ Health='Warn'; Reason='Service in pending state' }
    }

    return [PSCustomObject]@{ Health='OK'; Reason=$null }
}

function Get-ServiceHealthLocal {
    param(
        [string[]]$Name,
        [string[]]$DisplayName,
        [string]$State,
        [string]$StartMode,
        [bool]$OnlyProblems,
        [string[]]$ExpectedRunning,
        [bool]$IncludePath,
        [bool]$IncludeDependencies
    )

    $now = Get-Date
    $rows = New-Object System.Collections.Generic.List[object]

    try {
        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop

        foreach ($s in @($services)) {
            if (-not (Match-AnyWildcard -Value $s.Name -Patterns $Name)) { continue }
            if (-not (Match-AnyWildcard -Value $s.DisplayName -Patterns $DisplayName)) { continue }

            if ($State -ne 'All' -and $s.State -ne $State) { continue }
            if ($StartMode -ne 'All' -and $s.StartMode -ne $StartMode) { continue }

            $health = Get-Health -ServiceName $s.Name -CurrentState $s.State -StartMode $s.StartMode -ExpectedRunningPatterns $ExpectedRunning
            if ($OnlyProblems -and $health.Health -eq 'OK') { continue }

            $obj = [ordered]@{
                Timestamp      = $now
                ComputerName   = $env:COMPUTERNAME
                Name           = $s.Name
                DisplayName    = $s.DisplayName
                State          = $s.State
                StartMode      = $s.StartMode
                StartName      = $s.StartName
                ProcessId      = $s.ProcessId
                ExitCode       = $s.ExitCode
                ServiceType    = $s.ServiceType
                Health         = $health.Health
                Reason         = $health.Reason

                PathName       = $null
                ServicesDependedOnCount = $null
                DependentServicesCount  = $null
                Error          = $null
            }

            if ($IncludePath) {
                $obj.PathName = $s.PathName
            }

            if ($IncludeDependencies) {
                try { $obj.ServicesDependedOnCount = @($s.ServicesDependedOn).Count } catch {}
                try { $obj.DependentServicesCount  = @($s.DependentServices).Count } catch {}
            }

            $rows.Add([PSCustomObject]$obj)
        }
    }
    catch {
        $rows.Add([PSCustomObject]@{
            Timestamp      = $now
            ComputerName   = $env:COMPUTERNAME
            Name           = $null
            DisplayName    = $null
            State          = $null
            StartMode      = $null
            StartName      = $null
            ProcessId      = $null
            ExitCode       = $null
            ServiceType    = $null
            Health         = 'Error'
            Reason         = 'Service query failed'
            PathName       = $null
            ServicesDependedOnCount = $null
            DependentServicesCount  = $null
            Error          = $_.Exception.Message
        })
    }

    $rows
}

$results = New-Object System.Collections.Generic.List[object]

# If multiple computers, use PSSessions for efficiency/throttle control
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-ServiceHealthLocal} -ArgumentList @(
            $Name, $DisplayName, $State, $StartMode,
            [bool]$OnlyProblems, $ExpectedRunning,
            [bool]$IncludePath, [bool]$IncludeDependencies
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
                $rows = Get-ServiceHealthLocal -Name $Name -DisplayName $DisplayName -State $State -StartMode $StartMode `
                    -OnlyProblems:$OnlyProblems -ExpectedRunning $ExpectedRunning -IncludePath:$IncludePath -IncludeDependencies:$IncludeDependencies
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-ServiceHealthLocal} -ArgumentList @(
                    $Name, $DisplayName, $State, $StartMode,
                    [bool]$OnlyProblems, $ExpectedRunning,
                    [bool]$IncludePath, [bool]$IncludeDependencies
                )
            }

            foreach ($r in @($rows)) {
                # Normalize ComputerName for remote suggests (script returns local env:COMPUTERNAME)
                if ($r -and $r.PSObject.Properties.Match('ComputerName').Count -gt 0) {
                    # Keep original host value; it’s already correct when executed remotely.
                }
                $results.Add($r)
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Timestamp      = (Get-Date)
                ComputerName   = $target
                Name           = $null
                DisplayName    = $null
                State          = $null
                StartMode      = $null
                StartName      = $null
                ProcessId      = $null
                ExitCode       = $null
                ServiceType    = $null
                Health         = 'Error'
                Reason         = 'Remote query failed'
                PathName       = $null
                ServicesDependedOnCount = $null
                DependentServicesCount  = $null
                Error          = $_.Exception.Message
            })
        }
    }
}

$results
