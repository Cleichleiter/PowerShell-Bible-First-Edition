<#
.SYNOPSIS
Finds (and optionally removes) stale local user profiles on RDS/terminal servers.

.DESCRIPTION
Enumerates user profiles via Win32_UserProfile and flags profiles as stale based on LastUseTime.
By default, the script only reports. Use -Remove to actually delete profiles.

Safeguards:
- Never removes profiles that are currently Loaded
- Supports -WhatIf and -Confirm
- Exclusion patterns for usernames and profile paths
- Optional size estimation (disabled by default due to time/cost)

.PARAMETER ComputerName
One or more servers to query. Defaults to local computer.

.PARAMETER StaleDays
Profiles not used in this many days (based on LastUseTime) are considered stale.

.PARAMETER Remove
Actually remove stale profiles. Without this switch, script is report-only.

.PARAMETER ExcludeUsers
Exclude usernames (supports wildcard patterns), e.g. 'admin*','svc_*'

.PARAMETER ExcludeProfilePaths
Exclude profile paths (supports wildcard), e.g. '*\Administrator','*\Default*'

.PARAMETER IncludeSpecial
Include Special profiles (Default, Public, system profiles). Default: excluded.

.PARAMETER IncludeLoaded
Include loaded profiles in reporting. Removal is still blocked for loaded profiles.

.PARAMETER EstimateSize
Estimate profile size on disk (can be slow). Recommended only when needed.

.PARAMETER MinProfileSizeMB
Only consider profiles at least this size (requires -EstimateSize).

.PARAMETER TimeoutSeconds
CIM query timeout (best-effort). Default 15 seconds.

.EXAMPLE
Report stale profiles not used in 45+ days on one host (no deletion).

.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 45 | Format-Table -Auto

.EXAMPLE
Remove stale profiles not used in 90+ days, excluding admins (safe prompts).

.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 90 -Remove -ExcludeUsers 'admin*' -Verbose

.EXAMPLE
Automation style (no prompts) across multiple hosts:

.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01,RDSH02 -StaleDays 120 -Remove -Confirm:$false -Verbose

.NOTES
Author: Cheri
Requires: CIM/WMI access to target hosts.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory)]
    [ValidateRange(1, 3650)]
    [int]$StaleDays,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [string[]]$ExcludeUsers = @('Administrator','DefaultAccount','Guest'),

    [Parameter()]
    [string[]]$ExcludeProfilePaths = @('*\Windows\*','*\ProgramData\*','*\Default*','*\Public*'),

    [Parameter()]
    [switch]$IncludeSpecial,

    [Parameter()]
    [switch]$IncludeLoaded,

    [Parameter()]
    [switch]$EstimateSize,

    [Parameter()]
    [ValidateRange(0, 1024000)]
    [int]$MinProfileSizeMB = 0,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-CimDate {
    param([string]$CimDate)
    if ([string]::IsNullOrWhiteSpace($CimDate)) { return $null }
    try { return [Management.ManagementDateTimeConverter]::ToDateTime($CimDate) } catch { return $null }
}

function Try-ResolveSidToName {
    param([Parameter(Mandatory)][string]$Sid)

    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $nt = $sidObj.Translate([System.Security.Principal.NTAccount])
        return $nt.Value
    }
    catch {
        return $null
    }
}

function Should-Exclude {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string[]]$Patterns
    )
    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($Value -like $p) { return $true }
    }
    return $false
}

function Get-ProfileSizeMB {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$Path
    )

    # For remote hosts, use CIM + a remote command is complex; instead:
    # - If local, measure directly
    # - If remote, attempt UNC path resolution only if admin share is reachable
    try {
        if ($Computer -eq $env:COMPUTERNAME -or $Computer -eq 'localhost') {
            if (-not (Test-Path $Path)) { return $null }
            $bytes = (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
            if ($null -eq $bytes) { return 0 }
            return [math]::Round(($bytes / 1MB), 2)
        }

        # Remote UNC attempt (best-effort). Convert "C:\Users\X" to "\\HOST\C$\Users\X"
        $drive = $Path.Substring(0, 1)
        $rest  = $Path.Substring(2).TrimStart('\')
        $unc   = "\\$Computer\$drive`$$\$rest"

        if (-not (Test-Path $unc)) { return $null }

        $bytes = (Get-ChildItem -LiteralPath $unc -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        if ($null -eq $bytes) { return 0 }
        return [math]::Round(($bytes / 1MB), 2)
    }
    catch {
        return $null
    }
}

$cutoff = (Get-Date).AddDays(-1 * $StaleDays)

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $computer = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }

    Write-Verbose "Enumerating profiles on: $computer"

    $profiles = @()
    try {
        $profiles = Get-CimInstance -ComputerName $computer -ClassName Win32_UserProfile -OperationTimeoutSec $TimeoutSeconds
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp     = Get-Date
            ComputerName  = $computer
            Action        = 'QueryProfiles'
            Result        = 'Failed'
            ProfilePath   = $null
            Sid           = $null
            Username      = $null
            LastUseTime   = $null
            Loaded        = $null
            Special       = $null
            Stale         = $null
            SizeMB        = $null
            Message       = $_.Exception.Message
        })
        continue
    }

    foreach ($p in $profiles) {
        $path = $p.LocalPath
        if ([string]::IsNullOrWhiteSpace($path)) { continue }

        # Filter Special profiles unless requested
        if (-not $IncludeSpecial -and $p.Special) { continue }

        # Filter Loaded profiles unless requested (removal still blocked)
        if (-not $IncludeLoaded -and $p.Loaded) { continue }

        # Exclude profile path patterns
        if (Should-Exclude -Value $path -Patterns $ExcludeProfilePaths) { continue }

        $lastUse = Convert-CimDate -CimDate $p.LastUseTime
        $stale = $false
        if ($lastUse -and $lastUse -lt $cutoff) { $stale = $true }

        $username = Try-ResolveSidToName -Sid $p.SID
        if ($username) {
            # Exclude user patterns (match on full DOMAIN\User or just User)
            $userOnly = ($username -split '\\')[-1]
            if (Should-Exclude -Value $username -Patterns $ExcludeUsers -or Should-Exclude -Value $userOnly -Patterns $ExcludeUsers) {
                continue
            }
        }

        $sizeMB = $null
        if ($EstimateSize) {
            $sizeMB = Get-ProfileSizeMB -Computer $computer -Path $path
            if ($MinProfileSizeMB -gt 0 -and $null -ne $sizeMB -and $sizeMB -lt $MinProfileSizeMB) {
                continue
            }
        }

        $action = if ($Remove -and $stale) { 'RemoveProfile' } else { 'ReportProfile' }

        if ($Remove -and $stale) {
            # Safety: never remove loaded profiles
            if ($p.Loaded) {
                $results.Add([PSCustomObject]@{
                    Timestamp     = Get-Date
                    ComputerName  = $computer
                    Action        = $action
                    Result        = 'Skipped'
                    ProfilePath   = $path
                    Sid           = $p.SID
                    Username      = $username
                    LastUseTime   = $lastUse
                    Loaded        = [bool]$p.Loaded
                    Special       = [bool]$p.Special
                    Stale         = $stale
                    SizeMB        = $sizeMB
                    Message       = 'Profile is currently loaded; removal blocked.'
                })
                continue
            }

            $target = "$computer $path ($($p.SID))"
            $msg = "Remove stale profile (LastUseTime=$lastUse, StaleDays=$StaleDays)"

            try {
                if ($PSCmdlet.ShouldProcess($target, $msg)) {
                    # Delete via CIM method on Win32_UserProfile
                    $null = Invoke-CimMethod -InputObject $p -MethodName Delete -ErrorAction Stop

                    $results.Add([PSCustomObject]@{
                        Timestamp     = Get-Date
                        ComputerName  = $computer
                        Action        = $action
                        Result        = 'Success'
                        ProfilePath   = $path
                        Sid           = $p.SID
                        Username      = $username
                        LastUseTime   = $lastUse
                        Loaded        = [bool]$p.Loaded
                        Special       = [bool]$p.Special
                        Stale         = $stale
                        SizeMB        = $sizeMB
                        Message       = 'Removed'
                    })
                }
            }
            catch {
                $results.Add([PSCustomObject]@{
                    Timestamp     = Get-Date
                    ComputerName  = $computer
                    Action        = $action
                    Result        = 'Failed'
                    ProfilePath   = $path
                    Sid           = $p.SID
                    Username      = $username
                    LastUseTime   = $lastUse
                    Loaded        = [bool]$p.Loaded
                    Special       = [bool]$p.Special
                    Stale         = $stale
                    SizeMB        = $sizeMB
                    Message       = $_.Exception.Message
                })
            }
        }
        else {
            # Report-only row
            $results.Add([PSCustomObject]@{
                Timestamp     = Get-Date
                ComputerName  = $computer
                Action        = $action
                Result        = 'Info'
                ProfilePath   = $path
                Sid           = $p.SID
                Username      = $username
                LastUseTime   = $lastUse
                Loaded        = [bool]$p.Loaded
                Special       = [bool]$p.Special
                Stale         = $stale
                SizeMB        = $sizeMB
                Message       = if ($stale) { "Stale (cutoff=$cutoff)" } else { 'Not stale' }
            })
        }
    }
}

$results | Sort-Object ComputerName, Stale -Descending, Loaded, Username, ProfilePath
