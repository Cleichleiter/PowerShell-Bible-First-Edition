<#
.SYNOPSIS
Disconnects idle RDS sessions on one or more session hosts.

.DESCRIPTION
Uses built-in `quser` to enumerate sessions and disconnects those that meet criteria.
Disconnecting preserves the session (does not log off), which is useful for:
- Reducing resource usage
- Encouraging clean reconnect behavior
- Avoiding long-running active sessions

By default, this script targets DISCONNECTED sessions that are idle beyond the threshold.
Use -IncludeActive to also disconnect ACTIVE idle sessions.

.PARAMETER ComputerName
One or more servers to query. Defaults to the local computer.

.PARAMETER MinIdleMinutes
Only disconnect sessions idle at least this many minutes.

.PARAMETER IncludeActive
Also disconnect ACTIVE sessions if they meet MinIdleMinutes.

.PARAMETER IncludeDisconnected
Disconnect DISCONNECTED sessions if they meet MinIdleMinutes. Default: True.

.PARAMETER ExcludeUsers
Usernames to exclude (supports wildcard). Example: 'admin*','svc_*'

.PARAMETER IncludeSystem
Include system/service sessions (rarely desired). Default: False.

.PARAMETER Force
Do not prompt for confirmation (useful for automation). Equivalent to -Confirm:$false behavior.

.PARAMETER UseLogoffInstead
If set, uses `logoff <SessionId>` instead of `tsdiscon <SessionId>`.
Not recommended unless tsdiscon is unavailable.

.EXAMPLE
Disconnect disconnected sessions idle for 8 hours (local server).

.\Disconnect-RDIdleSessions.ps1 -MinIdleMinutes 480 -Verbose

.EXAMPLE
Disconnect active sessions idle more than 2 hours on a specific host.

.\Disconnect-RDIdleSessions.ps1 -ComputerName RDSH01 -MinIdleMinutes 120 -IncludeActive -Verbose

.EXAMPLE
Disconnect idle sessions across multiple hosts, excluding admins.

.\Disconnect-RDIdleSessions.ps1 -ComputerName RDSH01,RDSH02 -MinIdleMinutes 240 -IncludeActive -ExcludeUsers 'admin*' -Force

.NOTES
Author: Cheri
Requires: quser.exe, tsdiscon.exe (both standard on Windows Server with RDS)
Permissions: Must have rights to query/disconnect sessions on the target host(s).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter(Mandatory)]
    [ValidateRange(1, 525600)]
    [int]$MinIdleMinutes,

    [Parameter()]
    [switch]$IncludeActive,

    [Parameter()]
    [bool]$IncludeDisconnected = $true,

    [Parameter()]
    [string[]]$ExcludeUsers = @(),

    [Parameter()]
    [switch]$IncludeSystem,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$UseLogoffInstead
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Convert-IdleToMinutes {
    param([string]$Idle)

    if ([string]::IsNullOrWhiteSpace($Idle)) { return $null }

    $idleTrim = $Idle.Trim()

    if ($idleTrim -eq '.') { return 0 }
    if ($idleTrim -match '^(none|n/a)$') { return 0 }

    if ($idleTrim -match '^(?<d>\d+)\+(?<h>\d{1,2}):(?<m>\d{2})$') {
        return ([int]$Matches.d * 1440) + ([int]$Matches.h * 60) + ([int]$Matches.m)
    }
    if ($idleTrim -match '^(?<h>\d{1,2}):(?<m>\d{2})$') {
        return ([int]$Matches.h * 60) + ([int]$Matches.m)
    }
    if ($idleTrim -match '^(?<d>\d+)\+$') {
        return ([int]$Matches.d * 1440)
    }
    if ($idleTrim -match '^\d+$') {
        return [int]$idleTrim
    }

    return $null
}

function Parse-QuserLine {
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][string]$Computer
    )

    $raw = $Line.Trim()
    if ($raw.StartsWith('>')) { $raw = $raw.TrimStart('>').TrimStart() }

    $cols = $raw -split '\s{2,}'
    if ($cols.Count -lt 5) { return $null }

    $username = $cols[0]

    $sessionName = $null
    $id = $null
    $state = $null
    $idle = $null
    $logon = $null

    if ($cols.Count -ge 6) {
        $sessionName = $cols[1]
        $id          = $cols[2]
        $state       = $cols[3]
        $idle        = $cols[4]
        $logon       = ($cols[5..($cols.Count-1)] -join ' ')
    }
    else {
        $sessionName = $null
        $id          = $cols[1]
        $state       = $cols[2]
        $idle        = $cols[3]
        $logon       = ($cols[4..($cols.Count-1)] -join ' ')
    }

    $idleMinutes = Convert-IdleToMinutes -Idle $idle

    [PSCustomObject]@{
        ComputerName  = $Computer
        Username      = $username
        SessionName   = $sessionName
        SessionId     = [int]($id -as [int])
        State         = $state
        Idle          = $idle
        IdleMinutes   = $idleMinutes
        LogonTimeRaw  = $logon
        QueryTime     = Get-Date
    }
}

function Invoke-Quser {
    param(
        [Parameter(Mandatory)][string]$Computer
    )

    $args = @()
    if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
        $args += "/server:$Computer"
    }

    $stdout = & quser.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($stdout | Out-String).Trim()
    }

    return ($stdout -split "`r?`n" | Where-Object { $_ -and $_.Trim() -ne '' })
}

function Should-ExcludeUser {
    param(
        [Parameter(Mandatory)][string]$User,
        [string[]]$Patterns
    )

    foreach ($p in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ($User -like $p) { return $true }
    }
    return $false
}

function Invoke-DisconnectSession {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][int]$SessionId,
        [Parameter(Mandatory)][switch]$UseLogoffInstead
    )

    if ($UseLogoffInstead) {
        # logoff supports /server:NAME for remote targets
        $args = @("$SessionId")
        if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
            $args += "/server:$Computer"
        }
        $out = & logoff.exe @args 2>&1
        return ($out | Out-String).Trim()
    }
    else {
        # tsdiscon supports /server:NAME
        $args = @("$SessionId")
        if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
            $args += "/server:$Computer"
        }
        $out = & tsdiscon.exe @args 2>&1
        return ($out | Out-String).Trim()
    }
}

# For automation: -Force means don't prompt
if ($Force) {
    $ConfirmPreference = 'None'
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $computer = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }

    Write-Verbose "Querying sessions on: $computer"

    $sessions = @()
    try {
        $lines = Invoke-Quser -Computer $computer
        $dataLines = $lines | Where-Object { $_ -notmatch '^\s*USERNAME\s+' }

        foreach ($line in $dataLines) {
            $s = Parse-QuserLine -Line $line -Computer $computer
            if ($s) { $sessions += $s }
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp    = Get-Date
            ComputerName = $computer
            Action       = 'QuerySessions'
            Result       = 'Failed'
            Username     = $null
            SessionId    = $null
            State        = $null
            IdleMinutes  = $null
            Message      = $_.Exception.Message
        })
        continue
    }

    foreach ($s in $sessions) {

        # Exclude system-ish sessions unless requested
        if (-not $IncludeSystem) {
            if ($s.Username -match '^(services|console|rdp-tcp|dwm-|umfd-)$') { continue }
        }

        if (Should-ExcludeUser -User $s.Username -Patterns $ExcludeUsers) {
            Write-Verbose "Excluded by pattern: $($s.Username) on $computer (SessionId $($s.SessionId))"
            continue
        }

        # Only disconnect if idle minutes known and meets threshold
        if ($null -eq $s.IdleMinutes -or $s.IdleMinutes -lt $MinIdleMinutes) {
            continue
        }

        # Determine if this session is eligible based on state flags
        $isDisc = ($s.State -eq 'Disc')
        $isActive = ($s.State -eq 'Active')

        if ($isDisc -and -not $IncludeDisconnected) { continue }
        if ($isActive -and -not $IncludeActive) { continue }

        # Some environments return other states (e.g., "Conn"). We skip those by default.
        if (-not ($isDisc -or $isActive)) { continue }

        $actionLabel = if ($UseLogoffInstead) { 'LogoffSession' } else { 'DisconnectSession' }
        $targetLabel = "$computer SessionId $($s.SessionId) ($($s.Username))"

        try {
            $msg = "Disconnect idle session (State=$($s.State), IdleMinutes=$($s.IdleMinutes))"
            if ($PSCmdlet.ShouldProcess($targetLabel, $msg)) {
                $output = Invoke-DisconnectSession -Computer $computer -SessionId $s.SessionId -UseLogoffInstead:$UseLogoffInstead

                $results.Add([PSCustomObject]@{
                    Timestamp    = Get-Date
                    ComputerName = $computer
                    Action       = $actionLabel
                    Result       = 'Success'
                    Username     = $s.Username
                    SessionId    = $s.SessionId
                    State        = $s.State
                    IdleMinutes  = $s.IdleMinutes
                    Message      = if ($output) { $output } else { 'OK' }
                })
            }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Timestamp    = Get-Date
                ComputerName = $computer
                Action       = $actionLabel
                Result       = 'Failed'
                Username     = $s.Username
                SessionId    = $s.SessionId
                State        = $s.State
                IdleMinutes  = $s.IdleMinutes
                Message      = $_.Exception.Message
            })
        }
    }
}

$results | Sort-Object ComputerName, Result, Username, SessionId
