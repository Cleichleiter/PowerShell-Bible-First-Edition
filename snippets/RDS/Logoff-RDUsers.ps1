<#
.SYNOPSIS
Logs off RDS (Terminal Services) user sessions that meet criteria.

.DESCRIPTION
Uses built-in `quser` to enumerate sessions and logs off targeted sessions using `logoff`.
Designed for:
- Nightly cleanup on terminal servers/RDS session hosts
- Datto RMM scheduled components
- Preventing long-running sessions and profile/lock issues

Defaults are conservative:
- Targets DISCONNECTED sessions only (when -DisconnectedOnly is used)
- Supports idle thresholds and exclusion patterns

.PARAMETER ComputerName
One or more servers to query. Defaults to the local computer.

.PARAMETER DisconnectedOnly
If set, only logs off sessions in Disc state.

.PARAMETER IncludeActive
If set, also logs off ACTIVE sessions that meet MinIdleMinutes.
Use with care.

.PARAMETER MinIdleMinutes
Only log off sessions idle at least this many minutes. If 0, idle time is not used as a filter.

.PARAMETER ExcludeUsers
Usernames to exclude (supports wildcard patterns), e.g. 'admin*','svc_*'.

.PARAMETER IncludeSystem
Include system/service sessions (rarely desired). Default is to exclude obvious non-user sessions.

.PARAMETER Force
Do not prompt for confirmation (useful for automation). Equivalent to -Confirm:$false behavior.

.PARAMETER TimeoutSeconds
Timeout for each server query (best-effort). Default 10 seconds.

.EXAMPLE
Log off all disconnected sessions on the local server (no idle filter).

.\Logoff-RDUsers.ps1 -DisconnectedOnly -Force -Verbose

.EXAMPLE
Log off disconnected sessions idle more than 8 hours on one host.

.\Logoff-RDUsers.ps1 -ComputerName RDSH01 -DisconnectedOnly -MinIdleMinutes 480 -Force -Verbose

.EXAMPLE
Log off ACTIVE sessions idle more than 12 hours, excluding admins (aggressive).

.\Logoff-RDUsers.ps1 -ComputerName RDSH01 -IncludeActive -MinIdleMinutes 720 -ExcludeUsers 'admin*' -Force -Verbose

.NOTES
Author: Cheri
Requires: quser.exe, logoff.exe (standard on Windows)
Permissions: Must have rights to query/logoff sessions on target hosts.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$DisconnectedOnly,

    [Parameter()]
    [switch]$IncludeActive,

    [Parameter()]
    [ValidateRange(0, 525600)]
    [int]$MinIdleMinutes = 0,

    [Parameter()]
    [string[]]$ExcludeUsers = @(),

    [Parameter()]
    [switch]$IncludeSystem,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 10
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
        ComputerName = $Computer
        Username     = $username
        SessionName  = $sessionName
        SessionId    = [int]($id -as [int])
        State        = $state
        Idle         = $idle
        IdleMinutes  = $idleMinutes
        LogonTimeRaw = $logon
        QueryTime    = Get-Date
    }
}

function Invoke-Quser {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $args = @()
    if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
        $args += "/server:$Computer"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "quser.exe"
    $psi.Arguments = ($args -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi

    $null = $p.Start()
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        try { $p.Kill() } catch {}
        throw "Timeout after $TimeoutSeconds seconds."
    }

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        if ([string]::IsNullOrWhiteSpace($stdout)) {
            throw $stderr.Trim()
        }
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

function Invoke-LogoffSession {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][int]$SessionId
    )

    $args = @("$SessionId")
    if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
        $args += "/server:$Computer"
    }

    $out = & logoff.exe @args 2>&1
    return ($out | Out-String).Trim()
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
        $lines = Invoke-Quser -Computer $computer -TimeoutSeconds $TimeoutSeconds
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

        # State gating
        $isDisc = ($s.State -eq 'Disc')
        $isActive = ($s.State -eq 'Active')

        if ($DisconnectedOnly -and -not $isDisc) { continue }
        if (-not $IncludeActive -and $isActive -and -not $DisconnectedOnly) {
            # If they didn't request IncludeActive, do not touch active sessions
            continue
        }

        if ($MinIdleMinutes -gt 0) {
            if ($null -eq $s.IdleMinutes -or $s.IdleMinutes -lt $MinIdleMinutes) { continue }
        }

        # Skip unknown states by default unless they explicitly opt into active handling
        if (-not ($isDisc -or $isActive)) { continue }

        $targetLabel = "$computer SessionId $($s.SessionId) ($($s.Username))"
        $msg = "Log off session (State=$($s.State), IdleMinutes=$($s.IdleMinutes))"

        try {
            if ($PSCmdlet.ShouldProcess($targetLabel, $msg)) {
                $output = Invoke-LogoffSession -Computer $computer -SessionId $s.SessionId

                $results.Add([PSCustomObject]@{
                    Timestamp    = Get-Date
                    ComputerName = $computer
                    Action       = 'LogoffSession'
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
                Action       = 'LogoffSession'
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
