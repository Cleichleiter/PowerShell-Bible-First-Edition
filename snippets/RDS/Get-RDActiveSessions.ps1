<#
.SYNOPSIS
Gets active/disconnected RDS (Terminal Services) sessions from one or more session hosts.

.DESCRIPTION
Queries session information using the built-in `quser` command and parses results into structured objects.

Designed for:
- RDS Session Hosts (including standalone terminal servers)
- Environments without RD Connection Broker / RDMS modules
- Datto RMM / scheduled task usage

Features:
- Works locally or remotely (quser /server:HOST)
- Normalizes session state and idle time
- Optional filtering by State, Username, or SessionName
- Outputs objects suitable for Export-Csv

.PARAMETER ComputerName
One or more servers to query. Defaults to the local computer.

.PARAMETER IncludeSystem
Include system/service sessions such as "services", "console", etc. Default is to exclude obvious non-user sessions.

.PARAMETER State
Filter by session state: Active, Disc, or All (default).

.PARAMETER Username
Filter to a specific username (supports wildcard).

.PARAMETER SessionName
Filter to a specific session name (supports wildcard), e.g. "rdp-tcp#12".

.PARAMETER MinIdleMinutes
Only return sessions idle at least this many minutes.

.PARAMETER TimeoutSeconds
Timeout for each server query (best-effort). Default 10 seconds.

.EXAMPLE
.\Get-RDActiveSessions.ps1

.EXAMPLE
.\Get-RDActiveSessions.ps1 -ComputerName RDSH01,RDSH02 -State All

.EXAMPLE
.\Get-RDActiveSessions.ps1 -ComputerName RDSH01 -State Disc | Format-Table -Auto

.EXAMPLE
.\Get-RDActiveSessions.ps1 -ComputerName RDSH01 -MinIdleMinutes 60 -State Active

.EXAMPLE
.\Get-RDActiveSessions.ps1 -ComputerName RDSH01 | Export-Csv C:\Reports\RDS-Sessions.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: None beyond built-in quser.exe
Permissions: You need rights to query session info on the target host(s).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeSystem,

    [Parameter()]
    [ValidateSet('Active','Disc','All')]
    [string]$State = 'All',

    [Parameter()]
    [string]$Username,

    [Parameter()]
    [string]$SessionName,

    [Parameter()]
    [ValidateRange(0, 525600)]
    [int]$MinIdleMinutes = 0,

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

    # quser uses:
    #  "."          -> less than 1 minute
    #  "none"       -> no idle (varies by version)
    #  "5"          -> minutes
    #  "1:23"       -> hours:minutes
    #  "2+03:04"    -> days+hours:minutes
    #  "3+"         -> days (rare but possible)
    if ($idleTrim -eq '.') { return 0 }
    if ($idleTrim -match '^(none|n/a)$') { return 0 }

    # days+hh:mm
    if ($idleTrim -match '^(?<d>\d+)\+(?<h>\d{1,2}):(?<m>\d{2})$') {
        return ([int]$Matches.d * 1440) + ([int]$Matches.h * 60) + ([int]$Matches.m)
    }

    # hh:mm
    if ($idleTrim -match '^(?<h>\d{1,2}):(?<m>\d{2})$') {
        return ([int]$Matches.h * 60) + ([int]$Matches.m)
    }

    # days+
    if ($idleTrim -match '^(?<d>\d+)\+$') {
        return ([int]$Matches.d * 1440)
    }

    # minutes
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

    # Remove leading '>' marker for current session
    $raw = $Line.Trim()
    if ($raw.StartsWith('>')) { $raw = $raw.TrimStart('>').TrimStart() }

    # Split on 2+ spaces (quser is columnar)
    $cols = $raw -split '\s{2,}'

    # Most common shapes:
    # Username  SessionName  Id  State  IdleTime  LogonTime
    # Username  Id           State IdleTime LogonTime        (no sessionname)
    if ($cols.Count -lt 5) {
        return $null
    }

    $username = $cols[0]

    $sessionName = $null
    $id = $null
    $state = $null
    $idle = $null
    $logon = $null

    if ($cols.Count -ge 6) {
        # Has session name
        $sessionName = $cols[1]
        $id          = $cols[2]
        $state       = $cols[3]
        $idle        = $cols[4]
        $logon       = ($cols[5..($cols.Count-1)] -join ' ')
    }
    else {
        # No session name
        $sessionName = $null
        $id          = $cols[1]
        $state       = $cols[2]
        $idle        = $cols[3]
        $logon       = ($cols[4..($cols.Count-1)] -join ' ')
    }

    $idleMinutes = Convert-IdleToMinutes -Idle $idle

    [PSCustomObject]@{
        ComputerName   = $Computer
        Username       = $username
        SessionName    = $sessionName
        SessionId      = [int]($id -as [int])
        State          = $state
        Idle           = $idle
        IdleMinutes    = $idleMinutes
        LogonTimeRaw   = $logon
        QueryTime      = Get-Date
    }
}

function Invoke-Quser {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    # quser on remote: quser /server:NAME
    $args = @()
    if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
        $args += "/server:$Computer"
    }

    # Use Start-Process to allow rudimentary timeout handling
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
        # quser sometimes writes non-fatal to stderr; treat as error when stdout empty
        if ([string]::IsNullOrWhiteSpace($stdout)) {
            throw $stderr.Trim()
        }
    }

    return ($stdout -split "`r?`n" | Where-Object { $_ -and $_.Trim() -ne '' })
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $computer = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }

    try {
        $lines = Invoke-Quser -Computer $computer -TimeoutSeconds $TimeoutSeconds

        # If no sessions, quser may return header only, or a single line stating none
        if (-not $lines -or $lines.Count -eq 0) { continue }

        # Skip header line(s)
        $dataLines = $lines | Where-Object { $_ -notmatch '^\s*USERNAME\s+' }

        foreach ($line in $dataLines) {
            $obj = Parse-QuserLine -Line $line -Computer $computer
            if (-not $obj) { continue }

            # Exclude obvious system sessions unless requested
            if (-not $IncludeSystem) {
                if ($obj.Username -match '^(services|console|rdp-tcp|dwm-|umfd-)' ) { continue }
                if ($obj.Username -match '^\s*$') { continue }
            }

            # Filters
            if ($State -ne 'All') {
                if ($obj.State -ne $State) { continue }
            }

            if ($PSBoundParameters.ContainsKey('Username')) {
                if ($obj.Username -notlike $Username) { continue }
            }

            if ($PSBoundParameters.ContainsKey('SessionName')) {
                if (($obj.SessionName ?? '') -notlike $SessionName) { continue }
            }

            if ($MinIdleMinutes -gt 0) {
                if ($null -eq $obj.IdleMinutes -or $obj.IdleMinutes -lt $MinIdleMinutes) { continue }
            }

            $all.Add($obj)
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            ComputerName = $computer
            Username     = $null
            SessionName  = $null
            SessionId    = $null
            State        = $null
            Idle         = $null
            IdleMinutes  = $null
            LogonTimeRaw = $null
            QueryTime    = Get-Date
            Error        = $_.Exception.Message
        })
    }
}

$all | Sort-Object ComputerName, State, Username, SessionId
