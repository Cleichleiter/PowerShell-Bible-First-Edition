<#
.SYNOPSIS
Validates basic RDS "user logon path" health for one or more session hosts.

.DESCRIPTION
Performs pragmatic checks that commonly block or degrade RDS logons:
- Name resolution
- Network reachability
- RDP port availability
- Core RDS services state
- Ability to enumerate sessions (quser) as a proxy signal

This script does NOT perform an actual interactive logon (by design).
Instead, it provides fast indicators to answer:
"Is this host likely to accept RDP logons right now?"

.PARAMETER ComputerName
One or more servers to test. Defaults to local computer.

.PARAMETER RdpPort
RDP port to test. Default 3389.

.PARAMETER SkipPing
Skip ICMP ping (useful where ping is blocked).

.PARAMETER TimeoutSeconds
Timeout for network tests per host. Default 5 seconds.

.PARAMETER SessionQueryTimeoutSeconds
Timeout for session query per host. Default 8 seconds.

.PARAMETER RequireAllCoreServicesRunning
If set, marks OverallStatus as Fail if any core service is not Running.

.EXAMPLE
.\Test-RDUserLogon.ps1 -ComputerName RDSH01

.EXAMPLE
.\Test-RDUserLogon.ps1 -ComputerName RDSH01,RDSH02 -SkipPing | Format-Table -Auto

.EXAMPLE
.\Test-RDUserLogon.ps1 -ComputerName RDSH01 -RequireAllCoreServicesRunning -Verbose

.NOTES
Author: Cheri
Requires: Test-NetConnection (Windows), quser.exe
Permissions: quser requires rights to query the host.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$RdpPort = 3389,

    [Parameter()]
    [switch]$SkipPing,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5,

    [Parameter()]
    [ValidateRange(1, 120)]
    [int]$SessionQueryTimeoutSeconds = 8,

    [Parameter()]
    [switch]$RequireAllCoreServicesRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$coreServices = @(
    'TermService',   # Remote Desktop Services
    'UmRdpService',  # Remote Desktop Services UserMode Port Redirector
    'SessionEnv'     # Remote Desktop Configuration
)

function Resolve-Host {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $res = Resolve-DnsName -Name $Name -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        return [PSCustomObject]@{
            Resolved = $true
            IPAddress = $res.IPAddress
            Error = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Resolved = $false
            IPAddress = $null
            Error = $_.Exception.Message
        }
    }
}

function Test-PingHost {
    param([Parameter(Mandatory)][string]$Name)

    try {
        $ok = Test-Connection -ComputerName $Name -Count 1 -Quiet -ErrorAction Stop
        return [PSCustomObject]@{ Ping = [bool]$ok; Error = $null }
    }
    catch {
        return [PSCustomObject]@{ Ping = $null; Error = $_.Exception.Message }
    }
}

function Test-RdpPort {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    try {
        $tnc = Test-NetConnection -ComputerName $Name -Port $Port -WarningAction SilentlyContinue -InformationLevel Detailed
        return [PSCustomObject]@{
            TcpTestSucceeded = [bool]$tnc.TcpTestSucceeded
            RemoteAddress    = $tnc.RemoteAddress
            Error            = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            TcpTestSucceeded = $false
            RemoteAddress    = $null
            Error            = $_.Exception.Message
        }
    }
}

function Get-ServiceMap {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$ServiceNames
    )

    $map = [ordered]@{}
    foreach ($svc in $ServiceNames) { $map[$svc] = 'NotFound' }

    try {
        $svcs = Get-Service -ComputerName $Name -ErrorAction Stop | Where-Object { $ServiceNames -contains $_.Name }
        foreach ($s in $svcs) { $map[$s.Name] = $s.Status.ToString() }
        $map['__Error'] = $null
    }
    catch {
        $map['__Error'] = $_.Exception.Message
    }

    return $map
}

function Invoke-QuserLines {
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
        throw "quser timeout after $TimeoutSeconds seconds."
    }

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if (-not [string]::IsNullOrWhiteSpace($stderr) -and [string]::IsNullOrWhiteSpace($stdout)) {
        throw $stderr.Trim()
    }

    return ($stdout -split "`r?`n" | Where-Object { $_ -and $_.Trim() -ne '' })
}

function Get-NlaIndicator {
    param([Parameter(Mandatory)][string]$Computer)

    # Best-effort: check fDenyTSConnections and UserAuthentication.
    # UserAuthentication=1 generally indicates NLA required.
    $hklm = 2147483650
    try {
        $reg = Get-CimInstance -ComputerName $Computer -ClassName StdRegProv -Namespace root\default -OperationTimeoutSec 10

        $deny = Invoke-CimMethod -InputObject $reg -MethodName GetDWORDValue -Arguments @{
            hDefKey     = $hklm
            sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
            sValueName  = 'fDenyTSConnections'
        }

        $nla = Invoke-CimMethod -InputObject $reg -MethodName GetDWORDValue -Arguments @{
            hDefKey     = $hklm
            sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
            sValueName  = 'UserAuthentication'
        }

        $denyVal = if ($deny.ReturnValue -eq 0) { $deny.uValue } else { $null }
        $nlaVal  = if ($nla.ReturnValue -eq 0) { $nla.uValue } else { $null }

        [PSCustomObject]@{
            RdpConnectionsDenied = if ($null -ne $denyVal) { [bool]($denyVal -eq 1) } else { $null }
            NlaRequired          = if ($null -ne $nlaVal)  { [bool]($nlaVal -eq 1) } else { $null }
            Error                = $null
        }
    }
    catch {
        [PSCustomObject]@{
            RdpConnectionsDenied = $null
            NlaRequired          = $null
            Error                = $_.Exception.Message
        }
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $hostName = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($hostName)) { continue }

    Write-Verbose "Testing RDS logon path for: $hostName"

    $dns = Resolve-Host -Name $hostName

    $ping = if ($SkipPing) {
        [PSCustomObject]@{ Ping = $null; Error = 'Skipped' }
    } else {
        Test-PingHost -Name $hostName
    }

    $rdp = Test-RdpPort -Name $hostName -Port $RdpPort -TimeoutSeconds $TimeoutSeconds
    $svc = Get-ServiceMap -Name $hostName -ServiceNames $coreServices

    $quserOk = $false
    $quserErr = $null
    try {
        $null = Invoke-QuserLines -Computer $hostName -TimeoutSeconds $SessionQueryTimeoutSeconds
        $quserOk = $true
    }
    catch {
        $quserOk = $false
        $quserErr = $_.Exception.Message
    }

    $nla = Get-NlaIndicator -Computer $hostName

    $coreServiceNotRunning = $false
    $missingOrStopped = @()
    foreach ($s in $coreServices) {
        if ($svc[$s] -ne 'Running') {
            $coreServiceNotRunning = $true
            $missingOrStopped += "$s=$($svc[$s])"
        }
    }

    $signals = New-Object System.Collections.Generic.List[string]
    if (-not $dns.Resolved) { $signals.Add('DNS_FAIL') }
    if (-not $SkipPing -and $ping.Ping -eq $false) { $signals.Add('PING_FAIL_OR_BLOCKED') }
    if (-not $rdp.TcpTestSucceeded) { $signals.Add('RDP_PORT_FAIL') }
    if ($svc['__Error']) { $signals.Add('SERVICE_QUERY_FAIL') }
    if ($coreServiceNotRunning) { $signals.Add("CORE_SERVICE_NOT_RUNNING: $($missingOrStopped -join ', ')") }
    if (-not $quserOk) { $signals.Add("QUSER_FAIL: $quserErr") }
    if ($nla.RdpConnectionsDenied -eq $true) { $signals.Add('RDP_DENIED_BY_CONFIG') }

    $overall = 'Pass'
    if (-not $dns.Resolved -or -not $rdp.TcpTestSucceeded) { $overall = 'Fail' }
    if ($RequireAllCoreServicesRunning -and $coreServiceNotRunning) { $overall = 'Fail' }
    if ($svc['__Error']) { $overall = 'Warn' }
    if (-not $quserOk -and $overall -eq 'Pass') { $overall = 'Warn' }

    $results.Add([PSCustomObject]@{
        Timestamp                 = Get-Date
        ComputerName              = $hostName
        OverallStatus             = $overall

        DnsResolved               = $dns.Resolved
        ResolvedIPAddress         = $dns.IPAddress
        DnsError                  = $dns.Error

        PingSucceeded             = $ping.Ping
        PingError                 = $ping.Error

        RdpPort                   = $RdpPort
        RdpPortOpen               = $rdp.TcpTestSucceeded
        RdpRemoteAddress          = $rdp.RemoteAddress
        RdpPortError              = $rdp.Error

        TermService               = $svc['TermService']
        UmRdpService              = $svc['UmRdpService']
        SessionEnv                = $svc['SessionEnv']
        ServiceQueryError         = $svc['__Error']

        CanQuerySessionsQuser      = $quserOk
        QuserError                = $quserErr

        RdpConnectionsDenied      = $nla.RdpConnectionsDenied
        NlaRequired               = $nla.NlaRequired
        NlaQueryError             = $nla.Error

        Signals                   = if ($signals.Count -gt 0) { $signals -join '; ' } else { $null }
    })
}

$results | Sort-Object OverallStatus, ComputerName
