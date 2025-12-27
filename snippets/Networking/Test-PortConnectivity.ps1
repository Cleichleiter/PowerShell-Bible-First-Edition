<#
.SYNOPSIS
Tests TCP (and optional UDP best-effort) port connectivity to one or more targets.

.DESCRIPTION
Bulk port testing for incident triage and firewall validation:
- Multiple targets and ports in one run
- TCP uses Test-NetConnection when available; falls back to .NET TcpClient
- Optional UDP "best-effort" probe (UDP has no handshake; results are limited)
- Structured output suitable for automation and reporting
- Optional parallel execution for speed

Designed to answer:
- "Is the port open from here?"
- "Is it DNS, routing, or firewall?"
- "Which targets/ports are failing?"

.PARAMETER Target
One or more hostnames/IPs to test. Accepts pipeline.

.PARAMETER Port
One or more ports to test.

.PARAMETER Protocol
TCP or UDP or Both. Default TCP.

.PARAMETER TimeoutSeconds
Timeout per test. Default 3 seconds.

.PARAMETER ResolveDNS
Resolve hostnames to IPs before testing and include resolved IP in output.

.PARAMETER SkipPing
Skip ICMP pre-check (useful where ping is blocked). Default: ping pre-check is NOT required anyway;
this only affects the optional PingSucceeded field.

.PARAMETER IncludePing
Include a ping signal (best-effort, may be blocked). Does not gate TCP/UDP testing.

.PARAMETER Parallel
Use PowerShell 7+ parallel execution to speed up large test matrices.
If running Windows PowerShell 5.1, the script automatically runs sequentially.

.PARAMETER ThrottleLimit
Parallel throttle limit when -Parallel is used. Default 20.

.PARAMETER TargetFile
Path to a text file containing targets (one per line). Lines starting with # are ignored.

.PARAMETER PortFile
Path to a text file containing ports (one per line). Lines starting with # are ignored.

.PARAMETER OutputSummary
Also emit a grouped summary object (counts by status). Raw rows are always output.

.EXAMPLE
.\Test-PortConnectivity.ps1 -Target RDSH01 -Port 3389,445,443 | Format-Table -Auto

.EXAMPLE
.\Test-PortConnectivity.ps1 -TargetFile .\targets.txt -Port 443 -ResolveDNS -IncludePing |
  Export-Csv C:\Reports\PortTest.csv -NoTypeInformation

.EXAMPLE
"sql01","sql02" | .\Test-PortConnectivity.ps1 -Port 1433 -TimeoutSeconds 5 -Parallel -ThrottleLimit 30

.NOTES
Author: Cheri
TCP: reliable. UDP: best-effort only (no handshake).
Requires: Test-NetConnection for richest output; falls back to .NET when needed.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('ComputerName','Host','Name')]
    [string[]]$Target,

    [Parameter()]
    [int[]]$Port,

    [Parameter()]
    [ValidateSet('TCP','UDP','Both')]
    [string]$Protocol = 'TCP',

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 3,

    [Parameter()]
    [switch]$ResolveDNS,

    [Parameter()]
    [switch]$IncludePing,

    [Parameter()]
    [switch]$SkipPing,

    [Parameter()]
    [switch]$Parallel,

    [Parameter()]
    [ValidateRange(1, 200)]
    [int]$ThrottleLimit = 20,

    [Parameter()]
    [string]$TargetFile,

    [Parameter()]
    [string]$PortFile,

    [Parameter()]
    [switch]$OutputSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-Lines {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "File not found: $Path" }
    Get-Content -Path $Path -ErrorAction Stop |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') }
}

function Resolve-HostToIP {
    param([Parameter(Mandatory)][string]$Host)
    try {
        # Prefer Resolve-DnsName; fallback to .NET
        $r = Resolve-DnsName -Name $Host -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        return [PSCustomObject]@{ IP = $r.IPAddress; Error = $null }
    } catch {
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Host)
            $ip = $ips | Where-Object { $_.AddressFamily -in @('InterNetwork','InterNetworkV6') } | Select-Object -First 1
            if ($ip) { return [PSCustomObject]@{ IP = $ip.IPAddressToString; Error = $null } }
            return [PSCustomObject]@{ IP = $null; Error = "No IP addresses returned." }
        } catch {
            return [PSCustomObject]@{ IP = $null; Error = $_.Exception.Message }
        }
    }
}

function Try-Ping {
    param([Parameter(Mandatory)][string]$Host)
    try {
        $ok = Test-Connection -ComputerName $Host -Count 1 -Quiet -ErrorAction Stop
        return [PSCustomObject]@{ Succeeded = [bool]$ok; Error = $null }
    } catch {
        return [PSCustomObject]@{ Succeeded = $null; Error = $_.Exception.Message }
    }
}

function Test-Tcp {
    param(
        [Parameter(Mandatory)][string]$Host,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    # Prefer Test-NetConnection when available
    $tnc = $null
    try {
        $tnc = Test-NetConnection -ComputerName $Host -Port $Port -WarningAction SilentlyContinue -InformationLevel Detailed
        return [PSCustomObject]@{
            Succeeded      = [bool]$tnc.TcpTestSucceeded
            RemoteAddress  = $tnc.RemoteAddress
            RemotePort     = $Port
            SourceAddress  = $tnc.SourceAddress
            LatencyMs      = $null
            Error          = $null
            Method         = 'Test-NetConnection'
        }
    } catch {
        # Fallback to TcpClient
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($Host, $Port, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
            if (-not $ok) {
                $client.Close()
                return [PSCustomObject]@{
                    Succeeded      = $false
                    RemoteAddress  = $null
                    RemotePort     = $Port
                    SourceAddress  = $null
                    LatencyMs      = $null
                    Error          = "Timeout after $TimeoutSeconds seconds"
                    Method         = '.NET TcpClient'
                }
            }
            $client.EndConnect($iar)
            $client.Close()
            return [PSCustomObject]@{
                Succeeded      = $true
                RemoteAddress  = $null
                RemotePort     = $Port
                SourceAddress  = $null
                LatencyMs      = $null
                Error          = $null
                Method         = '.NET TcpClient'
            }
        } catch {
            return [PSCustomObject]@{
                Succeeded      = $false
                RemoteAddress  = $null
                RemotePort     = $Port
                SourceAddress  = $null
                LatencyMs      = $null
                Error          = $_.Exception.Message
                Method         = '.NET TcpClient'
            }
        }
    }
}

function Test-UdpBestEffort {
    param(
        [Parameter(Mandatory)][string]$Host,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    # UDP has no handshake. We send a small packet and attempt to receive an ICMP unreachable or response.
    # Many services won't respond; "NoResponse" is not proof of closed.
    try {
        $udp = New-Object System.Net.Sockets.UdpClient
        $udp.Client.ReceiveTimeout = $TimeoutSeconds * 1000

        $payload = [byte[]](0x00)
        [void]$udp.Send($payload, $payload.Length, $Host, $Port)

        try {
            $remoteEP = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Any), 0
            $bytes = $udp.Receive([ref]$remoteEP)
            $udp.Close()
            return [PSCustomObject]@{
                Succeeded      = $true
                RemoteAddress  = $remoteEP.Address.IPAddressToString
                RemotePort     = $remoteEP.Port
                Error          = $null
                Method         = 'UDP probe'
                Note           = 'ReceivedResponse'
            }
        } catch {
            $udp.Close()
            return [PSCustomObject]@{
                Succeeded      = $null
                RemoteAddress  = $null
                RemotePort     = $Port
                Error          = 'No response (expected for many UDP services)'
                Method         = 'UDP probe'
                Note           = 'NoResponse'
            }
        }
    } catch {
        return [PSCustomObject]@{
            Succeeded      = $false
            RemoteAddress  = $null
            RemotePort     = $Port
            Error          = $_.Exception.Message
            Method         = 'UDP probe'
            Note           = 'ProbeFailed'
        }
    }
}

function New-Row {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)][string]$Protocol,
        [Parameter(Mandatory)][int]$Port,
        [Parameter()][string]$ResolvedIP,
        [Parameter()][object]$Ping,
        [Parameter(Mandatory)][object]$Test
    )

    $status =
        if ($Protocol -eq 'TCP') {
            if ($Test.Succeeded -eq $true) { 'Open' }
            elseif ($Test.Succeeded -eq $false -and $Test.Error -like 'Timeout*') { 'Timeout' }
            else { 'ClosedOrFiltered' }
        }
        else {
            # UDP signal is inherently ambiguous
            if ($Test.Succeeded -eq $true) { 'Responded' }
            elseif ($Test.Succeeded -eq $false) { 'Error' }
            else { 'NoResponse' }
        }

    [PSCustomObject]@{
        Timestamp      = Get-Date
        ComputerName   = $env:COMPUTERNAME

        Target         = $Target
        ResolvedIP     = $ResolvedIP

        Protocol       = $Protocol
        Port           = $Port

        PingSucceeded  = if ($Ping) { $Ping.Succeeded } else { $null }
        PingError      = if ($Ping) { $Ping.Error } else { $null }

        Status         = $status
        Succeeded      = $Test.Succeeded
        RemoteAddress  = $Test.RemoteAddress
        RemotePort     = $Test.RemotePort
        SourceAddress  = $Test.SourceAddress
        Method         = $Test.Method
        Error          = $Test.Error

        Note           = if ($Test.PSObject.Properties.Name -contains 'Note') { $Test.Note } else { $null }
    }
}

# Merge inputs from files if provided
$targets = New-Object System.Collections.Generic.List[string]
$ports   = New-Object System.Collections.Generic.List[int]

if ($TargetFile) {
    foreach ($line in (Read-Lines -Path $TargetFile)) { $targets.Add($line) }
}
if ($PortFile) {
    foreach ($line in (Read-Lines -Path $PortFile)) {
        if ($line -match '^\d+$') { $ports.Add([int]$line) }
    }
}

process {
    if ($Target) {
        foreach ($t in $Target) {
            $x = $t.Trim()
            if ($x) { $targets.Add($x) }
        }
    }
}

end {
    if ($Port) { foreach ($p in $Port) { $ports.Add([int]$p) } }

    $targets = @($targets | Where-Object { $_ } | Select-Object -Unique)
    $ports   = @($ports | Where-Object { $_ -ge 1 -and $_ -le 65535 } | Select-Object -Unique | Sort-Object)

    if (-not $targets -or $targets.Count -eq 0) { throw "No targets provided. Use -Target or -TargetFile." }
    if (-not $ports -or $ports.Count -eq 0) { throw "No ports provided. Use -Port or -PortFile." }

    $doTcp = $Protocol -in @('TCP','Both')
    $doUdp = $Protocol -in @('UDP','Both')

    $matrix = foreach ($t in $targets) {
        foreach ($p in $ports) {
            [PSCustomObject]@{ Target = $t; Port = $p }
        }
    }

    $rows = New-Object System.Collections.Generic.List[object]

    $runner = {
        param($item,$TimeoutSeconds,$ResolveDNS,$IncludePing,$SkipPing,$doTcp,$doUdp)

        $target = $item.Target
        $port   = [int]$item.Port

        $resolvedIP = $null
        $dnsErr = $null
        if ($ResolveDNS) {
            $r = Resolve-HostToIP -Host $target
            $resolvedIP = $r.IP
            $dnsErr = $r.Error
        }

        $ping = $null
        if ($IncludePing -and -not $SkipPing) {
            $ping = Try-Ping -Host $target
        }

        $out = New-Object System.Collections.Generic.List[object]

        if ($ResolveDNS -and -not $resolvedIP) {
            # If DNS resolution failed, still run TCP test by hostname (might still work via hosts file/other resolver),
            # but note the DNS error in the row Error field when relevant.
            # We'll attach DNS error only if port test also fails.
        }

        if ($doTcp) {
            $tcp = Test-Tcp -Host $target -Port $port -TimeoutSeconds $TimeoutSeconds
            $row = New-Row -Target $target -Protocol 'TCP' -Port $port -ResolvedIP $resolvedIP -Ping $ping -Test $tcp

            if ($ResolveDNS -and $dnsErr -and $row.Succeeded -ne $true) {
                $row.Error = if ($row.Error) { "$($row.Error) | DNS: $dnsErr" } else { "DNS: $dnsErr" }
            }

            $out.Add($row)
        }

        if ($doUdp) {
            $udp = Test-UdpBestEffort -Host $target -Port $port -TimeoutSeconds $TimeoutSeconds
            $row = New-Row -Target $target -Protocol 'UDP' -Port $port -ResolvedIP $resolvedIP -Ping $ping -Test $udp

            if ($ResolveDNS -and $dnsErr -and $row.Succeeded -eq $false) {
                $row.Error = if ($row.Error) { "$($row.Error) | DNS: $dnsErr" } else { "DNS: $dnsErr" }
            }

            $out.Add($row)
        }

        $out
    }

    $isPwsh7 = $PSVersionTable.PSVersion.Major -ge 7

    if ($Parallel -and $isPwsh7) {
        $parallelOut = $matrix | ForEach-Object -Parallel {
            & $using:runner -item $_ -TimeoutSeconds $using:TimeoutSeconds -ResolveDNS:$using:ResolveDNS `
                -IncludePing:$using:IncludePing -SkipPing:$using:SkipPing -doTcp:$using:doTcp -doUdp:$using:doUdp
        } -ThrottleLimit $ThrottleLimit

        foreach ($r in @($parallelOut)) { $rows.Add($r) }
    }
    else {
        foreach ($i in $matrix) {
            $out = & $runner -item $i -TimeoutSeconds $TimeoutSeconds -ResolveDNS:$ResolveDNS `
                -IncludePing:$IncludePing -SkipPing:$SkipPing -doTcp:$doTcp -doUdp:$doUdp
            foreach ($r in @($out)) { $rows.Add($r) }
        }
    }

    $rows = $rows | Sort-Object Target, Protocol, Port

    $rows

    if ($OutputSummary) {
        $summary = $rows | Group-Object Protocol, Status | Sort-Object Name | ForEach-Object {
            [PSCustomObject]@{
                Protocol = ($_.Name -split ',')[0].Trim()
                Status   = ($_.Name -split ',')[1].Trim()
                Count    = $_.Count
            }
        }

        $summary
    }
}
