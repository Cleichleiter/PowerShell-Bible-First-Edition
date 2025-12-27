<#
.SYNOPSIS
Tests end-to-end network reachability to a target (DNS, ping, TCP port, traceroute).

.DESCRIPTION
Designed for incident triage to quickly answer:
- Is DNS resolving correctly?
- Is the target reachable at Layer 3 (ping)?
- Is a specific service reachable (TCP port)?
- Where does traffic die (traceroute hops)?

Outputs structured objects suitable for reporting and automation.
Optional hop-level output for traceroute results.

.PARAMETER Target
Hostname or IP address to test. Accepts pipeline.

.PARAMETER Port
Optional TCP port to test (e.g., 3389, 443, 1433). If omitted, no TCP port test is performed.

.PARAMETER TraceRoute
Perform traceroute/hop discovery. Uses Test-NetConnection -TraceRoute when available;
falls back to tracert.exe parsing.

.PARAMETER MaxHops
Max hops for traceroute. Default 30.

.PARAMETER TimeoutSeconds
Timeout for ping/port tests. Default 5 seconds.

.PARAMETER SkipPing
Skip ICMP ping test (useful where ICMP is blocked).

.PARAMETER IncludeReverseLookup
If the target resolves to an IP, attempt reverse lookup (PTR) on the resolved IP.

.PARAMETER AsHops
If set, outputs hop objects instead of the summary object. Useful for Format-Table.

.EXAMPLE
.\Test-NetworkPath.ps1 -Target "rds.contoso.local"

.EXAMPLE
"rds.contoso.local","fs01.contoso.local" | .\Test-NetworkPath.ps1 -Port 445 -TraceRoute -SkipPing |
  Format-Table -Auto

.EXAMPLE
.\Test-NetworkPath.ps1 -Target 10.0.0.10 -IncludeReverseLookup -TraceRoute

.EXAMPLE
.\Test-NetworkPath.ps1 -Target "sql01" -Port 1433 | Format-List

.NOTES
Author: Cheri
Requires: Test-NetConnection (Windows 8+/Server 2012+). Traceroute fallback uses tracert.exe.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('Host','Name','ComputerName','Destination')]
    [string[]]$Target,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$Port,

    [Parameter()]
    [switch]$TraceRoute,

    [Parameter()]
    [ValidateRange(1, 64)]
    [int]$MaxHops = 30,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5,

    [Parameter()]
    [switch]$SkipPing,

    [Parameter()]
    [switch]$IncludeReverseLookup,

    [Parameter()]
    [switch]$AsHops
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Target {
    param([Parameter(Mandatory)][string]$T)

    # If it's already an IP, treat as resolved.
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($T, [ref]$ip)) {
        return [PSCustomObject]@{
            Input              = $T
            Resolved           = $true
            ResolvedName       = $null
            ResolvedIP         = $T
            DnsError           = $null
        }
    }

    try {
        # Prefer A/AAAA answers; take first IP
        $res = Resolve-DnsName -Name $T -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
        return [PSCustomObject]@{
            Input              = $T
            Resolved           = $true
            ResolvedName       = $T
            ResolvedIP         = $res.IPAddress
            DnsError           = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Input              = $T
            Resolved           = $false
            ResolvedName       = $T
            ResolvedIP         = $null
            DnsError           = $_.Exception.Message
        }
    }
}

function Try-ReverseLookup {
    param([Parameter(Mandatory)][string]$IP)

    try {
        $ptr = Resolve-DnsName -Name $IP -Type PTR -ErrorAction Stop | Where-Object { $_.NameHost } | Select-Object -First 1
        return [PSCustomObject]@{ PtrName = $ptr.NameHost; Error = $null }
    }
    catch {
        return [PSCustomObject]@{ PtrName = $null; Error = $_.Exception.Message }
    }
}

function Test-PingOnce {
    param([Parameter(Mandatory)][string]$T,[Parameter(Mandatory)][int]$TimeoutSeconds)

    try {
        # Test-Connection -Quiet does not take explicit timeout reliably across all versions
        $ok = Test-Connection -ComputerName $T -Count 1 -Quiet -ErrorAction Stop
        return [PSCustomObject]@{ Succeeded = [bool]$ok; Error = $null }
    }
    catch {
        return [PSCustomObject]@{ Succeeded = $null; Error = $_.Exception.Message }
    }
}

function Test-TcpPort {
    param([Parameter(Mandatory)][string]$T,[Parameter(Mandatory)][int]$Port)

    try {
        $tnc = Test-NetConnection -ComputerName $T -Port $Port -WarningAction SilentlyContinue -InformationLevel Detailed
        return [PSCustomObject]@{
            Succeeded     = [bool]$tnc.TcpTestSucceeded
            RemoteAddress = $tnc.RemoteAddress
            Error         = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Succeeded     = $false
            RemoteAddress = $null
            Error         = $_.Exception.Message
        }
    }
}

function Get-TraceRoute {
    param(
        [Parameter(Mandatory)][string]$T,
        [Parameter(Mandatory)][int]$MaxHops
    )

    # First try Test-NetConnection -TraceRoute (best structured signal)
    $supportsTrace = $false
    try {
        $cmd = Get-Command Test-NetConnection -ErrorAction Stop
        # TraceRoute is supported on modern Windows; if it errors we fallback anyway.
        $supportsTrace = $true
    } catch { $supportsTrace = $false }

    if ($supportsTrace) {
        try {
            $tnc = Test-NetConnection -ComputerName $T -TraceRoute -WarningAction SilentlyContinue -InformationLevel Detailed
            # Different builds expose trace data differently; handle common patterns:
            $hops = @()

            if ($tnc.TraceRoute) {
                # Often an array of hop IPs
                $i = 0
                foreach ($h in @($tnc.TraceRoute)) {
                    $i++
                    if (-not $h) { continue }
                    $hops += [PSCustomObject]@{
                        Hop        = $i
                        Address    = [string]$h
                        Hostname   = $null
                        Source     = 'Test-NetConnection'
                        Note       = $null
                    }
                }
            }

            if ($hops.Count -gt 0) { return $hops }
        }
        catch {
            # Fall through to tracert
        }
    }

    # Fallback: tracert.exe parse (best-effort)
    try {
        $args = @('-d', '-h', "$MaxHops", $T) # -d skips DNS for speed/stability; we can reverse later if needed
        $out = & tracert.exe @args 2>&1
        $lines = @($out | ForEach-Object { $_.ToString() }) | Where-Object { $_ -and $_.Trim() -ne '' }

        $hopLines = $lines | Where-Object { $_ -match '^\s*\d+\s+' }

        $hops = @()
        foreach ($ln in $hopLines) {
            $m = [regex]::Match($ln, '^\s*(\d+)\s+(.+)$')
            if (-not $m.Success) { continue }

            $hopNum = [int]$m.Groups[1].Value
            $rest = $m.Groups[2].Value.Trim()

            # Extract an IP if present
            $ipMatch = [regex]::Match($rest, '(\d{1,3}\.){3}\d{1,3}')
            $addr = if ($ipMatch.Success) { $ipMatch.Value } else { $null }

            $note = $null
            if ($rest -like '*Request timed out*') { $note = 'TimedOut' }
            elseif (-not $addr) { $note = $rest }

            $hops += [PSCustomObject]@{
                Hop        = $hopNum
                Address    = $addr
                Hostname   = $null
                Source     = 'tracert'
                Note       = $note
            }
        }

        return $hops
    }
    catch {
        return @([PSCustomObject]@{
            Hop      = $null
            Address  = $null
            Hostname = $null
            Source   = 'tracert'
            Note     = "Traceroute failed: $($_.Exception.Message)"
        })
    }
}

$results = New-Object System.Collections.Generic.List[object]

process {
    foreach ($t in $Target) {
        $tgt = $t.Trim()
        if ([string]::IsNullOrWhiteSpace($tgt)) { continue }

        $dns = Resolve-Target -T $tgt

        $ptrName = $null
        $ptrErr  = $null
        if ($IncludeReverseLookup -and $dns.Resolved -and $dns.ResolvedIP) {
            $ptr = Try-ReverseLookup -IP $dns.ResolvedIP
            $ptrName = $ptr.PtrName
            $ptrErr  = $ptr.Error
        }

        $ping = if ($SkipPing) {
            [PSCustomObject]@{ Succeeded = $null; Error = 'Skipped' }
        } elseif ($dns.ResolvedIP) {
            Test-PingOnce -T $dns.ResolvedIP -TimeoutSeconds $TimeoutSeconds
        } else {
            [PSCustomObject]@{ Succeeded = $false; Error = 'DNS not resolved; ping not attempted.' }
        }

        $tcp = $null
        if ($PSBoundParameters.ContainsKey('Port')) {
            if ($dns.ResolvedIP) {
                $tcp = Test-TcpPort -T $dns.ResolvedIP -Port $Port
            } else {
                $tcp = [PSCustomObject]@{ Succeeded = $false; RemoteAddress = $null; Error = 'DNS not resolved; TCP test not attempted.' }
            }
        }

        $hops = @()
        if ($TraceRoute) {
            $hops = Get-TraceRoute -T $tgt -MaxHops $MaxHops

            # Optional reverse lookup of hop addresses for readability (best-effort indicate only)
            foreach ($h in $hops) {
                if ($h.Address -and $IncludeReverseLookup) {
                    $ptrHop = Try-ReverseLookup -IP $h.Address
                    if ($ptrHop.PtrName) { $h.Hostname = $ptrHop.PtrName }
                }
            }
        }

        # Determine overall status
        $signals = New-Object System.Collections.Generic.List[string]
        if (-not $dns.Resolved) { $signals.Add('DNS_FAIL') }
        if (-not $SkipPing -and $ping.Succeeded -eq $false) { $signals.Add('PING_FAIL_OR_BLOCKED') }
        if ($tcp -and $tcp.Succeeded -eq $false) { $signals.Add("TCP_$Port`_FAIL") }

        $overall =
            if (-not $dns.Resolved) { 'Fail' }
            elseif ($tcp -and $tcp.Succeeded -eq $true) { 'Pass' }
            elseif ($tcp -and $tcp.Succeeded -eq $false) { 'Fail' }
            elseif ($SkipPing) { 'Warn' }  # no L3 signal
            elseif ($ping.Succeeded -eq $true) { 'Pass' }
            else { 'Warn' }

        if ($AsHops -and $TraceRoute) {
            foreach ($h in $hops) {
                # Emit hop objects with target context
                $results.Add([PSCustomObject]@{
                    Timestamp     = Get-Date
                    ComputerName  = $env:COMPUTERNAME
                    Target        = $tgt
                    ResolvedIP    = $dns.ResolvedIP
                    Hop           = $h.Hop
                    Address       = $h.Address
                    Hostname      = $h.Hostname
                    Source        = $h.Source
                    Note          = $h.Note
                })
            }
        }
        else {
            $results.Add([PSCustomObject]@{
                Timestamp            = Get-Date
                ComputerName         = $env:COMPUTERNAME
                Target               = $tgt

                DnsResolved          = $dns.Resolved
                ResolvedIP           = $dns.ResolvedIP
                ReverseName          = $ptrName
                DnsError             = $dns.DnsError
                ReverseLookupError   = $ptrErr

                PingSucceeded        = $ping.Succeeded
                PingError            = $ping.Error

                TcpPort              = if ($PSBoundParameters.ContainsKey('Port')) { $Port } else { $null }
                TcpSucceeded         = if ($tcp) { $tcp.Succeeded } else { $null }
                TcpRemoteAddress     = if ($tcp) { $tcp.RemoteAddress } else { $null }
                TcpError             = if ($tcp) { $tcp.Error } else { $null }

                TraceRouteEnabled    = [bool]$TraceRoute
                HopCount             = if ($TraceRoute -and $hops) { ($hops | Where-Object { $_.Hop }).Count } else { 0 }
                Hops                 = $hops

                OverallStatus        = $overall
                Signals              = if ($signals.Count -gt 0) { $signals -join '; ' } else { $null }
            })
        }
    }
}

end {
    $results
}
