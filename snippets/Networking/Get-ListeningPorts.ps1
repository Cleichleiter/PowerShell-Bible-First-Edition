<#
.SYNOPSIS
Lists listening TCP (and optional UDP) ports with process/service context.

.DESCRIPTION
Enumerates ports currently bound on a system to quickly answer:
- "Is the service actually listening?"
- "What process owns that port?"
- "Is something else occupying the expected port?"

Features:
- TCP listening ports (default)
- Optional UDP listeners
- PID, process name, executable path (best-effort)
- Service name/display name for service-hosted processes (best-effort)
- Filters for port, process name, service name, address, protocol
- Remote support via Invoke-Command (WinRM)

Outputs objects suitable for reporting and automation.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER IncludeUDP
Include UDP endpoints in addition to TCP listeners.

.PARAMETER Port
Filter by local port (single port or list).

.PARAMETER ProcessName
Filter by process name (wildcards supported), e.g. "svchost*", "sqlservr".

.PARAMETER ServiceName
Filter by Windows service name or display name (wildcards supported).

.PARAMETER Address
Filter by local address (wildcards supported), e.g. "0.0.0.0", "127.*", "::".

.PARAMETER ExcludeLoopback
Exclude loopback-bound endpoints (127.0.0.1 and ::1).

.PARAMETER IncludePath
Include executable path (best-effort; may require admin rights).

.PARAMETER IncludeOwner
Include owning user (best-effort; may require admin rights).

.PARAMETER SortBy
Sort output by Port, Process, or Address. Default Port.

.EXAMPLE
.\Get-ListeningPorts.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-ListeningPorts.ps1 -Port 3389,443,80 | Format-Table -Auto

.EXAMPLE
.\Get-ListeningPorts.ps1 -ProcessName "sqlservr" -IncludePath | Format-List

.EXAMPLE
.\Get-ListeningPorts.ps1 -ComputerName RDSH01,RDSH02 -Port 3389 |
  Export-Csv C:\Reports\RDS-ListeningPorts.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: Get-NetTCPConnection (Windows 8+/Server 2012+)
UDP uses Get-NetUDPEndpoint.
Remote requires WinRM.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeUDP,

    [Parameter()]
    [int[]]$Port,

    [Parameter()]
    [string]$ProcessName,

    [Parameter()]
    [string]$ServiceName,

    [Parameter()]
    [string]$Address,

    [Parameter()]
    [switch]$ExcludeLoopback,

    [Parameter()]
    [switch]$IncludePath,

    [Parameter()]
    [switch]$IncludeOwner,

    [Parameter()]
    [ValidateSet('Port','Process','Address')]
    [string]$SortBy = 'Port'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalListeningPorts {
    param(
        [bool]$IncludeUDP,
        [int[]]$Port,
        [string]$ProcessName,
        [string]$ServiceName,
        [string]$Address,
        [bool]$ExcludeLoopback,
        [bool]$IncludePath,
        [bool]$IncludeOwner,
        [string]$SortBy
    )

    # Build process map
    $procMap = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $procMap[[int]$p.Id] = $p
    }

    # Build PID -> services map (best-effort)
    $svcByPid = @{}
    try {
        $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Select-Object Name, DisplayName, ProcessId
        foreach ($s in @($svcs)) {
            if (-not $svcByPid.ContainsKey([int]$s.ProcessId)) {
                $svcByPid[[int]$s.ProcessId] = New-Object System.Collections.Generic.List[object]
            }
            $svcByPid[[int]$s.ProcessId].Add($s)
        }
    } catch {
        # If this fails, we still proceed without service mapping
    }

    $rows = New-Object System.Collections.Generic.List[object]

    # TCP listeners
    $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop

    foreach ($t in @($tcp)) {
        if ($Port -and ($Port -notcontains [int]$t.LocalPort)) { continue }
        if ($Address -and ($t.LocalAddress -notlike $Address)) { continue }
        if ($ExcludeLoopback -and ($t.LocalAddress -eq '127.0.0.1' -or $t.LocalAddress -eq '::1')) { continue }

        $pid = [int]$t.OwningProcess
        $p = $procMap[$pid]

        $pName = if ($p) { $p.ProcessName } else { $null }
        if ($ProcessName -and ($pName -notlike $ProcessName)) { continue }

        $svcNames = $null
        $svcDisplays = $null
        if ($svcByPid.ContainsKey($pid)) {
            $svcNames = @($svcByPid[$pid] | Select-Object -ExpandProperty Name) -join '; '
            $svcDisplays = @($svcByPid[$pid] | Select-Object -ExpandProperty DisplayName) -join '; '
        }

        if ($ServiceName) {
            $match = $false
            if ($svcNames -and ($svcNames -like $ServiceName)) { $match = $true }
            if ($svcDisplays -and ($svcDisplays -like $ServiceName)) { $match = $true }
            if (-not $match) { continue }
        }

        $path = $null
        if ($IncludePath -and $p) {
            try { $path = $p.Path } catch { $path = $null }
        }

        $owner = $null
        if ($IncludeOwner -and $p) {
            try {
                $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction Stop
                $o = Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner -ErrorAction Stop
                if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
            } catch { $owner = $null }
        }

        $rows.Add([PSCustomObject]@{
            Timestamp          = Get-Date
            ComputerName       = $env:COMPUTERNAME
            Protocol           = 'TCP'
            LocalAddress       = $t.LocalAddress
            LocalPort          = [int]$t.LocalPort
            State              = $t.State
            PID                = $pid
            ProcessName        = $pName
            ServiceName        = $svcNames
            ServiceDisplayName = $svcDisplays
            Path               = if ($IncludePath) { $path } else { $null }
            Owner              = if ($IncludeOwner) { $owner } else { $null }
        })
    }

    # UDP endpoints (no "listen state" like TCP; endpoints are effectively listeners)
    if ($IncludeUDP) {
        $udp = Get-NetUDPEndpoint -ErrorAction Stop

        foreach ($u in @($udp)) {
            if ($Port -and ($Port -notcontains [int]$u.LocalPort)) { continue }
            if ($Address -and ($u.LocalAddress -notlike $Address)) { continue }
            if ($ExcludeLoopback -and ($u.LocalAddress -eq '127.0.0.1' -or $u.LocalAddress -eq '::1')) { continue }

            $pid = [int]$u.OwningProcess
            $p = $procMap[$pid]

            $pName = if ($p) { $p.ProcessName } else { $null }
            if ($ProcessName -and ($pName -notlike $ProcessName)) { continue }

            $svcNames = $null
            $svcDisplays = $null
            if ($svcByPid.ContainsKey($pid)) {
                $svcNames = @($svcByPid[$pid] | Select-Object -ExpandProperty Name) -join '; '
                $svcDisplays = @($svcByPid[$pid] | Select-Object -ExpandProperty DisplayName) -join '; '
            }

            if ($ServiceName) {
                $match = $false
                if ($svcNames -and ($svcNames -like $ServiceName)) { $match = $true }
                if ($svcDisplays -and ($svcDisplays -like $ServiceName)) { $match = $true }
                if (-not $match) { continue }
            }

            $path = $null
            if ($IncludePath -and $p) {
                try { $path = $p.Path } catch { $path = $null }
            }

            $owner = $null
            if ($IncludeOwner -and $p) {
                try {
                    $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction Stop
                    $o = Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner -ErrorAction Stop
                    if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
                } catch { $owner = $null }
            }

            $rows.Add([PSCustomObject]@{
                Timestamp          = Get-Date
                ComputerName       = $env:COMPUTERNAME
                Protocol           = 'UDP'
                LocalAddress       = $u.LocalAddress
                LocalPort          = [int]$u.LocalPort
                State              = 'Listen'
                PID                = $pid
                ProcessName        = $pName
                ServiceName        = $svcNames
                ServiceDisplayName = $svcDisplays
                Path               = if ($IncludePath) { $path } else { $null }
                Owner              = if ($IncludeOwner) { $owner } else { $null }
            })
        }
    }

    $sortExpr = switch ($SortBy) {
        'Port'    { @('LocalPort','Protocol','LocalAddress','ProcessName') }
        'Process' { @('ProcessName','LocalPort','Protocol','LocalAddress') }
        'Address' { @('LocalAddress','LocalPort','Protocol','ProcessName') }
    }

    $rows | Sort-Object $sortExpr
}

function Get-RemoteListeningPorts {
    param(
        [Parameter(Mandatory)][string]$Computer
    )

    $sb = {
        param($IncludeUDP,$Port,$ProcessName,$ServiceName,$Address,$ExcludeLoopback,$IncludePath,$IncludeOwner,$SortBy)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        # Inline local function for remote execution
        function Get-LocalListeningPortsInternal {
            param($IncludeUDP,$Port,$ProcessName,$ServiceName,$Address,$ExcludeLoopback,$IncludePath,$IncludeOwner,$SortBy)

            $procMap = @{}
            foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) { $procMap[[int]$p.Id] = $p }

            $svcByPid = @{}
            try {
                $svcs = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop | Select-Object Name, DisplayName, ProcessId
                foreach ($s in @($svcs)) {
                    if (-not $svcByPid.ContainsKey([int]$s.ProcessId)) {
                        $svcByPid[[int]$s.ProcessId] = New-Object System.Collections.Generic.List[object]
                    }
                    $svcByPid[[int]$s.ProcessId].Add($s)
                }
            } catch { }

            $rows = New-Object System.Collections.Generic.List[object]

            $tcp = Get-NetTCPConnection -State Listen -ErrorAction Stop
            foreach ($t in @($tcp)) {
                if ($Port -and ($Port -notcontains [int]$t.LocalPort)) { continue }
                if ($Address -and ($t.LocalAddress -notlike $Address)) { continue }
                if ($ExcludeLoopback -and ($t.LocalAddress -eq '127.0.0.1' -or $t.LocalAddress -eq '::1')) { continue }

                $pid = [int]$t.OwningProcess
                $p = $procMap[$pid]
                $pName = if ($p) { $p.ProcessName } else { $null }
                if ($ProcessName -and ($pName -notlike $ProcessName)) { continue }

                $svcNames = $null
                $svcDisplays = $null
                if ($svcByPid.ContainsKey($pid)) {
                    $svcNames = @($svcByPid[$pid] | Select-Object -ExpandProperty Name) -join '; '
                    $svcDisplays = @($svcByPid[$pid] | Select-Object -ExpandProperty DisplayName) -join '; '
                }

                if ($ServiceName) {
                    $match = $false
                    if ($svcNames -and ($svcNames -like $ServiceName)) { $match = $true }
                    if ($svcDisplays -and ($svcDisplays -like $ServiceName)) { $match = $true }
                    if (-not $match) { continue }
                }

                $path = $null
                if ($IncludePath -and $p) { try { $path = $p.Path } catch { $path = $null } }

                $owner = $null
                if ($IncludeOwner -and $p) {
                    try {
                        $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction Stop
                        $o = Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner -ErrorAction Stop
                        if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
                    } catch { $owner = $null }
                }

                $rows.Add([PSCustomObject]@{
                    Timestamp          = Get-Date
                    ComputerName       = $env:COMPUTERNAME
                    Protocol           = 'TCP'
                    LocalAddress       = $t.LocalAddress
                    LocalPort          = [int]$t.LocalPort
                    State              = $t.State
                    PID                = $pid
                    ProcessName        = $pName
                    ServiceName        = $svcNames
                    ServiceDisplayName = $svcDisplays
                    Path               = if ($IncludePath) { $path } else { $null }
                    Owner              = if ($IncludeOwner) { $owner } else { $null }
                })
            }

            if ($IncludeUDP) {
                $udp = Get-NetUDPEndpoint -ErrorAction Stop
                foreach ($u in @($udp)) {
                    if ($Port -and ($Port -notcontains [int]$u.LocalPort)) { continue }
                    if ($Address -and ($u.LocalAddress -notlike $Address)) { continue }
                    if ($ExcludeLoopback -and ($u.LocalAddress -eq '127.0.0.1' -or $u.LocalAddress -eq '::1')) { continue }

                    $pid = [int]$u.OwningProcess
                    $p = $procMap[$pid]
                    $pName = if ($p) { $p.ProcessName } else { $null }
                    if ($ProcessName -and ($pName -notlike $ProcessName)) { continue }

                    $svcNames = $null
                    $svcDisplays = $null
                    if ($svcByPid.ContainsKey($pid)) {
                        $svcNames = @($svcByPid[$pid] | Select-Object -ExpandProperty Name) -join '; '
                        $svcDisplays = @($svcByPid[$pid] | Select-Object -ExpandProperty DisplayName) -join '; '
                    }

                    if ($ServiceName) {
                        $match = $false
                        if ($svcNames -and ($svcNames -like $ServiceName)) { $match = $true }
                        if ($svcDisplays -and ($svcDisplays -like $ServiceName)) { $match = $true }
                        if (-not $match) { continue }
                    }

                    $path = $null
                    if ($IncludePath -and $p) { try { $path = $p.Path } catch { $path = $null } }

                    $owner = $null
                    if ($IncludeOwner -and $p) {
                        try {
                            $cimProc = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -ErrorAction Stop
                            $o = Invoke-CimMethod -InputObject $cimProc -MethodName GetOwner -ErrorAction Stop
                            if ($o.ReturnValue -eq 0) { $owner = "$($o.Domain)\$($o.User)" }
                        } catch { $owner = $null }
                    }

                    $rows.Add([PSCustomObject]@{
                        Timestamp          = Get-Date
                        ComputerName       = $env:COMPUTERNAME
                        Protocol           = 'UDP'
                        LocalAddress       = $u.LocalAddress
                        LocalPort          = [int]$u.LocalPort
                        State              = 'Listen'
                        PID                = $pid
                        ProcessName        = $pName
                        ServiceName        = $svcNames
                        ServiceDisplayName = $svcDisplays
                        Path               = if ($IncludePath) { $path } else { $null }
                        Owner              = if ($IncludeOwner) { $owner } else { $null }
                    })
                }
            }

            $sortExpr = switch ($SortBy) {
                'Port'    { @('LocalPort','Protocol','LocalAddress','ProcessName') }
                'Process' { @('ProcessName','LocalPort','Protocol','LocalAddress') }
                'Address' { @('LocalAddress','LocalPort','Protocol','ProcessName') }
            }

            $rows | Sort-Object $sortExpr
        }

        Get-LocalListeningPortsInternal -IncludeUDP $IncludeUDP -Port $Port -ProcessName $ProcessName -ServiceName $ServiceName `
            -Address $Address -ExcludeLoopback $ExcludeLoopback -IncludePath $IncludePath -IncludeOwner $IncludeOwner -SortBy $SortBy
    }

    Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ArgumentList @(
        [bool]$IncludeUDP, $Port, $ProcessName, $ServiceName, $Address, [bool]$ExcludeLoopback,
        [bool]$IncludePath, [bool]$IncludeOwner, $SortBy
    ) -ErrorAction Stop
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-LocalListeningPorts -IncludeUDP:$IncludeUDP -Port $Port -ProcessName $ProcessName -ServiceName $ServiceName `
                -Address $Address -ExcludeLoopback:$ExcludeLoopback -IncludePath:$IncludePath -IncludeOwner:$IncludeOwner -SortBy $SortBy
            foreach ($r in $rows) { $all.Add($r) }
        } else {
            $rows = Get-RemoteListeningPorts -Computer $target
            foreach ($r in $rows) { $all.Add($r) }
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            Timestamp          = Get-Date
            ComputerName       = $target
            Protocol           = $null
            LocalAddress       = $null
            LocalPort          = $null
            State              = $null
            PID                = $null
            ProcessName        = $null
            ServiceName        = $null
            ServiceDisplayName = $null
            Path               = if ($IncludePath) { $null } else { $null }
            Owner              = if ($IncludeOwner) { $null } else { $null }
            Error              = $_.Exception.Message
        })
    }
}

$all
