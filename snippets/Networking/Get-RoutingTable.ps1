<#
.SYNOPSIS
Gets IPv4/IPv6 routing table data with practical incident-focused context.

.DESCRIPTION
Returns route entries with:
- Destination prefix, next hop, route metric
- Interface alias/index, interface metric, if status
- Route type/protocol, store (Active/Persistent) where available
- Flags for default routes and common VPN/virtual interfaces (heuristic)

Designed to answer:
- "Why is traffic taking the wrong path?"
- "What is the effective default route?"
- "Are there persistent routes or VPN routes overriding expected behavior?"

Outputs structured objects suitable for reporting and automation.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER AddressFamily
IPv4, IPv6, or Both. Default Both.

.PARAMETER ActiveOnly
Only show active routes (where supported). Default: show all returned by Get-NetRoute.

.PARAMETER IncludePersistent
Include persistent routes (Store = Persistent) when available. Default: included.

.PARAMETER DefaultOnly
Show only default routes (0.0.0.0/0 and ::/0).

.PARAMETER Prefix
Filter by destination prefix (wildcard match), e.g. "10.*" or "0.0.0.0/0".

.PARAMETER NextHop
Filter by next hop (wildcard match), e.g. "10.0.0.1".

.PARAMETER IncludeVirtual
Include virtual/VPN adapters. Default included.
Use -ExcludeVirtual to remove common virtual adapters.

.PARAMETER ExcludeVirtual
Exclude common virtual adapters using heuristics.

.PARAMETER IncludeRaw
Include a RawRoute object (serialized) for deeper troubleshooting.

.PARAMETER TimeoutSeconds
Best-effort timeout for remote CIM queries. Default 15 seconds.

.EXAMPLE
.\Get-RoutingTable.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-RoutingTable.ps1 -DefaultOnly | Format-Table -Auto

.EXAMPLE
.\Get-RoutingTable.ps1 -AddressFamily IPv4 -Prefix "10.*" | Format-Table -Auto

.EXAMPLE
.\Get-RoutingTable.ps1 -ComputerName RDSH01,RDSH02 -DefaultOnly |
  Export-Csv C:\Reports\Routing-Defaults.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: NetTCPIP module (Get-NetRoute/Get-NetIPInterface/Get-NetAdapter).
Remote: uses Invoke-Command for best fidelity.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateSet('IPv4','IPv6','Both')]
    [string]$AddressFamily = 'Both',

    [Parameter()]
    [switch]$ActiveOnly,

    [Parameter()]
    [switch]$IncludePersistent,

    [Parameter()]
    [switch]$DefaultOnly,

    [Parameter()]
    [string]$Prefix,

    [Parameter()]
    [string]$NextHop,

    [Parameter()]
    [switch]$IncludeVirtual,

    [Parameter()]
    [switch]$ExcludeVirtual,

    [Parameter()]
    [switch]$IncludeRaw,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$virtualPatterns = @(
    'Hyper-V', 'vEthernet', 'VMware', 'VirtualBox', 'Loopback', 'TAP', 'TUN',
    'WireGuard', 'OpenVPN', 'Forti', 'Sophos', 'Cisco AnyConnect', 'AnyConnect',
    'Juniper', 'Pulse Secure', 'GlobalProtect', 'Zscaler', 'ZeroTier', 'Tailscale',
    'WAN Miniport', 'Bluetooth', 'Npcap', 'Container', 'WSL'
)

function Is-VirtualAlias {
    param([string]$Alias, [string]$Desc)
    foreach ($p in $virtualPatterns) {
        if (($Alias -and $Alias -like "*$p*") -or ($Desc -and $Desc -like "*$p*")) { return $true }
    }
    return $false
}

function Get-LocalRoutes {
    param(
        [string]$AddressFamily,
        [bool]$ActiveOnly,
        [bool]$IncludePersistent,
        [bool]$DefaultOnly,
        [string]$Prefix,
        [string]$NextHop,
        [bool]$ExcludeVirtual,
        [bool]$IncludeVirtual,
        [bool]$IncludeRaw
    )

    $families = switch ($AddressFamily) {
        'IPv4' { @('IPv4') }
        'IPv6' { @('IPv6') }
        'Both' { @('IPv4','IPv6') }
    }

    # Build adapter metadata maps for fast joins
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $adapterByIfIndex = @{}
    foreach ($a in @($adapters)) { $adapterByIfIndex[$a.ifIndex] = $a }

    $ipIfs = Get-NetIPInterface -ErrorAction SilentlyContinue
    $ipIfByKey = @{}
    foreach ($i in @($ipIfs)) { $ipIfByKey["$($i.InterfaceIndex)|$($i.AddressFamily)"] = $i }

    $all = New-Object System.Collections.Generic.List[object]

    foreach ($fam in $families) {
        $routes = Get-NetRoute -AddressFamily $fam -ErrorAction Stop

        if ($ActiveOnly) {
            # Best-effort: many builds expose "State". If absent, ignore.
            $routes = $routes | Where-Object { $_.State -eq 'Active' -or -not $_.PSObject.Properties.Name.Contains('State') }
        }

        if (-not $IncludePersistent) {
            if ($routes -and ($routes | Get-Member -Name Store -ErrorAction SilentlyContinue)) {
                $routes = $routes | Where-Object { $_.Store -ne 'Persistent' }
            }
        }

        if ($DefaultOnly) {
            $routes = $routes | Where-Object {
                ($fam -eq 'IPv4' -and $_.DestinationPrefix -eq '0.0.0.0/0') -or
                ($fam -eq 'IPv6' -and $_.DestinationPrefix -eq '::/0')
            }
        }

        if ($Prefix) {
            $routes = $routes | Where-Object { $_.DestinationPrefix -like $Prefix }
        }

        if ($NextHop) {
            $routes = $routes | Where-Object { $_.NextHop -like $NextHop }
        }

        foreach ($r in @($routes)) {
            $ifIndex = $r.InterfaceIndex
            $adapter = $adapterByIfIndex[$ifIndex]
            $ipIf = $ipIfByKey["$ifIndex|$fam"]

            $ifAlias = $r.InterfaceAlias
            $ifDesc = if ($adapter) { $adapter.InterfaceDescription } else { $null }
            $isVirtual = Is-VirtualAlias -Alias $ifAlias -Desc $ifDesc

            if ($ExcludeVirtual -and $isVirtual) { continue }
            if (-not $IncludeVirtual -and $isVirtual) { continue }

            $isDefault = ($fam -eq 'IPv4' -and $r.DestinationPrefix -eq '0.0.0.0/0') -or
                         ($fam -eq 'IPv6' -and $r.DestinationPrefix -eq '::/0')

            # VPN-ish heuristic: virtual adapter OR next hop on private ranges with low metrics often indicates tunnels.
            $vpnHint = $false
            if ($isVirtual) { $vpnHint = $true }
            if ($ifAlias -match 'VPN|Tunnel|WireGuard|Tailscale|AnyConnect|GlobalProtect|Pulse|Zscaler') { $vpnHint = $true }

            $obj = [PSCustomObject]@{
                Timestamp            = Get-Date
                ComputerName         = $env:COMPUTERNAME

                AddressFamily        = $fam
                DestinationPrefix    = $r.DestinationPrefix
                NextHop              = $r.NextHop

                RouteMetric          = $r.RouteMetric
                InterfaceIndex       = $ifIndex
                InterfaceAlias       = $ifAlias
                InterfaceStatus      = if ($adapter) { $adapter.Status } else { $null }
                LinkSpeed            = if ($adapter) { $adapter.LinkSpeed } else { $null }
                MacAddress           = if ($adapter) { $adapter.MacAddress } else { $null }
                InterfaceDescription = $ifDesc

                InterfaceMetric      = if ($ipIf) { $ipIf.InterfaceMetric } else { $null }
                RouteMetricSetting   = if ($ipIf) { $ipIf.RouteMetric } else { $null }

                Protocol             = $r.Protocol
                Type                 = $r.Type

                Store                = if ($r.PSObject.Properties.Name -contains 'Store') { $r.Store } else { $null }
                State                = if ($r.PSObject.Properties.Name -contains 'State') { $r.State } else { $null }

                IsDefaultRoute       = $isDefault
                IsVirtualInterface   = $isVirtual
                IsVpnHint            = $vpnHint
            }

            if ($IncludeRaw) {
                # Store raw route as a string snapshot (CSV-friendly)
                $raw = $r | Select-Object * | Out-String
                $obj | Add-Member -NotePropertyName RawRoute -NotePropertyValue $raw -Force
            }

            $all.Add($obj)
        }
    }

    # Sort with defaults first, then by family, then lowest effective metrics
    $all |
        Sort-Object -Property @{Expression = { -not $_.IsDefaultRoute }; Ascending = $true },
                              AddressFamily,
                              @{Expression = { $_.RouteMetric }; Ascending = $true },
                              @{Expression = { $_.InterfaceMetric }; Ascending = $true },
                              DestinationPrefix
}

function Get-RemoteRoutes {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [string]$AddressFamily,
        [bool]$ActiveOnly,
        [bool]$IncludePersistent,
        [bool]$DefaultOnly,
        [string]$Prefix,
        [string]$NextHop,
        [bool]$ExcludeVirtual,
        [bool]$IncludeVirtual,
        [bool]$IncludeRaw
    )

    $sb = {
        param($AddressFamily,$ActiveOnly,$IncludePersistent,$DefaultOnly,$Prefix,$NextHop,$ExcludeVirtual,$IncludeVirtual,$IncludeRaw)

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $virtualPatterns = @(
            'Hyper-V', 'vEthernet', 'VMware', 'VirtualBox', 'Loopback', 'TAP', 'TUN',
            'WireGuard', 'OpenVPN', 'Forti', 'Sophos', 'Cisco AnyConnect', 'AnyConnect',
            'Juniper', 'Pulse Secure', 'GlobalProtect', 'Zscaler', 'ZeroTier', 'Tailscale',
            'WAN Miniport', 'Bluetooth', 'Npcap', 'Container', 'WSL'
        )

        function Is-VirtualAlias {
            param([string]$Alias, [string]$Desc)
            foreach ($p in $virtualPatterns) {
                if (($Alias -and $Alias -like "*$p*") -or ($Desc -and $Desc -like "*$p*")) { return $true }
            }
            return $false
        }

        function Get-LocalRoutesInternal {
            param($AddressFamily,$ActiveOnly,$IncludePersistent,$DefaultOnly,$Prefix,$NextHop,$ExcludeVirtual,$IncludeVirtual,$IncludeRaw)

            $families = switch ($AddressFamily) {
                'IPv4' { @('IPv4') }
                'IPv6' { @('IPv6') }
                'Both' { @('IPv4','IPv6') }
            }

            $adapters = Get-NetAdapter -ErrorAction SilentlyContinue
            $adapterByIfIndex = @{}
            foreach ($a in @($adapters)) { $adapterByIfIndex[$a.ifIndex] = $a }

            $ipIfs = Get-NetIPInterface -ErrorAction SilentlyContinue
            $ipIfByKey = @{}
            foreach ($i in @($ipIfs)) { $ipIfByKey["$($i.InterfaceIndex)|$($i.AddressFamily)"] = $i }

            $all = New-Object System.Collections.Generic.List[object]

            foreach ($fam in $families) {
                $routes = Get-NetRoute -AddressFamily $fam -ErrorAction Stop

                if ($ActiveOnly) {
                    $routes = $routes | Where-Object { $_.State -eq 'Active' -or -not $_.PSObject.Properties.Name.Contains('State') }
                }

                if (-not $IncludePersistent) {
                    if ($routes -and ($routes | Get-Member -Name Store -ErrorAction SilentlyContinue)) {
                        $routes = $routes | Where-Object { $_.Store -ne 'Persistent' }
                    }
                }

                if ($DefaultOnly) {
                    $routes = $routes | Where-Object {
                        ($fam -eq 'IPv4' -and $_.DestinationPrefix -eq '0.0.0.0/0') -or
                        ($fam -eq 'IPv6' -and $_.DestinationPrefix -eq '::/0')
                    }
                }

                if ($Prefix) { $routes = $routes | Where-Object { $_.DestinationPrefix -like $Prefix } }
                if ($NextHop) { $routes = $routes | Where-Object { $_.NextHop -like $NextHop } }

                foreach ($r in @($routes)) {
                    $ifIndex = $r.InterfaceIndex
                    $adapter = $adapterByIfIndex[$ifIndex]
                    $ipIf = $ipIfByKey["$ifIndex|$fam"]

                    $ifAlias = $r.InterfaceAlias
                    $ifDesc = if ($adapter) { $adapter.InterfaceDescription } else { $null }
                    $isVirtual = Is-VirtualAlias -Alias $ifAlias -Desc $ifDesc

                    if ($ExcludeVirtual -and $isVirtual) { continue }
                    if (-not $IncludeVirtual -and $isVirtual) { continue }

                    $isDefault = ($fam -eq 'IPv4' -and $r.DestinationPrefix -eq '0.0.0.0/0') -or
                                 ($fam -eq 'IPv6' -and $r.DestinationPrefix -eq '::/0')

                    $vpnHint = $false
                    if ($isVirtual) { $vpnHint = $true }
                    if ($ifAlias -match 'VPN|Tunnel|WireGuard|Tailscale|AnyConnect|GlobalProtect|Pulse|Zscaler') { $vpnHint = $true }

                    $obj = [PSCustomObject]@{
                        Timestamp            = Get-Date
                        ComputerName         = $env:COMPUTERNAME

                        AddressFamily        = $fam
                        DestinationPrefix    = $r.DestinationPrefix
                        NextHop              = $r.NextHop

                        RouteMetric          = $r.RouteMetric
                        InterfaceIndex       = $ifIndex
                        InterfaceAlias       = $ifAlias
                        InterfaceStatus      = if ($adapter) { $adapter.Status } else { $null }
                        LinkSpeed            = if ($adapter) { $adapter.LinkSpeed } else { $null }
                        MacAddress           = if ($adapter) { $adapter.MacAddress } else { $null }
                        InterfaceDescription = $ifDesc

                        InterfaceMetric      = if ($ipIf) { $ipIf.InterfaceMetric } else { $null }
                        RouteMetricSetting   = if ($ipIf) { $ipIf.RouteMetric } else { $null }

                        Protocol             = $r.Protocol
                        Type                 = $r.Type

                        Store                = if ($r.PSObject.Properties.Name -contains 'Store') { $r.Store } else { $null }
                        State                = if ($r.PSObject.Properties.Name -contains 'State') { $r.State } else { $null }

                        IsDefaultRoute       = $isDefault
                        IsVirtualInterface   = $isVirtual
                        IsVpnHint            = $vpnHint
                    }

                    if ($IncludeRaw) {
                        $raw = $r | Select-Object * | Out-String
                        $obj | Add-Member -NotePropertyName RawRoute -NotePropertyValue $raw -Force
                    }

                    $all.Add($obj)
                }
            }

            $all |
                Sort-Object -Property @{Expression = { -not $_.IsDefaultRoute }; Ascending = $true },
                                      AddressFamily,
                                      @{Expression = { $_.RouteMetric }; Ascending = $true },
                                      @{Expression = { $_.InterfaceMetric }; Ascending = $true },
                                      DestinationPrefix
        }

        Get-LocalRoutesInternal -AddressFamily $AddressFamily -ActiveOnly $ActiveOnly -IncludePersistent $IncludePersistent `
            -DefaultOnly $DefaultOnly -Prefix $Prefix -NextHop $NextHop -ExcludeVirtual $ExcludeVirtual -IncludeVirtual $IncludeVirtual `
            -IncludeRaw $IncludeRaw
    }

    Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ArgumentList @(
        $AddressFamily, [bool]$ActiveOnly, [bool]$IncludePersistent, [bool]$DefaultOnly, $Prefix, $NextHop,
        [bool]$ExcludeVirtual, [bool]$IncludeVirtual, [bool]$IncludeRaw
    ) -ErrorAction Stop
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-LocalRoutes -AddressFamily $AddressFamily -ActiveOnly:$ActiveOnly -IncludePersistent:$IncludePersistent `
                -DefaultOnly:$DefaultOnly -Prefix $Prefix -NextHop $NextHop -ExcludeVirtual:$ExcludeVirtual -IncludeVirtual:$IncludeVirtual `
                -IncludeRaw:$IncludeRaw
            foreach ($r in $rows) { $all.Add($r) }
        }
        else {
            $rows = Get-RemoteRoutes -Computer $target -AddressFamily $AddressFamily -ActiveOnly:$ActiveOnly -IncludePersistent:$IncludePersistent `
                -DefaultOnly:$DefaultOnly -Prefix $Prefix -NextHop $NextHop -ExcludeVirtual:$ExcludeVirtual -IncludeVirtual:$IncludeVirtual `
                -IncludeRaw:$IncludeRaw
            foreach ($r in $rows) { $all.Add($r) }
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            Timestamp            = Get-Date
            ComputerName         = $target
            AddressFamily        = $null
            DestinationPrefix    = $null
            NextHop              = $null
            RouteMetric          = $null
            InterfaceIndex       = $null
            InterfaceAlias       = $null
            InterfaceStatus      = $null
            LinkSpeed            = $null
            MacAddress           = $null
            InterfaceDescription = $null
            InterfaceMetric      = $null
            RouteMetricSetting   = $null
            Protocol             = $null
            Type                 = $null
            Store                = $null
            State                = $null
            IsDefaultRoute       = $null
            IsVirtualInterface   = $null
            IsVpnHint            = $null
            Error                = $_.Exception.Message
        })
    }
}

$all
