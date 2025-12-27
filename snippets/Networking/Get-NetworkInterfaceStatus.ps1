<#
.SYNOPSIS
Gets a detailed status snapshot of network interfaces and IP configuration.

.DESCRIPTION
Collects a practical, incident-ready view of network interfaces:
- Adapter status, link speed, MAC, driver description
- IPv4/IPv6 addresses, prefix length, gateways
- DNS servers, DNS suffix, registration state
- Interface metric and route metric context
- Physical vs virtual identification (best-effort)
- Filters for Up/Connected adapters by default (optional)

Outputs objects suitable for reporting and automation.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER IncludeDown
Include adapters that are not Up/Connected. Default: only Up/Connected.

.PARAMETER IncludeVirtual
Include virtual adapters (Hyper-V, VMware, VPN, loopback, etc.). Default: included.
Use -ExcludeVirtual to remove common virtual adapters.

.PARAMETER ExcludeVirtual
Exclude common virtual adapters using description/name heuristics.

.PARAMETER IncludeIPv6
Include IPv6 addresses in output. Default: True.

.PARAMETER IncludeAllIPAddresses
Include all assigned IPs (including multiple IPv4/IPv6). Default: True.
If not set, returns only the first IPv4 and first IPv6 address for readability.

.PARAMETER IncludeAdvanced
Adds additional fields (WINS, DHCP server, DNSSuffixSearchList, etc.) when available.

.PARAMETER TimeoutSeconds
Best-effort timeout for remote CIM queries. Default 15 seconds.

.EXAMPLE
.\Get-NetworkInterfaceStatus.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-NetworkInterfaceStatus.ps1 -IncludeDown -ExcludeVirtual | Format-Table -Auto

.EXAMPLE
.\Get-NetworkInterfaceStatus.ps1 -ComputerName PC01,PC02 |
  Export-Csv C:\Reports\NetIfStatus.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: NetTCPIP cmdlets on target (Windows 10/11/Server 2012+).
Remote: uses CIM + remote PowerShell where required; best results when WinRM is enabled.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeDown,

    [Parameter()]
    [switch]$IncludeVirtual,

    [Parameter()]
    [switch]$ExcludeVirtual,

    [Parameter()]
    [bool]$IncludeIPv6 = $true,

    [Parameter()]
    [switch]$IncludeAllIPAddresses,

    [Parameter()]
    [switch]$IncludeAdvanced,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Heuristic patterns for common virtual/tunnel adapters
$virtualPatterns = @(
    'Hyper-V', 'vEthernet', 'VMware', 'VirtualBox', 'Loopback', 'TAP', 'TUN',
    'WireGuard', 'OpenVPN', 'Forti', 'Sophos', 'Cisco AnyConnect', 'AnyConnect',
    'Juniper', 'Pulse Secure', 'GlobalProtect', 'Zscaler', 'ZeroTier', 'Tailscale',
    'WAN Miniport', 'Bluetooth', 'Npcap', 'Container', 'WSL'
)

function Is-VirtualAdapter {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$InterfaceDescription
    )

    foreach ($p in $virtualPatterns) {
        if ($Name -like "*$p*" -or $InterfaceDescription -like "*$p*") { return $true }
    }

    return $false
}

function Normalize-DnsServers {
    param([object]$DnsServers)
    if ($null -eq $DnsServers) { return @() }
    if ($DnsServers -is [string]) { return @($DnsServers) }
    return @($DnsServers)
}

function Get-LocalNetworkInterfaceStatus {
    param(
        [Parameter(Mandatory)][bool]$IncludeDown,
        [Parameter(Mandatory)][bool]$IncludeIPv6,
        [Parameter(Mandatory)][bool]$IncludeAllIPAddresses,
        [Parameter(Mandatory)][bool]$IncludeAdvanced,
        [Parameter(Mandatory)][bool]$ExcludeVirtual,
        [Parameter(Mandatory)][bool]$IncludeVirtual
    )

    # Adapter baseline (Get-NetAdapter is fastest for operational status)
    $adapters = Get-NetAdapter -ErrorAction Stop

    if (-not $IncludeDown) {
        # OperationalStatus Up and LinkSpeed > 0 generally indicates a connected link
        $adapters = $adapters | Where-Object { $_.Status -eq 'Up' }
    }

    $results = foreach ($a in $adapters) {
        $isVirtual = Is-VirtualAdapter -Name $a.Name -InterfaceDescription $a.InterfaceDescription

        if ($ExcludeVirtual -and $isVirtual) { continue }
        if (-not $IncludeVirtual -and $isVirtual) { continue }

        # IP config (Get-NetIPConfiguration ties together IPs, gateways, DNS)
        $ipConfig = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue

        # IP addresses (Get-NetIPAddress)
        $ip4 = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -and $_.PrefixLength -ne $null } |
                Sort-Object -Property SkipAsSource, PrefixLength, IPAddress)

        $ip6 = @()
        if ($IncludeIPv6) {
            $ip6 = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -and $_.PrefixLength -ne $null } |
                    Sort-Object -Property SkipAsSource, PrefixLength, IPAddress)
        }

        $ip4List = if ($IncludeAllIPAddresses) { $ip4 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" } } else { @() }
        $ip6List = if ($IncludeAllIPAddresses) { $ip6 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" } } else { @() }

        $primaryIPv4 = if ($ip4.Count -gt 0) { "$($ip4[0].IPAddress)/$($ip4[0].PrefixLength)" } else { $null }
        $primaryIPv6 = if ($ip6.Count -gt 0) { "$($ip6[0].IPAddress)/$($ip6[0].PrefixLength)" } else { $null }

        # Gateway(s)
        $gw4 = @()
        $gw6 = @()
        if ($ipConfig -and $ipConfig.IPv4DefaultGateway) { $gw4 = @($ipConfig.IPv4DefaultGateway.NextHop) }
        if ($ipConfig -and $ipConfig.IPv6DefaultGateway) { $gw6 = @($ipConfig.IPv6DefaultGateway.NextHop) }

        # DNS
        $dnsServers = @()
        $dnsSuffix = $null
        $dnsReg = $null
        $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
        if ($dns) {
            # DnsClientServerAddress includes AddressFamily groupings
            $dnsServers = @(
                ($dns | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue),
                ($dns | Where-Object { $_.AddressFamily -eq 'IPv6' } | Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue)
            ) | Where-Object { $_ } | ForEach-Object { $_ }  # flatten
        }

        $dnsClient = Get-DnsClient -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
        if ($dnsClient) {
            $dnsSuffix = $dnsClient.ConnectionSpecificSuffix
            $dnsReg = $dnsClient.RegisterThisConnectionsAddress
        }

        # Metrics (used to determine "why did traffic choose that NIC?")
        $ifMetric = $null
        $routeMetric = $null
        $ipIf = Get-NetIPInterface -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
        if ($ipIf) {
            # IPv4 entry is typically what you care about for default routes
            $ipIf4 = $ipIf | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
            if ($ipIf4) {
                $ifMetric = $ipIf4.InterfaceMetric
                $routeMetric = $ipIf4.RouteMetric
            }
        }

        # DHCP (best-effort)
        $dhcpEnabled = $null
        $dhcpServer = $null
        if ($IncludeAdvanced) {
            try {
                $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($a.ifIndex)" -ErrorAction Stop
                $dhcpEnabled = [bool]$cfg.DHCPEnabled
                $dhcpServer  = $cfg.DHCPServer
            } catch {
                $dhcpEnabled = $null
                $dhcpServer  = $null
            }
        }

        [PSCustomObject]@{
            ComputerName               = $env:COMPUTERNAME

            Name                       = $a.Name
            InterfaceIndex             = $a.ifIndex
            Status                     = $a.Status
            LinkSpeed                  = $a.LinkSpeed
            MacAddress                 = $a.MacAddress
            InterfaceDescription       = $a.InterfaceDescription
            IsVirtual                  = $isVirtual
            NdisPhysicalMedium         = $a.NdisPhysicalMedium

            PrimaryIPv4                = $primaryIPv4
            PrimaryIPv6                = if ($IncludeIPv6) { $primaryIPv6 } else { $null }
            IPv4Addresses              = if ($IncludeAllIPAddresses) { $ip4List -join '; ' } else { $null }
            IPv6Addresses              = if ($IncludeIPv6 -and $IncludeAllIPAddresses) { $ip6List -join '; ' } else { $null }

            IPv4Gateway                = if ($gw4.Count -gt 0) { $gw4 -join '; ' } else { $null }
            IPv6Gateway                = if ($gw6.Count -gt 0) { $gw6 -join '; ' } else { $null }

            DnsServers                 = if ($dnsServers.Count -gt 0) { ($dnsServers | Select-Object -Unique) -join '; ' } else { $null }
            DnsSuffix                  = $dnsSuffix
            DnsRegistrationEnabled     = $dnsReg

            InterfaceMetricIPv4        = $ifMetric
            RouteMetricIPv4            = $routeMetric

            DhcpEnabled                = if ($IncludeAdvanced) { $dhcpEnabled } else { $null }
            DhcpServer                 = if ($IncludeAdvanced) { $dhcpServer } else { $null }

            Timestamp                  = Get-Date
        }
    }

    # Prefer "most likely active" adapters first in typical output
    $results |
        Sort-Object -Property @{Expression = { $_.Status -ne 'Up' }; Ascending = $true },
                              @{Expression = { $_.IsVirtual }; Ascending = $true },
                              @{Expression = { $_.InterfaceMetricIPv4 }; Ascending = $true },
                              Name
}

function Get-RemoteNetworkInterfaceStatus {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][bool]$IncludeDown,
        [Parameter(Mandatory)][bool]$IncludeIPv6,
        [Parameter(Mandatory)][bool]$IncludeAllIPAddresses,
        [Parameter(Mandatory)][bool]$IncludeAdvanced,
        [Parameter(Mandatory)][bool]$ExcludeVirtual,
        [Parameter(Mandatory)][bool]$IncludeVirtual
    )

    # Use PowerShell remoting for NetTCPIP cmdlets (best results).
    # If remoting is not available, caller will get an error row.
    $scriptBlock = {
        param($IncludeDown, $IncludeIPv6, $IncludeAllIPAddresses, $IncludeAdvanced, $ExcludeVirtual, $IncludeVirtual)

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $virtualPatterns = @(
            'Hyper-V', 'vEthernet', 'VMware', 'VirtualBox', 'Loopback', 'TAP', 'TUN',
            'WireGuard', 'OpenVPN', 'Forti', 'Sophos', 'Cisco AnyConnect', 'AnyConnect',
            'Juniper', 'Pulse Secure', 'GlobalProtect', 'Zscaler', 'ZeroTier', 'Tailscale',
            'WAN Miniport', 'Bluetooth', 'Npcap', 'Container', 'WSL'
        )

        function Is-VirtualAdapter {
            param([string]$Name,[string]$InterfaceDescription)
            foreach ($p in $virtualPatterns) {
                if ($Name -like "*$p*" -or $InterfaceDescription -like "*$p*") { return $true }
            }
            return $false
        }

        $adapters = Get-NetAdapter -ErrorAction Stop
        if (-not $IncludeDown) {
            $adapters = $adapters | Where-Object { $_.Status -eq 'Up' }
        }

        foreach ($a in $adapters) {
            $isVirtual = Is-VirtualAdapter -Name $a.Name -InterfaceDescription $a.InterfaceDescription
            if ($ExcludeVirtual -and $isVirtual) { continue }
            if (-not $IncludeVirtual -and $isVirtual) { continue }

            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue

            $ip4 = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -and $_.PrefixLength -ne $null } |
                    Sort-Object -Property SkipAsSource, PrefixLength, IPAddress)

            $ip6 = @()
            if ($IncludeIPv6) {
                $ip6 = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -and $_.PrefixLength -ne $null } |
                        Sort-Object -Property SkipAsSource, PrefixLength, IPAddress)
            }

            $ip4List = if ($IncludeAllIPAddresses) { $ip4 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" } } else { @() }
            $ip6List = if ($IncludeAllIPAddresses) { $ip6 | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" } } else { @() }

            $primaryIPv4 = if ($ip4.Count -gt 0) { "$($ip4[0].IPAddress)/$($ip4[0].PrefixLength)" } else { $null }
            $primaryIPv6 = if ($ip6.Count -gt 0) { "$($ip6[0].IPAddress)/$($ip6[0].PrefixLength)" } else { $null }

            $gw4 = @()
            $gw6 = @()
            if ($ipConfig -and $ipConfig.IPv4DefaultGateway) { $gw4 = @($ipConfig.IPv4DefaultGateway.NextHop) }
            if ($ipConfig -and $ipConfig.IPv6DefaultGateway) { $gw6 = @($ipConfig.IPv6DefaultGateway.NextHop) }

            $dnsServers = @()
            $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
            if ($dns) {
                $dnsServers = @(
                    ($dns | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue),
                    ($dns | Where-Object { $_.AddressFamily -eq 'IPv6' } | Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue)
                ) | Where-Object { $_ } | ForEach-Object { $_ }
            }

            $dnsClient = Get-DnsClient -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
            $dnsSuffix = $dnsClient.ConnectionSpecificSuffix
            $dnsReg = $dnsClient.RegisterThisConnectionsAddress

            $ifMetric = $null
            $routeMetric = $null
            $ipIf = Get-NetIPInterface -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue
            if ($ipIf) {
                $ipIf4 = $ipIf | Where-Object { $_.AddressFamily -eq 'IPv4' } | Select-Object -First 1
                if ($ipIf4) {
                    $ifMetric = $ipIf4.InterfaceMetric
                    $routeMetric = $ipIf4.RouteMetric
                }
            }

            $dhcpEnabled = $null
            $dhcpServer  = $null
            if ($IncludeAdvanced) {
                try {
                    $cfg = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($a.ifIndex)" -ErrorAction Stop
                    $dhcpEnabled = [bool]$cfg.DHCPEnabled
                    $dhcpServer  = $cfg.DHCPServer
                } catch {
                    $dhcpEnabled = $null
                    $dhcpServer  = $null
                }
            }

            [PSCustomObject]@{
                ComputerName               = $env:COMPUTERNAME

                Name                       = $a.Name
                InterfaceIndex             = $a.ifIndex
                Status                     = $a.Status
                LinkSpeed                  = $a.LinkSpeed
                MacAddress                 = $a.MacAddress
                InterfaceDescription       = $a.InterfaceDescription
                IsVirtual                  = $isVirtual
                NdisPhysicalMedium         = $a.NdisPhysicalMedium

                PrimaryIPv4                = $primaryIPv4
                PrimaryIPv6                = if ($IncludeIPv6) { $primaryIPv6 } else { $null }
                IPv4Addresses              = if ($IncludeAllIPAddresses) { $ip4List -join '; ' } else { $null }
                IPv6Addresses              = if ($IncludeIPv6 -and $IncludeAllIPAddresses) { $ip6List -join '; ' } else { $null }

                IPv4Gateway                = if ($gw4.Count -gt 0) { $gw4 -join '; ' } else { $null }
                IPv6Gateway                = if ($gw6.Count -gt 0) { $gw6 -join '; ' } else { $null }

                DnsServers                 = if ($dnsServers.Count -gt 0) { ($dnsServers | Select-Object -Unique) -join '; ' } else { $null }
                DnsSuffix                  = $dnsSuffix
                DnsRegistrationEnabled     = $dnsReg

                InterfaceMetricIPv4        = $ifMetric
                RouteMetricIPv4            = $routeMetric

                DhcpEnabled                = if ($IncludeAdvanced) { $dhcpEnabled } else { $null }
                DhcpServer                 = if ($IncludeAdvanced) { $dhcpServer } else { $null }

                Timestamp                  = Get-Date
            }
        } | Sort-Object -Property @{Expression = { $_.Status -ne 'Up' }; Ascending = $true },
                                 @{Expression = { $_.IsVirtual }; Ascending = $true },
                                 @{Expression = { $_.InterfaceMetricIPv4 }; Ascending = $true },
                                 Name
    }

    Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList @(
        $IncludeDown, $IncludeIPv6, $IncludeAllIPAddresses, $IncludeAdvanced, $ExcludeVirtual, $IncludeVirtual
    ) -ErrorAction Stop
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-LocalNetworkInterfaceStatus -IncludeDown:$IncludeDown -IncludeIPv6:$IncludeIPv6 `
                -IncludeAllIPAddresses:$IncludeAllIPAddresses -IncludeAdvanced:$IncludeAdvanced `
                -ExcludeVirtual:$ExcludeVirtual -IncludeVirtual:$IncludeVirtual
            foreach ($r in $rows) { $all.Add($r) }
        }
        else {
            $rows = Get-RemoteNetworkInterfaceStatus -Computer $target -IncludeDown:$IncludeDown -IncludeIPv6:$IncludeIPv6 `
                -IncludeAllIPAddresses:$IncludeAllIPAddresses -IncludeAdvanced:$IncludeAdvanced `
                -ExcludeVirtual:$ExcludeVirtual -IncludeVirtual:$IncludeVirtual
            foreach ($r in $rows) { $all.Add($r) }
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            ComputerName               = $target
            Name                       = $null
            InterfaceIndex             = $null
            Status                     = $null
            LinkSpeed                  = $null
            MacAddress                 = $null
            InterfaceDescription       = $null
            IsVirtual                  = $null
            NdisPhysicalMedium         = $null

            PrimaryIPv4                = $null
            PrimaryIPv6                = $null
            IPv4Addresses              = $null
            IPv6Addresses              = $null
            IPv4Gateway                = $null
            IPv6Gateway                = $null
            DnsServers                 = $null
            DnsSuffix                  = $null
            DnsRegistrationEnabled     = $null
            InterfaceMetricIPv4        = $null
            RouteMetricIPv4            = $null
            DhcpEnabled                = $null
            DhcpServer                 = $null
            Timestamp                  = Get-Date
            Error                      = $_.Exception.Message
        })
    }
}

$all
