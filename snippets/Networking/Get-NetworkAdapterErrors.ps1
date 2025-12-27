<#
.SYNOPSIS
Reports NIC error/discard/drop counters and link state for troubleshooting.

.DESCRIPTION
Collects high-signal network adapter health counters:
- Sent/Received errors
- Discards
- Outbound queue length
- Link state + speed
- MAC + interface alias/index
- (Best-effort) driver version/provider/date via Win32_PnPSignedDriver

Primary use-cases:
- "Is the NIC flapping?"
- "Are we seeing CRC/packet errors or discards that indicate cabling/switch issues?"
- "Is this a bad driver or duplex/autoneg mismatch symptom?"

Outputs structured objects suitable for automation and reporting.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER IncludeDisabled
Include adapters that are disabled.

.PARAMETER IncludeVirtual
Include virtual adapters (Hyper-V, VMware, VPN, etc.). Default excluded.

.PARAMETER InterfaceAlias
Filter by interface alias (wildcards supported), e.g. "Ethernet*", "Wi-Fi".

.PARAMETER IncludeDriverInfo
Include driver provider/version/date (best-effort; can be slower).

.PARAMETER IncludeRaw
Include raw counter snapshots (string) for deeper review.

.EXAMPLE
.\Get-NetworkAdapterErrors.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-NetworkAdapterErrors.ps1 -InterfaceAlias "Ethernet*" | Format-Table -Auto

.EXAMPLE
.\Get-NetworkAdapterErrors.ps1 -ComputerName RDSH01,RDSH02 -IncludeDriverInfo |
  Export-Csv C:\Reports\NIC-Errors.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: NetAdapter module (Get-NetAdapter, Get-NetAdapterStatistics).
Remote requires WinRM.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [switch]$IncludeVirtual,

    [Parameter()]
    [string]$InterfaceAlias,

    [Parameter()]
    [switch]$IncludeDriverInfo,

    [Parameter()]
    [switch]$IncludeRaw
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$virtualPatterns = @(
    'Hyper-V','vEthernet','VMware','VirtualBox','Loopback','TAP','TUN',
    'WireGuard','OpenVPN','Forti','Sophos','AnyConnect','GlobalProtect','Pulse','Zscaler',
    'ZeroTier','Tailscale','WAN Miniport','Npcap','Container','WSL'
)

function Is-VirtualAdapter {
    param([string]$Alias,[string]$Desc)
    foreach ($p in $virtualPatterns) {
        if (($Alias -and $Alias -like "*$p*") -or ($Desc -and $Desc -like "*$p*")) { return $true }
    }
    return $false
}

function Get-DriverInfoMap {
    param()

    # Map by DeviceID (PNPDeviceID) where possible
    $map = @{}
    try {
        $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop |
            Select-Object DeviceID, DriverProviderName, DriverVersion, DriverDate, Manufacturer, FriendlyName

        foreach ($d in @($drivers)) {
            if ($d.DeviceID -and -not $map.ContainsKey($d.DeviceID)) {
                $map[$d.DeviceID] = $d
            }
        }
    } catch {
        # ignore
    }
    return $map
}

function Get-LocalNetworkAdapterErrors {
    param(
        [bool]$IncludeDisabled,
        [bool]$IncludeVirtual,
        [string]$InterfaceAlias,
        [bool]$IncludeDriverInfo,
        [bool]$IncludeRaw
    )

    $driverMap = @{}
    if ($IncludeDriverInfo) { $driverMap = Get-DriverInfoMap }

    $adapters = Get-NetAdapter -ErrorAction Stop

    if (-not $IncludeDisabled) {
        $adapters = $adapters | Where-Object { $_.Status -ne 'Disabled' }
    }

    if ($InterfaceAlias) {
        $adapters = $adapters | Where-Object { $_.Name -like $InterfaceAlias -or $_.InterfaceAlias -like $InterfaceAlias }
    }

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($a in @($adapters)) {
        $alias = $a.InterfaceAlias
        $desc  = $a.InterfaceDescription

        $isVirtual = Is-VirtualAdapter -Alias $alias -Desc $desc
        if (-not $IncludeVirtual -and $isVirtual) { continue }

        $stats = $null
        try { $stats = Get-NetAdapterStatistics -Name $a.Name -ErrorAction Stop } catch { $stats = $null }

        # Best-effort driver info matching
        $drvProvider = $null
        $drvVersion  = $null
        $drvDate     = $null
        $drvMfg      = $null
        if ($IncludeDriverInfo) {
            try {
                # a.PnPDeviceID often matches Win32_PnPSignedDriver.DeviceID
                $pnpId = $a.PnPDeviceID
                if ($pnpId -and $driverMap.ContainsKey($pnpId)) {
                    $d = $driverMap[$pnpId]
                    $drvProvider = $d.DriverProviderName
                    $drvVersion  = $d.DriverVersion
                    $drvDate     = $d.DriverDate
                    $drvMfg      = $d.Manufacturer
                }
            } catch { }
        }

        $rxErrors    = if ($stats) { $stats.ReceivedPacketErrors } else { $null }
        $txErrors    = if ($stats) { $stats.SentPacketErrors } else { $null }
        $rxDiscards  = if ($stats) { $stats.ReceivedDiscardedPackets } else { $null }
        $txDiscards  = if ($stats) { $stats.OutboundDiscardedPackets } else { $null } # property name varies; best-effort below
        $rxDrops     = if ($stats) { $stats.ReceivedPacketErrors } else { $null }     # Windows doesn't expose "drops" consistently; keep errors/discards as signal

        # Some OS builds expose slightly different names; try to normalize:
        if ($stats) {
            if ($stats.PSObject.Properties.Name -contains 'OutboundDiscardedPackets') { $txDiscards = $stats.OutboundDiscardedPackets }
            elseif ($stats.PSObject.Properties.Name -contains 'SentDiscardedPackets') { $txDiscards = $stats.SentDiscardedPackets }
        }

        $hadAnyErrors =
            (($rxErrors -as [long]) -gt 0) -or
            (($txErrors -as [long]) -gt 0) -or
            (($rxDiscards -as [long]) -gt 0) -or
            (($txDiscards -as [long]) -gt 0)

        $obj = [PSCustomObject]@{
            Timestamp            = Get-Date
            ComputerName         = $env:COMPUTERNAME

            Name                 = $a.Name
            InterfaceAlias       = $alias
            InterfaceIndex       = $a.ifIndex
            Status               = $a.Status
            LinkSpeed            = $a.LinkSpeed
            MacAddress           = $a.MacAddress
            DriverDescription    = $desc
            IsVirtual            = $isVirtual

            # Counters
            ReceivedErrors       = $rxErrors
            SentErrors           = $txErrors
            ReceivedDiscards     = $rxDiscards
            SentDiscards         = $txDiscards

            OutboundQueueLength  = if ($stats -and ($stats.PSObject.Properties.Name -contains 'OutboundQueueLength')) { $stats.OutboundQueueLength } else { $null }

            # Totals (context)
            ReceivedBytes        = if ($stats) { $stats.ReceivedBytes } else { $null }
            SentBytes            = if ($stats) { $stats.SentBytes } else { $null }
            ReceivedUnicastPkts  = if ($stats -and ($stats.PSObject.Properties.Name -contains 'ReceivedUnicastPackets')) { $stats.ReceivedUnicastPackets } else { $null }
            SentUnicastPkts      = if ($stats -and ($stats.PSObject.Properties.Name -contains 'SentUnicastPackets')) { $stats.SentUnicastPackets } else { $null }

            HasAnyErrorsOrDiscards = $hadAnyErrors

            # Driver info (optional)
            DriverProvider       = if ($IncludeDriverInfo) { $drvProvider } else { $null }
            DriverVersion        = if ($IncludeDriverInfo) { $drvVersion } else { $null }
            DriverDate           = if ($IncludeDriverInfo) { $drvDate } else { $null }
            DriverManufacturer    = if ($IncludeDriverInfo) { $drvMfg } else { $null }
        }

        if ($IncludeRaw -and $stats) {
            $obj | Add-Member -NotePropertyName RawStatistics -NotePropertyValue ($stats | Select-Object * | Out-String) -Force
        }

        $rows.Add($obj)
    }

    # Sort: problem adapters first
    $rows | Sort-Object @{Expression={-not $_.HasAnyErrorsOrDiscards}; Ascending=$true},
                        @{Expression={$_.IsVirtual}; Ascending=$true},
                        Name
}

function Get-RemoteNetworkAdapterErrors {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [bool]$IncludeDisabled,
        [bool]$IncludeVirtual,
        [string]$InterfaceAlias,
        [bool]$IncludeDriverInfo,
        [bool]$IncludeRaw
    )

    $sb = {
        param($IncludeDisabled,$IncludeVirtual,$InterfaceAlias,$IncludeDriverInfo,$IncludeRaw)

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        $virtualPatterns = @(
            'Hyper-V','vEthernet','VMware','VirtualBox','Loopback','TAP','TUN',
            'WireGuard','OpenVPN','Forti','Sophos','AnyConnect','GlobalProtect','Pulse','Zscaler',
            'ZeroTier','Tailscale','WAN Miniport','Npcap','Container','WSL'
        )

        function Is-VirtualAdapter {
            param([string]$Alias,[string]$Desc)
            foreach ($p in $virtualPatterns) {
                if (($Alias -and $Alias -like "*$p*") -or ($Desc -and $Desc -like "*$p*")) { return $true }
            }
            return $false
        }

        function Get-DriverInfoMap {
            $map = @{}
            try {
                $drivers = Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop |
                    Select-Object DeviceID, DriverProviderName, DriverVersion, DriverDate, Manufacturer, FriendlyName
                foreach ($d in @($drivers)) {
                    if ($d.DeviceID -and -not $map.ContainsKey($d.DeviceID)) { $map[$d.DeviceID] = $d }
                }
            } catch { }
            return $map
        }

        $driverMap = @{}
        if ($IncludeDriverInfo) { $driverMap = Get-DriverInfoMap }

        $adapters = Get-NetAdapter -ErrorAction Stop

        if (-not $IncludeDisabled) {
            $adapters = $adapters | Where-Object { $_.Status -ne 'Disabled' }
        }

        if ($InterfaceAlias) {
            $adapters = $adapters | Where-Object { $_.Name -like $InterfaceAlias -or $_.InterfaceAlias -like $InterfaceAlias }
        }

        $rows = New-Object System.Collections.Generic.List[object]

        foreach ($a in @($adapters)) {
            $alias = $a.InterfaceAlias
            $desc  = $a.InterfaceDescription

            $isVirtual = Is-VirtualAdapter -Alias $alias -Desc $desc
            if (-not $IncludeVirtual -and $isVirtual) { continue }

            $stats = $null
            try { $stats = Get-NetAdapterStatistics -Name $a.Name -ErrorAction Stop } catch { $stats = $null }

            $drvProvider = $null; $drvVersion = $null; $drvDate = $null; $drvMfg = $null
            if ($IncludeDriverInfo) {
                try {
                    $pnpId = $a.PnPDeviceID
                    if ($pnpId -and $driverMap.ContainsKey($pnpId)) {
                        $d = $driverMap[$pnpId]
                        $drvProvider = $d.DriverProviderName
                        $drvVersion  = $d.DriverVersion
                        $drvDate     = $d.DriverDate
                        $drvMfg      = $d.Manufacturer
                    }
                } catch { }
            }

            $rxErrors   = if ($stats) { $stats.ReceivedPacketErrors } else { $null }
            $txErrors   = if ($stats) { $stats.SentPacketErrors } else { $null }
            $rxDiscards = if ($stats) { $stats.ReceivedDiscardedPackets } else { $null }
            $txDiscards = $null
            if ($stats) {
                if ($stats.PSObject.Properties.Name -contains 'OutboundDiscardedPackets') { $txDiscards = $stats.OutboundDiscardedPackets }
                elseif ($stats.PSObject.Properties.Name -contains 'SentDiscardedPackets') { $txDiscards = $stats.SentDiscardedPackets }
            }

            $hadAnyErrors =
                (($rxErrors -as [long]) -gt 0) -or
                (($txErrors -as [long]) -gt 0) -or
                (($rxDiscards -as [long]) -gt 0) -or
                (($txDiscards -as [long]) -gt 0)

            $obj = [PSCustomObject]@{
                Timestamp            = Get-Date
                ComputerName         = $env:COMPUTERNAME
                Name                 = $a.Name
                InterfaceAlias       = $alias
                InterfaceIndex       = $a.ifIndex
                Status               = $a.Status
                LinkSpeed            = $a.LinkSpeed
                MacAddress           = $a.MacAddress
                DriverDescription    = $desc
                IsVirtual            = $isVirtual
                ReceivedErrors       = $rxErrors
                SentErrors           = $txErrors
                ReceivedDiscards     = $rxDiscards
                SentDiscards         = $txDiscards
                OutboundQueueLength  = if ($stats -and ($stats.PSObject.Properties.Name -contains 'OutboundQueueLength')) { $stats.OutboundQueueLength } else { $null }
                ReceivedBytes        = if ($stats) { $stats.ReceivedBytes } else { $null }
                SentBytes            = if ($stats) { $stats.SentBytes } else { $null }
                ReceivedUnicastPkts  = if ($stats -and ($stats.PSObject.Properties.Name -contains 'ReceivedUnicastPackets')) { $stats.ReceivedUnicastPackets } else { $null }
                SentUnicastPkts      = if ($stats -and ($stats.PSObject.Properties.Name -contains 'SentUnicastPackets')) { $stats.SentUnicastPackets } else { $null }
                HasAnyErrorsOrDiscards = $hadAnyErrors
                DriverProvider       = if ($IncludeDriverInfo) { $drvProvider } else { $null }
                DriverVersion        = if ($IncludeDriverInfo) { $drvVersion } else { $null }
                DriverDate           = if ($IncludeDriverInfo) { $drvDate } else { $null }
                DriverManufacturer    = if ($IncludeDriverInfo) { $drvMfg } else { $null }
            }

            if ($IncludeRaw -and $stats) {
                $obj | Add-Member -NotePropertyName RawStatistics -NotePropertyValue ($stats | Select-Object * | Out-String) -Force
            }

            $rows.Add($obj)
        }

        $rows | Sort-Object @{Expression={-not $_.HasAnyErrorsOrDiscards}; Ascending=$true},
                            @{Expression={$_.IsVirtual}; Ascending=$true},
                            Name
    }

    Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ArgumentList @(
        [bool]$IncludeDisabled, [bool]$IncludeVirtual, $InterfaceAlias, [bool]$IncludeDriverInfo, [bool]$IncludeRaw
    ) -ErrorAction Stop
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-LocalNetworkAdapterErrors -IncludeDisabled:$IncludeDisabled -IncludeVirtual:$IncludeVirtual `
                -InterfaceAlias $InterfaceAlias -IncludeDriverInfo:$IncludeDriverInfo -IncludeRaw:$IncludeRaw
            foreach ($r in $rows) { $all.Add($r) }
        }
        else {
            $rows = Get-RemoteNetworkAdapterErrors -Computer $target -IncludeDisabled:$IncludeDisabled -IncludeVirtual:$IncludeVirtual `
                -InterfaceAlias $InterfaceAlias -IncludeDriverInfo:$IncludeDriverInfo -IncludeRaw:$IncludeRaw
            foreach ($r in $rows) { $all.Add($r) }
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            Timestamp              = Get-Date
            ComputerName           = $target
            Name                   = $null
            InterfaceAlias         = $null
            InterfaceIndex         = $null
            Status                 = $null
            LinkSpeed              = $null
            MacAddress             = $null
            DriverDescription      = $null
            IsVirtual              = $null
            ReceivedErrors         = $null
            SentErrors             = $null
            ReceivedDiscards       = $null
            SentDiscards           = $null
            OutboundQueueLength    = $null
            ReceivedBytes          = $null
            SentBytes              = $null
            ReceivedUnicastPkts    = $null
            SentUnicastPkts        = $null
            HasAnyErrorsOrDiscards = $null
            DriverProvider         = $null
            DriverVersion          = $null
            DriverDate             = $null
            DriverManufacturer      = $null
            Error                  = $_.Exception.Message
        })
    }
}

$all
