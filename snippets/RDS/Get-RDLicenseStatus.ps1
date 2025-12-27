<#
.SYNOPSIS
Gets RDS licensing configuration and status indicators for one or more servers.

.DESCRIPTION
Retrieves RDS licensing configuration primarily from registry and OS feature inventory.
Designed for environments where:
- You may not have RDMS/Connection Broker modules available
- You need quick validation of licensing mode + license server settings
- You want CSV-friendly output for audits and troubleshooting

What this script does well:
- Reads configured licensing mode and license servers from the Session Host registry keys
- Attempts to identify installed RDS roles/features (best effort)
- Surfaces common misconfig signals (mode not set, no license server configured)

Limitations (by design):
- True CAL availability/consumption lives on the RD Licensing Server and often requires
  WMI classes (Win32_TSLicenseKeyPack) and/or RD Licensing Manager context.
  This script focuses on Session Host configuration and health indicators.

.PARAMETER ComputerName
One or more servers to query. Defaults to the local computer.

.PARAMETER TimeoutSeconds
CIM/WMI timeout (best-effort). Default 10 seconds.

.EXAMPLE
.\Get-RDLicenseStatus.ps1

.EXAMPLE
.\Get-RDLicenseStatus.ps1 -ComputerName RDSH01,RDSH02 | Format-Table -Auto

.EXAMPLE
.\Get-RDLicenseStatus.ps1 -ComputerName RDSH01 |
  Export-Csv C:\Reports\RDS-LicenseStatus.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: Remote registry/WMI access to target hosts.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RemoteRegValue {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$SubKey,
        [Parameter(Mandatory)][string]$ValueName,
        [ValidateSet('String','DWORD','MultiString')]
        [string]$Type
    )

    $hklm = 2147483650

    $reg = Get-CimInstance -ComputerName $Computer -ClassName StdRegProv -Namespace root\default -OperationTimeoutSec $TimeoutSeconds

    switch ($Type) {
        'String' {
            $r = Invoke-CimMethod -InputObject $reg -MethodName GetStringValue -Arguments @{
                hDefKey     = $hklm
                sSubKeyName = $SubKey
                sValueName  = $ValueName
            }
            if ($r.ReturnValue -eq 0) { return $r.sValue }
        }
        'DWORD' {
            $r = Invoke-CimMethod -InputObject $reg -MethodName GetDWORDValue -Arguments @{
                hDefKey     = $hklm
                sSubKeyName = $SubKey
                sValueName  = $ValueName
            }
            if ($r.ReturnValue -eq 0) { return $r.uValue }
        }
        'MultiString' {
            $r = Invoke-CimMethod -InputObject $reg -MethodName GetMultiStringValue -Arguments @{
                hDefKey     = $hklm
                sSubKeyName = $SubKey
                sValueName  = $ValueName
            }
            if ($r.ReturnValue -eq 0) { return $r.sValue }
        }
    }

    return $null
}

function Get-RemoteRegSubKeys {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$SubKey
    )

    $hklm = 2147483650
    $reg = Get-CimInstance -ComputerName $Computer -ClassName StdRegProv -Namespace root\default -OperationTimeoutSec $TimeoutSeconds

    $r = Invoke-CimMethod -InputObject $reg -MethodName EnumKey -Arguments @{
        hDefKey     = $hklm
        sSubKeyName = $SubKey
    }

    if ($r.ReturnValue -eq 0) { return @($r.sNames) }
    return @()
}

function Convert-LicensingMode {
    param([Nullable[int]]$Mode)

    # Common RDS licensing mode mapping used in registry:
    # 2 = Per Device
    # 4 = Per User
    # Some systems may show 0/1/5/etc depending on policy/older versions; treat unknown as Unknown(<n>)
    if ($null -eq $Mode) { return 'NotSet' }

    switch ($Mode) {
        2 { 'PerDevice' }
        4 { 'PerUser' }
        default { "Unknown($Mode)" }
    }
}

function Try-GetWindowsFeatures {
    param([Parameter(Mandatory)][string]$Computer)

    # Best-effort: Get-WindowsFeature is ServerManager module (usually on servers).
    # If unavailable or blocked, return null.
    try {
        $null = Import-Module ServerManager -ErrorAction Stop
        $features = Get-WindowsFeature -ComputerName $Computer -ErrorAction Stop |
            Where-Object { $_.Installed -eq $true -and $_.Name -match '^RDS|^Remote-Desktop' } |
            Select-Object -ExpandProperty Name
        return @($features)
    }
    catch {
        return $null
    }
}

# Registry keys of interest on Session Hosts
$tsKey = 'SYSTEM\CurrentControlSet\Control\Terminal Server\RCM\Licensing Core'
$policyKey = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$localKey  = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\RCM\Licensing Core'

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $computer = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }

    try {
        # Licensing mode can be set via:
        # - Local configuration (HKLM\SYSTEM...\Licensing Core\LicensingMode)
        # - Policy (HKLM\SOFTWARE\Policies...\Terminal Services\LicensingMode)
        $modeLocal  = $null
        $modePolicy = $null
        $serversPolicy = $null

        try { $modeLocal  = Get-RemoteRegValue -Computer $computer -SubKey $tsKey -ValueName 'LicensingMode' -Type DWORD } catch {}
        try { $modePolicy = Get-RemoteRegValue -Computer $computer -SubKey $policyKey -ValueName 'LicensingMode' -Type DWORD } catch {}

        # License servers are commonly set in policy key as:
        # HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\LicenseServers
        # with subkeys per server name (or values in some builds).
        $licenseServers = @()

        try {
            $sub = Get-RemoteRegSubKeys -Computer $computer -SubKey "$policyKey\LicenseServers"
            if ($sub -and $sub.Count -gt 0) {
                $licenseServers += $sub
                $serversPolicy = $true
            }
        } catch {}

        # Some environments store servers in values; attempt a multi-string read fallback
        if (-not $licenseServers -or $licenseServers.Count -eq 0) {
            try {
                $ms = Get-RemoteRegValue -Computer $computer -SubKey $policyKey -ValueName 'LicenseServers' -Type MultiString
                if ($ms) { $licenseServers += $ms; $serversPolicy = $true }
            } catch {}
        }

        # Determine effective mode (Policy should win)
        $effectiveMode = if ($null -ne $modePolicy) { $modePolicy } else { $modeLocal }
        $effectiveModeText = Convert-LicensingMode -Mode $effectiveMode

        # Identify RDS roles/features (best-effort)
        $features = Try-GetWindowsFeatures -Computer $computer

        # Basic health signals
        $warnings = New-Object System.Collections.Generic.List[string]

        if ($effectiveModeText -eq 'NotSet') {
            $warnings.Add('LicensingModeNotSet')
        }

        if (-not $licenseServers -or $licenseServers.Count -eq 0) {
            $warnings.Add('NoLicenseServerConfigured')
        }

        if ($serversPolicy -ne $true -and ($licenseServers.Count -gt 0)) {
            $warnings.Add('LicenseServersDetectedNonPolicy')
        }

        # RDSH role installed signal (best-effort)
        if ($features -and ($features -notcontains 'RDS-RD-Server') -and ($features -notcontains 'Remote-Desktop-Services')) {
            # Not a hard fail, but useful context
            $warnings.Add('RDSHRoleNotDetectedByServerManager')
        }

        # Pending grace period keys can vary; this is best-effort:
        # Many times, the "grace period" indicator is not trivially readable without specific WMI.
        # We’ll surface whether the TS licensing core key exists, which is a prerequisite.
        $tsKeyExists = $false
        try {
            $keys = Get-RemoteRegSubKeys -Computer $computer -SubKey 'SYSTEM\CurrentControlSet\Control\Terminal Server\RCM'
            if ($keys -contains 'Licensing Core') { $tsKeyExists = $true }
        } catch {}

        $results.Add([PSCustomObject]@{
            Timestamp            = Get-Date
            ComputerName         = $computer
            LicensingModePolicy  = Convert-LicensingMode -Mode $modePolicy
            LicensingModeLocal   = Convert-LicensingMode -Mode $modeLocal
            LicensingModeEffective = $effectiveModeText
            LicenseServers       = if ($licenseServers) { ($licenseServers | Sort-Object -Unique) -join '; ' } else { $null }
            LicenseServersFromPolicy = [bool]$serversPolicy
            LicensingCoreKeyPresent  = $tsKeyExists
            RdsFeaturesInstalled = if ($features) { ($features -join '; ') } else { $null }
            Warnings            = if ($warnings.Count -gt 0) { ($warnings -join '; ') } else { $null }
        })
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp              = Get-Date
            ComputerName           = $computer
            LicensingModePolicy    = $null
            LicensingModeLocal     = $null
            LicensingModeEffective = $null
            LicenseServers         = $null
            LicenseServersFromPolicy = $null
            LicensingCoreKeyPresent  = $null
            RdsFeaturesInstalled   = $null
            Warnings               = $null
            Error                  = $_.Exception.Message
        })
    }
}

$results | Sort-Object ComputerName
