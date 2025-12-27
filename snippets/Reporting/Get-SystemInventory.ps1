<#
.SYNOPSIS
Collects baseline system inventory information.

.DESCRIPTION
Returns a structured inventory object per computer including:
- OS details
- Hardware (CPU, RAM, manufacturer, model)
- Disk summary
- Network summary
- Uptime and last boot time
- Domain / workgroup context

Designed for:
- Asset inventory
- Baseline snapshots
- Audit and documentation
- MSP reporting and RMM execution

All output is object-based and safe for automation.

.PARAMETER ComputerName
One or more computers to inventory. Defaults to the local computer.

.PARAMETER IncludeDisks
Include logical disk summary (fixed drives).

.PARAMETER IncludeNetwork
Include primary network adapter details.

.PARAMETER ThrottleLimit
Throttle limit for remoting. Default 16.

.EXAMPLE
.\Get-SystemInventory.ps1 | Format-Table -Auto

.EXAMPLE
.\Get-SystemInventory.ps1 -ComputerName PC01,PC02 |
  Export-Csv C:\Reports\SystemInventory.csv -NoTypeInformation

.EXAMPLE
.\Get-SystemInventory.ps1 -IncludeDisks -IncludeNetwork |
  ConvertTo-Html -Title "System Inventory" |
  Out-File C:\Reports\Inventory.html

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeDisks,

    [Parameter()]
    [switch]$IncludeNetwork,

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SystemInventoryLocal {
    param(
        [bool]$IncludeDisks,
        [bool]$IncludeNetwork
    )

    $now = Get-Date

    try {
        $os   = Get-CimInstance Win32_OperatingSystem
        $cs   = Get-CimInstance Win32_ComputerSystem
        $cpu  = Get-CimInstance Win32_Processor | Select-Object -First 1
        $bios = Get-CimInstance Win32_BIOS

        $uptime = $now - $os.LastBootUpTime

        $diskSummary = $null
        if ($IncludeDisks) {
            $diskSummary = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" |
                Select-Object `
                    DeviceID,
                    @{n='SizeGB';e={[math]::Round($_.Size / 1GB,2)}},
                    @{n='FreeGB';e={[math]::Round($_.FreeSpace / 1GB,2)}},
                    @{n='PercentFree';e={[math]::Round(($_.FreeSpace / $_.Size) * 100,2)}}
        }

        $netSummary = $null
        if ($IncludeNetwork) {
            $netSummary = Get-CimInstance Win32_NetworkAdapterConfiguration |
                Where-Object { $_.IPEnabled } |
                Select-Object `
                    Description,
                    MACAddress,
                    IPAddress,
                    DefaultIPGateway,
                    DNSServerSearchOrder
        }

        [PSCustomObject]@{
            Timestamp          = $now
            ComputerName       = $env:COMPUTERNAME
            Domain             = $cs.Domain
            Manufacturer       = $cs.Manufacturer
            Model              = $cs.Model
            SerialNumber       = $bios.SerialNumber
            OSName             = $os.Caption
            OSVersion          = $os.Version
            OSBuild            = $os.BuildNumber
            InstallDate        = $os.InstallDate
            LastBootTime       = $os.LastBootUpTime
            UptimeDays         = [math]::Round($uptime.TotalDays,2)
            CPUModel           = $cpu.Name
            LogicalProcessors  = $cpu.NumberOfLogicalProcessors
            TotalMemoryGB      = [math]::Round($cs.TotalPhysicalMemory / 1GB,2)
            Disks              = $diskSummary
            NetworkAdapters    = $netSummary
            Error              = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Timestamp          = $now
            ComputerName       = $env:COMPUTERNAME
            Domain             = $null
            Manufacturer       = $null
            Model              = $null
            SerialNumber       = $null
            OSName             = $null
            OSVersion          = $null
            OSBuild            = $null
            InstallDate        = $null
            LastBootTime       = $null
            UptimeDays         = $null
            CPUModel           = $null
            LogicalProcessors  = $null
            TotalMemoryGB      = $null
            Disks              = $null
            NetworkAdapters    = $null
            Error              = $_.Exception.Message
        }
    }
}

$results = New-Object System.Collections.Generic.List[object]

if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-SystemInventoryLocal} -ArgumentList $IncludeDisks,$IncludeNetwork
        foreach ($r in $rows) { $results.Add($r) }
    }
    finally {
        if ($sessions) { $sessions | Remove-PSSession -ErrorAction SilentlyContinue }
    }
}
else {
    foreach ($c in $ComputerName) {
        if ($c -eq $env:COMPUTERNAME -or $c -eq 'localhost') {
            $results.Add((Get-SystemInventoryLocal -IncludeDisks:$IncludeDisks -IncludeNetwork:$IncludeNetwork))
        }
        else {
            $r = Invoke-Command -ComputerName $c -ScriptBlock ${function:Get-SystemInventoryLocal} -ArgumentList $IncludeDisks,$IncludeNetwork
            $results.Add($r)
        }
    }
}

$results
