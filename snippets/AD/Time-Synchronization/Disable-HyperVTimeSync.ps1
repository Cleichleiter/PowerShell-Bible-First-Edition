<#
.SYNOPSIS
  Disables Hyper-V "Time synchronization" Integration Service for a specified VM.

.DESCRIPTION
  Domain Controllers should not inherit time from the hypervisor. In many environments,
  Hyper-V's Time Synchronization integration can override Windows Time (W32Time) behavior
  and contribute to domain-wide drift if the DC is the PDC Emulator or otherwise relied upon.

  This script disables the Hyper-V Integration Service named "Time Synchronization"
  for a target VM and verifies the resulting state.

  It is designed to be run on a Hyper-V host.

.REQUIREMENTS
  - Run on the Hyper-V host (or a management station with Hyper-V PowerShell module
    and rights to manage the target host)
  - Hyper-V PowerShell module available
  - Permissions to manage VM integration services

.PARAMETER VMName
  Name of the target VM (as shown in Hyper-V Manager).

.PARAMETER ComputerName
  Hyper-V host to target. Defaults to the local computer.

.EXAMPLE
  .\Disable-HyperVTimeSync.ps1 -VMName "MCC-DC1"

.EXAMPLE
  .\Disable-HyperVTimeSync.ps1 -ComputerName "HV-HOST01" -VMName "MCC-DC1"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$VMName,
  [string]$ComputerName = $env:COMPUTERNAME
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
  param([Parameter(Mandatory)][string]$Title)
  Write-Host ""
  Write-Host ("=" * 80)
  Write-Host $Title
  Write-Host ("=" * 80)
}

function Ensure-HyperVModule {
  if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    throw "Hyper-V PowerShell module not found. Install Hyper-V management tools or run on a Hyper-V host."
  }
  Import-Module Hyper-V -ErrorAction Stop
}

function Get-TimeIntegrationService {
  param(
    [Parameter(Mandatory)][string]$HostName,
    [Parameter(Mandatory)][string]$Name
  )

  Get-VMIntegrationService -ComputerName $HostName -VMName $Name |
    Where-Object { $_.Name -eq "Time Synchronization" } |
    Select-Object -First 1
}

# ------------------------- Main -------------------------

Write-Section "Disable Hyper-V Time Synchronization Integration Service"

Ensure-HyperVModule

Write-Host "Hyper-V Host : $ComputerName"
Write-Host "VM Name      : $VMName"

$svc = Get-TimeIntegrationService -HostName $ComputerName -Name $VMName
if (-not $svc) {
  throw "Could not locate 'Time Synchronization' integration service for VM '$VMName' on host '$ComputerName'. Verify VM name and host."
}

Write-Host ""
Write-Host ("Current state: Enabled={0}" -f $svc.Enabled)

if ($svc.Enabled -eq $false) {
  Write-Host "No change required: Time Synchronization is already disabled for $VMName."
  Write-Host "SUCCESS: Time Synchronization is disabled for $VMName"
  return
}

Disable-VMIntegrationService -ComputerName $ComputerName -VMName $VMName -Name "Time Synchronization"

# Re-query to confirm
$svc2 = Get-TimeIntegrationService -HostName $ComputerName -Name $VMName
if (-not $svc2) {
  throw "Verification failed: integration service not found after change (unexpected)."
}

Write-Host ""
Write-Host ("Updated state: Enabled={0}" -f $svc2.Enabled)

if ($svc2.Enabled -eq $false) {
  Write-Host "SUCCESS: Time Synchronization is disabled for $VMName"
} else {
  throw "FAILED: Time Synchronization still appears enabled for $VMName. Check permissions and Hyper-V host connectivity."
}
