<#
.SYNOPSIS
  Configures the PDC Emulator to use authoritative external NTP and verifies sync.

.DESCRIPTION
  This script is intended for server-side correction when the domain time authority is unhealthy.
  It performs a safe, explicit configuration of Windows Time (W32Time) on the specified PDC:

    - Sets external NTP peers (manual peer list)
    - Sets sync flags to manual
    - Marks the server as a reliable time source (AnnounceFlags)
    - Restarts W32Time
    - Forces resync
    - Validates the resulting time source and status

  IMPORTANT:
    - This script makes changes.
    - Prefer GPO-based enforcement for long-term configuration. This script is appropriate for:
        * emergency correction,
        * lab environments,
        * initial stabilization before implementing GPO,
        * or when you intentionally want a local configuration.

  NOTE ABOUT POLICY:
    If RSOP/GPO forces Type=NT5DS (Policy), manual configuration may NOT take effect.
    In that case:
      - fix GPO precedence first (RSOP on the DC),
      - then rerun this script.

.REQUIREMENTS
  - Run from a domain-joined workstation/server
  - WinRM access to the PDC (Invoke-Command)
  - Permissions to modify HKLM registry and restart services on the PDC

.PARAMETER Pdc
  The PDC emulator (FQDN or hostname). If not specified, script auto-detects via AD.

.PARAMETER Peers
  External NTP peers in w32tm format. Example:
    "time.windows.com,0x9 pool.ntp.org,0x9"

.PARAMETER ForceTypeNtp
  If set, forces HKLM:\...\W32Time\Parameters\Type to "NTP".
  Use this only when you understand the impact and have confirmed policy is not enforcing Type.

.PARAMETER SkipMarkReliable
  If set, does not set AnnounceFlags=5. (Default is to mark reliable.)

.PARAMETER VerifyStripchart
  If set, runs w32tm /stripchart against the first peer to validate UDP/123 reachability.

.PARAMETER StripchartSamples
  Number of stripchart samples to collect during verification.

.EXAMPLE
  .\Fix-PdcTimeSource.ps1

.EXAMPLE
  .\Fix-PdcTimeSource.ps1 -Peers "time.windows.com,0x9 pool.ntp.org,0x9" -VerifyStripchart

.EXAMPLE
  .\Fix-PdcTimeSource.ps1 -Pdc "MCC-DC1.MORROW.local" -ForceTypeNtp
#>

[CmdletBinding()]
param(
  [string]$Pdc,
  [string]$Peers = "time.windows.com,0x9 pool.ntp.org,0x9",
  [switch]$ForceTypeNtp,
  [switch]$SkipMarkReliable,
  [switch]$VerifyStripchart,
  [int]$StripchartSamples = 5
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

function Get-PdcFromAD {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory module not found. Install RSAT AD module or specify -Pdc explicitly."
  }
  Import-Module ActiveDirectory -ErrorAction Stop
  (Get-ADDomain).PDCEmulator
}

function Invoke-Pdc {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][scriptblock]$ScriptBlock,
    [object[]]$ArgumentList = @()
  )
  Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

function Get-RemoteW32TimePolicyHint {
  param([Parameter(Mandatory)][string]$ComputerName)

  # Best-effort: detect if Type is being enforced by policy based on w32tm /query /configuration output.
  $cfg = Invoke-Pdc -ComputerName $ComputerName -ScriptBlock { w32tm /query /configuration 2>&1 | Out-String }
  $typeLine = ($cfg -split "`r?`n" | Where-Object { $_ -match "^\s*Type:\s*" } | Select-Object -First 1)

  [PSCustomObject]@{
    TypeLine = $typeLine
    IsPolicyEnforcedNT5DS = [bool]($typeLine -match "NT5DS" -and $typeLine -match "Policy")
    IsPolicyEnforcedNTP   = [bool]($typeLine -match "\bNTP\b" -and $typeLine -match "Policy")
    RawConfig             = $cfg
  }
}

function Configure-PdcTime {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$PeerList,
    [Parameter(Mandatory)][bool]$ForceType,
    [Parameter(Mandatory)][bool]$MarkReliable
  )

  Invoke-Pdc -ComputerName $ComputerName -ScriptBlock {
    param($peers, $forceTypeNtp, $markReliable)

    $regBase = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time"
    $paramKey = Join-Path $regBase "Parameters"
    $cfgKey   = Join-Path $regBase "Config"

    # Optional hard-set Type=NTP (only use when not enforced by policy)
    if ($forceTypeNtp) {
      Set-ItemProperty -Path $paramKey -Name "Type" -Value "NTP"
    }

    # Set peers in both w32tm config and registry Parameters\NtpServer
    # w32tm /config writes into registry and notifies time service
    w32tm /config /manualpeerlist:$peers /syncfromflags:manual /update | Out-Null

    # Mark as reliable time source for domain clients (AnnounceFlags=5)
    if ($markReliable) {
      Set-ItemProperty -Path $cfgKey -Name "AnnounceFlags" -Value 5
    }

    # Restart W32Time to ensure clean state
    Stop-Service w32time -Force
    Start-Service w32time

    # Force resync; /force may fail if policy conflicts exist
    $resync = (w32tm /resync /force 2>&1 | Out-String)

    [PSCustomObject]@{
      ResyncOutput = $resync
      Source       = (w32tm /query /source 2>&1 | Out-String).Trim()
      Status       = (w32tm /query /status 2>&1 | Out-String)
      Config       = (w32tm /query /configuration 2>&1 | Out-String)
    }
  } -ArgumentList @($PeerList, $ForceType, $MarkReliable)
}

function Test-Stripchart {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][int]$Samples
  )

  Invoke-Pdc -ComputerName $ComputerName -ScriptBlock {
    param($t, $s)
    w32tm /stripchart /computer:$t /dataonly /samples:$s 2>&1 | Out-String
  } -ArgumentList @($Target, $Samples)
}

# ------------------------- Main -------------------------

Write-Section "Fix PDC Time Source (Authoritative NTP)"

if (-not $Pdc) {
  $Pdc = Get-PdcFromAD
}

Write-Host "Target PDC Emulator : $Pdc"
Write-Host "Peer List           : $Peers"
Write-Host "Force Type = NTP    : $ForceTypeNtp"
Write-Host "Mark Reliable       : $(-not $SkipMarkReliable)"
Write-Host "Verify Stripchart   : $VerifyStripchart"
Write-Host "Stripchart Samples  : $StripchartSamples"

Write-Section "Pre-check: Policy Hint (w32tm configuration)"
$hint = Get-RemoteW32TimePolicyHint -ComputerName $Pdc
Write-Host ("Observed Type line: {0}" -f ($hint.TypeLine ?? "<none>"))

if ($hint.IsPolicyEnforcedNT5DS) {
  Write-Host ""
  Write-Host "WARNING: NtpClient Type appears to be enforced as NT5DS by Policy."
  Write-Host "         Manual configuration may not take effect until GPO precedence is corrected."
  Write-Host "         Consider running RSOP.msc on the PDC and removing conflicting time policies."
}

Write-Section "Apply Configuration"
$markReliable = -not $SkipMarkReliable
$apply = Configure-PdcTime -ComputerName $Pdc -PeerList $Peers -ForceType ([bool]$ForceTypeNtp) -MarkReliable $markReliable

Write-Host ""
Write-Host "Resync output:"
Write-Host $apply.ResyncOutput.Trim()

Write-Host ""
Write-Host "Source:"
Write-Host $apply.Source

Write-Host ""
Write-Host "Status:"
Write-Host $apply.Status

Write-Section "Post-check: Policy Hint (w32tm configuration)"
$postHint = Get-RemoteW32TimePolicyHint -ComputerName $Pdc
Write-Host ("Observed Type line: {0}" -f ($postHint.TypeLine ?? "<none>"))

if ($VerifyStripchart) {
  Write-Section "Verification: Stripchart (UDP/123) from PDC"
  # Stripchart against first target in peer list; parse out hostname token before comma if present.
  $first = ($Peers -split "\s+")[0]
  $target = ($first -split ",")[0]

  Write-Host "Testing: $target"
  $strip = Test-Stripchart -ComputerName $Pdc -Target $target -Samples $StripchartSamples
  Write-Host $strip
}

Write-Section "Interpretation Guidance"
Write-Host " - If Source is time.windows.com/pool.ntp.org and Leap Indicator shows no warning, PDC is healthy."
Write-Host " - If Source remains Local CMOS Clock or resync reports no time data, check RSOP/GPO precedence."
Write-Host " - Prefer enforcing the final configuration via a PDC-scoped GPO for long-term stability."
