<#
.SYNOPSIS
  Diagnoses Active Directory domain time health with a focus on the PDC Emulator.

.DESCRIPTION
  Read-only diagnostics intended to answer one question quickly and defensibly:
    "Is the domain time authority (PDC Emulator) healthy, or is the issue likely endpoint-specific?"

  What it does:
    - Discovers domain + PDC Emulator (authoritative time source in AD)
    - Validates W32Time service state on the PDC
    - Captures w32tm status/config/source from the PDC
    - Flags risky sources (Local CMOS Clock, VM IC Time Synchronization Provider)
    - Validates external NTP reachability using w32tm stripchart (UDP/123) from the PDC
    - Runs an RSOP/registry-derived policy check to detect if W32Time "Type" is enforced by policy
    - Collects recent Time-Service/W32Time-related System events from the PDC
    - Writes a detailed JSON report and a human-readable TXT summary

  This script does NOT:
    - Make configuration changes
    - Modify GPOs
    - Restart services

.REQUIREMENTS
  - Run from a domain-joined workstation or server
  - ActiveDirectory PowerShell module (RSAT) to discover PDC
  - WinRM access to the PDC (Invoke-Command)
  - Sufficient rights to query service status and event logs on the PDC

.PARAMETER OutDir
  Output directory for report artifacts.

.PARAMETER EventHours
  How many hours back to pull time-related System events from the PDC.

.PARAMETER StripchartSamples
  Number of samples for each stripchart test.

.PARAMETER NtpTargets
  External NTP targets to test from the PDC using w32tm /stripchart.

.EXAMPLE
  .\Diagnose-DomainTime.ps1

.EXAMPLE
  .\Diagnose-DomainTime.ps1 -OutDir C:\Temp\TimeDiag -EventHours 48 -NtpTargets @("time.windows.com","pool.ntp.org")
#>

[CmdletBinding()]
param(
  [string]$OutDir = ".\Time-Diagnostics",
  [int]$EventHours = 24,
  [int]$StripchartSamples = 5,
  [string[]]$NtpTargets = @("time.windows.com", "pool.ntp.org")
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

function Add-Check {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet("PASS","WARN","FAIL")] [string]$Status,
    [Parameter(Mandatory)][string]$Detail
  )
  $Result.Value.Checks += [PSCustomObject]@{
    Name   = $Name
    Status = $Status
    Detail = $Detail
  }
}

function New-ResultObject {
  [PSCustomObject]@{
    GeneratedLocal = (Get-Date).ToString("s")
    Domain         = $null
    PdcEmulator    = $null
    Runner         = [PSCustomObject]@{
      ComputerName = $env:COMPUTERNAME
      UserName     = $env:USERNAME
    }
    Checks         = @()
    Summary        = $null
    Raw            = [ordered]@{}
  }
}

function Ensure-OutDir {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
  (Resolve-Path -Path $Path).Path
}

function Resolve-DomainAndPdc {
  param(
    [Parameter(Mandatory)][ref]$Result
  )

  try {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
      throw "ActiveDirectory PowerShell module not found. Install RSAT: Active Directory module."
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = (Get-ADDomain).DNSRoot
    $pdc    = (Get-ADDomain).PDCEmulator

    $Result.Value.Domain      = $domain
    $Result.Value.PdcEmulator = $pdc

    Add-Check -Result $Result -Name "AD Domain Discovery" -Status "PASS" -Detail "Domain: $domain | PDC Emulator: $pdc"
  }
  catch {
    Add-Check -Result $Result -Name "AD Domain Discovery" -Status "FAIL" -Detail $_.Exception.Message
    throw
  }
}

function Invoke-Pdc {
  param(
    [Parameter(Mandatory)][string]$Pdc,
    [Parameter(Mandatory)][scriptblock]$ScriptBlock,
    [object[]]$ArgumentList = @()
  )
  Invoke-Command -ComputerName $Pdc -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

function Get-PdcW32TimeService {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Pdc
  )

  try {
    $svc = Invoke-Pdc -Pdc $Pdc -ScriptBlock { Get-Service -Name w32time | Select-Object Name, Status, StartType }
    $Result.Value.Raw["PDC_w32time_service"] = $svc

    if ($svc.Status -eq "Running") {
      Add-Check -Result $Result -Name "W32Time Service" -Status "PASS" -Detail "W32Time is Running on $Pdc (StartType: $($svc.StartType))."
    } else {
      Add-Check -Result $Result -Name "W32Time Service" -Status "FAIL" -Detail "W32Time is NOT running on $Pdc (Status: $($svc.Status), StartType: $($svc.StartType))."
    }
  }
  catch {
    Add-Check -Result $Result -Name "W32Time Service" -Status "FAIL" -Detail "Failed to query W32Time service on $Pdc. Error: $($_.Exception.Message)"
  }
}

function Get-PdcW32tmOutputs {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Pdc
  )

  try {
    $status = Invoke-Pdc -Pdc $Pdc -ScriptBlock { w32tm /query /status 2>&1 | Out-String }
    $config = Invoke-Pdc -Pdc $Pdc -ScriptBlock { w32tm /query /configuration 2>&1 | Out-String }
    $source = Invoke-Pdc -Pdc $Pdc -ScriptBlock { w32tm /query /source 2>&1 | Out-String }

    $Result.Value.Raw["PDC_w32tm_status"]        = $status
    $Result.Value.Raw["PDC_w32tm_configuration"] = $config
    $Result.Value.Raw["PDC_w32tm_source"]        = $source

    Add-Check -Result $Result -Name "Remote Query (WinRM)" -Status "PASS" -Detail "Captured w32tm status/config/source from $Pdc."
    return [PSCustomObject]@{ Status = $status; Config = $config; Source = $source }
  }
  catch {
    Add-Check -Result $Result -Name "Remote Query (WinRM)" -Status "FAIL" -Detail "Failed to capture w32tm outputs from $Pdc. Error: $($_.Exception.Message)"
    throw
  }
}

function Parse-W32tmStatus {
  param([Parameter(Mandatory)][string]$StatusText)

  $obj = [ordered]@{
    LeapIndicator          = $null
    Stratum                = $null
    ReferenceId            = $null
    RootDelay              = $null
    RootDispersion         = $null
    LastSuccessfulSyncTime = $null
    Source                 = $null
    PollInterval           = $null
  }

  foreach ($line in ($StatusText -split "`r?`n")) {
    if ($line -match "^\s*Leap Indicator:\s*(.+)$") { $obj.LeapIndicator = $Matches[1].Trim() }
    elseif ($line -match "^\s*Stratum:\s*(.+)$") { $obj.Stratum = $Matches[1].Trim() }
    elseif ($line -match "^\s*ReferenceId:\s*(.+)$") { $obj.ReferenceId = $Matches[1].Trim() }
    elseif ($line -match "^\s*Root Delay:\s*(.+)$") { $obj.RootDelay = $Matches[1].Trim() }
    elseif ($line -match "^\s*Root Dispersion:\s*(.+)$") { $obj.RootDispersion = $Matches[1].Trim() }
    elseif ($line -match "^\s*Last Successful Sync Time:\s*(.+)$") { $obj.LastSuccessfulSyncTime = $Matches[1].Trim() }
    elseif ($line -match "^\s*Source:\s*(.+)$") { $obj.Source = $Matches[1].Trim() }
    elseif ($line -match "^\s*Poll Interval:\s*(.+)$") { $obj.PollInterval = $Matches[1].Trim() }
  }

  [PSCustomObject]$obj
}

function Parse-W32tmConfigKeyLines {
  param([Parameter(Mandatory)][string]$ConfigText)

  # Minimal parse: look for NtpClient Type and NtpServer line
  $typeLine = ($ConfigText -split "`r?`n" | Where-Object { $_ -match "^\s*Type:\s*" } | Select-Object -First 1)
  $ntpLine  = ($ConfigText -split "`r?`n" | Where-Object { $_ -match "^\s*NtpServer:\s*" } | Select-Object -First 1)

  [PSCustomObject]@{
    NtpClientType = if ($typeLine) { ($typeLine -replace "^\s*Type:\s*", "").Trim() } else { $null }
    NtpServerLine = if ($ntpLine) { ($ntpLine -replace "^\s*NtpServer:\s*", "").Trim() } else { $null }
  }
}

function Evaluate-PdcTimeSignals {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Pdc,
    [Parameter(Mandatory)]$W32
  )

  $parsed = Parse-W32tmStatus -StatusText $W32.Status
  $cfg    = Parse-W32tmConfigKeyLines -ConfigText $W32.Config

  $Result.Value.Raw["PDC_status_parsed"] = $parsed
  $Result.Value.Raw["PDC_config_keylines"] = $cfg

  if (-not $parsed.Source) {
    Add-Check -Result $Result -Name "PDC Time Source" -Status "FAIL" -Detail "Could not parse time source from w32tm /query /status."
  } else {
    Add-Check -Result $Result -Name "PDC Time Source" -Status "PASS" -Detail "PDC reports time source: $($parsed.Source)"
  }

  # Flag risky sources
  if ($parsed.Source -match "VM IC Time Synchronization Provider") {
    Add-Check -Result $Result -Name "PDC Source Risk" -Status "FAIL" -Detail "PDC is syncing from Hypervisor integration (VM IC). This commonly causes domain-wide drift. Disable VM time sync for the DC VM and configure authoritative NTP."
  }
  elseif ($parsed.Source -match "Local CMOS Clock") {
    Add-Check -Result $Result -Name "PDC Source Risk" -Status "WARN" -Detail "PDC is using Local CMOS Clock. This is not authoritative and will drift over time. Configure external NTP for the PDC."
  }
  else {
    Add-Check -Result $Result -Name "PDC Source Risk" -Status "PASS" -Detail "PDC time source is not a known high-risk source (VM IC/Local CMOS)."
  }

  # Leap Indicator sanity
  if ($parsed.LeapIndicator -match "not synchronized") {
    Add-Check -Result $Result -Name "PDC Synchronization State" -Status "FAIL" -Detail "Leap Indicator reports NOT synchronized. Domain time authority is unhealthy."
  } else {
    Add-Check -Result $Result -Name "PDC Synchronization State" -Status "PASS" -Detail "Leap Indicator does not indicate 'not synchronized'."
  }

  # NtpClient Type visibility
  if ($cfg.NtpClientType) {
    # Type line may include "(Policy)" or "(Local)" depending on source text
    if ($cfg.NtpClientType -match "NT5DS" -and $cfg.NtpClientType -match "Policy") {
      Add-Check -Result $Result -Name "PDC NtpClient Type (Policy)" -Status "WARN" -Detail "NtpClient Type is enforced as NT5DS by Policy. For PDC authoritative NTP, ensure GPO allows Type=NTP on the PDC and remove conflicting time policies."
    }
    elseif ($cfg.NtpClientType -match "NTP" -and $cfg.NtpClientType -match "Policy") {
      Add-Check -Result $Result -Name "PDC NtpClient Type (Policy)" -Status "PASS" -Detail "NtpClient Type is enforced as NTP by Policy (expected for PDC authoritative NTP configuration)."
    }
    else {
      Add-Check -Result $Result -Name "PDC NtpClient Type" -Status "PASS" -Detail "NtpClient Type observed: $($cfg.NtpClientType)"
    }
  } else {
    Add-Check -Result $Result -Name "PDC NtpClient Type" -Status "WARN" -Detail "Could not parse NtpClient Type from configuration output."
  }

  if ($cfg.NtpServerLine) {
    Add-Check -Result $Result -Name "PDC NtpServer (configured peers)" -Status "PASS" -Detail "NtpServer line: $($cfg.NtpServerLine)"
  } else {
    Add-Check -Result $Result -Name "PDC NtpServer (configured peers)" -Status "WARN" -Detail "No NtpServer line parsed. If authoritative NTP is expected, configure peers via GPO or w32tm /config."
  }
}

function Test-PdcExternalNtpStripchart {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Pdc,
    [Parameter(Mandatory)][string[]]$Targets,
    [Parameter(Mandatory)][int]$Samples
  )

  $tests = @()

  foreach ($t in $Targets) {
    $entry = [ordered]@{
      Target        = $t
      Success       = $false
      SampleCount   = $Samples
      Offsets       = @()
      Raw           = $null
      Error         = $null
    }

    try {
      $raw = Invoke-Pdc -Pdc $Pdc -ScriptBlock {
        param($target, $samples)
        w32tm /stripchart /computer:$target /dataonly /samples:$samples 2>&1 | Out-String
      } -ArgumentList @($t, $Samples)

      $entry.Raw = $raw

      $offsets = @()
      foreach ($line in ($raw -split "`r?`n")) {
        # Example: 10:54:05, +00.0050058s
        if ($line -match "^\s*\d{1,2}:\d{2}:\d{2},\s*([+\-]\d+(\.\d+)?)s") {
          $offsets += [double]$Matches[1]
        }
      }

      $entry.Offsets = $offsets
      if ($offsets.Count -gt 0) {
        $entry.Success = $true
      }
    }
    catch {
      $entry.Error = $_.Exception.Message
    }

    $tests += [PSCustomObject]$entry
  }

  $Result.Value.Raw["PDC_stripchart_tests"] = $tests

  $failed = $tests | Where-Object { -not $_.Success }
  if ($failed -and $failed.Count -gt 0) {
    Add-Check -Result $Result -Name "External NTP Reachability (UDP/123)" -Status "WARN" -Detail ("One or more stripchart tests returned no offsets: " + (($failed | Select-Object -ExpandProperty Target) -join ", ") + ". If PDC cannot sync, verify outbound UDP/123 and NTP target accessibility.")
  } else {
    Add-Check -Result $Result -Name "External NTP Reachability (UDP/123)" -Status "PASS" -Detail "Stripchart returned offsets for all configured NTP targets (UDP/123 reachable)."
  }
}

function Get-PdcTimeEvents {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Pdc,
    [Parameter(Mandatory)][int]$Hours
  )

  $since = (Get-Date).AddHours(-1 * $Hours)

  try {
    $events = Invoke-Pdc -Pdc $Pdc -ScriptBlock {
      param($start)
      $filter = @{
        LogName   = "System"
        StartTime = $start
      }

      Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
        Where-Object {
          $_.ProviderName -in @("Microsoft-Windows-Time-Service","W32Time") -or
          $_.Message -match "(w32time|NTP|time service|clock|skew|synchron)"
        } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 200
    } -ArgumentList @($since)

    $Result.Value.Raw["PDC_time_events_last_${Hours}h"] = $events

    if (-not $events -or $events.Count -eq 0) {
      Add-Check -Result $Result -Name "Recent Time Events" -Status "PASS" -Detail "No obvious time-service related System events found on $Pdc in the last $Hours hours."
      return
    }

    $bad = $events | Where-Object { $_.LevelDisplayName -in @("Error","Warning") }
    if ($bad -and $bad.Count -gt 0) {
      Add-Check -Result $Result -Name "Recent Time Events" -Status "WARN" -Detail "Found $($bad.Count) warning/error time-related System events on $Pdc in the last $Hours hours. Review JSON report for details."
    } else {
      Add-Check -Result $Result -Name "Recent Time Events" -Status "WARN" -Detail "Found time-related System events on $Pdc in the last $Hours hours. Review JSON report for context."
    }
  }
  catch {
    Add-Check -Result $Result -Name "Recent Time Events" -Status "WARN" -Detail "Could not query System events on $Pdc. Error: $($_.Exception.Message)"
  }
}

function Build-Summary {
  param([Parameter(Mandatory)][ref]$Result)

  $failCount = @($Result.Value.Checks | Where-Object { $_.Status -eq "FAIL" }).Count
  $warnCount = @($Result.Value.Checks | Where-Object { $_.Status -eq "WARN" }).Count
  $passCount = @($Result.Value.Checks | Where-Object { $_.Status -eq "PASS" }).Count

  $overall =
    if ($failCount -gt 0) { "FAIL" }
    elseif ($warnCount -gt 0) { "WARN" }
    else { "PASS" }

  $Result.Value.Summary = [PSCustomObject]@{
    Overall   = $overall
    PassCount = $passCount
    WarnCount = $warnCount
    FailCount = $failCount
  }
}

function Write-Reports {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$OutPath
  )

  $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $jsonPath  = Join-Path $OutPath ("DomainTimeDiag_{0}.json" -f $timestamp)
  $txtPath   = Join-Path $OutPath ("DomainTimeDiag_{0}.txt" -f $timestamp)

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("Domain Time Diagnostics")
  $lines.Add("Generated: $($Result.Value.GeneratedLocal)")
  $lines.Add("Domain   : $($Result.Value.Domain)")
  $lines.Add("PDC      : $($Result.Value.PdcEmulator)")
  $lines.Add("")
  $lines.Add(("Summary  : {0} | PASS={1} WARN={2} FAIL={3}" -f $Result.Value.Summary.Overall, $Result.Value.Summary.PassCount, $Result.Value.Summary.WarnCount, $Result.Value.Summary.FailCount))
  $lines.Add("")
  $lines.Add("Checks:")
  foreach ($c in $Result.Value.Checks) {
    $lines.Add((" - [{0}] {1}: {2}" -f $c.Status, $c.Name, $c.Detail))
  }
  $lines.Add("")
  $lines.Add("Raw sections included in JSON report:")
  foreach ($k in $Result.Value.Raw.Keys) { $lines.Add(" - $k") }

  $lines | Out-File -FilePath $txtPath -Encoding utf8
  $Result.Value | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8

  return [PSCustomObject]@{
    TextPath = $txtPath
    JsonPath = $jsonPath
  }
}

# ------------------------- Main -------------------------

$result = New-ResultObject
$resultRef = [ref]$result

Write-Section "AD Domain Time Diagnostics"

Resolve-DomainAndPdc -Result $resultRef
$pdc = $result.PdcEmulator

Write-Host "Domain      : $($result.Domain)"
Write-Host "PDC Emulator : $pdc"

Write-Section "Check 1: W32Time Service (PDC)"
Get-PdcW32TimeService -Result $resultRef -Pdc $pdc

Write-Section "Check 2: w32tm Status / Configuration (PDC)"
$w32 = Get-PdcW32tmOutputs -Result $resultRef -Pdc $pdc
Evaluate-PdcTimeSignals -Result $resultRef -Pdc $pdc -W32 $w32

Write-Section "Check 3: External NTP Reachability (Stripchart from PDC)"
Test-PdcExternalNtpStripchart -Result $resultRef -Pdc $pdc -Targets $NtpTargets -Samples $StripchartSamples

Write-Section "Check 4: Recent Time-Related Events (PDC)"
Get-PdcTimeEvents -Result $resultRef -Pdc $pdc -Hours $EventHours

Build-Summary -Result $resultRef

$fullOut = Ensure-OutDir -Path $OutDir
$paths = Write-Reports -Result $resultRef -OutPath $fullOut

Write-Section "Result"
Write-Host ("Overall: {0} (PASS={1} WARN={2} FAIL={3})" -f $result.Summary.Overall, $result.Summary.PassCount, $result.Summary.WarnCount, $result.Summary.FailCount)
Write-Host "Text report: $($paths.TextPath)"
Write-Host "JSON report: $($paths.JsonPath)"

Write-Host ""
Write-Host "Interpretation Guidance:"
Write-Host " - If the PDC shows VM IC or Local CMOS as its source, fix server-side time authority before touching endpoints."
Write-Host " - If external NTP stripchart works but PDC still won't sync to NTP, investigate GPO precedence/RSOP forcing NT5DS."
Write-Host " - If the PDC is healthy, remaining issues are likely endpoint-specific (sleep/hibernation, CMOS battery, VPN reachability, service disabled)."
