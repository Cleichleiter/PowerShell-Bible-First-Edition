<#
.SYNOPSIS
  Verifies Active Directory domain time health after remediation.

.DESCRIPTION
  Read-only verification script to confirm that the domain time hierarchy is operating correctly.

  Focus:
    - PDC Emulator is sourcing time from an external authoritative NTP source (not VM IC / not Local CMOS)
    - PDC reports a healthy synchronization state (Leap Indicator not "not synchronized")
    - Optional: verify other DCs are syncing from the PDC (or at least not drifting)
    - Optional: check a list of endpoints for time source and offsets

  Outputs:
    - Console summary with PASS/WARN/FAIL checks
    - Detailed JSON + TXT report saved to OutDir

  Notes:
    - UDP/123 reachability cannot be fully validated by Test-NetConnection (UDP), so w32tm /stripchart is used.
    - If RSOP/GPO still enforces NT5DS or conflicting settings, PDC may revert. Investigate precedence via rsop.msc.

.REQUIREMENTS
  - Domain-joined workstation/server
  - ActiveDirectory module (RSAT) recommended (auto-discovers PDC and DC list)
  - WinRM access to DCs (Invoke-Command)
  - Rights to query services and run w32tm on DCs

.PARAMETER OutDir
  Output directory for report artifacts.

.PARAMETER EventHours
  How many hours back to pull time-related events from the PDC (System log).

.PARAMETER StripchartSamples
  Number of samples used for stripchart verification.

.PARAMETER NtpTargets
  External NTP targets for stripchart verification (from PDC).

.PARAMETER CheckAllDCs
  If specified, queries all domain controllers for their time source and status.

.PARAMETER EndpointComputerNames
  Optional list of endpoints to query for time source and w32time status (best-effort).

.EXAMPLE
  .\Verify-DomainTimeHealth.ps1

.EXAMPLE
  .\Verify-DomainTimeHealth.ps1 -CheckAllDCs -EventHours 48

.EXAMPLE
  .\Verify-DomainTimeHealth.ps1 -EndpointComputerNames @("PC-01","PC-02") -CheckAllDCs
#>

[CmdletBinding()]
param(
  [string]$OutDir = ".\Time-Verification",
  [int]$EventHours = 24,
  [int]$StripchartSamples = 5,
  [string[]]$NtpTargets = @("time.windows.com", "pool.ntp.org"),
  [switch]$CheckAllDCs,
  [string[]]$EndpointComputerNames = @()
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

function New-ResultObject {
  [PSCustomObject]@{
    GeneratedLocal = (Get-Date).ToString("s")
    Domain         = $null
    PdcEmulator    = $null
    DomainControllers = @()
    Checks         = @()
    Summary        = $null
    Raw            = [ordered]@{}
  }
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

function Ensure-OutDir {
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
  (Resolve-Path -Path $Path).Path
}

function Ensure-ADModule {
  if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory PowerShell module not found. Install RSAT AD module or run from a server with AD tools."
  }
  Import-Module ActiveDirectory -ErrorAction Stop
}

function Invoke-Remote {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][scriptblock]$ScriptBlock,
    [object[]]$ArgumentList = @()
  )
  Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

function Resolve-DomainInfo {
  param([Parameter(Mandatory)][ref]$Result)

  Ensure-ADModule

  $domain = (Get-ADDomain).DNSRoot
  $pdc    = (Get-ADDomain).PDCEmulator

  $dcs = @()
  try {
    $dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
  } catch {
    # Non-fatal, we can still verify PDC.
    $dcs = @()
  }

  $Result.Value.Domain = $domain
  $Result.Value.PdcEmulator = $pdc
  $Result.Value.DomainControllers = $dcs

  Add-Check -Result $Result -Name "AD Discovery" -Status "PASS" -Detail "Domain: $domain | PDC Emulator: $pdc | DCs: $($dcs.Count)"
}

function Get-W32tmBundle {
  param([Parameter(Mandatory)][string]$ComputerName)

  Invoke-Remote -ComputerName $ComputerName -ScriptBlock {
    $svc = Get-Service w32time | Select-Object Name, Status, StartType

    [PSCustomObject]@{
      ComputerName = $env:COMPUTERNAME
      Service      = $svc
      Source       = (w32tm /query /source 2>&1 | Out-String).Trim()
      StatusText   = (w32tm /query /status 2>&1 | Out-String)
      ConfigText   = (w32tm /query /configuration 2>&1 | Out-String)
    }
  }
}

function Parse-W32tmStatus {
  param([Parameter(Mandatory)][string]$StatusText)

  $obj = [ordered]@{
    LeapIndicator          = $null
    Stratum                = $null
    LastSuccessfulSyncTime = $null
    Source                 = $null
    ReferenceId            = $null
    RootDispersion         = $null
  }

  foreach ($line in ($StatusText -split "`r?`n")) {
    if ($line -match "^\s*Leap Indicator:\s*(.+)$") { $obj.LeapIndicator = $Matches[1].Trim() }
    elseif ($line -match "^\s*Stratum:\s*(.+)$") { $obj.Stratum = $Matches[1].Trim() }
    elseif ($line -match "^\s*Last Successful Sync Time:\s*(.+)$") { $obj.LastSuccessfulSyncTime = $Matches[1].Trim() }
    elseif ($line -match "^\s*Source:\s*(.+)$") { $obj.Source = $Matches[1].Trim() }
    elseif ($line -match "^\s*ReferenceId:\s*(.+)$") { $obj.ReferenceId = $Matches[1].Trim() }
    elseif ($line -match "^\s*Root Dispersion:\s*(.+)$") { $obj.RootDispersion = $Matches[1].Trim() }
  }

  [PSCustomObject]$obj
}

function Stripchart-Test {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][int]$Samples
  )

  Invoke-Remote -ComputerName $ComputerName -ScriptBlock {
    param($t, $s)
    w32tm /stripchart /computer:$t /dataonly /samples:$s 2>&1 | Out-String
  } -ArgumentList @($Target, $Samples)
}

function Get-RecentTimeEvents {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][int]$Hours
  )

  $since = (Get-Date).AddHours(-1 * $Hours)

  Invoke-Remote -ComputerName $ComputerName -ScriptBlock {
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
}

function Evaluate-PdcHealth {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string]$Pdc
  )

  $bundle = Get-W32tmBundle -ComputerName $Pdc
  $parsed = Parse-W32tmStatus -StatusText $bundle.StatusText

  $Result.Value.Raw["PDC_bundle"] = $bundle
  $Result.Value.Raw["PDC_status_parsed"] = $parsed

  if ($bundle.Service.Status -eq "Running") {
    Add-Check -Result $Result -Name "PDC W32Time Service" -Status "PASS" -Detail "W32Time is Running (StartType: $($bundle.Service.StartType))."
  } else {
    Add-Check -Result $Result -Name "PDC W32Time Service" -Status "FAIL" -Detail "W32Time is NOT running (Status: $($bundle.Service.Status), StartType: $($bundle.Service.StartType))."
  }

  if ($parsed.Source) {
    Add-Check -Result $Result -Name "PDC Time Source" -Status "PASS" -Detail "Source: $($parsed.Source)"
  } else {
    Add-Check -Result $Result -Name "PDC Time Source" -Status "FAIL" -Detail "Unable to parse Source from w32tm /query /status."
  }

  # Risk sources
  if ($parsed.Source -match "VM IC Time Synchronization Provider") {
    Add-Check -Result $Result -Name "PDC Source Risk" -Status "FAIL" -Detail "PDC is syncing from VM IC Time Synchronization Provider (hypervisor). Disable VM time sync and configure authoritative NTP."
  }
  elseif ($parsed.Source -match "Local CMOS Clock") {
    Add-Check -Result $Result -Name "PDC Source Risk" -Status "FAIL" -Detail "PDC is using Local CMOS Clock. Configure authoritative external NTP and verify GPO precedence."
  }
  else {
    Add-Check -Result $Result -Name "PDC Source Risk" -Status "PASS" -Detail "PDC source is not a high-risk source (VM IC/Local CMOS)."
  }

  if ($parsed.LeapIndicator -match "not synchronized") {
    Add-Check -Result $Result -Name "PDC Synchronization State" -Status "FAIL" -Detail "Leap Indicator reports NOT synchronized."
  } else {
    Add-Check -Result $Result -Name "PDC Synchronization State" -Status "PASS" -Detail "Leap Indicator: $($parsed.LeapIndicator)"
  }

  # Stratum sanity
  if ($parsed.Stratum) {
    $s = $null
    if ([int]::TryParse(($parsed.Stratum -replace "[^\d]",""), [ref]$s)) {
      if ($s -ge 1 -and $s -le 5) {
        Add-Check -Result $Result -Name "PDC Stratum" -Status "PASS" -Detail "Stratum appears normal: $s"
      }
      elseif ($s -ge 6 -and $s -le 10) {
        Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Stratum is elevated ($s). Could indicate indirect sync or degraded upstream."
      }
      else {
        Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Stratum is unusual ($s). Investigate upstream time sync."
      }
    } else {
      Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Could not parse Stratum numeric value."
    }
  } else {
    Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Could not parse Stratum."
  }

  # External NTP reachability from PDC
  $stripResults = @()
  foreach ($t in $NtpTargets) {
    $raw = $null
    $ok = $false
    $offsets = @()

    try {
      $raw = Stripchart-Test -ComputerName $Pdc -Target $t -Samples $StripchartSamples
      foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match "^\s*\d{1,2}:\d{2}:\d{2},\s*([+\-]\d+(\.\d+)?)s") {
          $offsets += [double]$Matches[1]
        }
      }
      if ($offsets.Count -gt 0) { $ok = $true }
    } catch {
      $raw = "ERROR: $($_.Exception.Message)"
    }

    $stripResults += [PSCustomObject]@{
      Target  = $t
      Success = $ok
      Offsets = $offsets
      Raw     = $raw
    }
  }

  $Result.Value.Raw["PDC_stripchart"] = $stripResults

  $failed = @($stripResults | Where-Object { -not $_.Success })
  if ($failed.Count -gt 0) {
    Add-Check -Result $Result -Name "PDC External NTP Reachability" -Status "WARN" -Detail ("One or more NTP targets did not return offsets: " + (($failed | Select-Object -ExpandProperty Target) -join ", "))
  } else {
    Add-Check -Result $Result -Name "PDC External NTP Reachability" -Status "PASS" -Detail "All configured NTP targets returned stripchart offsets from the PDC."
  }

  # Recent events (best-effort)
  try {
    $events = Get-RecentTimeEvents -ComputerName $Pdc -Hours $EventHours
    $Result.Value.Raw["PDC_time_events_last_${EventHours}h"] = $events

    $bad = @($events | Where-Object { $_.LevelDisplayName -in @("Error","Warning") })
    if ($bad.Count -gt 0) {
      Add-Check -Result $Result -Name "PDC Recent Time Events" -Status "WARN" -Detail "Found $($bad.Count) warning/error time-related System events on the PDC in last $EventHours hours."
    } else {
      Add-Check -Result $Result -Name "PDC Recent Time Events" -Status "PASS" -Detail "No warning/error time-related System events on the PDC in last $EventHours hours."
    }
  }
  catch {
    Add-Check -Result $Result -Name "PDC Recent Time Events" -Status "WARN" -Detail "Could not query System events on the PDC. Error: $($_.Exception.Message)"
  }
}

function Evaluate-OtherDcs {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string[]]$Dcs,
    [Parameter(Mandatory)][string]$Pdc
  )

  $rows = @()

  foreach ($dc in $Dcs) {
    if (-not $dc) { continue }

    try {
      $bundle = Get-W32tmBundle -ComputerName $dc
      $parsed = Parse-W32tmStatus -StatusText $bundle.StatusText

      $rows += [PSCustomObject]@{
        ComputerName  = $dc
        ServiceStatus = $bundle.Service.Status
        Source        = $parsed.Source
        LeapIndicator = $parsed.LeapIndicator
        Stratum       = $parsed.Stratum
        LastSync      = $parsed.LastSuccessfulSyncTime
      }
    }
    catch {
      $rows += [PSCustomObject]@{
        ComputerName  = $dc
        ServiceStatus = "ERROR"
        Source        = $null
        LeapIndicator = $null
        Stratum       = $null
        LastSync      = $null
      }
    }
  }

  $Result.Value.Raw["DC_summary"] = $rows

  # Heuristic: other DCs should not be on Local CMOS / VM IC
  $bad = @($rows | Where-Object { $_.ServiceStatus -ne "Running" -or $_.Source -match "Local CMOS Clock|VM IC Time Synchronization Provider" })
  if ($bad.Count -gt 0) {
    Add-Check -Result $Result -Name "Other DCs Time Health" -Status "WARN" -Detail "One or more DCs show unhealthy source or service state. Review DC_summary in JSON report."
  } else {
    Add-Check -Result $Result -Name "Other DCs Time Health" -Status "PASS" -Detail "All queried DCs show running W32Time and no obvious high-risk time sources."
  }

  # If multiple DCs present, also check if they appear to follow domain hierarchy (often source is the PDC/another DC)
  $pdcFollowers = @($rows | Where-Object { $_.ComputerName -ne $Pdc -and $_.Source -match [regex]::Escape($Pdc.Split(".")[0]) })
  if ($rows.Count -gt 1 -and $pdcFollowers.Count -gt 0) {
    Add-Check -Result $Result -Name "DCs Following PDC (heuristic)" -Status "PASS" -Detail "At least one DC reports a source that appears to reference the PDC (heuristic check)."
  } elseif ($rows.Count -gt 1) {
    Add-Check -Result $Result -Name "DCs Following PDC (heuristic)" -Status "WARN" -Detail "DC sources do not clearly reference the PDC by name. This may still be normal depending on topology; review DC_summary."
  }
}

function Evaluate-Endpoints {
  param(
    [Parameter(Mandatory)][ref]$Result,
    [Parameter(Mandatory)][string[]]$ComputerNames
  )

  if (-not $ComputerNames -or $ComputerNames.Count -eq 0) {
    return
  }

  $rows = @()
  foreach ($c in $ComputerNames) {
    if (-not $c) { continue }

    try {
      $bundle = Get-W32tmBundle -ComputerName $c
      $parsed = Parse-W32tmStatus -StatusText $bundle.StatusText

      $rows += [PSCustomObject]@{
        ComputerName  = $c
        ServiceStatus = $bundle.Service.Status
        Source        = $parsed.Source
        LeapIndicator = $parsed.LeapIndicator
        Stratum       = $parsed.Stratum
        LastSync      = $parsed.LastSuccessfulSyncTime
      }
    }
    catch {
      $rows += [PSCustomObject]@{
        ComputerName  = $c
        ServiceStatus = "ERROR"
        Source        = $null
        LeapIndicator = $null
        Stratum       = $null
        LastSync      = $null
      }
    }
  }

  $Result.Value.Raw["Endpoint_summary"] = $rows

  $bad = @($rows | Where-Object { $_.ServiceStatus -ne "Running" -or $_.Source -match "Local CMOS Clock|VM IC Time Synchronization Provider" })
  if ($bad.Count -gt 0) {
    Add-Check -Result $Result -Name "Endpoint Time Health (best-effort)" -Status "WARN" -Detail "One or more endpoints show unhealthy source/service state or could not be queried. Review Endpoint_summary in JSON report."
  } else {
    Add-Check -Result $Result -Name "Endpoint Time Health (best-effort)" -Status "PASS" -Detail "All queried endpoints show running W32Time and no obvious high-risk time sources."
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
  $jsonPath  = Join-Path $OutPath ("DomainTimeVerify_{0}.json" -f $timestamp)
  $txtPath   = Join-Path $OutPath ("DomainTimeVerify_{0}.txt" -f $timestamp)

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("Domain Time Verification")
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
  $Result.Value | ConvertTo-Json -Depth 12 | Out-File -FilePath $jsonPath -Encoding utf8

  return [PSCustomObject]@{
    TextPath = $txtPath
    JsonPath = $jsonPath
  }
}

# ------------------------- Main -------------------------

$result = New-ResultObject
$resultRef = [ref]$result

Write-Section "AD Domain Time Verification"

Resolve-DomainInfo -Result $resultRef
$pdc = $result.PdcEmulator

Write-Host "Domain      : $($result.Domain)"
Write-Host "PDC Emulator : $pdc"

Write-Section "Verify 1: PDC Health"
Evaluate-PdcHealth -Result $resultRef -Pdc $pdc

if ($CheckAllDCs -and $result.DomainControllers -and $result.DomainControllers.Count -gt 0) {
  Write-Section "Verify 2: Other Domain Controllers (best-effort)"
  Evaluate-OtherDcs -Result $resultRef -Dcs $result.DomainControllers -Pdc $pdc
} else {
  Add-Check -Result $resultRef -Name "Other DCs Time Health" -Status "WARN" -Detail "Skipped (use -CheckAllDCs to query all DCs)."
}

if ($EndpointComputerNames -and $EndpointComputerNames.Count -gt 0) {
  Write-Section "Verify 3: Endpoints (best-effort)"
  Evaluate-Endpoints -Result $resultRef -ComputerNames $EndpointComputerNames
} else {
  Add-Check -Result $resultRef -Name "Endpoint Time Health (best-effort)" -Status "WARN" -Detail "Skipped (no -EndpointComputerNames provided)."
}

Build-Summary -Result $resultRef

$fullOut = Ensure-OutDir -Path $OutDir
$paths = Write-Reports -Result $resultRef -OutPath $fullOut

Write-Section "Result"
Write-Host ("Overall: {0} (PASS={1} WARN={2} FAIL={3})" -f $result.Summary.Overall, $result.Summary.PassCount, $result.Summary.WarnCount, $result.Summary.FailCount)
Write-Host "Text report: $($paths.TextPath)"
Write-Host "JSON report: $($paths.JsonPath)"

Write-Host ""
Write-Host "Interpretation Guidance:"
Write-Host " - If the PDC source is external NTP (not VM IC / not Local CMOS) and Leap Indicator is healthy, the domain time authority is fixed."
Write-Host " - If endpoints still drift after PDC is healthy, treat as endpoint-specific (sleep/hibernation, CMOS battery, isolated VLAN/VPN, service disabled)."
Write-Host " - If the PDC reverts to Local CMOS or cannot resync, check RSOP/GPO precedence and confirm no conflicting time policies exist."
