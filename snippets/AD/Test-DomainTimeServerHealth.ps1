<#
.SYNOPSIS
  Checks whether the domain time source (server/DC) is likely the cause of multi-PC time drift.

.DESCRIPTION
  This script:
    - Detects the domain and the PDC Emulator (authoritative time source in AD)
    - Queries the PDC for W32Time status, configuration, source, and time offset
    - Checks whether the PDC is configured correctly (domain hierarchy vs manual NTP)
    - Optionally tests configured NTP peers for UDP/123 reachability (best-effort)
    - Pulls recent W32Time/System time-related events from the PDC
    - Provides a clear PASS/WARN/FAIL summary and writes a detailed report file

.NOTES
  Run from a domain-joined workstation/server with RSAT (ActiveDirectory module).
  Recommended: run as a domain admin or with rights to query the DC remotely.
  Does NOT make changes; read-only checks only.

.EXAMPLE
  .\Test-DomainTimeServerHealth.ps1

.EXAMPLE
  .\Test-DomainTimeServerHealth.ps1 -OutDir C:\Temp -EventHours 48 -AlsoCheckDC
#>

[CmdletBinding()]
param(
  [string]$OutDir = ".\TimeHealthReport",
  [int]$EventHours = 24,
  [switch]$AlsoCheckDC
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section([string]$Title) {
  Write-Host ""
  Write-Host ("=" * 80)
  Write-Host $Title
  Write-Host ("=" * 80)
}

function Ensure-Array {
  param([object]$InputObject)
  if ($null -eq $InputObject) { return @() }
  return @($InputObject)
}

function Get-Count {
  param([object]$InputObject)
  return (Ensure-Array $InputObject).Count
}

function New-ResultObject {
  [PSCustomObject]@{
    TimestampLocal = (Get-Date).ToString("s")
    Domain         = $null
    PdcEmulator    = $null
    Checks         = @()
    Summary        = $null
    Raw            = [ordered]@{}
  }
}

function Add-Check {
  param(
    [Parameter(Mandatory)]$Result,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet("PASS","WARN","FAIL")] [string]$Status,
    [Parameter(Mandatory)][string]$Detail
  )
  $Result.Checks += [PSCustomObject]@{
    Name   = $Name
    Status = $Status
    Detail = $Detail
  }
}

function Resolve-DomainAndPdc {
  param([Parameter(Mandatory)]$Result)

  try {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
      throw "ActiveDirectory PowerShell module not found. Install RSAT or run from a server with AD tools."
    }
    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = (Get-ADDomain).DNSRoot
    $pdc    = (Get-ADDomain).PDCEmulator

    $Result.Domain = $domain
    $Result.PdcEmulator = $pdc

    Add-Check -Result $Result -Name "AD Domain Discovery" -Status "PASS" -Detail "Domain: $domain | PDC Emulator: $pdc"
  }
  catch {
    Add-Check -Result $Result -Name "AD Domain Discovery" -Status "FAIL" -Detail $_.Exception.Message
    throw
  }
}

function Get-W32TimeStatus {
  param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Pdc)

  try {
    $statusText = Invoke-Command -ComputerName $Pdc -ScriptBlock { w32tm /query /status 2>&1 | Out-String } -ErrorAction Stop
    $configText = Invoke-Command -ComputerName $Pdc -ScriptBlock { w32tm /query /configuration 2>&1 | Out-String } -ErrorAction Stop
    $sourceText = Invoke-Command -ComputerName $Pdc -ScriptBlock { w32tm /query /source 2>&1 | Out-String } -ErrorAction Stop

    $Result.Raw["PDC_w32tm_status"] = $statusText
    $Result.Raw["PDC_w32tm_configuration"] = $configText
    $Result.Raw["PDC_w32tm_source"] = $sourceText

    Add-Check -Result $Result -Name "Remote Query (WinRM)" -Status "PASS" -Detail "Successfully queried w32tm status/config/source on $Pdc via WinRM."

    return [PSCustomObject]@{
      Status = $statusText
      Config = $configText
      Source = $sourceText
    }
  }
  catch {
    Add-Check -Result $Result -Name "Remote Query (WinRM)" -Status "FAIL" -Detail "Could not query $Pdc via WinRM. Error: $($_.Exception.Message). Enable WinRM or run this script locally on the DC/PDC."
    throw
  }
}

function Parse-W32tmStatus {
  param([string]$StatusText)

  $obj = [ordered]@{
    LeapIndicator          = $null
    Stratum                = $null
    Precision              = $null
    RootDelay              = $null
    RootDispersion         = $null
    ReferenceId            = $null
    LastSuccessfulSyncTime = $null
    Source                 = $null
    PollInterval           = $null
  }

  foreach ($line in ($StatusText -split "`r?`n")) {
    if ($line -match "^\s*Stratum:\s*(.+)$") { $obj.Stratum = $Matches[1].Trim() }
    elseif ($line -match "^\s*Last Successful Sync Time:\s*(.+)$") { $obj.LastSuccessfulSyncTime = $Matches[1].Trim() }
    elseif ($line -match "^\s*Source:\s*(.+)$") { $obj.Source = $Matches[1].Trim() }
    elseif ($line -match "^\s*Poll Interval:\s*(.+)$") { $obj.PollInterval = $Matches[1].Trim() }
    elseif ($line -match "^\s*ReferenceId:\s*(.+)$") { $obj.ReferenceId = $Matches[1].Trim() }
    elseif ($line -match "^\s*Root Delay:\s*(.+)$") { $obj.RootDelay = $Matches[1].Trim() }
    elseif ($line -match "^\s*Root Dispersion:\s*(.+)$") { $obj.RootDispersion = $Matches[1].Trim() }
    elseif ($line -match "^\s*Leap Indicator:\s*(.+)$") { $obj.LeapIndicator = $Matches[1].Trim() }
    elseif ($line -match "^\s*Precision:\s*(.+)$") { $obj.Precision = $Matches[1].Trim() }
  }

  [PSCustomObject]$obj
}

function Parse-W32tmConfigPeers {
  param([string]$ConfigText)

  $ntpServerLine = ($ConfigText -split "`r?`n" | Where-Object { $_ -match "^\s*NtpServer:\s*" } | Select-Object -First 1)
  if (-not $ntpServerLine) { return @() }

  $raw = ($ntpServerLine -replace "^\s*NtpServer:\s*", "").Trim()
  if (-not $raw) { return @() }

  $tokens = @()
  foreach ($p in ($raw -split "\s+")) {
    if ($p) { $tokens += ($p -split ",") }
  }

  $peers = @()
  foreach ($t0 in $tokens) {
    $t = $t0.Trim()
    if (-not $t) { continue }
    if ($t -match "^0x[0-9A-Fa-f]+$") { continue }
    $t = ($t -split ",")[0].Trim()
    if ($t) { $peers += $t }
  }

  @($peers | Select-Object -Unique)
}

function Test-Udp123BestEffort {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string[]]$Peers
  )

  $results = @()

  foreach ($peer in $Peers) {
    $res = [ordered]@{
      Peer          = $peer
      DnsResolved   = $false
      DnsTargets    = @()
      StripchartOk  = $false
      StripchartRaw = $null
      Error         = $null
    }

    try {
      $dns = Resolve-DnsName -Name $peer -ErrorAction Stop
      $ips = $dns | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress -Unique
      if ($ips) {
        $res.DnsResolved = $true
        $res.DnsTargets  = @($ips)
      }
    } catch {
      $res.Error = "DNS resolve failed: $($_.Exception.Message)"
    }

    try {
      $raw = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        param($p)
        w32tm /stripchart /computer:$p /dataonly /samples:2 2>&1 | Out-String
      } -ArgumentList $peer -ErrorAction Stop

      $res.StripchartRaw = $raw
      if ($raw -match "^\s*\d+") { $res.StripchartOk = $true }
      elseif ($raw -match "The computer did not respond") { $res.StripchartOk = $false }
    } catch {
      $res.Error = ("Stripchart failed: " + $_.Exception.Message)
    }

    $results += [PSCustomObject]$res
  }

  $results
}

function Get-PdcTimeOffset {
  param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Pdc)

  try {
    $monitorText = w32tm /monitor /computers:$Pdc 2>&1 | Out-String
    $Result.Raw["PDC_w32tm_monitor_from_runner"] = $monitorText

    $offsetLine = ($monitorText -split "`r?`n" | Where-Object { $_ -match "offset:" } | Select-Object -First 1)
    $offsetSeconds = $null
    if ($offsetLine -match "offset:\s*([+\-]?\d+(\.\d+)?)s") {
      $offsetSeconds = [double]$Matches[1]
    }

    if ($null -eq $offsetSeconds) {
      Add-Check -Result $Result -Name "PDC Offset (from runner)" -Status "WARN" -Detail "Could not parse offset from w32tm /monitor output. See raw output in report."
      return $null
    }

    $abs = [math]::Abs($offsetSeconds)

    if ($abs -le 1) {
      Add-Check -Result $Result -Name "PDC Offset (from runner)" -Status "PASS" -Detail ("Offset is {0:N3}s (within 1s)" -f $offsetSeconds)
    }
    elseif ($abs -le 10) {
      Add-Check -Result $Result -Name "PDC Offset (from runner)" -Status "WARN" -Detail ("Offset is {0:N3}s (over 1s). Monitor drift and verify upstream NTP." -f $offsetSeconds)
    }
    elseif ($abs -le 300) {
      Add-Check -Result $Result -Name "PDC Offset (from runner)" -Status "FAIL" -Detail ("Offset is {0:N3}s (over 10s). Likely time source issue impacting domain clients." -f $offsetSeconds)
    }
    else {
      Add-Check -Result $Result -Name "PDC Offset (from runner)" -Status "FAIL" -Detail ("Offset is {0:N3}s (over 5 minutes). High risk: Kerberos/auth/certs/log correlation issues." -f $offsetSeconds)
    }

    return $offsetSeconds
  }
  catch {
    Add-Check -Result $Result -Name "PDC Offset (from runner)" -Status "FAIL" -Detail "Failed to query offset via w32tm /monitor. Error: $($_.Exception.Message)"
    return $null
  }
}

function Get-TimeServiceHealthOnPdc {
  param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Pdc)

  try {
    $svc = Invoke-Command -ComputerName $Pdc -ScriptBlock { Get-Service -Name w32time | Select-Object Name, Status, StartType } -ErrorAction Stop
    $Result.Raw["PDC_w32time_service"] = $svc

    if ($svc.Status -ne "Running") {
      Add-Check -Result $Result -Name "W32Time Service" -Status "FAIL" -Detail "W32Time is not running on $Pdc (Status: $($svc.Status), StartType: $($svc.StartType))."
    }
    else {
      Add-Check -Result $Result -Name "W32Time Service" -Status "PASS" -Detail "W32Time is running on $Pdc (StartType: $($svc.StartType))."
    }
  }
  catch {
    Add-Check -Result $Result -Name "W32Time Service" -Status "FAIL" -Detail "Could not query W32Time service on $Pdc. Error: $($_.Exception.Message)"
  }
}

function Get-RecentTimeEventsOnPdc {
  param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Pdc, [Parameter(Mandatory)][int]$Hours)

  $since = (Get-Date).AddHours(-1 * $Hours)

  try {
    $events = Invoke-Command -ComputerName $Pdc -ScriptBlock {
      param($start)
      $filter = @{
        LogName   = "System"
        StartTime = $start
      }

      Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
        Where-Object {
          $_.ProviderName -in @("Microsoft-Windows-Time-Service","W32Time") -or
          $_.Message -match "(time|w32time|NTP|clock|skew|synchron)"
        } |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Sort-Object TimeCreated -Descending |
        Select-Object -First 200
    } -ArgumentList $since -ErrorAction Stop

    $Result.Raw["PDC_time_events_last_${Hours}h"] = $events

    if (Get-Count $events -eq 0) {
      Add-Check -Result $Result -Name "Recent Time Events" -Status "PASS" -Detail "No obvious time-service related System events found on $Pdc in the last $Hours hours."
      return
    }

    $bad = @($events | Where-Object { $_.LevelDisplayName -in @("Error","Warning") })
    if (Get-Count $bad -gt 0) {
      Add-Check -Result $Result -Name "Recent Time Events" -Status "WARN" -Detail "Found $(Get-Count $bad) warning/error time-related System events on $Pdc in the last $Hours hours. Review report for details."
    } else {
      Add-Check -Result $Result -Name "Recent Time Events" -Status "WARN" -Detail "Found time-related System events on $Pdc in the last $Hours hours. Review report for context."
    }
  }
  catch {
    Add-Check -Result $Result -Name "Recent Time Events" -Status "WARN" -Detail "Could not query System events on $Pdc. Error: $($_.Exception.Message)"
  }
}

function Evaluate-PdcConfig {
  param(
    [Parameter(Mandatory)]$Result,
    [Parameter(Mandatory)][string]$Pdc,
    [Parameter(Mandatory)]$W32tm
  )

  $statusParsed = Parse-W32tmStatus -StatusText $W32tm.Status
  $peers = Ensure-Array (Parse-W32tmConfigPeers -ConfigText $W32tm.Config)

  $Result.Raw["PDC_status_parsed"] = $statusParsed
  $Result.Raw["PDC_config_peers"]  = $peers

  if (-not $statusParsed.Source) {
    Add-Check -Result $Result -Name "PDC Time Source" -Status "FAIL" -Detail "Could not determine time source from w32tm /query /status."
  }
  else {
    Add-Check -Result $Result -Name "PDC Time Source" -Status "PASS" -Detail "PDC reports time source as: $($statusParsed.Source)"
  }

  if ($statusParsed.Stratum) {
    $s = $null
    if ([int]::TryParse(($statusParsed.Stratum -replace "[^\d]",""), [ref]$s)) {
      if ($s -ge 1 -and $s -le 5) {
        Add-Check -Result $Result -Name "PDC Stratum" -Status "PASS" -Detail "Stratum appears normal: $s"
      }
      elseif ($s -ge 6 -and $s -le 10) {
        Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Stratum is elevated ($s). Could indicate indirect sync or degraded upstream."
      }
      else {
        Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Stratum is unusual ($s). Investigate upstream time sync."
      }
    }
  } else {
    Add-Check -Result $Result -Name "PDC Stratum" -Status "WARN" -Detail "Could not parse Stratum from status output."
  }

  if ($statusParsed.LastSuccessfulSyncTime) {
    Add-Check -Result $Result -Name "PDC Last Sync Time" -Status "PASS" -Detail "Last Successful Sync Time: $($statusParsed.LastSuccessfulSyncTime)"
  } else {
    Add-Check -Result $Result -Name "PDC Last Sync Time" -Status "WARN" -Detail "Could not parse Last Successful Sync Time."
  }

  if (Get-Count $peers -gt 0) {
    Add-Check -Result $Result -Name "PDC NTP Peers" -Status "PASS" -Detail ("Configured NTP peers (from NtpServer): " + ($peers -join ", "))
  } else {
    Add-Check -Result $Result -Name "PDC NTP Peers" -Status "WARN" -Detail "No NTP peers parsed from PDC configuration. PDC may be using domain hierarchy or default config."
  }

  return $peers
}

function Optional-CheckDcHealth {
  param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$Pdc)

  try {
    $dcdiag = Invoke-Command -ComputerName $Pdc -ScriptBlock {
      dcdiag /test:Advertising /test:Services /test:Replications /test:SysVolCheck /test:KccEvent /test:NetLogons 2>&1 | Out-String
    } -ErrorAction Stop

    $Result.Raw["PDC_dcdiag_summary"] = $dcdiag

    if ($dcdiag -match "failed test" -or $dcdiag -match "Fail") {
      Add-Check -Result $Result -Name "DC Health (DCDIAG)" -Status "WARN" -Detail "DCDIAG shows potential failures. Review dcdiag output in report."
    } else {
      Add-Check -Result $Result -Name "DC Health (DCDIAG)" -Status "PASS" -Detail "Basic DCDIAG tests did not show obvious failures."
    }
  }
  catch {
    Add-Check -Result $Result -Name "DC Health (DCDIAG)" -Status "WARN" -Detail "Could not run DCDIAG on $Pdc. Error: $($_.Exception.Message)"
  }
}

function Build-Summary {
  param([Parameter(Mandatory)]$Result)

  $checks = Ensure-Array $Result.Checks
  $fails = (Ensure-Array ($checks | Where-Object { $_.Status -eq "FAIL" })).Count
  $warns = (Ensure-Array ($checks | Where-Object { $_.Status -eq "WARN" })).Count
  $pass  = (Ensure-Array ($checks | Where-Object { $_.Status -eq "PASS" })).Count

  $overall =
    if ($fails -gt 0) { "FAIL" }
    elseif ($warns -gt 0) { "WARN" }
    else { "PASS" }

  $Result.Summary = [PSCustomObject]@{
    Overall   = $overall
    FailCount = $fails
    WarnCount = $warns
    PassCount = $pass
  }

  $Result
}

# ------------------------- Main -------------------------

$result = New-ResultObject

Write-Section "Domain Time Source Health Check"

Resolve-DomainAndPdc -Result $result
$pdc = $result.PdcEmulator

Write-Host "Domain      : $($result.Domain)"
Write-Host "PDC Emulator : $pdc"

Write-Section "Check 1: W32Time Service (PDC)"
Get-TimeServiceHealthOnPdc -Result $result -Pdc $pdc

Write-Section "Check 2: Offset Between Runner and PDC"
$null = Get-PdcTimeOffset -Result $result -Pdc $pdc

Write-Section "Check 3: PDC w32tm Status / Configuration"
$w32 = Get-W32TimeStatus -Result $result -Pdc $pdc
$peers = Ensure-Array (Evaluate-PdcConfig -Result $result -Pdc $pdc -W32tm $w32)

Write-Section "Check 4: NTP Peer Reachability (Best-Effort)"
if (Get-Count $peers -gt 0) {
  $peerTests = Test-Udp123BestEffort -ComputerName $pdc -Peers $peers
  $result.Raw["PDC_peer_tests"] = $peerTests

  $badPeers = @($peerTests | Where-Object { -not $_.StripchartOk })
  if (Get-Count $badPeers -gt 0) {
    Add-Check -Result $result -Name "NTP Peer Stripchart" -Status "WARN" -Detail ("One or more NTP peers did not respond to stripchart from PDC: " + (($badPeers | Select-Object -ExpandProperty Peer) -join ", "))
  } else {
    Add-Check -Result $result -Name "NTP Peer Stripchart" -Status "PASS" -Detail "Configured NTP peers responded to stripchart from PDC (best-effort)."
  }
} else {
  Add-Check -Result $result -Name "NTP Peer Stripchart" -Status "WARN" -Detail "No NTP peers parsed to test. If environment expects manual NTP, confirm PDC NtpServer list."
}

Write-Section "Check 5: Recent Time-Related Events (PDC)"
Get-RecentTimeEventsOnPdc -Result $result -Pdc $pdc -Hours $EventHours

if ($AlsoCheckDC) {
  Write-Section "Optional: DC Health (DCDIAG subset)"
  Optional-CheckDcHealth -Result $result -Pdc $pdc
}

$result = Build-Summary -Result $result

$fullOutDir = (Resolve-Path -Path (New-Item -Path $OutDir -ItemType Directory -Force).FullName).Path

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$jsonPath = Join-Path $fullOutDir "TimeHealthReport_$timestamp.json"
$txtPath  = Join-Path $fullOutDir "TimeHealthReport_$timestamp.txt"

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("Domain Time Source Health Check")
$lines.Add("Generated: $(Get-Date -Format s)")
$lines.Add("Domain   : $($result.Domain)")
$lines.Add("PDC      : $($result.PdcEmulator)")
$lines.Add("")
$lines.Add("Summary  : $($result.Summary.Overall) | PASS=$($result.Summary.PassCount) WARN=$($result.Summary.WarnCount) FAIL=$($result.Summary.FailCount)")
$lines.Add("")
$lines.Add("Checks:")
foreach ($c in (Ensure-Array $result.Checks)) {
  $lines.Add((" - [{0}] {1}: {2}" -f $c.Status, $c.Name, $c.Detail))
}
$lines.Add("")
$lines.Add("Raw sections included in JSON report:")
foreach ($k in $result.Raw.Keys) { $lines.Add(" - $k") }

$lines | Out-File -FilePath $txtPath -Encoding utf8
$result | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding utf8

Write-Section "Result"
Write-Host ("Overall: {0} (PASS={1} WARN={2} FAIL={3})" -f $result.Summary.Overall, $result.Summary.PassCount, $result.Summary.WarnCount, $result.Summary.FailCount)
Write-Host "Text report: $txtPath"
Write-Host "JSON report: $jsonPath"
