<#
.SYNOPSIS
Summarizes user logon/logoff activity from the Security event log.

.DESCRIPTION
Queries the Security event log for logon and logoff events over a time window
and returns structured objects suitable for reporting and triage.

Default behavior focuses on interactive-style activity:
- 4624 (Logon) filtered to LogonType 2 (Interactive) and 10 (RemoteInteractive/RDP)
- 4634 (Logoff)
- 4647 (User initiated logoff)

Outputs per ComputerName:
- Total logons by type
- Distinct users observed
- Top users by logon count
- Most recent interactive logon time
- Optional sample events (latest N)

Notes / Caveats:
- Reading Security log requires appropriate rights (local admin or delegated event log read).
- Some environments log differently depending on audit policy.
- Domain controllers contain logons for the domain; member servers contain local/server activity.

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER Hours
If StartTime not specified, query window is now - Hours. Default 24.

.PARAMETER StartTime
Start of time window.

.PARAMETER EndTime
End of time window. Default: now.

.PARAMETER IncludeLogonTypes
Which logon types to include (default 2 and 10).
Common:
  2  = Interactive (console)
  3  = Network (file share, service access)
  4  = Batch
  5  = Service
  7  = Unlock
  8  = NetworkCleartext
  9  = NewCredentials
  10 = RemoteInteractive (RDP)
  11 = CachedInteractive

.PARAMETER IncludeLogoff
Include logoff event counts (4634, 4647). Default on.

.PARAMETER IncludeSamples
Include latest sample event rows for triage.

.PARAMETER SampleCount
How many sample events to include. Default 25.

.PARAMETER MaxEvents
Guardrail: max events to retrieve. Default 10000.

.PARAMETER ExcludeMachineAccounts
Exclude usernames ending with '$' from user counts/top users. Default on.

.EXAMPLE
.\Get-UserLoginActivity.ps1 | Format-Table -Auto

.EXAMPLE
# Last 6 hours, include RDP + console logons, include samples
.\Get-UserLoginActivity.ps1 -Hours 6 -IncludeSamples -SampleCount 20 | Format-List

.EXAMPLE
# Multi-host CSV summary
.\Get-UserLoginActivity.ps1 -ComputerName RDSH01,RDSH02 -Hours 24 |
  Export-Csv C:\Reports\UserLoginActivity.csv -NoTypeInformation

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution (permissions permitting).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateRange(1,8760)]
    [int]$Hours = 24,

    [Parameter()]
    [datetime]$StartTime,

    [Parameter()]
    [datetime]$EndTime = (Get-Date),

    [Parameter()]
    [ValidateRange(1,20)]
    [int[]]$IncludeLogonTypes = @(2,10),

    [Parameter()]
    [switch]$IncludeLogoff,

    [Parameter()]
    [switch]$IncludeSamples,

    [Parameter()]
    [ValidateRange(1,500)]
    [int]$SampleCount = 25,

    [Parameter()]
    [ValidateRange(1,200000)]
    [int]$MaxEvents = 10000,

    [Parameter()]
    [switch]$ExcludeMachineAccounts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-EventDataValue {
    param(
        [xml]$EventXml,
        [string]$Name
    )

    # EventData/Data nodes often look like: <Data Name="TargetUserName">bob</Data>
    try {
        $node = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($node -and $node.'#text') { return [string]$node.'#text' }
        return $null
    }
    catch {
        return $null
    }
}

function Get-UserLoginActivityLocal {
    param(
        [datetime]$StartTime,
        [datetime]$EndTime,
        [int[]]$IncludeLogonTypes,
        [bool]$IncludeLogoff,
        [bool]$IncludeSamples,
        [int]$SampleCount,
        [int]$MaxEvents,
        [bool]$ExcludeMachineAccounts
    )

    $now = Get-Date

    # Core event IDs
    $ids = if ($IncludeLogoff) { @(4624,4634,4647) } else { @(4624) }

    $filter = @{
        LogName   = 'Security'
        StartTime = $StartTime
        EndTime   = $EndTime
        Id        = $ids
    }

    $events = @()
    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
    }
    catch {
        return [PSCustomObject]@{
            Timestamp                 = $now
            ComputerName              = $env:COMPUTERNAME
            StartTime                 = $StartTime
            EndTime                   = $EndTime
            TotalEvents               = $null
            InteractiveLogons         = $null
            RemoteInteractiveLogons   = $null
            OtherLogons               = $null
            Logoffs                   = $null
            DistinctUsers             = $null
            TopUsers                  = $null
            MostRecentInteractiveLogon= $null
            SampleEvents              = $null
            Error                     = $_.Exception.Message
        }
    }

    $parsed = New-Object System.Collections.Generic.List[object]

    foreach ($e in @($events)) {
        $id = $e.Id
        $time = $e.TimeCreated
        $provider = $e.ProviderName

        $xml = $null
        try { $xml = [xml]$e.ToXml() } catch { $xml = $null }

        $user = $null
        $domain = $null
        $logonType = $null
        $ip = $null
        $workstation = $null

        if ($xml) {
            # For 4624, these fields exist:
            $user = Get-EventDataValue -EventXml $xml -Name 'TargetUserName'
            $domain = Get-EventDataValue -EventXml $xml -Name 'TargetDomainName'
            $logonType = Get-EventDataValue -EventXml $xml -Name 'LogonType'
            $ip = Get-EventDataValue -EventXml $xml -Name 'IpAddress'
            $workstation = Get-EventDataValue -EventXml $xml -Name 'WorkstationName'
        }

        $userNorm = $null
        if ($user) {
            $userNorm = if ($domain) { "$domain\$user" } else { $user }
        }

        # Optionally exclude machine accounts from user summaries
        if ($ExcludeMachineAccounts -and $user -and $user.EndsWith('$')) {
            # keep event but don't count toward users; flag later
        }

        $parsed.Add([PSCustomObject]@{
            TimeCreated     = $time
            EventId         = $id
            ProviderName    = $provider
            User            = $userNorm
            TargetUserName  = $user
            TargetDomain    = $domain
            LogonType       = if ($logonType) { [int]$logonType } else { $null }
            IpAddress       = $ip
            WorkstationName = $workstation
        })
    }

    # Filter to requested logon types for 4624 counts
    $logons = @($parsed | Where-Object { $_.EventId -eq 4624 -and $_.LogonType -in $IncludeLogonTypes })

    $interactiveCount = @($logons | Where-Object { $_.LogonType -eq 2 }).Count
    $rdpCount         = @($logons | Where-Object { $_.LogonType -eq 10 }).Count
    $otherCount       = @($parsed | Where-Object { $_.EventId -eq 4624 -and $_.LogonType -notin $IncludeLogonTypes }).Count

    $logoffCount = 0
    if ($IncludeLogoff) {
        $logoffCount = @($parsed | Where-Object { $_.EventId -in @(4634,4647) }).Count
    }

    # Distinct users (exclude machine accounts if requested)
    $userEvents = $logons
    if ($ExcludeMachineAccounts) {
        $userEvents = $userEvents | Where-Object { $_.TargetUserName -and -not $_.TargetUserName.EndsWith('$') }
    }

    $distinctUsers = @($userEvents | Where-Object { $_.User } | Select-Object -ExpandProperty User -Unique).Count

    $topUsers = $userEvents |
        Where-Object { $_.User } |
        Group-Object User |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object { "{0} ({1})" -f $_.Name, $_.Count } |
        -join '; '

    $mostRecentInteractive = $null
    $recent = $logons | Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($recent) { $mostRecentInteractive = $recent.TimeCreated }

    $samples = $null
    if ($IncludeSamples) {
        $samples = $parsed |
            Sort-Object TimeCreated -Descending |
            Select-Object -First $SampleCount |
            Select-Object TimeCreated,EventId,User,LogonType,IpAddress,WorkstationName
    }

    [PSCustomObject]@{
        Timestamp                  = $now
        ComputerName               = $env:COMPUTERNAME
        StartTime                  = $StartTime
        EndTime                    = $EndTime
        TotalEvents                = @($parsed).Count

        InteractiveLogons          = $interactiveCount
        RemoteInteractiveLogons    = $rdpCount
        OtherLogons                = $otherCount
        Logoffs                    = $logoffCount

        DistinctUsers              = $distinctUsers
        TopUsers                   = if ($topUsers) { $topUsers } else { $null }
        MostRecentInteractiveLogon = $mostRecentInteractive

        SampleEvents               = $samples
        Error                      = $null
    }
}

if (-not $PSBoundParameters.ContainsKey('StartTime')) {
    $StartTime = (Get-Date).AddHours(-$Hours)
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $results.Add((Get-UserLoginActivityLocal -StartTime $StartTime -EndTime $EndTime `
                -IncludeLogonTypes $IncludeLogonTypes -IncludeLogoff:$IncludeLogoff `
                -IncludeSamples:$IncludeSamples -SampleCount $SampleCount -MaxEvents $MaxEvents `
                -ExcludeMachineAccounts:$ExcludeMachineAccounts))
        }
        else {
            $r = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-UserLoginActivityLocal} -ArgumentList @(
                [datetime]$StartTime,
                [datetime]$EndTime,
                $IncludeLogonTypes,
                [bool]$IncludeLogoff,
                [bool]$IncludeSamples,
                [int]$SampleCount,
                [int]$MaxEvents,
                [bool]$ExcludeMachineAccounts
            ) -ErrorAction Stop
            $results.Add($r)
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp                  = (Get-Date)
            ComputerName               = $target
            StartTime                  = $StartTime
            EndTime                    = $EndTime
            TotalEvents                = $null
            InteractiveLogons          = $null
            RemoteInteractiveLogons    = $null
            OtherLogons                = $null
            Logoffs                    = $null
            DistinctUsers              = $null
            TopUsers                   = $null
            MostRecentInteractiveLogon = $null
            SampleEvents               = $null
            Error                      = $_.Exception.Message
        })
    }
}

$results
