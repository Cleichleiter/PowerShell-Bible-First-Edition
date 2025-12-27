<#
.SYNOPSIS
Summarizes Windows Firewall rules into high-signal operational and risk metrics.

.DESCRIPTION
Produces an incident-friendly firewall rule summary:
- Counts of Enabled rules by Direction/Action/Profile
- Counts of enabled inbound Allow rules by local port (top N)
- Detects "allow-any inbound" patterns (remote any + local any + any port) as a risk heuristic
- Optional inclusion of sample rule details for each category
- Optional focus filters (RDP/SMB/WinRM/HTTP/HTTPS) to quickly validate expected rules

Designed for troubleshooting:
- "Why is this port blocked?"
- "Are we on the wrong profile?"
- "Do we have overly-permissive inbound rules?"

Outputs structured objects suitable for reporting and automation.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER Direction
Inbound, Outbound, or Both. Default Both.

.PARAMETER EnabledOnly
Only evaluate enabled rules. Default True.

.PARAMETER IncludePortBreakdown
Include a top-N breakdown of inbound allowed local ports (can be slower).

.PARAMETER TopPorts
How many top inbound allow ports to return. Default 15.

.PARAMETER IncludeRiskRules
Include sample rules for risk findings (e.g., allow-any inbound). Default False.

.PARAMETER Focus
Optional quick focus set. Limits detailed lookups to rules matching these patterns:
RDP, SMB, WinRM, HTTP, HTTPS, DNS, NTP. (Counts still reflect all evaluated rules.)

.PARAMETER IncludeRawCounts
Include the raw grouped count table.

.EXAMPLE
.\Get-FirewallRuleSummary.ps1 | Format-List

.EXAMPLE
.\Get-FirewallRuleSummary.ps1 -ComputerName RDSH01,RDSH02 -IncludePortBreakdown |
  Export-Csv C:\Reports\FirewallRuleSummary.csv -NoTypeInformation

.EXAMPLE
.\Get-FirewallRuleSummary.ps1 -Focus RDP,WinRM -IncludeRiskRules | Format-List

.NOTES
Author: Cheri
Requires: NetSecurity module.
Remote requires WinRM.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [ValidateSet('Inbound','Outbound','Both')]
    [string]$Direction = 'Both',

    [Parameter()]
    [switch]$EnabledOnly = $true,

    [Parameter()]
    [switch]$IncludePortBreakdown,

    [Parameter()]
    [ValidateRange(1,100)]
    [int]$TopPorts = 15,

    [Parameter()]
    [switch]$IncludeRiskRules,

    [Parameter()]
    [ValidateSet('RDP','SMB','WinRM','HTTP','HTTPS','DNS','NTP')]
    [string[]]$Focus,

    [Parameter()]
    [switch]$IncludeRawCounts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-FocusRegex {
    param([string[]]$Focus)
    if (-not $Focus -or $Focus.Count -eq 0) { return $null }

    $parts = foreach ($f in $Focus) {
        switch ($f) {
            'RDP'   { 'Remote Desktop|RDP|3389' }
            'SMB'   { 'File and Printer Sharing|SMB|445|139' }
            'WinRM' { 'Windows Remote Management|WinRM|5985|5986' }
            'HTTP'  { '\bHTTP\b|80' }
            'HTTPS' { '\bHTTPS\b|443' }
            'DNS'   { '\bDNS\b|53' }
            'NTP'   { '\bNTP\b|123' }
        }
    }
    return ($parts -join '|')
}

function Summarize-LocalFirewallRules {
    param(
        [string]$Direction,
        [bool]$EnabledOnly,
        [bool]$IncludePortBreakdown,
        [int]$TopPorts,
        [bool]$IncludeRiskRules,
        [string[]]$Focus,
        [bool]$IncludeRawCounts
    )

    $dirFilter = switch ($Direction) {
        'Inbound'  { @('Inbound') }
        'Outbound' { @('Outbound') }
        'Both'     { @('Inbound','Outbound') }
    }

    $focusRegex = Get-FocusRegex -Focus $Focus

    # Pull rules (enabled-only by default) and keep it efficient
    $rules = if ($EnabledOnly) {
        Get-NetFirewallRule -Enabled True -ErrorAction Stop
    } else {
        Get-NetFirewallRule -ErrorAction Stop
    }

    $rules = $rules | Where-Object { $_.Direction -in $dirFilter }

    $totalEvaluated = @($rules).Count

    # Raw grouped counts: Direction/Action/Profile
    $groupCounts = $rules |
        Group-Object Direction, Action, Profile |
        ForEach-Object {
            $n = $_.Name -split ','
            [PSCustomObject]@{
                Direction = $n[0].Trim()
                Action    = $n[1].Trim()
                Profile   = $n[2].Trim()
                Count     = $_.Count
            }
        } | Sort-Object Direction, Action, Profile

    # Profile-level allow/deny counts (enabled-only if selected)
    $inAllow = $rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
    $inBlock = $rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }
    $outAllow = $rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow' }
    $outBlock = $rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }

    # Risk heuristic: "Allow Any" inbound rules
    # remote=Any and local=Any and localport=Any (requires joining filters)
    $allowAnyCount = 0
    $allowAnyRules = @()

    try {
        $addrFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $inAllow -ErrorAction SilentlyContinue
        $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $inAllow -ErrorAction SilentlyContinue

        $addrById = @{}
        foreach ($a in @($addrFilters)) { $addrById[$a.InstanceID] = $a }
        $portById = @{}
        foreach ($p in @($portFilters)) { $portById[$p.InstanceID] = $p }

        foreach ($r in @($inAllow)) {
            $a = $addrById[$r.InstanceID]
            $p = $portById[$r.InstanceID]

            $remote = if ($a) { $a.RemoteAddress } else { $null }
            $local  = if ($a) { $a.LocalAddress } else { $null }
            $lport  = if ($p) { $p.LocalPort } else { $null }

            $remoteAny = ($remote -eq 'Any' -or $remote -eq $null -or $remote -eq '*')
            $localAny  = ($local -eq 'Any' -or $local -eq $null -or $local -eq '*')
            $portAny   = ($lport -eq 'Any' -or $lport -eq $null -or $lport -eq '*')

            if ($remoteAny -and $localAny -and $portAny) {
                $allowAnyCount++
                if ($IncludeRiskRules) {
                    $allowAnyRules += [PSCustomObject]@{
                        Name        = $r.Name
                        DisplayName = $r.DisplayName
                        Group       = $r.Group
                        Profile     = $r.Profile
                        Program     = $r.Program
                        Service     = $r.Service
                    }
                }
            }
        }
    } catch {
        # If filter joins fail, continue without allow-any details
    }

    # Port breakdown for enabled inbound allow rules (top N)
    $portBreakdown = @()
    if ($IncludePortBreakdown) {
        try {
            $inAllowPorts = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $inAllow -ErrorAction SilentlyContinue |
                Where-Object { $_.LocalPort -and $_.LocalPort -ne 'Any' }

            # LocalPort can be: "80", "135-139", "5000,5001" etc. We keep it as a string key to avoid heavy parsing.
            $portBreakdown = $inAllowPorts |
                Group-Object LocalPort |
                Sort-Object Count -Descending |
                Select-Object -First $TopPorts |
                ForEach-Object {
                    [PSCustomObject]@{
                        LocalPort = $_.Name
                        RuleCount = $_.Count
                    }
                }
        } catch { }
    }

    # Focus samples (optional): helps quickly confirm expected allow rules exist
    $focusSample = @()
    if ($focusRegex) {
        $focusSample = $rules |
            Where-Object {
                ($_.DisplayName -match $focusRegex) -or
                ($_.DisplayGroup -match $focusRegex) -or
                ($_.Name -match $focusRegex)
            } |
            Select-Object -First 25 Direction, Action, Enabled, Profile, DisplayName, DisplayGroup, Program, Service
    }

    [PSCustomObject]@{
        Timestamp              = Get-Date
        ComputerName           = $env:COMPUTERNAME

        DirectionEvaluated     = $Direction
        EnabledOnly            = $EnabledOnly
        TotalRulesEvaluated    = $totalEvaluated

        InboundAllowCount      = @($inAllow).Count
        InboundBlockCount      = @($inBlock).Count
        OutboundAllowCount     = @($outAllow).Count
        OutboundBlockCount     = @($outBlock).Count

        AllowAnyInboundRuleCount = $allowAnyCount
        AllowAnyInboundRules     = if ($IncludeRiskRules) { $allowAnyRules } else { $null }

        TopInboundAllowPorts    = if ($IncludePortBreakdown) { $portBreakdown } else { $null }

        Focus                  = if ($Focus) { $Focus -join '; ' } else { $null }
        FocusRuleSample        = if ($focusRegex) { $focusSample } else { $null }

        RawGroupedCounts       = if ($IncludeRawCounts) { $groupCounts } else { $null }

        Risk_AllowAnyInboundRules = ($allowAnyCount -gt 0)
    }
}

function Summarize-RemoteFirewallRules {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [string]$Direction,
        [bool]$EnabledOnly,
        [bool]$IncludePortBreakdown,
        [int]$TopPorts,
        [bool]$IncludeRiskRules,
        [string[]]$Focus,
        [bool]$IncludeRawCounts
    )

    $sb = {
        param($Direction,$EnabledOnly,$IncludePortBreakdown,$TopPorts,$IncludeRiskRules,$Focus,$IncludeRawCounts)

        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        function Get-FocusRegex {
            param([string[]]$Focus)
            if (-not $Focus -or $Focus.Count -eq 0) { return $null }
            $parts = foreach ($f in $Focus) {
                switch ($f) {
                    'RDP'   { 'Remote Desktop|RDP|3389' }
                    'SMB'   { 'File and Printer Sharing|SMB|445|139' }
                    'WinRM' { 'Windows Remote Management|WinRM|5985|5986' }
                    'HTTP'  { '\bHTTP\b|80' }
                    'HTTPS' { '\bHTTPS\b|443' }
                    'DNS'   { '\bDNS\b|53' }
                    'NTP'   { '\bNTP\b|123' }
                }
            }
            return ($parts -join '|')
        }

        $dirFilter = switch ($Direction) {
            'Inbound'  { @('Inbound') }
            'Outbound' { @('Outbound') }
            'Both'     { @('Inbound','Outbound') }
        }

        $focusRegex = Get-FocusRegex -Focus $Focus

        $rules = if ($EnabledOnly) { Get-NetFirewallRule -Enabled True -ErrorAction Stop } else { Get-NetFirewallRule -ErrorAction Stop }
        $rules = $rules | Where-Object { $_.Direction -in $dirFilter }

        $totalEvaluated = @($rules).Count

        $groupCounts = $rules |
            Group-Object Direction, Action, Profile |
            ForEach-Object {
                $n = $_.Name -split ','
                [PSCustomObject]@{
                    Direction = $n[0].Trim()
                    Action    = $n[1].Trim()
                    Profile   = $n[2].Trim()
                    Count     = $_.Count
                }
            } | Sort-Object Direction, Action, Profile

        $inAllow  = $rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
        $inBlock  = $rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Block' }
        $outAllow = $rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow' }
        $outBlock = $rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block' }

        $allowAnyCount = 0
        $allowAnyRules = @()

        try {
            $addrFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $inAllow -ErrorAction SilentlyContinue
            $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $inAllow -ErrorAction SilentlyContinue
            $addrById = @{}; foreach ($a in @($addrFilters)) { $addrById[$a.InstanceID] = $a }
            $portById = @{}; foreach ($p in @($portFilters)) { $portById[$p.InstanceID] = $p }

            foreach ($r in @($inAllow)) {
                $a = $addrById[$r.InstanceID]
                $p = $portById[$r.InstanceID]
                $remote = if ($a) { $a.RemoteAddress } else { $null }
                $local  = if ($a) { $a.LocalAddress } else { $null }
                $lport  = if ($p) { $p.LocalPort } else { $null }

                $remoteAny = ($remote -eq 'Any' -or $remote -eq $null -or $remote -eq '*')
                $localAny  = ($local -eq 'Any' -or $local -eq $null -or $local -eq '*')
                $portAny   = ($lport -eq 'Any' -or $lport -eq $null -or $lport -eq '*')

                if ($remoteAny -and $localAny -and $portAny) {
                    $allowAnyCount++
                    if ($IncludeRiskRules) {
                        $allowAnyRules += [PSCustomObject]@{
                            Name        = $r.Name
                            DisplayName = $r.DisplayName
                            Group       = $r.Group
                            Profile     = $r.Profile
                            Program     = $r.Program
                            Service     = $r.Service
                        }
                    }
                }
            }
        } catch { }

        $portBreakdown = @()
        if ($IncludePortBreakdown) {
            try {
                $inAllowPorts = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $inAllow -ErrorAction SilentlyContinue |
                    Where-Object { $_.LocalPort -and $_.LocalPort -ne 'Any' }

                $portBreakdown = $inAllowPorts |
                    Group-Object LocalPort |
                    Sort-Object Count -Descending |
                    Select-Object -First $TopPorts |
                    ForEach-Object {
                        [PSCustomObject]@{
                            LocalPort = $_.Name
                            RuleCount = $_.Count
                        }
                    }
            } catch { }
        }

        $focusSample = @()
        if ($focusRegex) {
            $focusSample = $rules |
                Where-Object {
                    ($_.DisplayName -match $focusRegex) -or
                    ($_.DisplayGroup -match $focusRegex) -or
                    ($_.Name -match $focusRegex)
                } |
                Select-Object -First 25 Direction, Action, Enabled, Profile, DisplayName, DisplayGroup, Program, Service
        }

        [PSCustomObject]@{
            Timestamp              = Get-Date
            ComputerName           = $env:COMPUTERNAME
            DirectionEvaluated     = $Direction
            EnabledOnly            = $EnabledOnly
            TotalRulesEvaluated    = $totalEvaluated
            InboundAllowCount      = @($inAllow).Count
            InboundBlockCount      = @($inBlock).Count
            OutboundAllowCount     = @($outAllow).Count
            OutboundBlockCount     = @($outBlock).Count
            AllowAnyInboundRuleCount = $allowAnyCount
            AllowAnyInboundRules     = if ($IncludeRiskRules) { $allowAnyRules } else { $null }
            TopInboundAllowPorts    = if ($IncludePortBreakdown) { $portBreakdown } else { $null }
            Focus                  = if ($Focus) { $Focus -join '; ' } else { $null }
            FocusRuleSample        = if ($focusRegex) { $focusSample } else { $null }
            RawGroupedCounts       = if ($IncludeRawCounts) { $groupCounts } else { $null }
            Risk_AllowAnyInboundRules = ($allowAnyCount -gt 0)
        }
    }

    Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ArgumentList @(
        $Direction, [bool]$EnabledOnly, [bool]$IncludePortBreakdown, [int]$TopPorts,
        [bool]$IncludeRiskRules, $Focus, [bool]$IncludeRawCounts
    ) -ErrorAction Stop
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $all.Add((Summarize-LocalFirewallRules -Direction $Direction -EnabledOnly:$EnabledOnly `
                -IncludePortBreakdown:$IncludePortBreakdown -TopPorts $TopPorts -IncludeRiskRules:$IncludeRiskRules `
                -Focus $Focus -IncludeRawCounts:$IncludeRawCounts))
        } else {
            $all.Add((Summarize-RemoteFirewallRules -Computer $target -Direction $Direction -EnabledOnly:$EnabledOnly `
                -IncludePortBreakdown:$IncludePortBreakdown -TopPorts $TopPorts -IncludeRiskRules:$IncludeRiskRules `
                -Focus $Focus -IncludeRawCounts:$IncludeRawCounts))
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            Timestamp               = Get-Date
            ComputerName            = $target
            DirectionEvaluated      = $Direction
            EnabledOnly             = $EnabledOnly
            TotalRulesEvaluated     = $null
            InboundAllowCount       = $null
            InboundBlockCount       = $null
            OutboundAllowCount      = $null
            OutboundBlockCount      = $null
            AllowAnyInboundRuleCount = $null
            AllowAnyInboundRules     = $null
            TopInboundAllowPorts     = $null
            Focus                   = if ($Focus) { $Focus -join '; ' } else { $null }
            FocusRuleSample         = $null
            RawGroupedCounts        = $null
            Risk_AllowAnyInboundRules = $null
            Error                   = $_.Exception.Message
        })
    }
}

$all
