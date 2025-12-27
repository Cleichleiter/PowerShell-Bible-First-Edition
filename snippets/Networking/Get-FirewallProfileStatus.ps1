<#
.SYNOPSIS
Gets Windows Firewall profile status and key policy signals (local or remote).

.DESCRIPTION
Incident-focused firewall/profile visibility:
- Domain/Private/Public profile: Enabled, DefaultInbound/OutboundAction, Logging, Notifications
- Active network profiles (Get-NetConnectionProfile) to detect "wrong profile" issues
- High-signal checks:
  - Any profile disabled?
  - Any profile DefaultInboundAction = Allow?
  - Any "Allow Any" inbound rules enabled (high risk)
  - RDP/SMB rule presence and enabled state (optional)
- Remote support via Invoke-Command (WinRM)

Outputs structured objects suitable for reporting and automation.

.PARAMETER ComputerName
One or more computers to query. Defaults to local computer.

.PARAMETER IncludeRuleSignals
Includes basic rule signals (e.g., inbound allow-any rules, RDP/SMB rules) which can be slower.

.PARAMETER IncludeAllAllowAnyRules
If set, returns all enabled inbound allow-any rules (name/display/group) in the output.

.PARAMETER IncludeRaw
Include raw profile objects (string snapshot) for deeper troubleshooting.

.EXAMPLE
.\Get-FirewallProfileStatus.ps1 | Format-List

.EXAMPLE
.\Get-FirewallProfileStatus.ps1 -ComputerName RDSH01,RDSH02 -IncludeRuleSignals |
  Format-Table -Auto

.EXAMPLE
.\Get-FirewallProfileStatus.ps1 -IncludeRuleSignals -IncludeAllAllowAnyRules |
  Select-Object ComputerName, ActiveNetworkCategory, EnabledProfiles, DisabledProfiles, DefaultInboundSummary, AllowAnyInboundRuleCount

.NOTES
Author: Cheri
Requires: NetSecurity module (Get-NetFirewallProfile/Get-NetFirewallRule) and NetTCPIP (Get-NetConnectionProfile).
Remote requires WinRM.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeRuleSignals,

    [Parameter()]
    [switch]$IncludeAllAllowAnyRules,

    [Parameter()]
    [switch]$IncludeRaw
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LocalFirewallProfileStatus {
    param(
        [bool]$IncludeRuleSignals,
        [bool]$IncludeAllAllowAnyRules,
        [bool]$IncludeRaw
    )

    $profiles = Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name
    $connProfiles = @()
    try { $connProfiles = Get-NetConnectionProfile -ErrorAction Stop } catch { $connProfiles = @() }

    $activeCategories = @($connProfiles | Select-Object -ExpandProperty NetworkCategory -ErrorAction SilentlyContinue) | Select-Object -Unique
    $activeIfAliases  = @($connProfiles | Select-Object -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue)

    $enabled = @($profiles | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Name)
    $disabled = @($profiles | Where-Object { $_.Enabled -eq $false } | Select-Object -ExpandProperty Name)

    $defaultInbound = $profiles | ForEach-Object { "$($_.Name)=$($_.DefaultInboundAction)" }
    $defaultOutbound = $profiles | ForEach-Object { "$($_.Name)=$($_.DefaultOutboundAction)" }

    $anyInboundAllowProfiles = @(
        $profiles | Where-Object { $_.DefaultInboundAction -eq 'Allow' } | Select-Object -ExpandProperty Name
    )

    # Logging signals (best-effort fields differ by build)
    $logSummary = $profiles | ForEach-Object {
        $logFile = $null
        $logAllowed = $null
        $logBlocked = $null
        try { $logFile = $_.LogFileName } catch {}
        try { $logAllowed = $_.LogAllowed } catch {}
        try { $logBlocked = $_.LogBlocked } catch {}
        "$($_.Name): File=$logFile Allowed=$logAllowed Blocked=$logBlocked"
    }

    $allowAnyInboundRules = @()
    $allowAnyCount = 0
    $rdpRules = @()
    $smbRules = @()

    if ($IncludeRuleSignals) {
        # Enabled inbound rules that allow traffic from ANY remote address to ANY local address/port (high-risk heuristic)
        # Note: We intentionally keep this heuristic conservative and export-friendly.
        try {
            $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop

            # Join to filter/port/address details
            $addrFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules -ErrorAction SilentlyContinue
            $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rules -ErrorAction SilentlyContinue

            $addrByInstance = @{}
            foreach ($a in @($addrFilters)) { $addrByInstance[$a.InstanceID] = $a }

            $portByInstance = @{}
            foreach ($p in @($portFilters)) { $portByInstance[$p.InstanceID] = $p }

            foreach ($r in @($rules)) {
                $a = $addrByInstance[$r.InstanceID]
                $p = $portByInstance[$r.InstanceID]

                $remote = if ($a) { $a.RemoteAddress } else { $null }
                $local  = if ($a) { $a.LocalAddress } else { $null }

                $lport  = if ($p) { $p.LocalPort } else { $null }
                $proto  = if ($p) { $p.Protocol } else { $null }

                # Heuristic: remote is Any and local is Any and localport is Any
                $remoteAny = ($remote -eq 'Any' -or $remote -eq $null -or $remote -eq '*')
                $localAny  = ($local -eq 'Any' -or $local -eq $null -or $local -eq '*')
                $portAny   = ($lport -eq 'Any' -or $lport -eq $null -or $lport -eq '*')

                if ($remoteAny -and $localAny -and $portAny) {
                    $allowAnyCount++
                    if ($IncludeAllAllowAnyRules) {
                        $allowAnyInboundRules += [PSCustomObject]@{
                            Name         = $r.Name
                            DisplayName  = $r.DisplayName
                            Group        = $r.Group
                            Profile      = $r.Profile
                            Program      = $r.Program
                            Service      = $r.Service
                            LocalPort    = $lport
                            Protocol     = $proto
                        }
                    }
                }
            }

            # Basic RDP/SMB rule signals (presence + enabled state)
            $rdpRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayGroup -like '*Remote Desktop*' -or $_.DisplayName -like '*Remote Desktop*' } |
                Select-Object -First 20 Name, DisplayName, Enabled, Profile, Direction, Action

            $smbRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like '*File and Printer Sharing*' -or $_.DisplayGroup -like '*File and Printer Sharing*' } |
                Select-Object -First 20 Name, DisplayName, Enabled, Profile, Direction, Action
        }
        catch {
            # If rules query fails, keep signal fields empty but still return profiles.
        }
    }

    $obj = [PSCustomObject]@{
        Timestamp               = Get-Date
        ComputerName            = $env:COMPUTERNAME

        # Network profile context
        ActiveNetworkCategory   = if ($activeCategories.Count -gt 0) { $activeCategories -join '; ' } else { $null }
        ActiveInterfaces        = if ($activeIfAliases.Count -gt 0) { $activeIfAliases -join '; ' } else { $null }

        # Firewall profile states
        EnabledProfiles         = if ($enabled.Count -gt 0) { $enabled -join '; ' } else { $null }
        DisabledProfiles        = if ($disabled.Count -gt 0) { $disabled -join '; ' } else { $null }

        DefaultInboundSummary   = $defaultInbound -join '; '
        DefaultOutboundSummary  = $defaultOutbound -join '; '

        ProfilesWithInboundAllow = if ($anyInboundAllowProfiles.Count -gt 0) { $anyInboundAllowProfiles -join '; ' } else { $null }

        LoggingSummary          = $logSummary -join ' | '

        # Rule signals
        AllowAnyInboundRuleCount = if ($IncludeRuleSignals) { $allowAnyCount } else { $null }
        AllowAnyInboundRules     = if ($IncludeRuleSignals -and $IncludeAllAllowAnyRules) { $allowAnyInboundRules } else { $null }

        RdpRuleSample            = if ($IncludeRuleSignals) { $rdpRules } else { $null }
        SmbRuleSample            = if ($IncludeRuleSignals) { $smbRules } else { $null }

        # High-level flags
        Risk_FirewallDisabled    = ($disabled.Count -gt 0)
        Risk_InboundDefaultAllow = ($anyInboundAllowProfiles.Count -gt 0)
        Risk_AllowAnyInboundRules = if ($IncludeRuleSignals) { ($allowAnyCount -gt 0) } else { $null }
    }

    if ($IncludeRaw) {
        $raw = $profiles | Select-Object * | Out-String
        $obj | Add-Member -NotePropertyName RawProfiles -NotePropertyValue $raw -Force
    }

    $obj
}

function Get-RemoteFirewallProfileStatus {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [bool]$IncludeRuleSignals,
        [bool]$IncludeAllAllowAnyRules,
        [bool]$IncludeRaw
    )

    $sb = {
        param($IncludeRuleSignals,$IncludeAllAllowAnyRules,$IncludeRaw)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        function Get-LocalFirewallProfileStatusInternal {
            param($IncludeRuleSignals,$IncludeAllAllowAnyRules,$IncludeRaw)

            $profiles = Get-NetFirewallProfile -ErrorAction Stop | Sort-Object Name
            $connProfiles = @()
            try { $connProfiles = Get-NetConnectionProfile -ErrorAction Stop } catch { $connProfiles = @() }

            $activeCategories = @($connProfiles | Select-Object -ExpandProperty NetworkCategory -ErrorAction SilentlyContinue) | Select-Object -Unique
            $activeIfAliases  = @($connProfiles | Select-Object -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue)

            $enabled = @($profiles | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Name)
            $disabled = @($profiles | Where-Object { $_.Enabled -eq $false } | Select-Object -ExpandProperty Name)

            $defaultInbound = $profiles | ForEach-Object { "$($_.Name)=$($_.DefaultInboundAction)" }
            $defaultOutbound = $profiles | ForEach-Object { "$($_.Name)=$($_.DefaultOutboundAction)" }

            $anyInboundAllowProfiles = @(
                $profiles | Where-Object { $_.DefaultInboundAction -eq 'Allow' } | Select-Object -ExpandProperty Name
            )

            $logSummary = $profiles | ForEach-Object {
                $logFile = $null; $logAllowed = $null; $logBlocked = $null
                try { $logFile = $_.LogFileName } catch {}
                try { $logAllowed = $_.LogAllowed } catch {}
                try { $logBlocked = $_.LogBlocked } catch {}
                "$($_.Name): File=$logFile Allowed=$logAllowed Blocked=$logBlocked"
            }

            $allowAnyInboundRules = @()
            $allowAnyCount = 0
            $rdpRules = @()
            $smbRules = @()

            if ($IncludeRuleSignals) {
                try {
                    $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop
                    $addrFilters = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules -ErrorAction SilentlyContinue
                    $portFilters = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rules -ErrorAction SilentlyContinue

                    $addrByInstance = @{}
                    foreach ($a in @($addrFilters)) { $addrByInstance[$a.InstanceID] = $a }

                    $portByInstance = @{}
                    foreach ($p in @($portFilters)) { $portByInstance[$p.InstanceID] = $p }

                    foreach ($r in @($rules)) {
                        $a = $addrByInstance[$r.InstanceID]
                        $p = $portByInstance[$r.InstanceID]

                        $remote = if ($a) { $a.RemoteAddress } else { $null }
                        $local  = if ($a) { $a.LocalAddress } else { $null }
                        $lport  = if ($p) { $p.LocalPort } else { $null }
                        $proto  = if ($p) { $p.Protocol } else { $null }

                        $remoteAny = ($remote -eq 'Any' -or $remote -eq $null -or $remote -eq '*')
                        $localAny  = ($local -eq 'Any' -or $local -eq $null -or $local -eq '*')
                        $portAny   = ($lport -eq 'Any' -or $lport -eq $null -or $lport -eq '*')

                        if ($remoteAny -and $localAny -and $portAny) {
                            $allowAnyCount++
                            if ($IncludeAllAllowAnyRules) {
                                $allowAnyInboundRules += [PSCustomObject]@{
                                    Name         = $r.Name
                                    DisplayName  = $r.DisplayName
                                    Group        = $r.Group
                                    Profile      = $r.Profile
                                    Program      = $r.Program
                                    Service      = $r.Service
                                    LocalPort    = $lport
                                    Protocol     = $proto
                                }
                            }
                        }
                    }

                    $rdpRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayGroup -like '*Remote Desktop*' -or $_.DisplayName -like '*Remote Desktop*' } |
                        Select-Object -First 20 Name, DisplayName, Enabled, Profile, Direction, Action

                    $smbRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -like '*File and Printer Sharing*' -or $_.DisplayGroup -like '*File and Printer Sharing*' } |
                        Select-Object -First 20 Name, DisplayName, Enabled, Profile, Direction, Action
                } catch { }
            }

            $obj = [PSCustomObject]@{
                Timestamp               = Get-Date
                ComputerName            = $env:COMPUTERNAME
                ActiveNetworkCategory   = if ($activeCategories.Count -gt 0) { $activeCategories -join '; ' } else { $null }
                ActiveInterfaces        = if ($activeIfAliases.Count -gt 0) { $activeIfAliases -join '; ' } else { $null }
                EnabledProfiles         = if ($enabled.Count -gt 0) { $enabled -join '; ' } else { $null }
                DisabledProfiles        = if ($disabled.Count -gt 0) { $disabled -join '; ' } else { $null }
                DefaultInboundSummary   = $defaultInbound -join '; '
                DefaultOutboundSummary  = $defaultOutbound -join '; '
                ProfilesWithInboundAllow = if ($anyInboundAllowProfiles.Count -gt 0) { $anyInboundAllowProfiles -join '; ' } else { $null }
                LoggingSummary          = $logSummary -join ' | '
                AllowAnyInboundRuleCount = if ($IncludeRuleSignals) { $allowAnyCount } else { $null }
                AllowAnyInboundRules     = if ($IncludeRuleSignals -and $IncludeAllAllowAnyRules) { $allowAnyInboundRules } else { $null }
                RdpRuleSample            = if ($IncludeRuleSignals) { $rdpRules } else { $null }
                SmbRuleSample            = if ($IncludeRuleSignals) { $smbRules } else { $null }
                Risk_FirewallDisabled    = ($disabled.Count -gt 0)
                Risk_InboundDefaultAllow = ($anyInboundAllowProfiles.Count -gt 0)
                Risk_AllowAnyInboundRules = if ($IncludeRuleSignals) { ($allowAnyCount -gt 0) } else { $null }
            }

            if ($IncludeRaw) {
                $raw = $profiles | Select-Object * | Out-String
                $obj | Add-Member -NotePropertyName RawProfiles -NotePropertyValue $raw -Force
            }

            $obj
        }

        Get-LocalFirewallProfileStatusInternal -IncludeRuleSignals $IncludeRuleSignals -IncludeAllAllowAnyRules $IncludeAllAllowAnyRules -IncludeRaw $IncludeRaw
    }

    Invoke-Command -ComputerName $Computer -ScriptBlock $sb -ArgumentList @(
        [bool]$IncludeRuleSignals, [bool]$IncludeAllAllowAnyRules, [bool]$IncludeRaw
    ) -ErrorAction Stop
}

$all = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $all.Add((Get-LocalFirewallProfileStatus -IncludeRuleSignals:$IncludeRuleSignals -IncludeAllAllowAnyRules:$IncludeAllAllowAnyRules -IncludeRaw:$IncludeRaw))
        }
        else {
            $all.Add((Get-RemoteFirewallProfileStatus -Computer $target -IncludeRuleSignals:$IncludeRuleSignals -IncludeAllAllowAnyRules:$IncludeAllAllowAnyRules -IncludeRaw:$IncludeRaw))
        }
    }
    catch {
        $all.Add([PSCustomObject]@{
            Timestamp                = Get-Date
            ComputerName             = $target
            ActiveNetworkCategory    = $null
            ActiveInterfaces         = $null
            EnabledProfiles          = $null
            DisabledProfiles         = $null
            DefaultInboundSummary    = $null
            DefaultOutboundSummary   = $null
            ProfilesWithInboundAllow = $null
            LoggingSummary           = $null
            AllowAnyInboundRuleCount = $null
            AllowAnyInboundRules     = $null
            RdpRuleSample            = $null
            SmbRuleSample            = $null
            Risk_FirewallDisabled    = $null
            Risk_InboundDefaultAllow = $null
            Risk_AllowAnyInboundRules = $null
            Error                    = $_.Exception.Message
        })
    }
}

$all
