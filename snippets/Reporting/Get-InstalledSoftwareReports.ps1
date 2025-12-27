<#
.SYNOPSIS
Generates a normalized installed software inventory report (object output).

.DESCRIPTION
Collects installed software from the standard registry uninstall locations:
- HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall
- HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
- HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall (optional)

Normalizes duplicates across 32/64-bit views and provides:
- DisplayName, DisplayVersion, Publisher, InstallDate, EstimatedSizeMB
- UninstallString / QuietUninstallString presence signals
- Source hive/view (HKLM32/HKLM64/HKCU)
- Best-effort "NormalizedKey" for dedupe grouping
- Health classification flags for common issues (stale entries, missing uninstall, etc.)

Designed for:
- Asset inventory and audit baselines
- Software standardization / cleanup projects
- Evidence collection (CSV exports)

.PARAMETER ComputerName
One or more computers to query. Defaults to local.

.PARAMETER IncludeCurrentUser
Include HKCU uninstall entries for the executing user context (local or remote session user).

.PARAMETER Name
Filter by DisplayName (supports wildcards). Example: "*QuickBooks*", "*Thomson*"

.PARAMETER Publisher
Filter by Publisher (supports wildcards). Example: "*Microsoft*", "*Intuit*"

.PARAMETER OnlyProblems
Return only entries with Health <> OK (e.g., missing uninstall strings).

.PARAMETER Dedupe
Deduplicate entries by NormalizedName + Version + Publisher (best-effort). Default on.

.PARAMETER IncludeRawKey
Include the underlying registry key name (useful for troubleshooting).

.PARAMETER ThrottleLimit
Throttle limit for multi-host inventory via PSSession. Default 16.

.EXAMPLE
.\Get-InstalledSoftwareReport.ps1 | Sort-Object DisplayName | Format-Table -Auto

.EXAMPLE
# Focus on common MSP apps
.\Get-InstalledSoftwareReport.ps1 -Name "*QuickBooks*","*Thomson*","*Adobe*" | Format-Table -Auto

.EXAMPLE
# Only suspicious/stale entries
.\Get-InstalledSoftwareReport.ps1 -OnlyProblems | Export-Csv C:\Reports\Software-Problems.csv -NoTypeInformation

.EXAMPLE
# Multi-host
.\Get-InstalledSoftwareReport.ps1 -ComputerName PC01,PC02 -Dedupe |
  Export-Csv C:\Reports\InstalledSoftware.csv -NoTypeInformation

.NOTES
Author: Cheri
Read-only. Safe for scheduled and RMM execution.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeCurrentUser,

    [Parameter()]
    [string[]]$Name,

    [Parameter()]
    [string[]]$Publisher,

    [Parameter()]
    [switch]$OnlyProblems,

    [Parameter()]
    [switch]$Dedupe = $true,

    [Parameter()]
    [switch]$IncludeRawKey,

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Match-AnyWildcard {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) {
        if ($Value -like $p) { return $true }
    }
    return $false
}

function Normalize-Name {
    param([string]$s)
    if (-not $s) { return $null }
    $x = $s.Trim().ToLowerInvariant()
    # remove common noise tokens
    $x = $x -replace '\(64-bit\)|\(32-bit\)|64-bit|32-bit',''
    $x = $x -replace '\b(x64|x86)\b',''
    $x = $x -replace '\s+',' '
    return $x.Trim()
}

function Parse-InstallDate {
    param($raw)
    # Common patterns: yyyymmdd, yyyy-mm-dd, locale strings
    if (-not $raw) { return $null }
    $s = [string]$raw
    $s = $s.Trim()
    if ($s -match '^\d{8}$') {
        try { return [datetime]::ParseExact($s,'yyyyMMdd',$null) } catch { return $null }
    }
    try { return [datetime]$s } catch { return $null }
}

function Get-HealthForSoftware {
    param(
        [string]$DisplayName,
        [string]$DisplayVersion,
        [string]$UninstallString,
        [string]$QuietUninstallString,
        [string]$WindowsInstaller,
        [string]$InstallLocation
    )

    # Health is about record quality for reporting/cleanup, not "secure" vs "insecure"
    $issues = New-Object System.Collections.Generic.List[string]

    if (-not $DisplayName) { $issues.Add('Missing DisplayName') }

    $hasUninstall = [bool]($UninstallString) -or [bool]($QuietUninstallString)
    if (-not $hasUninstall) { $issues.Add('Missing uninstall strings') }

    # MSI entries usually have WindowsInstaller=1 and uninstall via msiexec; still flag if missing both uninstall strings
    if ($WindowsInstaller -eq '1' -and -not $hasUninstall) { $issues.Add('MSI flagged but uninstall strings missing') }

    if (-not $DisplayVersion) { $issues.Add('Missing version') }

    # Not always bad, but helpful indicator
    if (-not $InstallLocation) { $issues.Add('Missing install location') }

    if ($issues.Count -eq 0) {
        return [PSCustomObject]@{ Health='OK'; Reason=$null }
    }

    # Critical only when the entry is unusable for management
    if ($issues -contains 'Missing DisplayName') {
        return [PSCustomObject]@{ Health='Critical'; Reason=($issues -join '; ') }
    }

    return [PSCustomObject]@{ Health='Warn'; Reason=($issues -join '; ') }
}

function Get-UninstallEntriesFromPath {
    param(
        [string]$BasePath,
        [string]$SourceTag
    )

    $items = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path $BasePath)) { return $items }

    $keys = Get-ChildItem -Path $BasePath -ErrorAction SilentlyContinue
    foreach ($k in @($keys)) {
        try {
            $p = Get-ItemProperty -Path $k.PSPath -ErrorAction Stop

            $displayName = $p.DisplayName
            if (-not $displayName) { continue } # Skip empty entries by default

            $obj = [ordered]@{
                DisplayName          = [string]$displayName
                DisplayVersion       = [string]$p.DisplayVersion
                Publisher            = [string]$p.Publisher
                InstallDate          = Parse-InstallDate $p.InstallDate
                EstimatedSizeMB      = if ($p.EstimatedSize) { [math]::Round(([double]$p.EstimatedSize / 1024), 2) } else { $null } # EstimatedSize is KB
                InstallLocation      = [string]$p.InstallLocation
                UninstallString      = [string]$p.UninstallString
                QuietUninstallString = [string]$p.QuietUninstallString
                WindowsInstaller     = [string]$p.WindowsInstaller
                SystemComponent      = [string]$p.SystemComponent
                ReleaseType          = [string]$p.ReleaseType

                Source               = $SourceTag
                RawKeyName           = $k.PSChildName

                NormalizedName       = Normalize-Name $displayName
                NormalizedPublisher  = Normalize-Name ([string]$p.Publisher)
                NormalizedKey        = $null

                Health               = $null
                Reason               = $null
            }

            $obj.NormalizedKey = "{0}|{1}|{2}" -f $obj.NormalizedName, ($obj.DisplayVersion ?? ''), ($obj.NormalizedPublisher ?? '')

            $health = Get-HealthForSoftware -DisplayName $obj.DisplayName -DisplayVersion $obj.DisplayVersion `
                -UninstallString $obj.UninstallString -QuietUninstallString $obj.QuietUninstallString `
                -WindowsInstaller $obj.WindowsInstaller -InstallLocation $obj.InstallLocation

            $obj.Health = $health.Health
            $obj.Reason = $health.Reason

            $items.Add([PSCustomObject]$obj)
        }
        catch {
            # Ignore single-key read failures
            continue
        }
    }

    $items
}

function Get-InstalledSoftwareLocal {
    param(
        [bool]$IncludeCurrentUser,
        [string[]]$Name,
        [string[]]$Publisher,
        [bool]$OnlyProblems,
        [bool]$Dedupe,
        [bool]$IncludeRawKey
    )

    $now = Get-Date
    $out = New-Object System.Collections.Generic.List[object]

    try {
        $paths = @(
            @{ Path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall';            Tag='HKLM64' }
            @{ Path='HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Tag='HKLM32' }
        )

        if ($IncludeCurrentUser) {
            $paths += @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'; Tag='HKCU' }
        }

        foreach ($pp in $paths) {
            $rows = Get-UninstallEntriesFromPath -BasePath $pp.Path -SourceTag $pp.Tag
            foreach ($r in @($rows)) { $out.Add($r) }
        }

        # Filter: name/publisher
        $filtered = $out | Where-Object {
            (Match-AnyWildcard -Value $_.DisplayName -Patterns $Name) -and
            (Match-AnyWildcard -Value $_.Publisher -Patterns $Publisher)
        }

        if ($OnlyProblems) {
            $filtered = $filtered | Where-Object { $_.Health -ne 'OK' }
        }

        if ($Dedupe) {
            # Keep the "best" row per NormalizedKey:
            # Prefer HKLM64 over HKLM32 over HKCU; prefer rows with uninstall strings; prefer install date
            $priority = @{
                'HKLM64' = 1
                'HKLM32' = 2
                'HKCU'   = 3
            }

            $filtered = $filtered |
                Group-Object NormalizedKey |
                ForEach-Object {
                    $_.Group |
                        Sort-Object `
                            @{Expression={ $priority[$_.Source] }; Ascending=$true},
                            @{Expression={ -not ([bool]$_.UninstallString -or [bool]$_.QuietUninstallString) }; Ascending=$true},
                            @{Expression={ if ($_.InstallDate) { 0 } else { 1 } }; Ascending=$true} |
                        Select-Object -First 1
                }
        }

        foreach ($r in @($filtered)) {
            # Standardize output schema
            $obj = [ordered]@{
                Timestamp           = $now
                ComputerName        = $env:COMPUTERNAME

                DisplayName         = $r.DisplayName
                DisplayVersion      = $r.DisplayVersion
                Publisher           = $r.Publisher
                InstallDate         = $r.InstallDate
                EstimatedSizeMB     = $r.EstimatedSizeMB
                InstallLocation     = $r.InstallLocation

                UninstallString     = $r.UninstallString
                QuietUninstallString= $r.QuietUninstallString
                WindowsInstaller    = $r.WindowsInstaller

                Source              = $r.Source
                NormalizedKey       = $r.NormalizedKey

                Health              = $r.Health
                Reason              = $r.Reason

                RawKeyName          = $null
                Error               = $null
            }

            if ($IncludeRawKey) {
                $obj.RawKeyName = $r.RawKeyName
            }

            [PSCustomObject]$obj
        }
    }
    catch {
        [PSCustomObject]@{
            Timestamp            = $now
            ComputerName         = $env:COMPUTERNAME
            DisplayName          = $null
            DisplayVersion       = $null
            Publisher            = $null
            InstallDate          = $null
            EstimatedSizeMB      = $null
            InstallLocation      = $null
            UninstallString      = $null
            QuietUninstallString = $null
            WindowsInstaller     = $null
            Source               = $null
            NormalizedKey        = $null
            Health               = 'Error'
            Reason               = 'Software inventory failed'
            RawKeyName           = $null
            Error                = $_.Exception.Message
        }
    }
}

$results = New-Object System.Collections.Generic.List[object]

# If multiple computers, use PSSessions for efficiency/throttle control
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Get-InstalledSoftwareLocal} -ArgumentList @(
            [bool]$IncludeCurrentUser,
            $Name,
            $Publisher,
            [bool]$OnlyProblems,
            [bool]$Dedupe,
            [bool]$IncludeRawKey
        )
        foreach ($r in @($rows)) { $results.Add($r) }
    }
    finally {
        if ($sessions) { $sessions | Remove-PSSession -ErrorAction SilentlyContinue }
    }
}
else {
    foreach ($c in $ComputerName) {
        $target = $c.Trim()
        if ([string]::IsNullOrWhiteSpace($target)) { continue }

        try {
            if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
                $rows = Get-InstalledSoftwareLocal -IncludeCurrentUser:$IncludeCurrentUser -Name $Name -Publisher $Publisher `
                    -OnlyProblems:$OnlyProblems -Dedupe:$Dedupe -IncludeRawKey:$IncludeRawKey
            }
            else {
                $rows = Invoke-Command -ComputerName $target -ScriptBlock ${function:Get-InstalledSoftwareLocal} -ArgumentList @(
                    [bool]$IncludeCurrentUser,
                    $Name,
                    $Publisher,
                    [bool]$OnlyProblems,
                    [bool]$Dedupe,
                    [bool]$IncludeRawKey
                ) -ErrorAction Stop
            }

            foreach ($r in @($rows)) { $results.Add($r) }
        }
        catch {
            $results.Add([PSCustomObject]@{
                Timestamp            = (Get-Date)
                ComputerName         = $target
                DisplayName          = $null
                DisplayVersion       = $null
                Publisher            = $null
                InstallDate          = $null
                EstimatedSizeMB      = $null
                InstallLocation      = $null
                UninstallString      = $null
                QuietUninstallString = $null
                WindowsInstaller     = $null
                Source               = $null
                NormalizedKey        = $null
                Health               = 'Error'
                Reason               = 'Remote query failed'
                RawKeyName           = $null
                Error                = $_.Exception.Message
            })
        }
    }
}

$results
