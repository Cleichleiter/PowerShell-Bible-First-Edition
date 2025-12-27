<#
.SYNOPSIS
Finds common AD object issues that frequently cause Entra Connect / hybrid sync errors.

.DESCRIPTION
Scans AD users and flags common causes of sync failure or service impact:
- Missing/invalid UPN
- UPN suffix not allowed (optional)
- Duplicate UPN
- Duplicate proxyAddresses (case-insensitive)
- Missing mailNickname and invalid mailNickname characters
- Missing/invalid mail

Outputs objects that can be exported to CSV and reviewed quickly.

.PARAMETER SearchBase
Optional OU distinguishedName to scope the scan.

.PARAMETER IncludeDisabled
Include disabled users (default: True).

.PARAMETER AllowedUpnSuffixes
Optional list of allowed UPN suffixes (e.g. contoso.com, corp.contoso.com).
If provided, UPN suffixes outside the list are flagged.

.PARAMETER IncludeProxyDuplicates
If set, include proxyAddresses duplicate checks (more expensive in large directories).

.PARAMETER IncludeMailChecks
If set, include mail checks.

.PARAMETER IncludeMailNicknameChecks
If set, include mailNickname checks (recommended if Exchange attributes matter).

.EXAMPLE
.\Find-ADSyncTroubleObjects.ps1

.EXAMPLE
.\Find-ADSyncTroubleObjects.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -AllowedUpnSuffixes contoso.com,corp.contoso.com

.EXAMPLE
.\Find-ADSyncTroubleObjects.ps1 -IncludeProxyDuplicates -IncludeMailChecks -IncludeMailNicknameChecks |
  Export-Csv C:\Reports\ADSyncTroubleObjects.csv -NoTypeInformation

.NOTES
Requires RSAT ActiveDirectory module.

Performance note:
- Proxy duplicate detection flattens proxyAddresses and can be heavy in large orgs.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [bool]$IncludeDisabled = $true,

    [Parameter()]
    [string[]]$AllowedUpnSuffixes,

    [Parameter()]
    [switch]$IncludeProxyDuplicates,

    [Parameter()]
    [switch]$IncludeMailChecks,

    [Parameter()]
    [switch]$IncludeMailNicknameChecks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

function New-Finding {
    param(
        [string]$FindingType,
        [string]$Severity,
        [string]$Value,
        [object]$UserObject,
        [string]$Notes
    )

    [PSCustomObject]@{
        Timestamp         = Get-Date
        FindingType       = $FindingType
        Severity          = $Severity
        Value             = $Value
        SamAccountName    = $UserObject.SamAccountName
        DisplayName       = $UserObject.DisplayName
        Enabled           = $UserObject.Enabled
        UserPrincipalName = $UserObject.UserPrincipalName
        Mail              = $UserObject.mail
        MailNickname      = $UserObject.mailNickname
        DistinguishedName = $UserObject.DistinguishedName
        Notes             = $Notes
    }
}

function Test-IsValidUpn {
    param([string]$Upn)
    if ([string]::IsNullOrWhiteSpace($Upn)) { return $false }
    # Basic sanity: user@domain.tld (not full RFC validation)
    return ($Upn -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
}

function Get-UpnSuffix {
    param([string]$Upn)
    if ([string]::IsNullOrWhiteSpace($Upn)) { return $null }
    if ($Upn -notmatch '@') { return $null }
    return ($Upn.Split('@')[-1]).ToLowerInvariant()
}

function Test-IsValidEmailLike {
    param([string]$Email)
    if ([string]::IsNullOrWhiteSpace($Email)) { return $false }
    return ($Email -match '^[^@\s]+@[^@\s]+\.[^@\s]+$')
}

function Test-IsValidMailNickname {
    param([string]$Nick)
    if ([string]::IsNullOrWhiteSpace($Nick)) { return $false }

    # Conservative allowed set:
    # letters, digits, dot, underscore, hyphen
    # (avoids spaces and many special characters that often cause downstream issues)
    return ($Nick -match '^[A-Za-z0-9._-]+$')
}

# Pull user set
$params = @{
    Filter     = '*'
    Properties = @(
        'Enabled','DisplayName','UserPrincipalName','mail','mailNickname','proxyAddresses','DistinguishedName'
    )
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

$users = Get-ADUser @params

if (-not $IncludeDisabled) {
    $users = $users | Where-Object { $_.Enabled -eq $true }
}

$findings = New-Object System.Collections.Generic.List[object]

# 1) Per-user validations (UPN, mail, mailNickname)
foreach ($u in $users) {

    # UPN missing/invalid
    if ([string]::IsNullOrWhiteSpace($u.UserPrincipalName)) {
        $findings.Add((New-Finding -FindingType 'UPN_Missing' -Severity 'High' -Value $null -UserObject $u -Notes 'UserPrincipalName is empty.'))
    }
    elseif (-not (Test-IsValidUpn -Upn $u.UserPrincipalName)) {
        $findings.Add((New-Finding -FindingType 'UPN_InvalidFormat' -Severity 'High' -Value $u.UserPrincipalName -UserObject $u -Notes 'UPN does not match basic user@domain format.'))
    }
    else {
        # Optional: enforce allowed suffix list
        if ($AllowedUpnSuffixes -and $AllowedUpnSuffixes.Count -gt 0) {
            $suffix = Get-UpnSuffix -Upn $u.UserPrincipalName
            $allowed = $AllowedUpnSuffixes | ForEach-Object { $_.ToLowerInvariant() }
            if ($suffix -and ($allowed -notcontains $suffix)) {
                $findings.Add((New-Finding -FindingType 'UPN_SuffixNotAllowed' -Severity 'Medium' -Value $u.UserPrincipalName -UserObject $u -Notes "UPN suffix '$suffix' not in AllowedUpnSuffixes."))
            }
        }
    }

    # Optional: mail checks
    if ($IncludeMailChecks) {
        if ([string]::IsNullOrWhiteSpace($u.mail)) {
            $findings.Add((New-Finding -FindingType 'Mail_Missing' -Severity 'Medium' -Value $null -UserObject $u -Notes 'mail attribute is empty.'))
        }
        elseif (-not (Test-IsValidEmailLike -Email $u.mail)) {
            $findings.Add((New-Finding -FindingType 'Mail_InvalidFormat' -Severity 'Medium' -Value $u.mail -UserObject $u -Notes 'mail does not match basic user@domain format.'))
        }
    }

    # Optional: mailNickname checks
    if ($IncludeMailNicknameChecks) {
        if ([string]::IsNullOrWhiteSpace($u.mailNickname)) {
            $findings.Add((New-Finding -FindingType 'MailNickname_Missing' -Severity 'Medium' -Value $null -UserObject $u -Notes 'mailNickname is empty.'))
        }
        elseif (-not (Test-IsValidMailNickname -Nick $u.mailNickname)) {
            $findings.Add((New-Finding -FindingType 'MailNickname_InvalidChars' -Severity 'Medium' -Value $u.mailNickname -UserObject $u -Notes 'mailNickname contains characters outside [A-Za-z0-9._-].'))
        }
    }
}

# 2) Duplicate UPN detection (case-insensitive)
$upnDupes = $users |
    Where-Object { $_.UserPrincipalName } |
    ForEach-Object {
        [PSCustomObject]@{
            UpnLower = $_.UserPrincipalName.ToLowerInvariant()
            User     = $_
        }
    } |
    Group-Object -Property UpnLower |
    Where-Object { $_.Count -gt 1 }

foreach ($group in $upnDupes) {
    $upn = $group.Group[0].User.UserPrincipalName
    foreach ($entry in $group.Group) {
        $u = $entry.User
        $findings.Add((New-Finding -FindingType 'UPN_Duplicate' -Severity 'High' -Value $upn -UserObject $u -Notes 'Duplicate UPN detected (case-insensitive).'))
    }
}

# 3) Duplicate proxyAddresses detection (optional, case-insensitive)
if ($IncludeProxyDuplicates) {

    $proxyFlat = foreach ($u in $users) {
        foreach ($p in @($u.proxyAddresses)) {
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                [PSCustomObject]@{
                    ProxyLower = $p.ToLowerInvariant()
                    Proxy      = $p
                    User       = $u
                }
            }
        }
    }

    $proxyDupes = $proxyFlat |
        Group-Object -Property ProxyLower |
        Where-Object { $_.Count -gt 1 }

    foreach ($group in $proxyDupes) {
        $proxyVal = $group.Group[0].Proxy
        foreach ($entry in $group.Group) {
            $u = $entry.User
            $findings.Add((New-Finding -FindingType 'ProxyAddress_Duplicate' -Severity 'High' -Value $proxyVal -UserObject $u -Notes 'Duplicate proxyAddresses detected (case-insensitive).'))
        }
    }
}

# Output findings
$findings | Sort-Object Severity, FindingType, SamAccountName
