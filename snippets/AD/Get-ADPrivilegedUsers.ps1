<#
.SYNOPSIS
Reports privileged users in Active Directory by enumerating membership of sensitive groups.

.DESCRIPTION
Enumerates members of common privileged AD groups (Domain Admins, Enterprise Admins, etc.).
Supports:
- Default "known privileged groups" list
- Custom group list
- Optional recursive membership expansion
- Optional user enrichment (Enabled, LastLogonDate, PasswordLastSet, etc.)
- Output as objects suitable for CSV export

.PARAMETER GroupIdentities
Optional list of group identities (Name, SamAccountName, DN, GUID) to audit.
If not provided, a default set of privileged groups is used.

.PARAMETER Recursive
If set, expands nested group membership (-Recursive).
If not set, returns direct group members only.

.PARAMETER IncludeGroupObjects
If set, includes group members that are groups/computers/etc. (not just users).

.PARAMETER IncludeDisabledUsers
If set, includes disabled users in results. Default: True.

.PARAMETER IncludeUserDetails
If set, enriches user objects with common triage fields.

.PARAMETER SearchBase
Optional OU DN to scope user enrichment queries (does not limit group membership resolution).

.EXAMPLE
.\Get-ADPrivilegedUsers.ps1

.EXAMPLE
.\Get-ADPrivilegedUsers.ps1 -Recursive -IncludeUserDetails |
  Export-Csv C:\Reports\PrivilegedUsers.csv -NoTypeInformation

.EXAMPLE
.\Get-ADPrivilegedUsers.ps1 -GroupIdentities "Domain Admins","Administrators" -Recursive

.NOTES
Requires RSAT ActiveDirectory module.
Enterprise Admins and Schema Admins may not exist in all environments (e.g., non-forest root contexts).
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$GroupIdentities,

    [Parameter()]
    [switch]$Recursive,

    [Parameter()]
    [switch]$IncludeGroupObjects,

    [Parameter()]
    [bool]$IncludeDisabledUsers = $true,

    [Parameter()]
    [switch]$IncludeUserDetails,

    [Parameter()]
    [string]$SearchBase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

# Default privileged groups (edit to fit your org)
$defaultGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
    'Cert Publishers'
)

if (-not $GroupIdentities -or $GroupIdentities.Count -eq 0) {
    $GroupIdentities = $defaultGroups
}

function Try-GetGroup {
    param([Parameter(Mandatory)][string]$Identity)

    try {
        return Get-ADGroup -Identity $Identity -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Try-GetUserDetails {
    param([Parameter(Mandatory)][string]$Identity)

    $props = @(
        'Enabled','LockedOut','LastLogonDate','PasswordLastSet','PasswordNeverExpires','PasswordExpired',
        'UserPrincipalName','mail','Title','Department','Manager','DistinguishedName'
    )

    $params = @{
        Identity   = $Identity
        Properties = $props
        ErrorAction= 'Stop'
    }
    if ($SearchBase) { $params['SearchBase'] = $SearchBase }

    try {
        return Get-ADUser @params
    }
    catch {
        return $null
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($gId in $GroupIdentities) {

    $group = Try-GetGroup -Identity $gId
    if (-not $group) {
        $results.Add([PSCustomObject]@{
            Timestamp         = Get-Date
            GroupName         = $gId
            GroupSamAccountName= $null
            GroupDN           = $null
            MemberType        = $null
            SamAccountName    = $null
            DisplayName       = $null
            UserPrincipalName = $null
            Enabled           = $null
            Finding           = 'GroupNotFound'
            Notes             = "Group '$gId' not found or not accessible."
        })
        continue
    }

    $members = @()
    try {
        if ($Recursive) {
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop
        }
        else {
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
        }
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp          = Get-Date
            GroupName          = $group.Name
            GroupSamAccountName= $group.SamAccountName
            GroupDN            = $group.DistinguishedName
            MemberType         = $null
            SamAccountName     = $null
            DisplayName        = $null
            UserPrincipalName  = $null
            Enabled            = $null
            Finding            = 'GroupMemberQueryFailed'
            Notes              = $_.Exception.Message
        })
        continue
    }

    foreach ($m in $members) {

        # If they only want users, skip non-users unless IncludeGroupObjects
        if (-not $IncludeGroupObjects -and $m.objectClass -ne 'user') {
            continue
        }

        # Build base record
        $base = [ordered]@{
            Timestamp          = Get-Date
            GroupName          = $group.Name
            GroupSamAccountName= $group.SamAccountName
            GroupDN            = $group.DistinguishedName
            Recursive          = [bool]$Recursive
            MemberType         = $m.objectClass
            MemberName         = $m.Name
            SamAccountName     = $m.SamAccountName
            DistinguishedName  = $m.DistinguishedName
            # User-enriched fields (nullable)
            DisplayName        = $null
            UserPrincipalName  = $null
            Mail               = $null
            Enabled            = $null
            LockedOut          = $null
            LastLogonDate      = $null
            PasswordLastSet    = $null
            PasswordNeverExpires= $null
            PasswordExpired    = $null
            Title              = $null
            Department         = $null
            Manager            = $null
            Finding            = 'PrivilegedGroupMember'
            Notes              = $null
        }

        if ($m.objectClass -eq 'user' -and $IncludeUserDetails) {
            $ud = Try-GetUserDetails -Identity $m.DistinguishedName

            if ($ud) {
                $base.DisplayName         = $ud.DisplayName
                $base.UserPrincipalName   = $ud.UserPrincipalName
                $base.Mail                = $ud.mail
                $base.Enabled             = $ud.Enabled
                $base.LockedOut           = $ud.LockedOut
                $base.LastLogonDate       = $ud.LastLogonDate
                $base.PasswordLastSet     = $ud.PasswordLastSet
                $base.PasswordNeverExpires= $ud.PasswordNeverExpires
                $base.PasswordExpired     = $ud.PasswordExpired
                $base.Title               = $ud.Title
                $base.Department          = $ud.Department

                if ($ud.Manager) {
                    try {
                        $mgr = Get-ADUser -Identity $ud.Manager -Properties DisplayName -ErrorAction Stop
                        $base.Manager = $mgr.DisplayName
                    } catch {
                        $base.Manager = $ud.Manager
                    }
                }

                if (-not $IncludeDisabledUsers -and $ud.Enabled -eq $false) {
                    continue
                }
            }
            else {
                $base.Finding = 'UserDetailLookupFailed'
                $base.Notes   = 'User object could not be enriched (permissions or object type mismatch).'
            }
        }
        elseif ($m.objectClass -eq 'user' -and -not $IncludeDisabledUsers) {
            # If not enriching, still allow filtering disabled by querying just Enabled (light)
            try {
                $uLight = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled -ErrorAction Stop
                if ($uLight.Enabled -eq $false) { continue }
            } catch { }
        }

        $results.Add([PSCustomObject]$base)
    }
}

# Stable ordering: group then member
$results |
    Sort-Object GroupName, MemberType, SamAccountName, MemberName
