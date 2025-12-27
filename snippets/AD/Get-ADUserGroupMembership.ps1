<#
.SYNOPSIS
Gets AD group memberships for a user (direct and/or nested).

.DESCRIPTION
Returns an object list of the groups the user belongs to.
By default returns direct memberships (MemberOf).
With -Recursive, returns nested memberships as well by querying the user's token groups.

.PARAMETER SamAccountName
The user's samAccountName.

.PARAMETER Recursive
If specified, returns nested memberships (token groups), not just direct MemberOf.

.PARAMETER IncludeGroupDetails
If specified, attempts to enrich output with group description and group scope/category.

.EXAMPLE
.\Get-ADUserGroupMembership.ps1 -SamAccountName jdoe

.EXAMPLE
.\Get-ADUserGroupMembership.ps1 -SamAccountName jdoe -Recursive

.EXAMPLE
.\Get-ADUserGroupMembership.ps1 -SamAccountName jdoe -Recursive -IncludeGroupDetails |
  Export-Csv C:\Reports\jdoe-groups.csv -NoTypeInformation

.NOTES
Requires RSAT ActiveDirectory module.
TokenGroups requires domain connectivity and appropriate rights.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName,

    [Parameter()]
    [switch]$Recursive,

    [Parameter()]
    [switch]$IncludeGroupDetails
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$user = Get-ADUser -Identity $SamAccountName -Properties MemberOf, TokenGroups, UserPrincipalName, DisplayName

# Direct memberships: Distinguished Names from MemberOf
$groupDns = @()
if (-not $Recursive) {
    $groupDns = @($user.MemberOf)
}
else {
    # Recursive memberships: TokenGroups returns SIDs -> resolve to groups
    $sids = @($user.TokenGroups)
    if ($sids.Count -eq 0) {
        $groupDns = @()
    }
    else {
        $groupDns = foreach ($sid in $sids) {
            try {
                (Get-ADGroup -Identity $sid -ErrorAction Stop).DistinguishedName
            }
            catch {
                # Some SIDs may not resolve to groups; ignore quietly (still object-first output)
                $null
            }
        }
        $groupDns = $groupDns | Where-Object { $_ }
    }
}

if (-not $groupDns -or $groupDns.Count -eq 0) {
    Write-Verbose "No group memberships found for $SamAccountName (Recursive=$Recursive)."
    return
}

$results = foreach ($dn in ($groupDns | Sort-Object -Unique)) {
    if ($IncludeGroupDetails) {
        $g = Get-ADGroup -Identity $dn -Properties Description, GroupScope, GroupCategory
        [PSCustomObject]@{
            SamAccountName      = $user.SamAccountName
            UserPrincipalName   = $user.UserPrincipalName
            DisplayName         = $user.DisplayName
            Recursive           = [bool]$Recursive
            GroupName           = $g.Name
            GroupSamAccountName = $g.SamAccountName
            GroupScope          = $g.GroupScope
            GroupCategory       = $g.GroupCategory
            Description         = $g.Description
            DistinguishedName   = $g.DistinguishedName
        }
    }
    else {
        $g = Get-ADGroup -Identity $dn -Properties SamAccountName
        [PSCustomObject]@{
            SamAccountName      = $user.SamAccountName
            UserPrincipalName   = $user.UserPrincipalName
            DisplayName         = $user.DisplayName
            Recursive           = [bool]$Recursive
            GroupName           = $g.Name
            GroupSamAccountName = $g.SamAccountName
            DistinguishedName   = $g.DistinguishedName
        }
    }
}

# Default presentation is object output; caller can format/export as needed.
$results | Sort-Object GroupName
