<#
.SYNOPSIS
Finds duplicate UserPrincipalName and proxyAddresses values in Active Directory.

.DESCRIPTION
Duplicate UPN and proxyAddresses are common causes of hybrid sync failures and mail issues.
This script searches users for duplicates and outputs findings as objects.

.PARAMETER SearchBase
Optional OU DN to scope the search.

.PARAMETER IncludeDisabled
Include disabled user accounts (default: True).

.EXAMPLE
.\Find-ADDuplicateUPNProxyAddresses.ps1

.EXAMPLE
.\Find-ADDuplicateUPNProxyAddresses.ps1 -SearchBase "OU=Users,DC=contoso,DC=com"

.NOTES
Requires RSAT ActiveDirectory module.
proxyAddresses matching is case-insensitive.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [bool]$IncludeDisabled = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$params = @{
    Filter     = '*'
    Properties = @('UserPrincipalName','proxyAddresses','Enabled','DistinguishedName','SamAccountName','DisplayName')
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

$users = Get-ADUser @params

if (-not $IncludeDisabled) {
    $users = $users | Where-Object { $_.Enabled -eq $true }
}

# --------- Duplicate UPNs ----------
$upnDupes = $users |
    Where-Object { $_.UserPrincipalName } |
    Group-Object -Property UserPrincipalName |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object {
        $upn = $_.Name
        foreach ($u in $_.Group) {
            [PSCustomObject]@{
                DuplicateType     = 'UserPrincipalName'
                Value             = $upn
                SamAccountName    = $u.SamAccountName
                DisplayName       = $u.DisplayName
                Enabled           = $u.Enabled
                DistinguishedName = $u.DistinguishedName
            }
        }
    }

# --------- Duplicate proxyAddresses ----------
# Flatten: one record per proxyAddress value
$proxyFlat = foreach ($u in $users) {
    foreach ($p in @($u.proxyAddresses)) {
        if ($p) {
            [PSCustomObject]@{
                ProxyLower        = $p.ToLowerInvariant()
                ProxyOriginal     = $p
                SamAccountName    = $u.SamAccountName
                DisplayName       = $u.DisplayName
                Enabled           = $u.Enabled
                DistinguishedName = $u.DistinguishedName
            }
        }
    }
}

$proxyDupes = $proxyFlat |
    Group-Object -Property ProxyLower |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object {
        $val = $_.Group[0].ProxyOriginal
        foreach ($rec in $_.Group) {
            [PSCustomObject]@{
                DuplicateType     = 'proxyAddresses'
                Value             = $val
                SamAccountName    = $rec.SamAccountName
                DisplayName       = $rec.DisplayName
                Enabled           = $rec.Enabled
                DistinguishedName = $rec.DistinguishedName
            }
        }
    }

$upnDupes + $proxyDupes
