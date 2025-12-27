<#
.SYNOPSIS
Returns a high-signal AD user summary for rapid triage.

.DESCRIPTION
Outputs a single object with the most common fields needed during helpdesk escalation,
incident response, and access troubleshooting.

.PARAMETER SamAccountName
User samAccountName to query.

.EXAMPLE
.\Get-ADUserSummary.ps1 -SamAccountName jdoe

.NOTES
Requires RSAT ActiveDirectory module.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$u = Get-ADUser -Identity $SamAccountName -Properties `
    Enabled, LockedOut, PasswordLastSet, PasswordNeverExpires, PasswordExpired, AccountExpirationDate, LastLogonDate, LastLogonTimeStamp, `
    UserPrincipalName, mail, DisplayName, Department, Title, Manager, DistinguishedName, MemberOf, whenCreated, whenChanged

$ou = $null
if ($u.DistinguishedName -match '^CN=.*?,(OU=.*)$') { $ou = $Matches[1] }

$llts = $null
if ($u.LastLogonTimeStamp -and $u.LastLogonTimeStamp -gt 0) {
    $llts = [DateTime]::FromFileTime($u.LastLogonTimeStamp)
}

$managerName = $null
if ($u.Manager) {
    try { $managerName = (Get-ADUser -Identity $u.Manager -Properties DisplayName).DisplayName } catch { }
}

[PSCustomObject]@{
    SamAccountName       = $u.SamAccountName
    DisplayName          = $u.DisplayName
    UserPrincipalName    = $u.UserPrincipalName
    Mail                 = $u.mail
    Enabled              = $u.Enabled
    LockedOut            = $u.LockedOut
    PasswordLastSet      = $u.PasswordLastSet
    PasswordNeverExpires = $u.PasswordNeverExpires
    PasswordExpired      = $u.PasswordExpired
    AccountExpirationDate= $u.AccountExpirationDate
    LastLogonDate        = $u.LastLogonDate
    LastLogonTimeStamp   = $llts
    GroupCount_Direct    = (@($u.MemberOf).Count)
    Department           = $u.Department
    Title                = $u.Title
    Manager              = $managerName
    OU                   = $ou
    WhenCreated          = $u.whenCreated
    WhenChanged          = $u.whenChanged
}
