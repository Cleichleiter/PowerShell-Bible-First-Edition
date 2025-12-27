<#
.SYNOPSIS
Returns authentication-relevant status details for an AD user.

.DESCRIPTION
Outputs a single object with common fields used during account triage:
Enabled, LockedOut, PasswordLastSet, PasswordNeverExpires, PasswordExpired,
AccountExpirationDate, LastLogonDate, LastLogonTimeStamp (converted), and UPN.

.PARAMETER SamAccountName
The user's samAccountName.

.EXAMPLE
.\Get-ADUserAuthStatus.ps1 -SamAccountName jdoe

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

$user = Get-ADUser -Identity $SamAccountName -Properties `
    Enabled, LockedOut, PasswordLastSet, PasswordNeverExpires, PasswordExpired, AccountExpirationDate, LastLogonDate, LastLogonTimeStamp, UserPrincipalName

$llts = $null
if ($user.LastLogonTimeStamp -and $user.LastLogonTimeStamp -gt 0) {
    $llts = [DateTime]::FromFileTime($user.LastLogonTimeStamp)
}

[PSCustomObject]@{
    SamAccountName       = $user.SamAccountName
    UserPrincipalName    = $user.UserPrincipalName
    Enabled              = $user.Enabled
    LockedOut            = $user.LockedOut
    PasswordLastSet      = $user.PasswordLastSet
    PasswordNeverExpires = $user.PasswordNeverExpires
    PasswordExpired      = $user.PasswordExpired
    AccountExpirationDate= $user.AccountExpirationDate
    LastLogonDate        = $user.LastLogonDate
    LastLogonTimeStamp   = $llts
}
