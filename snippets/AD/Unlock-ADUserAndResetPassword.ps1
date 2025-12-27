<#
.SYNOPSIS
Unlocks an AD user (if locked) and optionally resets their password.

.DESCRIPTION
Common service desk / admin workflow:
- Validates user exists
- Unlocks account if LockedOut = True
- Optionally resets password and forces change at next logon

Supports -WhatIf for safe dry runs.

.PARAMETER SamAccountName
The user's samAccountName.

.PARAMETER NewTempPassword
Optional temporary password to set. If omitted, only unlock is performed.

.PARAMETER ForcePasswordChangeAtLogon
If provided with NewTempPassword, forces password change at next sign-in.

.EXAMPLE
.\Unlock-ADUserAndResetPassword.ps1 -SamAccountName jdoe -WhatIf

.EXAMPLE
.\Unlock-ADUserAndResetPassword.ps1 -SamAccountName jdoe -NewTempPassword "TempP@ss2025!" -ForcePasswordChangeAtLogon

.NOTES
Requires RSAT ActiveDirectory module.
Avoid logging plaintext passwords. This script does not output the password.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$NewTempPassword,

    [Parameter()]
    [switch]$ForcePasswordChangeAtLogon
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$user = Get-ADUser -Identity $SamAccountName -Properties LockedOut, Enabled, UserPrincipalName

if (-not $user.Enabled) {
    Write-Warning "User '$SamAccountName' is disabled. Unlock/reset may not resolve sign-in issues."
}

$didUnlock = $false
$didReset  = $false

# Unlock if needed
if ($user.LockedOut) {
    if ($PSCmdlet.ShouldProcess($SamAccountName, "Unlock AD account")) {
        Unlock-ADAccount -Identity $SamAccountName -ErrorAction Stop
    }
    $didUnlock = $true
}
else {
    Write-Verbose "User '$SamAccountName' is not locked out."
}

# Reset password if requested
if ($PSBoundParameters.ContainsKey('NewTempPassword')) {
    $securePw = ConvertTo-SecureString $NewTempPassword -AsPlainText -Force

    if ($PSCmdlet.ShouldProcess($SamAccountName, "Reset password (temporary password set)")) {
        Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $securePw -ErrorAction Stop
    }
    $didReset = $true

    if ($ForcePasswordChangeAtLogon) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Force password change at next logon")) {
            Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
        }
    }
}

# Return a verification snapshot
$after = Get-ADUser -Identity $SamAccountName -Properties LockedOut, Enabled, PasswordLastSet, UserPrincipalName

[PSCustomObject]@{
    SamAccountName       = $after.SamAccountName
    UserPrincipalName    = $after.UserPrincipalName
    Enabled              = $after.Enabled
    LockedOut            = $after.LockedOut
    PasswordLastSet      = $after.PasswordLastSet
    PerformedUnlock      = $didUnlock
    PerformedReset       = $didReset
    ForcedChangeAtLogon  = [bool]$ForcePasswordChangeAtLogon
}
