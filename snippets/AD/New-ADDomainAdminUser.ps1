<#
.SYNOPSIS
Creates a new AD user and adds to Domain Admins.

.DESCRIPTION
Creates a user in a specified OU, sets a temporary password, forces password change,
and adds the user to "Domain Admins". Supports -WhatIf.

.PARAMETER SamAccountName
sAMAccountName for the new user (e.g., jake.admin)

.PARAMETER DisplayName
Display name (e.g., Jake Admin)

.PARAMETER UserPrincipalName
UPN (e.g., jake.admin@contoso.com)

.PARAMETER OU
DistinguishedName of OU where the user will be created.

.PARAMETER TempPassword
Temporary password to set.

.EXAMPLE
.\New-ADDomainAdminUser.ps1 -SamAccountName jake.admin -DisplayName "Jake Admin" -UserPrincipalName jake.admin@contoso.com `
  -OU "OU=Admin Accounts,DC=contoso,DC=com" -TempPassword "LBTemp2025!!" -WhatIf

.NOTES
High impact. Validate OU and naming conventions carefully.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DisplayName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$UserPrincipalName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OU,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TempPassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

# Validate OU exists
$null = Get-ADOrganizationalUnit -Identity $OU -ErrorAction Stop

# Validate user does not exist
if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction Stop) {
    throw "User already exists: $SamAccountName"
}

$securePw = ConvertTo-SecureString $TempPassword -AsPlainText -Force

$createAction = "Create user '$SamAccountName' in '$OU'"
if ($PSCmdlet.ShouldProcess($SamAccountName, $createAction)) {
    New-ADUser `
        -Name $DisplayName `
        -DisplayName $DisplayName `
        -SamAccountName $SamAccountName `
        -UserPrincipalName $UserPrincipalName `
        -Path $OU `
        -AccountPassword $securePw `
        -Enabled $true `
        -ErrorAction Stop

    Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
}

$group = "Domain Admins"
$addAction = "Add '$SamAccountName' to '$group'"
if ($PSCmdlet.ShouldProcess($group, $addAction)) {
    Add-ADGroupMember -Identity $group -Members $SamAccountName -ErrorAction Stop
}

[PSCustomObject]@{
    SamAccountName     = $SamAccountName
    DisplayName        = $DisplayName
    UserPrincipalName  = $UserPrincipalName
    OU                = $OU
    AddedToGroup       = $group
    PasswordChangeNext = $true
}
