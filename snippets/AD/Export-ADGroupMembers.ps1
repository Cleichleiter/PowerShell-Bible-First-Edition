<#
.SYNOPSIS
Exports AD group membership to CSV.

.DESCRIPTION
Exports direct or recursive group members for a specified AD group.
Outputs a CSV suitable for audits and access reviews.

.PARAMETER GroupIdentity
Group name, samAccountName, DN, or GUID accepted by Get-ADGroup.

.PARAMETER OutputPath
CSV output path.

.PARAMETER Recursive
If specified, includes nested group membership.

.EXAMPLE
.\Export-ADGroupMembers.ps1 -GroupIdentity "Domain Admins" -OutputPath "C:\Reports\DomainAdmins.csv" -Recursive

.NOTES
Requires RSAT ActiveDirectory module.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$GroupIdentity,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$Recursive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$group = Get-ADGroup -Identity $GroupIdentity -ErrorAction Stop

$members = if ($Recursive) {
    Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop
} else {
    Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
}

$results = foreach ($m in $members) {
    # For users/computers, try to enrich with display name / UPN where applicable
    $upn = $null
    $display = $null

    if ($m.objectClass -eq 'user') {
        try {
            $u = Get-ADUser -Identity $m.DistinguishedName -Properties UserPrincipalName, DisplayName -ErrorAction Stop
            $upn = $u.UserPrincipalName
            $display = $u.DisplayName
        } catch { }
    }

    [PSCustomObject]@{
        GroupName        = $group.Name
        GroupSamAccount  = $group.SamAccountName
        MemberName       = $m.Name
        MemberSamAccount = $m.SamAccountName
        MemberType       = $m.objectClass
        UserPrincipalName= $upn
        DisplayName      = $display
        DistinguishedName= $m.DistinguishedName
    }
}

# Ensure output folder exists
$parent = Split-Path -Path $OutputPath -Parent
if ($parent -and -not (Test-Path $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8

Write-Verbose "Exported $($results.Count) members to $OutputPath"
$results
