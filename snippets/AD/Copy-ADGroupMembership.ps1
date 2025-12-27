<#
.SYNOPSIS
Copies AD group membership from one user to another.

.DESCRIPTION
Adds the target user to the same groups as the source user.
Optionally excludes specific groups and supports -WhatIf.

.PARAMETER SourceSamAccountName
Source user (samAccountName) to copy membership from.

.PARAMETER TargetSamAccountName
Target user (samAccountName) to copy membership to.

.PARAMETER ExcludeGroups
Group names (sAMAccountName or CN) to exclude.

.EXAMPLE
.\Copy-ADGroupMembership.ps1 -SourceSamAccountName jsmith -TargetSamAccountName jdoe -WhatIf

.NOTES
Requires RSAT ActiveDirectory module.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceSamAccountName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TargetSamAccountName,

    [Parameter()]
    [string[]]$ExcludeGroups = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$source = Get-ADUser -Identity $SourceSamAccountName -Properties MemberOf
$target = Get-ADUser -Identity $TargetSamAccountName -Properties MemberOf

$sourceGroupsDn = @($source.MemberOf)
if (-not $sourceGroupsDn -or $sourceGroupsDn.Count -eq 0) {
    Write-Verbose "Source user has no group memberships."
    return
}

# Resolve DN to group name so exclusion is usable
$groups = foreach ($dn in $sourceGroupsDn) {
    $g = Get-ADGroup -Identity $dn -Properties SamAccountName, Name
    [PSCustomObject]@{
        DistinguishedName = $g.DistinguishedName
        SamAccountName    = $g.SamAccountName
        Name              = $g.Name
    }
}

if ($ExcludeGroups.Count -gt 0) {
    $groups = $groups | Where-Object {
        ($ExcludeGroups -notcontains $_.SamAccountName) -and
        ($ExcludeGroups -notcontains $_.Name)
    }
}

$results = foreach ($g in $groups) {
    $action = "Add '$($target.SamAccountName)' to group '$($g.Name)'"
    try {
        if ($PSCmdlet.ShouldProcess($g.DistinguishedName, $action)) {
            Add-ADGroupMember -Identity $g.DistinguishedName -Members $target.DistinguishedName -ErrorAction Stop
        }

        [PSCustomObject]@{
            SourceUser = $source.SamAccountName
            TargetUser = $target.SamAccountName
            GroupName  = $g.Name
            GroupSam   = $g.SamAccountName
            Result     = "Success"
            Reason     = $null
        }
    }
    catch {
        [PSCustomObject]@{
            SourceUser = $source.SamAccountName
            TargetUser = $target.SamAccountName
            GroupName  = $g.Name
            GroupSam   = $g.SamAccountName
            Result     = "Failed"
            Reason     = $_.Exception.Message
        }
    }
}

$results
