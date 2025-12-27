<#
.SYNOPSIS
Offboards an AD user: disable account, move to OU, stamp description, optionally clear attributes and remove group memberships.

.DESCRIPTION
This script performs a standardized offboarding workflow:
- Validates the user exists
- Disables the account
- Optionally moves the user to a target OU
- Stamps Description (audit/ticket context)
- Optionally clears Manager and/or selected attributes
- Optionally removes direct group memberships (with exclusion list)
- Returns an object report of actions taken and any failures

Designed to be safe to run multiple times; supports -WhatIf.

.PARAMETER SamAccountName
User samAccountName.

.PARAMETER TargetOU
DistinguishedName of the OU to move the user into (e.g. "OU=Disabled Users,DC=contoso,DC=com").
If omitted, user is not moved.

.PARAMETER Ticket
Optional ticket/reference to embed in Description.

.PARAMETER Notes
Optional freeform text to embed in Description (e.g., reason for termination).

.PARAMETER ClearManager
If set, clears the user's Manager attribute.

.PARAMETER ClearAttributes
If set, clears a conservative set of attributes often used for org chart / contact info.
By default clears: Title, Department, Office, TelephoneNumber, MobilePhone, HomePhone, Pager, Fax, Company.
(Does NOT clear mail/UPN by default.)

.PARAMETER RemoveGroups
If set, removes the user from direct group memberships (MemberOf).

.PARAMETER ExcludeGroups
Groups to never remove (by Name or SamAccountName). Default includes common safe baselines.

.PARAMETER DisableInsteadOfRemoveFromProtectedGroups
If set, does NOT attempt removal from protected groups (e.g., Domain Admins) and reports them instead.

.EXAMPLE
.\Disable-ADUserAndMoveToOU.ps1 -SamAccountName jdoe -TargetOU "OU=Disabled Users,DC=contoso,DC=com" -Ticket 12345 -Notes "Terminated" -WhatIf

.EXAMPLE
.\Disable-ADUserAndMoveToOU.ps1 -SamAccountName jdoe -TargetOU "OU=Disabled Users,DC=contoso,DC=com" -Ticket 12345 -ClearManager -ClearAttributes -RemoveGroups

.NOTES
Requires RSAT ActiveDirectory module.
High impact. Review ExcludeGroups and OU destination for your environment.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetOU,

    [Parameter()]
    [string]$Ticket,

    [Parameter()]
    [string]$Notes,

    [Parameter()]
    [switch]$ClearManager,

    [Parameter()]
    [switch]$ClearAttributes,

    [Parameter()]
    [switch]$RemoveGroups,

    [Parameter()]
    [string[]]$ExcludeGroups = @(
        # Common baseline groups (adjust to your org)
        'Domain Users',
        'Authenticated Users'
    ),

    [Parameter()]
    [switch]$DisableInsteadOfRemoveFromProtectedGroups
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

function New-ActionResult {
    param(
        [string]$Step,
        [string]$Result,
        [string]$Message
    )
    [PSCustomObject]@{
        Timestamp = Get-Date
        Computer  = $env:COMPUTERNAME
        User      = $SamAccountName
        Step      = $Step
        Result    = $Result
        Message   = $Message
    }
}

$results = New-Object System.Collections.Generic.List[object]

# Validate user
try {
    $user = Get-ADUser -Identity $SamAccountName -Properties `
        Enabled, DistinguishedName, Description, MemberOf, Manager, UserPrincipalName, DisplayName, mail
}
catch {
    throw "User not found: $SamAccountName. $($_.Exception.Message)"
}

# Validate OU (if provided)
if ($PSBoundParameters.ContainsKey('TargetOU')) {
    try {
        $null = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop
    }
    catch {
        throw "TargetOU not found or not accessible: $TargetOU. $($_.Exception.Message)"
    }
}

# Build Description stamp
$stampParts = New-Object System.Collections.Generic.List[string]
$stampParts.Add("OFFBOARDED")
$stampParts.Add((Get-Date -Format "yyyy-MM-dd HH:mm"))
if ($Ticket) { $stampParts.Add("Ticket:$Ticket") }
if ($Notes)  { $stampParts.Add($Notes) }
$stamp = ($stampParts -join " | ")

# 1) Disable account
try {
    if ($user.Enabled -eq $true) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Disable AD account")) {
            Disable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop
        }
        $results.Add((New-ActionResult -Step "DisableAccount" -Result "Success" -Message "Account disabled."))
    }
    else {
        $results.Add((New-ActionResult -Step "DisableAccount" -Result "Skipped" -Message "Account already disabled."))
    }
}
catch {
    $results.Add((New-ActionResult -Step "DisableAccount" -Result "Failed" -Message $_.Exception.Message))
}

# 2) Stamp Description
try {
    $newDesc = $stamp
    if ($PSCmdlet.ShouldProcess($SamAccountName, "Set Description to '$newDesc'")) {
        Set-ADUser -Identity $user.DistinguishedName -Description $newDesc -ErrorAction Stop
    }
    $results.Add((New-ActionResult -Step "StampDescription" -Result "Success" -Message "Description updated."))
}
catch {
    $results.Add((New-ActionResult -Step "StampDescription" -Result "Failed" -Message $_.Exception.Message))
}

# 3) Clear Manager
if ($ClearManager) {
    try {
        if ($user.Manager) {
            if ($PSCmdlet.ShouldProcess($SamAccountName, "Clear Manager attribute")) {
                Set-ADUser -Identity $user.DistinguishedName -Clear Manager -ErrorAction Stop
            }
            $results.Add((New-ActionResult -Step "ClearManager" -Result "Success" -Message "Manager cleared."))
        }
        else {
            $results.Add((New-ActionResult -Step "ClearManager" -Result "Skipped" -Message "Manager already empty."))
        }
    }
    catch {
        $results.Add((New-ActionResult -Step "ClearManager" -Result "Failed" -Message $_.Exception.Message))
    }
}

# 4) Clear selected attributes
if ($ClearAttributes) {
    # Conservative list (safe defaults): does NOT clear UPN/mail by default.
    $clearList = @(
        'Title','Department','Office','TelephoneNumber','MobilePhone','HomePhone','Pager','FacsimileTelephoneNumber','Company'
    )

    try {
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Clear attributes: $($clearList -join ', ')")) {
            Set-ADUser -Identity $user.DistinguishedName -Clear $clearList -ErrorAction Stop
        }
        $results.Add((New-ActionResult -Step "ClearAttributes" -Result "Success" -Message "Cleared: $($clearList -join ', ')"))
    }
    catch {
        $results.Add((New-ActionResult -Step "ClearAttributes" -Result "Failed" -Message $_.Exception.Message))
    }
}

# 5) Move to Disabled OU
if ($PSBoundParameters.ContainsKey('TargetOU')) {
    try {
        # Only move if not already under target OU
        if ($user.DistinguishedName -notlike "*,$TargetOU") {
            if ($PSCmdlet.ShouldProcess($SamAccountName, "Move user to OU '$TargetOU'")) {
                Move-ADObject -Identity $user.DistinguishedName -TargetPath $TargetOU -ErrorAction Stop
            }
            $results.Add((New-ActionResult -Step "MoveToOU" -Result "Success" -Message "Moved to: $TargetOU"))
        }
        else {
            $results.Add((New-ActionResult -Step "MoveToOU" -Result "Skipped" -Message "User already in target OU."))
        }
    }
    catch {
        $results.Add((New-ActionResult -Step "MoveToOU" -Result "Failed" -Message $_.Exception.Message))
    }
}

# 6) Remove group memberships (direct MemberOf)
if ($RemoveGroups) {
    try {
        $current = Get-ADUser -Identity $SamAccountName -Properties MemberOf
        $groupDns = @($current.MemberOf)

        if (-not $groupDns -or $groupDns.Count -eq 0) {
            $results.Add((New-ActionResult -Step "RemoveGroups" -Result "Skipped" -Message "No direct group memberships found."))
        }
        else {
            foreach ($dn in $groupDns) {
                $g = $null
                try { $g = Get-ADGroup -Identity $dn -Properties Name, SamAccountName } catch { }

                $gName = $g?.Name
                $gSam  = $g?.SamAccountName

                # Exclusion match by Name or SamAccountName (if resolvable)
                $excluded = $false
                if ($gName -and ($ExcludeGroups -contains $gName)) { $excluded = $true }
                if ($gSam  -and ($ExcludeGroups -contains $gSam))  { $excluded = $true }

                if ($excluded) {
                    $results.Add((New-ActionResult -Step "RemoveGroups" -Result "Skipped" -Message "Excluded group: $($gName ?? $dn)"))
                    continue
                }

                # Protected groups: optionally don't attempt removal
                $protected = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')
                if ($DisableInsteadOfRemoveFromProtectedGroups -and $gName -and ($protected -contains $gName)) {
                    $results.Add((New-ActionResult -Step "RemoveGroups" -Result "Warning" -Message "Protected group detected (not removed): $gName"))
                    continue
                }

                $msg = "Remove from group: $($gName ?? $dn)"
                if ($PSCmdlet.ShouldProcess($SamAccountName, $msg)) {
                    Remove-ADGroupMember -Identity $dn -Members $SamAccountName -Confirm:$false -ErrorAction Stop
                }

                $results.Add((New-ActionResult -Step "RemoveGroups" -Result "Success" -Message $msg))
            }
        }
    }
    catch {
        $results.Add((New-ActionResult -Step "RemoveGroups" -Result "Failed" -Message $_.Exception.Message))
    }
}

# Final verification snapshot
try {
    $final = Get-ADUser -Identity $SamAccountName -Properties Enabled, DistinguishedName, Description, MemberOf, Manager
    $results.Add([PSCustomObject]@{
        Timestamp = Get-Date
        Computer  = $env:COMPUTERNAME
        User      = $SamAccountName
        Step      = "FinalState"
        Result    = "Info"
        Message   = "Final state snapshot"
        Enabled   = $final.Enabled
        DN        = $final.DistinguishedName
        Description = $final.Description
        Manager     = $final.Manager
        DirectGroupCount = (@($final.MemberOf).Count)
    })
}
catch {
    $results.Add((New-ActionResult -Step "FinalState" -Result "Warning" -Message "Could not retrieve final state: $($_.Exception.Message)"))
}

$results
