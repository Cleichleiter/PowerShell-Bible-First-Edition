<#
.SYNOPSIS
Onboarding mirror: enable AD user, move to OU, stamp description, and rehydrate group membership and selected attributes.

.DESCRIPTION
This script is designed to complement Disable-ADUserAndMoveToOU.ps1.

Core actions:
- Enables an existing AD user
- Optionally moves the user to a target OU
- Optionally stamps Description with onboarding context
- Optionally sets/reset password and forces change at logon
- Rehydrates group membership from:
    - a template user (copy direct group memberships), OR
    - a CSV file containing group names/sAMAccountName values
- Optionally rehydrates selected attributes (from template user)

Outputs a step-by-step object report suitable for ticketing.

.PARAMETER SamAccountName
Target user samAccountName to onboard/rehydrate.

.PARAMETER TargetOU
DistinguishedName of OU to move user into (e.g. "OU=Users,DC=contoso,DC=com").
If omitted, user is not moved.

.PARAMETER Ticket
Optional reference (ticket #) embedded in Description.

.PARAMETER Notes
Optional text embedded in Description.

.PARAMETER TempPassword
If provided, resets password to this value.

.PARAMETER ForcePasswordChangeAtLogon
If set with TempPassword, forces password change at next sign-in.

.PARAMETER TemplateSamAccountName
If provided, copies direct group memberships from this template user.

.PARAMETER CopyAttributesFromTemplate
If set, copies a conservative set of attributes from TemplateSamAccountName:
Title, Department, Office, Company, Manager, TelephoneNumber.

.PARAMETER GroupsCsvPath
If provided, reads group identifiers from CSV and adds target user to those groups.
CSV can have a column named: GroupSamAccountName OR GroupName.

.PARAMETER ExcludeGroups
Groups to never add (by Name or SamAccountName). Default includes common baseline groups.

.PARAMETER WhatIf
Shows what would happen without making changes.

.EXAMPLE
.\Enable-ADUserAndRehydrate.ps1 -SamAccountName jdoe -TargetOU "OU=Users,DC=contoso,DC=com" -Ticket 70001 -Notes "Rehire" `
  -TemplateSamAccountName "template.sales" -CopyAttributesFromTemplate -WhatIf

.EXAMPLE
.\Enable-ADUserAndRehydrate.ps1 -SamAccountName jdoe -TargetOU "OU=Users,DC=contoso,DC=com" -TempPassword "TempP@ss2025!" `
  -ForcePasswordChangeAtLogon -GroupsCsvPath "C:\Reports\jdoe-groups.csv"

.NOTES
Requires RSAT ActiveDirectory module.
This script assumes the user object already exists. If you need user creation, add a separate New-ADUser onboarding script.
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
    [ValidateNotNullOrEmpty()]
    [string]$TempPassword,

    [Parameter()]
    [switch]$ForcePasswordChangeAtLogon,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TemplateSamAccountName,

    [Parameter()]
    [switch]$CopyAttributesFromTemplate,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$GroupsCsvPath,

    [Parameter()]
    [string[]]$ExcludeGroups = @(
        'Domain Users',
        'Authenticated Users'
    )
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

# Validate target user exists
try {
    $user = Get-ADUser -Identity $SamAccountName -Properties `
        Enabled, DistinguishedName, Description, MemberOf, Manager, UserPrincipalName, DisplayName
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

# Validate template (if provided)
$templateUser = $null
if ($PSBoundParameters.ContainsKey('TemplateSamAccountName')) {
    try {
        $templateUser = Get-ADUser -Identity $TemplateSamAccountName -Properties `
            MemberOf, Title, Department, Office, Company, Manager, TelephoneNumber, DisplayName, UserPrincipalName
    }
    catch {
        throw "Template user not found: $TemplateSamAccountName. $($_.Exception.Message)"
    }
}

# Validate CSV (if provided)
$csvGroups = @()
if ($PSBoundParameters.ContainsKey('GroupsCsvPath')) {
    if (-not (Test-Path $GroupsCsvPath)) {
        throw "GroupsCsvPath does not exist: $GroupsCsvPath"
    }

    $csv = Import-Csv -Path $GroupsCsvPath
    if (-not $csv -or $csv.Count -eq 0) {
        throw "GroupsCsvPath contains no rows: $GroupsCsvPath"
    }

    # Accept either GroupSamAccountName or GroupName
    $csvGroups = foreach ($row in $csv) {
        if ($row.GroupSamAccountName) { $row.GroupSamAccountName }
        elseif ($row.GroupName)       { $row.GroupName }
    } | Where-Object { $_ } | Sort-Object -Unique

    if (-not $csvGroups -or $csvGroups.Count -eq 0) {
        throw "GroupsCsvPath did not include 'GroupSamAccountName' or 'GroupName' values."
    }
}

# Build Description stamp
$stampParts = New-Object System.Collections.Generic.List[string]
$stampParts.Add("ONBOARDED")
$stampParts.Add((Get-Date -Format "yyyy-MM-dd HH:mm"))
if ($Ticket) { $stampParts.Add("Ticket:$Ticket") }
if ($Notes)  { $stampParts.Add($Notes) }
$stamp = ($stampParts -join " | ")

# 1) Enable account
try {
    if ($user.Enabled -ne $true) {
        if ($PSCmdlet.ShouldProcess($SamAccountName, "Enable AD account")) {
            Enable-ADAccount -Identity $user.DistinguishedName -ErrorAction Stop
        }
        $results.Add((New-ActionResult -Step "EnableAccount" -Result "Success" -Message "Account enabled."))
    }
    else {
        $results.Add((New-ActionResult -Step "EnableAccount" -Result "Skipped" -Message "Account already enabled."))
    }
}
catch {
    $results.Add((New-ActionResult -Step "EnableAccount" -Result "Failed" -Message $_.Exception.Message))
}

# 2) Stamp Description
try {
    if ($PSCmdlet.ShouldProcess($SamAccountName, "Set Description to '$stamp'")) {
        Set-ADUser -Identity $user.DistinguishedName -Description $stamp -ErrorAction Stop
    }
    $results.Add((New-ActionResult -Step "StampDescription" -Result "Success" -Message "Description updated."))
}
catch {
    $results.Add((New-ActionResult -Step "StampDescription" -Result "Failed" -Message $_.Exception.Message))
}

# 3) Move to OU
if ($PSBoundParameters.ContainsKey('TargetOU')) {
    try {
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

# 4) Password reset (optional)
if ($PSBoundParameters.ContainsKey('TempPassword')) {
    try {
        $securePw = ConvertTo-SecureString $TempPassword -AsPlainText -Force

        if ($PSCmdlet.ShouldProcess($SamAccountName, "Reset password (temporary password set)")) {
            Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $securePw -ErrorAction Stop
        }

        if ($ForcePasswordChangeAtLogon) {
            if ($PSCmdlet.ShouldProcess($SamAccountName, "Force password change at next logon")) {
                Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $true -ErrorAction Stop
            }
        }

        $results.Add((New-ActionResult -Step "ResetPassword" -Result "Success" -Message "Password reset performed. (Password not output.)"))
    }
    catch {
        $results.Add((New-ActionResult -Step "ResetPassword" -Result "Failed" -Message $_.Exception.Message))
    }
}

# 5) Rehydrate attributes from template (optional)
if ($CopyAttributesFromTemplate) {
    if (-not $templateUser) {
        $results.Add((New-ActionResult -Step "CopyAttributesFromTemplate" -Result "Skipped" -Message "TemplateSamAccountName not provided."))
    }
    else {
        try {
            # Conservative attribute copy
            $setParams = @{
                Identity = $user.DistinguishedName
            }

            if ($templateUser.Title)          { $setParams['Title'] = $templateUser.Title }
            if ($templateUser.Department)     { $setParams['Department'] = $templateUser.Department }
            if ($templateUser.Office)         { $setParams['Office'] = $templateUser.Office }
            if ($templateUser.Company)        { $setParams['Company'] = $templateUser.Company }
            if ($templateUser.TelephoneNumber){ $setParams['OfficePhone'] = $templateUser.TelephoneNumber } # maps to OfficePhone
            if ($templateUser.Manager)        { $setParams['Manager'] = $templateUser.Manager }

            if ($setParams.Keys.Count -le 1) {
                $results.Add((New-ActionResult -Step "CopyAttributesFromTemplate" -Result "Skipped" -Message "No template attributes available to copy."))
            }
            else {
                if ($PSCmdlet.ShouldProcess($SamAccountName, "Copy selected attributes from template '$TemplateSamAccountName'")) {
                    Set-ADUser @setParams -ErrorAction Stop
                }
                $results.Add((New-ActionResult -Step "CopyAttributesFromTemplate" -Result "Success" -Message "Selected attributes copied from template."))
            }
        }
        catch {
            $results.Add((New-ActionResult -Step "CopyAttributesFromTemplate" -Result "Failed" -Message $_.Exception.Message))
        }
    }
}

# Helper: determine excluded group
function Test-ExcludedGroup {
    param(
        [string]$GroupName,
        [string]$GroupSam
    )
    if ($GroupName -and ($ExcludeGroups -contains $GroupName)) { return $true }
    if ($GroupSam  -and ($ExcludeGroups -contains $GroupSam))  { return $true }
    return $false
}

# 6) Rehydrate groups (template user)
if ($templateUser) {
    try {
        $groupDns = @($templateUser.MemberOf)
        if (-not $groupDns -or $groupDns.Count -eq 0) {
            $results.Add((New-ActionResult -Step "AddGroupsFromTemplate" -Result "Skipped" -Message "Template user has no direct group memberships."))
        }
        else {
            foreach ($dn in ($groupDns | Sort-Object -Unique)) {
                $g = $null
                try { $g = Get-ADGroup -Identity $dn -Properties Name, SamAccountName } catch { }

                $gName = $g?.Name
                $gSam  = $g?.SamAccountName

                if (Test-ExcludedGroup -GroupName $gName -GroupSam $gSam) {
                    $results.Add((New-ActionResult -Step "AddGroupsFromTemplate" -Result "Skipped" -Message "Excluded group: $($gName ?? $dn)"))
                    continue
                }

                $msg = "Add to group (template): $($gName ?? $dn)"
                if ($PSCmdlet.ShouldProcess($SamAccountName, $msg)) {
                    Add-ADGroupMember -Identity $dn -Members $SamAccountName -ErrorAction Stop
                }
                $results.Add((New-ActionResult -Step "AddGroupsFromTemplate" -Result "Success" -Message $msg))
            }
        }
    }
    catch {
        $results.Add((New-ActionResult -Step "AddGroupsFromTemplate" -Result "Failed" -Message $_.Exception.Message))
    }
}

# 7) Rehydrate groups (CSV)
if ($csvGroups.Count -gt 0) {
    try {
        foreach ($groupId in $csvGroups) {
            $g = $null
            try { $g = Get-ADGroup -Identity $groupId -Properties Name, SamAccountName } catch { }

            if (-not $g) {
                $results.Add((New-ActionResult -Step "AddGroupsFromCsv" -Result "Failed" -Message "Group not found: $groupId"))
                continue
            }

            if (Test-ExcludedGroup -GroupName $g.Name -GroupSam $g.SamAccountName) {
                $results.Add((New-ActionResult -Step "AddGroupsFromCsv" -Result "Skipped" -Message "Excluded group: $($g.Name)"))
                continue
            }

            $msg = "Add to group (CSV): $($g.Name)"
            if ($PSCmdlet.ShouldProcess($SamAccountName, $msg)) {
                Add-ADGroupMember -Identity $g.DistinguishedName -Members $SamAccountName -ErrorAction Stop
            }
            $results.Add((New-ActionResult -Step "AddGroupsFromCsv" -Result "Success" -Message $msg))
        }
    }
    catch {
        $results.Add((New-ActionResult -Step "AddGroupsFromCsv" -Result "Failed" -Message $_.Exception.Message))
    }
}

# Final verification snapshot
try {
    $final = Get-ADUser -Identity $SamAccountName -Properties Enabled, DistinguishedName, Description, MemberOf, Manager, Title, Department, Office, Company
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
        Title       = $final.Title
        Department  = $final.Department
        Office      = $final.Office
        Company     = $final.Company
        Manager     = $final.Manager
        DirectGroupCount = (@($final.MemberOf).Count)
    })
}
catch {
    $results.Add((New-ActionResult -Step "FinalState" -Result "Warning" -Message "Could not retrieve final state: $($_.Exception.Message)"))
}

$results
