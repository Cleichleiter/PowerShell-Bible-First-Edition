<#
.SYNOPSIS
Exports privileged group membership snapshots (CSV) with an integrity manifest (SHA256).

.DESCRIPTION
Creates audit-friendly snapshots of sensitive AD group membership:
- Supports default privileged group list or custom group identities
- Supports direct membership or recursive membership expansion
- Exports to CSV (single file or per-group files)
- Generates a manifest JSON with member counts and SHA256 hashes for change tracking

.PARAMETER OutputFolder
Folder to write snapshot files into. Created if missing.

.PARAMETER GroupIdentities
Optional list of group identities (Name, SamAccountName, DN, GUID) to snapshot.
If not provided, a default privileged group list is used.

.PARAMETER Recursive
If set, expands nested membership.

.PARAMETER SplitPerGroup
If set, exports one CSV per group in addition to a combined CSV (optional).

.PARAMETER IncludeNonUsers
If set, includes non-user objects (groups, computers, etc.). Default is users only.

.PARAMETER IncludeUserDetails
If set, enriches user members with Enabled, LastLogonDate, PasswordLastSet, etc.

.PARAMETER IncludeDisabledUsers
If set, includes disabled users in results. Default: True.

.PARAMETER FilePrefix
Prefix for output file names.

.EXAMPLE
.\Export-ADPrivilegedGroupSnapshots.ps1 -OutputFolder C:\Reports\PrivSnapshots

.EXAMPLE
.\Export-ADPrivilegedGroupSnapshots.ps1 -OutputFolder C:\Reports\PrivSnapshots -Recursive -IncludeUserDetails -SplitPerGroup

.NOTES
Requires RSAT ActiveDirectory module.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputFolder,

    [Parameter()]
    [string[]]$GroupIdentities,

    [Parameter()]
    [switch]$Recursive,

    [Parameter()]
    [switch]$SplitPerGroup,

    [Parameter()]
    [switch]$IncludeNonUsers,

    [Parameter()]
    [switch]$IncludeUserDetails,

    [Parameter()]
    [bool]$IncludeDisabledUsers = $true,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$FilePrefix = 'PrivGroupSnapshot'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

# Default privileged groups (edit to fit your org)
$defaultGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Server Operators',
    'Backup Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
    'Cert Publishers'
)

if (-not $GroupIdentities -or $GroupIdentities.Count -eq 0) {
    $GroupIdentities = $defaultGroups
}

function Ensure-Folder {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function Try-GetGroup {
    param([Parameter(Mandatory)][string]$Identity)
    try { return Get-ADGroup -Identity $Identity -ErrorAction Stop } catch { return $null }
}

function Try-GetUserDetails {
    param([Parameter(Mandatory)][string]$Identity)

    $props = @(
        'Enabled','LockedOut','LastLogonDate','PasswordLastSet','PasswordNeverExpires','PasswordExpired',
        'UserPrincipalName','mail','Title','Department','Manager','DistinguishedName'
    )

    try {
        return Get-ADUser -Identity $Identity -Properties $props -ErrorAction Stop
    } catch {
        return $null
    }
}

function Sanitize-FileName {
    param([Parameter(Mandatory)][string]$Name)
    # Replace invalid filename chars with underscore
    $invalid = [IO.Path]::GetInvalidFileNameChars()
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Name.ToCharArray()) {
        if ($invalid -contains $ch) { [void]$sb.Append('_') }
        else { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

Ensure-Folder -Path $OutputFolder

$runId = Get-Date -Format "yyyyMMdd_HHmmss"
$combinedPath = Join-Path $OutputFolder "$FilePrefix-$runId.csv"
$manifestPath = Join-Path $OutputFolder "$FilePrefix-$runId.manifest.json"

$allRows = New-Object System.Collections.Generic.List[object]
$perGroupFiles = New-Object System.Collections.Generic.List[object]

foreach ($gId in $GroupIdentities) {

    $group = Try-GetGroup -Identity $gId
    if (-not $group) {
        # Write a "group not found" record into combined output for audit visibility
        $allRows.Add([PSCustomObject]@{
            SnapshotTime       = Get-Date
            GroupName          = $gId
            GroupSamAccountName= $null
            GroupDN            = $null
            Recursive          = [bool]$Recursive
            MemberType         = $null
            MemberName         = $null
            SamAccountName     = $null
            DistinguishedName  = $null
            DisplayName        = $null
            UserPrincipalName  = $null
            Mail               = $null
            Enabled            = $null
            LockedOut          = $null
            LastLogonDate      = $null
            PasswordLastSet    = $null
            PasswordNeverExpires= $null
            PasswordExpired    = $null
            Title              = $null
            Department         = $null
            Manager            = $null
            Finding            = 'GroupNotFound'
            Notes              = "Group '$gId' not found or not accessible."
        })
        continue
    }

    $members = @()
    try {
        $members = if ($Recursive) {
            Get-ADGroupMember -Identity $group.DistinguishedName -Recursive -ErrorAction Stop
        } else {
            Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
        }
    }
    catch {
        $allRows.Add([PSCustomObject]@{
            SnapshotTime       = Get-Date
            GroupName          = $group.Name
            GroupSamAccountName= $group.SamAccountName
            GroupDN            = $group.DistinguishedName
            Recursive          = [bool]$Recursive
            MemberType         = $null
            MemberName         = $null
            SamAccountName     = $null
            DistinguishedName  = $null
            DisplayName        = $null
            UserPrincipalName  = $null
            Mail               = $null
            Enabled            = $null
            LockedOut          = $null
            LastLogonDate      = $null
            PasswordLastSet    = $null
            PasswordNeverExpires= $null
            PasswordExpired    = $null
            Title              = $null
            Department         = $null
            Manager            = $null
            Finding            = 'GroupMemberQueryFailed'
            Notes              = $_.Exception.Message
        })
        continue
    }

    $groupRows = New-Object System.Collections.Generic.List[object]

    foreach ($m in $members) {

        if (-not $IncludeNonUsers -and $m.objectClass -ne 'user') {
            continue
        }

        $row = [ordered]@{
            SnapshotTime       = Get-Date
            GroupName          = $group.Name
            GroupSamAccountName= $group.SamAccountName
            GroupDN            = $group.DistinguishedName
            Recursive          = [bool]$Recursive
            MemberType         = $m.objectClass
            MemberName         = $m.Name
            SamAccountName     = $m.SamAccountName
            DistinguishedName  = $m.DistinguishedName
            DisplayName        = $null
            UserPrincipalName  = $null
            Mail               = $null
            Enabled            = $null
            LockedOut          = $null
            LastLogonDate      = $null
            PasswordLastSet    = $null
            PasswordNeverExpires= $null
            PasswordExpired    = $null
            Title              = $null
            Department         = $null
            Manager            = $null
            Finding            = 'PrivilegedGroupMember'
            Notes              = $null
        }

        if ($m.objectClass -eq 'user' -and $IncludeUserDetails) {
            $ud = Try-GetUserDetails -Identity $m.DistinguishedName
            if ($ud) {
                $row.DisplayName          = $ud.DisplayName
                $row.UserPrincipalName    = $ud.UserPrincipalName
                $row.Mail                 = $ud.mail
                $row.Enabled              = $ud.Enabled
                $row.LockedOut            = $ud.LockedOut
                $row.LastLogonDate        = $ud.LastLogonDate
                $row.PasswordLastSet      = $ud.PasswordLastSet
                $row.PasswordNeverExpires = $ud.PasswordNeverExpires
                $row.PasswordExpired      = $ud.PasswordExpired
                $row.Title                = $ud.Title
                $row.Department           = $ud.Department

                if (-not $IncludeDisabledUsers -and $ud.Enabled -eq $false) {
                    continue
                }

                if ($ud.Manager) {
                    try {
                        $mgr = Get-ADUser -Identity $ud.Manager -Properties DisplayName -ErrorAction Stop
                        $row.Manager = $mgr.DisplayName
                    } catch {
                        $row.Manager = $ud.Manager
                    }
                }
            }
            else {
                $row.Finding = 'UserDetailLookupFailed'
                $row.Notes   = 'User object could not be enriched.'
            }
        }
        elseif ($m.objectClass -eq 'user' -and -not $IncludeDisabledUsers) {
            # Lightweight disabled filter if not enriching
            try {
                $uLight = Get-ADUser -Identity $m.DistinguishedName -Properties Enabled -ErrorAction Stop
                if ($uLight.Enabled -eq $false) { continue }
            } catch { }
        }

        $obj = [PSCustomObject]$row
        $groupRows.Add($obj)
        $allRows.Add($obj)
    }

    if ($SplitPerGroup) {
        $safeName = Sanitize-FileName -Name $group.Name
        $path = Join-Path $OutputFolder "$FilePrefix-$runId-$safeName.csv"
        $groupRows | Sort-Object MemberType, SamAccountName, MemberName |
            Export-Csv -Path $path -NoTypeInformation -Encoding utf8

        $perGroupFiles.Add([PSCustomObject]@{
            GroupName   = $group.Name
            Path        = $path
            RowCount    = $groupRows.Count
            Sha256      = Get-Sha256Hex -Path $path
        })
    }
}

# Export combined CSV
$allRows | Sort-Object GroupName, MemberType, SamAccountName, MemberName |
    Export-Csv -Path $combinedPath -NoTypeInformation -Encoding utf8

# Build manifest
$manifest = [ordered]@{
    RunId               = $runId
    Timestamp           = Get-Date
    ComputerName        = $env:COMPUTERNAME
    Recursive           = [bool]$Recursive
    IncludeNonUsers     = [bool]$IncludeNonUsers
    IncludeUserDetails  = [bool]$IncludeUserDetails
    IncludeDisabledUsers= [bool]$IncludeDisabledUsers
    GroupsRequested     = $GroupIdentities
    CombinedCsv         = @{
        Path   = $combinedPath
        RowCount = $allRows.Count
        Sha256 = Get-Sha256Hex -Path $combinedPath
    }
    PerGroupCsvs        = @($perGroupFiles)
}

$manifest | ConvertTo-Json -Depth 6 | Out-File -FilePath $manifestPath -Encoding utf8

# Output summary object
[PSCustomObject]@{
    RunId        = $runId
    OutputFolder = $OutputFolder
    CombinedCsv  = $combinedPath
    ManifestJson = $manifestPath
    TotalRows    = $allRows.Count
    PerGroupFiles= @($perGroupFiles)
}
