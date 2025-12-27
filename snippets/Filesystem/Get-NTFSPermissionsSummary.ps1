<#
.SYNOPSIS
Summarizes NTFS permissions for a path (or paths) in an ops-friendly, reportable format.

.DESCRIPTION
Provides a high-signal view of NTFS ACLs without dumping raw Access collections.

Outputs one row per ACE (access rule) by default, with useful context:
- Owner, inheritance protection, inheritance flags
- Identity (optionally resolved)
- Rights, AccessControlType (Allow/Deny), AppliesTo scope
- Inherited vs explicit

Supports:
- Files and folders
- Multiple paths
- Optional recursion with depth limit
- Excluding inherited rules (explicit only)
- Filtering to common high-signal principals (Users/Everyone/Authenticated Users)
- CSV-ready object output for audits and migrations

.PARAMETER Path
One or more file/folder paths to inspect.

.PARAMETER ComputerName
Optional remote computer(s). Defaults to local. Requires PowerShell remoting.

.PARAMETER Recurse
Recursively inspect child directories (and optionally files).

.PARAMETER Depth
Limit recursion depth. 0 = just the root. Default: 0 unless -Recurse is used.

.PARAMETER IncludeFiles
Include files when recursing. Default: directories only (safer and faster).

.PARAMETER ExplicitOnly
Only return explicit (non-inherited) ACEs.

.PARAMETER IncludeOwner
Include the object owner (can be slow over many items).

.PARAMETER ResolveIdentity
Attempts to resolve SID -> NT account name where possible.

.PARAMETER FocusPrincipals
Limits output to high-signal principals (Everyone, Authenticated Users, Users, Domain Users, etc.).

.PARAMETER ExcludeInheritedFromParents
When recursing, skip children that simply inherit (no explicit ACL changes). Useful for large trees.

.EXAMPLE
.\Get-NTFSPermissionsSummary.ps1 -Path D:\Shares\Finance | Format-Table -Auto

.EXAMPLE
.\Get-NTFSPermissionsSummary.ps1 -Path D:\Shares -Recurse -Depth 2 -ExplicitOnly |
  Export-Csv C:\Reports\NTFS-Explicit-Acls.csv -NoTypeInformation

.EXAMPLE
.\Get-NTFSPermissionsSummary.ps1 -Path \\FS01\HR -FocusPrincipals | Format-Table -Auto

.EXAMPLE
.\Get-NTFSPermissionsSummary.ps1 -ComputerName FS01 -Path D:\Shares\Accounting -ExplicitOnly |
  Export-Csv C:\Reports\Accounting-Acls.csv -NoTypeInformation

.NOTES
Author: Cheri
Safe to run in production (read-only).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Path,

    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$Recurse,

    [Parameter()]
    [ValidateRange(0,100)]
    [int]$Depth = 0,

    [Parameter()]
    [switch]$IncludeFiles,

    [Parameter()]
    [switch]$ExplicitOnly,

    [Parameter()]
    [switch]$IncludeOwner,

    [Parameter()]
    [switch]$ResolveIdentity,

    [Parameter()]
    [switch]$FocusPrincipals,

    [Parameter()]
    [switch]$ExcludeInheritedFromParents
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AppliesTo {
    param(
        [System.Security.AccessControl.FileSystemAccessRule]$Rule
    )

    # AppliesTo logic (common readable mapping)
    $inh = $Rule.InheritanceFlags
    $prop = $Rule.PropagationFlags

    if ($inh -eq 'None') {
        return 'This folder/file only'
    }

    $containerInherit = ($inh -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0
    $objectInherit    = ($inh -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0

    if ($containerInherit -and $objectInherit) {
        return 'This folder, subfolders, and files'
    }
    elseif ($containerInherit) {
        return 'This folder and subfolders'
    }
    elseif ($objectInherit) {
        return 'This folder and files'
    }

    return 'Custom'
}

function Is-FocusPrincipal {
    param([string]$Identity)

    if (-not $Identity) { return $false }

    $i = $Identity.ToLowerInvariant()
    $focus = @(
        'everyone',
        'authenticated users',
        '\users',
        '\domain users',
        '\domain admins',
        '\administrators',
        'builtin\users',
        'builtin\administrators'
    )

    foreach ($f in $focus) {
        if ($i -like "*$f") { return $true }
    }

    return $false
}

function Resolve-IdentityBestEffort {
    param([string]$Identity)

    if (-not $Identity) { return $null }

    # If it's already DOMAIN\User format, keep it
    if ($Identity -match '^[^\\]+\\[^\\]+$') { return $Identity }

    # Try SID -> NTAccount
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($Identity)
        return ($sid.Translate([System.Security.Principal.NTAccount])).Value
    } catch {
        return $Identity
    }
}

function Get-AclRowsForItem {
    param(
        [string]$ItemPath,
        [bool]$ExplicitOnly,
        [bool]$IncludeOwner,
        [bool]$ResolveIdentity,
        [bool]$FocusPrincipals
    )

    $rows = New-Object System.Collections.Generic.List[object]

    try {
        $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop

        $owner = $null
        if ($IncludeOwner) {
            $owner = $acl.Owner
        }

        $isProtected = $acl.AreAccessRulesProtected

        foreach ($rule in $acl.Access) {

            # Filter: explicit only
            if ($ExplicitOnly -and $rule.IsInherited) { continue }

            $identity = $rule.IdentityReference.Value
            if ($ResolveIdentity) {
                $identity = Resolve-IdentityBestEffort -Identity $identity
            }

            if ($FocusPrincipals -and -not (Is-FocusPrincipal -Identity $identity)) {
                continue
            }

            $rows.Add([PSCustomObject]@{
                ComputerName           = $env:COMPUTERNAME
                Path                  = $ItemPath
                ItemType              = if ((Get-Item -LiteralPath $ItemPath -Force).PSIsContainer) { 'Directory' } else { 'File' }
                Owner                 = $owner
                InheritanceProtected  = $isProtected
                Identity              = $identity
                AccessType            = $rule.AccessControlType.ToString()
                Rights                = $rule.FileSystemRights.ToString()
                AppliesTo             = Get-AppliesTo -Rule $rule
                IsInherited           = [bool]$rule.IsInherited
                InheritanceFlags      = $rule.InheritanceFlags.ToString()
                PropagationFlags      = $rule.PropagationFlags.ToString()
            })
        }
    }
    catch {
        $rows.Add([PSCustomObject]@{
            ComputerName           = $env:COMPUTERNAME
            Path                  = $ItemPath
            ItemType              = $null
            Owner                 = $null
            InheritanceProtected  = $null
            Identity              = $null
            AccessType            = $null
            Rights                = $null
            AppliesTo             = $null
            IsInherited           = $null
            InheritanceFlags      = $null
            PropagationFlags      = $null
            Error                 = $_.Exception.Message
        })
    }

    $rows
}

function Get-ChildItemsByDepth {
    param(
        [string]$Root,
        [int]$Depth,
        [bool]$IncludeFiles
    )

    # Breadth-first traversal up to depth N
    $queue = New-Object System.Collections.Generic.Queue[object]
    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop

    $queue.Enqueue([PSCustomObject]@{ Path = $rootItem.FullName; Level = 0 })

    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        $nodePath = $node.Path
        $level = $node.Level

        # Yield current node
        $nodePath

        if ($level -ge $Depth) { continue }

        $children = Get-ChildItem -LiteralPath $nodePath -Force -ErrorAction SilentlyContinue
        foreach ($c in @($children)) {
            if ($c.PSIsContainer) {
                $queue.Enqueue([PSCustomObject]@{ Path = $c.FullName; Level = $level + 1 })
            } elseif ($IncludeFiles) {
                # Files are terminal
                $queue.Enqueue([PSCustomObject]@{ Path = $c.FullName; Level = $level + 1 })
            }
        }
    }
}

function Has-ExplicitAclChanges {
    param([string]$ItemPath)
    try {
        $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop
        if ($acl.AreAccessRulesProtected) { return $true } # inheritance blocked => meaningful
        foreach ($r in $acl.Access) {
            if (-not $r.IsInherited) { return $true }
        }
        return $false
    } catch {
        return $true # if we can't read, keep it (it matters)
    }
}

function Get-NTFSPermissionsSummaryLocal {
    param(
        [string[]]$Paths,
        [bool]$Recurse,
        [int]$Depth,
        [bool]$IncludeFiles,
        [bool]$ExplicitOnly,
        [bool]$IncludeOwner,
        [bool]$ResolveIdentity,
        [bool]$FocusPrincipals,
        [bool]$ExcludeInheritedFromParents
    )

    $all = New-Object System.Collections.Generic.List[object]

    foreach ($p in $Paths) {
        if (-not (Test-Path -LiteralPath $p)) {
            $all.Add([PSCustomObject]@{
                ComputerName = $env:COMPUTERNAME
                Path         = $p
                Error        = "Path not found"
            })
            continue
        }

        $targets = @()

        if ($Recurse) {
            $targets = @(Get-ChildItemsByDepth -Root $p -Depth $Depth -IncludeFiles:$IncludeFiles)
        } else {
            $targets = @($p)
        }

        foreach ($t in $targets) {

            if ($ExcludeInheritedFromParents -and -not (Has-ExplicitAclChanges -ItemPath $t)) {
                continue
            }

            $rows = Get-AclRowsForItem -ItemPath $t `
                -ExplicitOnly:$ExplicitOnly `
                -IncludeOwner:$IncludeOwner `
                -ResolveIdentity:$ResolveIdentity `
                -FocusPrincipals:$FocusPrincipals

            foreach ($r in @($rows)) { $all.Add($r) }
        }
    }

    $all
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $target = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($target)) { continue }

    try {
        if ($target -eq $env:COMPUTERNAME -or $target -eq 'localhost') {
            $rows = Get-NTFSPermissionsSummaryLocal -Paths $Path `
                -Recurse:$Recurse -Depth $Depth -IncludeFiles:$IncludeFiles `
                -ExplicitOnly:$ExplicitOnly -IncludeOwner:$IncludeOwner `
                -ResolveIdentity:$ResolveIdentity -FocusPrincipals:$FocusPrincipals `
                -ExcludeInheritedFromParents:$ExcludeInheritedFromParents
        } else {
            $sb = ${function:Get-NTFSPermissionsSummaryLocal}
            $rows = Invoke-Command -ComputerName $target -ScriptBlock $sb -ArgumentList @(
                $Path,
                [bool]$Recurse,
                [int]$Depth,
                [bool]$IncludeFiles,
                [bool]$ExplicitOnly,
                [bool]$IncludeOwner,
                [bool]$ResolveIdentity,
                [bool]$FocusPrincipals,
                [bool]$ExcludeInheritedFromParents
            ) -ErrorAction Stop
        }

        foreach ($r in @($rows)) { $results.Add($r) }
    }
    catch {
        $results.Add([PSCustomObject]@{
            ComputerName = $target
            Path         = ($Path -join ', ')
            Error        = $_.Exception.Message
        })
    }
}

$results
