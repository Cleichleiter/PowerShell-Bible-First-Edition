<#
.SYNOPSIS
  Template for an ops-focused PowerShell script.

.DESCRIPTION
  Use this template when creating a standalone script file under /snippets.

  Key behaviors:
  - CmdletBinding + strict mode
  - Object-first output (no inline formatting)
  - Safe defaults, guardrails, and -WhatIf support for change scripts
  - Optional exports (CSV/JSON) without breaking pipeline output
  - Remote-capable pattern using Invoke-Command for multi-host runs

.NOTES
  Author: Cheri
  Repo: PowerShell-Bible
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    # Example target input
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Target = 'Default',

    # Example filter patterns
    [Parameter()]
    [string[]]$Include,

    [Parameter()]
    [string[]]$Exclude,

    # Example behavior toggles
    [Parameter()]
    [switch]$IncludeDetail,

    # Optional exports (script still returns objects)
    [Parameter()]
    [string]$ExportCsv,

    [Parameter()]
    [string]$ExportJson,

    # Safety toggles
    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [ValidateRange(1,128)]
    [int]$ThrottleLimit = 16
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Match-AnyWildcard {
    param([string]$Value, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $true }
    foreach ($p in $Patterns) { if ($Value -like $p) { return $true } }
    return $false
}

function New-ResultObject {
    param(
        [string]$ComputerName,
        [string]$Target,
        [bool]$Success,
        [string]$Stage,
        [string]$Message,
        [hashtable]$Data
    )

    $obj = [ordered]@{
        Timestamp    = (Get-Date)
        ComputerName = $ComputerName
        Target       = $Target
        Stage        = $Stage
        Success      = $Success
        Message      = $Message
    }

    if ($Data) {
        foreach ($k in $Data.Keys) {
            $obj[$k] = $Data[$k]
        }
    }

    [PSCustomObject]$obj
}

function Invoke-LocalWork {
    param(
        [string]$Target,
        [string[]]$Include,
        [string[]]$Exclude,
        [bool]$IncludeDetail,
        [bool]$Force
    )

    $out = New-Object System.Collections.Generic.List[object]

    try {
        # TODO: Replace with script-specific discovery/collection/change logic.
        # Example: discover items
        $items = @("ItemA","ItemB","ItemC")

        foreach ($i in $items) {
            if (-not (Match-AnyWildcard -Value $i -Patterns $Include)) { continue }
            if ($Exclude -and (Match-AnyWildcard -Value $i -Patterns $Exclude)) { continue }

            # Example: change operation guardrail
            $action = "Process '$i' for target '$Target'"

            if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {

                # Example: optional confirmation unless -Force
                if (-not $Force) {
                    $caption = "Confirm operation"
                    $msg = "Proceed with: $action ?"
                    if (-not $PSCmdlet.ShouldContinue($msg, $caption)) {
                        $out.Add((New-ResultObject -ComputerName $env:COMPUTERNAME -Target $Target -Success $false -Stage 'Confirm' -Message 'User declined' -Data @{ Item = $i }))
                        continue
                    }
                }

                # TODO: do the work
                # Simulate success
                $out.Add((New-ResultObject -ComputerName $env:COMPUTERNAME -Target $Target -Success $true -Stage 'Process' -Message 'OK' -Data @{
                    Item   = $i
                    Detail = if ($IncludeDetail) { 'TODO: add detail fields' } else { $null }
                }))
            }
            else {
                $out.Add((New-ResultObject -ComputerName $env:COMPUTERNAME -Target $Target -Success $true -Stage 'WhatIf' -Message 'WhatIf: would process item' -Data @{ Item = $i }))
            }
        }
    }
    catch {
        $out.Add((New-ResultObject -ComputerName $env:COMPUTERNAME -Target $Target -Success $false -Stage 'Error' -Message $_.Exception.Message -Data $null))
    }

    $out
}

# --- Main execution ---
$results = New-Object System.Collections.Generic.List[object]

# Multi-host: use PSSession for efficiency when >1 host
if ($ComputerName.Count -gt 1) {
    $sessions = @()
    try {
        $sessions = New-PSSession -ComputerName $ComputerName -ThrottleLimit $ThrottleLimit
        $rows = Invoke-Command -Session $sessions -ScriptBlock ${function:Invoke-LocalWork} -ArgumentList @(
            $Target,
            $Include,
            $Exclude,
            [bool]$IncludeDetail,
            [bool]$Force
        )
        foreach ($r in @($rows)) { $results.Add($r) }
    }
    finally {
        if ($sessions) { $sessions | Remove-PSSession -ErrorAction SilentlyContinue }
    }
}
else {
    foreach ($c in $ComputerName) {
        $hostName = $c.Trim()
        if ([string]::IsNullOrWhiteSpace($hostName)) { continue }

        try {
            if ($hostName -eq $env:COMPUTERNAME -or $hostName -eq 'localhost') {
                $rows = Invoke-LocalWork -Target $Target -Include $Include -Exclude $Exclude -IncludeDetail:$IncludeDetail -Force:$Force
            }
            else {
                $rows = Invoke-Command -ComputerName $hostName -ScriptBlock ${function:Invoke-LocalWork} -ArgumentList @(
                    $Target,
                    $Include,
                    $Exclude,
                    [bool]$IncludeDetail,
                    [bool]$Force
                ) -ErrorAction Stop
            }

            foreach ($r in @($rows)) {
                # Ensure ComputerName reflects actual target when remoting
                if ($r.PSObject.Properties.Name -contains 'ComputerName') {
                    if ($hostName -ne $env:COMPUTERNAME -and $r.ComputerName -ne $hostName) {
                        $r | Add-Member -NotePropertyName ComputerName -NotePropertyValue $hostName -Force
                    }
                }
                $results.Add($r)
            }
        }
        catch {
            $results.Add((New-ResultObject -ComputerName $hostName -Target $Target -Success $false -Stage 'RemoteError' -Message $_.Exception.Message -Data $null))
        }
    }
}

# Optional exports
if ($ExportCsv) {
    $dir = Split-Path -Path $ExportCsv -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation
}

if ($ExportJson) {
    $dir = Split-Path -Path $ExportJson -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $results | ConvertTo-Json -Depth 8 | Out-File -FilePath $ExportJson -Encoding utf8
}

# Always return objects
$results
