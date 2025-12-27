<#
.SYNOPSIS
  Standardized logging function for PowerShell Bible scripts.

.DESCRIPTION
  Writes structured log entries to the console and optionally to a file.
  Designed to be imported or dot-sourced by other scripts.

  Features:
  - Consistent timestamped log records
  - Severity levels (Info, Warning, Error, Debug)
  - Optional file output
  - Pipeline-safe
  - RMM-friendly (no formatting assumptions)
  - Safe for use in catch blocks

.NOTES
  Author: Cheri
  Repo: PowerShell-Bible
#>

Set-StrictMode -Version Latest

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info','Warning','Error','Debug')]
        [string]$Level = 'Info',

        [Parameter()]
        [string]$Component,

        [Parameter()]
        [string]$ComputerName = $env:COMPUTERNAME,

        [Parameter()]
        [string]$LogPath,

        [Parameter()]
        [switch]$PassThru
    )

    $timestamp = Get-Date

    $record = [PSCustomObject]@{
        Timestamp    = $timestamp
        ComputerName = $ComputerName
        Level        = $Level
        Component    = $Component
        Message      = $Message
    }

    # Console output (minimal, predictable)
    switch ($Level) {
        'Error'   { Write-Error   $Message }
        'Warning' { Write-Warning $Message }
        'Debug'   { Write-Debug   $Message }
        default   { Write-Verbose $Message }
    }

    # Optional file logging
    if ($LogPath) {
        try {
            $dir = Split-Path -Path $LogPath -Parent
            if ($dir -and -not (Test-Path $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }

            $record |
                ConvertTo-Json -Depth 4 -Compress |
                Add-Content -Path $LogPath -Encoding UTF8
        }
        catch {
            # Logging must never break execution
            Write-Warning "Write-Log failed to write to log file: $($_.Exception.Message)"
        }
    }

    if ($PassThru) {
        return $record
    }
}
