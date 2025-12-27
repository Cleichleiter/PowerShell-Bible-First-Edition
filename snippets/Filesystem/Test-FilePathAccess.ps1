<#
.SYNOPSIS
  Tests filesystem access to a path (read/write/modify).

.DESCRIPTION
  Validates whether the current user (or execution context) can:
    - See the path
    - Read from the path
    - Write to the path
    - Modify (create + delete a temp file)

  Designed for troubleshooting permission issues on local or remote systems.

.PARAMETER Path
  File or folder path to test.

.PARAMETER ComputerName
  Optional remote computer(s) to test via PowerShell remoting.

.PARAMETER TestWrite
  Attempt to create a temporary file to validate write access.

.PARAMETER TestModify
  Attempt to create and delete a temporary file (implies write).

.PARAMETER Quiet
  Suppress non-critical warnings.

.EXAMPLE
  .\Test-FilePathAccess.ps1 -Path C:\Data

.EXAMPLE
  .\Test-FilePathAccess.ps1 -Path \\FS01\Finance -TestWrite -TestModify

.EXAMPLE
  .\Test-FilePathAccess.ps1 -ComputerName FS01 -Path D:\Shares\HR -TestWrite
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$Path,

    [string[]]$ComputerName,

    [switch]$TestWrite,
    [switch]$TestModify,
    [switch]$Quiet
)

$scriptBlock = {
    param ($Path, $TestWrite, $TestModify, $Quiet)

    $result = [ordered]@{
        ComputerName     = $env:COMPUTERNAME
        Path             = $Path
        Exists           = $false
        CanRead          = $false
        CanWrite         = $false
        CanModify        = $false
        Error            = $null
    }

    try {
        if (Test-Path -LiteralPath $Path) {
            $result.Exists = $true

            try {
                Get-Item -LiteralPath $Path -ErrorAction Stop | Out-Null
                $result.CanRead = $true
            } catch {
                $result.Error = "Read access denied"
            }

            if ($TestWrite -or $TestModify) {
                $tempFile = Join-Path $Path ("_access_test_{0}.tmp" -f ([guid]::NewGuid()))

                try {
                    New-Item -ItemType File -Path $tempFile -Force -ErrorAction Stop | Out-Null
                    $result.CanWrite = $true

                    if ($TestModify) {
                        Remove-Item $tempFile -Force -ErrorAction Stop
                        $result.CanModify = $true
                    }
                } catch {
                    if (-not $Quiet) {
                        $result.Error = $_.Exception.Message
                    }
                }
            }
        } else {
            $result.Error = "Path not found"
        }
    } catch {
        $result.Error = $_.Exception.Message
    }

    [pscustomobject]$result
}

if ($ComputerName) {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $Path,$TestWrite,$TestModify,$Quiet
} else {
    & $scriptBlock $Path $TestWrite $TestModify $Quiet
}
