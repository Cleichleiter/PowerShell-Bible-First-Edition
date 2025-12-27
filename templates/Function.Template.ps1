<#
.SYNOPSIS
  Template for a reusable advanced function (cmdlet-style).

.DESCRIPTION
  Use this template when you are building a function meant to be imported into
  a module or dot-sourced and reused across scripts.

  Key behaviors:
  - CmdletBinding for common parameters and -Verbose/-Debug support
  - Optional ShouldProcess support for change operations
  - Structured, object-first output (pipeline friendly)
  - Consistent error handling patterns and safe defaults

.NOTES
  Author: Cheri
  Repo: PowerShell-Bible
#>

Set-StrictMode -Version Latest

function Verb-Noun {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        # Primary input (support pipeline when possible)
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Identity,

        # Optional remoting target
        [Parameter(ValueFromPipelineByPropertyName)]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        # Example switch to enable heavier/slow signals
        [Parameter()]
        [switch]$IncludeDetail,

        # Example export path (function should generally return objects; export belongs in the caller)
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$OutputPath
    )

    begin {
        $ErrorActionPreference = 'Stop'

        # Optional: centralize common metadata
        $script:TemplateMeta = @{
            Timestamp = (Get-Date)
            User      = $env:USERNAME
            Host      = $env:COMPUTERNAME
        }

        # Helper: create a consistent error object without throwing
        function New-TemplateErrorRecord {
            param(
                [string]$ComputerName,
                [string]$Identity,
                [string]$Stage,
                [string]$Message
            )

            [PSCustomObject]@{
                Timestamp    = (Get-Date)
                ComputerName = $ComputerName
                Identity     = $Identity
                Stage        = $Stage
                Success      = $false
                Message      = $Message
            }
        }
    }

    process {
        foreach ($c in $ComputerName) {
            $target = $c

            try {
                # Example: make change operations explicit
                $action = "Perform Verb-Noun operation for '$Identity' on '$target'"

                if ($PSCmdlet.ShouldProcess($target, $action)) {
                    # TODO: Implement logic here
                    # Example placeholders:
                    # - query state
                    # - optionally change state
                    # - return normalized object output

                    $result = [PSCustomObject]@{
                        Timestamp    = (Get-Date)
                        ComputerName = $target
                        Identity     = $Identity
                        Success      = $true
                        Detail       = if ($IncludeDetail) { 'TODO: add detail fields' } else { $null }
                        Message      = 'OK'
                    }

                    # Optional: write to a file only if caller asked (still return object)
                    if ($OutputPath) {
                        try {
                            $dir = Split-Path -Path $OutputPath -Parent
                            if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                            $result | ConvertTo-Json -Depth 6 | Add-Content -Path $OutputPath -Encoding UTF8
                        }
                        catch {
                            Write-Warning "OutputPath write failed: $($_.Exception.Message)"
                        }
                    }

                    $result
                }
            }
            catch {
                # Prefer returning a structured error record for pipeline/reporting
                New-TemplateErrorRecord -ComputerName $target -Identity $Identity -Stage 'Process' -Message $_.Exception.Message
            }
        }
    }

    end {
        # No-op; keep for symmetry
    }
}

# Example usage:
# Verb-Noun -Identity "Example" -ComputerName "PC01" -IncludeDetail -WhatIf
