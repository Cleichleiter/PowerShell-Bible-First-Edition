<#
.SYNOPSIS
Disables AD computer accounts that have been inactive for N days.

.DESCRIPTION
Uses LastLogonTimeStamp to identify inactive computer objects and disables them.
Supports -WhatIf and logs actions via object output.

.PARAMETER DaysInactive
Disable computers inactive for at least this many days.

.PARAMETER SearchBase
Optional DN to scope the search (OU DN).

.EXAMPLE
.\Disable-StaleADComputers.ps1 -DaysInactive 120 -WhatIf

.NOTES
High impact. Validate scope and exclusions before running without -WhatIf.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive,

    [Parameter()]
    [string]$SearchBase
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

$cutoff = (Get-Date).AddDays(-$DaysInactive)

$params = @{
    Filter     = "Enabled -eq 'True' -and LastLogonTimeStamp -lt '$($cutoff.ToFileTime())'"
    Properties = @("LastLogonTimeStamp","DNSHostName")
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

$targets = Get-ADComputer @params

$results = foreach ($c in $targets) {
    $last = [DateTime]::FromFileTime($c.LastLogonTimeStamp)
    $action = "Disable computer account"
    try {
        if ($PSCmdlet.ShouldProcess($c.DistinguishedName, "$action (LastLogonTimeStamp=$last)")) {
            Disable-ADAccount -Identity $c.DistinguishedName -ErrorAction Stop
        }

        [PSCustomObject]@{
            ComputerName      = $c.Name
            DNSHostName       = $c.DNSHostName
            LastLogonTimeStamp= $last
            DaysInactive      = [int]((Get-Date) - $last).TotalDays
            Result            = "Success"
            Reason            = $null
        }
    }
    catch {
        [PSCustomObject]@{
            ComputerName      = $c.Name
            DNSHostName       = $c.DNSHostName
            LastLogonTimeStamp= $last
            DaysInactive      = [int]((Get-Date) - $last).TotalDays
            Result            = "Failed"
            Reason            = $_.Exception.Message
        }
    }
}

$results | Sort-Object DaysInactive -Descending
