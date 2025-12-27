<#
.SYNOPSIS
Finds stale AD computer accounts by last logon timestamp.

.PARAMETER DaysInactive
Computers inactive for at least this many days.

.PARAMETER SearchBase
Optional DN to scope the search (OU DN).

.EXAMPLE
.\Get-StaleADComputers.ps1 -DaysInactive 90

.EXAMPLE
.\Get-StaleADComputers.ps1 -DaysInactive 60 -SearchBase "OU=Workstations,DC=contoso,DC=com"
#>

[CmdletBinding()]
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
    Filter     = "LastLogonTimeStamp -lt '$($cutoff.ToFileTime())'"
    Properties = @("LastLogonTimeStamp","OperatingSystem","Enabled","DNSHostName")
}
if ($SearchBase) { $params.SearchBase = $SearchBase }

Get-ADComputer @params |
    Select-Object Name, DNSHostName, Enabled, OperatingSystem,
        @{Name="LastLogonTimeStamp";Expression={[DateTime]::FromFileTime($_.LastLogonTimeStamp)}},
        @{Name="DaysInactive";Expression=([int]((Get-Date) - [DateTime]::FromFileTime($_.LastLogonTimeStamp)).TotalDays)} |
    Sort-Object DaysInactive -Descending
