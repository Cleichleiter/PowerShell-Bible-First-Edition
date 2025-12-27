<#
.SYNOPSIS
Gets the most recent AD user LastLogon value by querying all domain controllers.

.DESCRIPTION
LastLogon is not replicated. This script queries each DC for the target user's LastLogon
and returns the most recent value, plus per-DC results.

.PARAMETER SamAccountName
User samAccountName.

.PARAMETER Domain
Optional DNS domain name (defaults to current domain).

.EXAMPLE
.\Get-ADUserLastLogonAllDCs.ps1 -SamAccountName jdoe

.NOTES
Requires RSAT ActiveDirectory module.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SamAccountName,

    [Parameter()]
    [string]$Domain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory -ErrorAction Stop

if (-not $Domain) {
    $Domain = (Get-ADDomain).DNSRoot
}

$dcs = Get-ADDomainController -Filter * -Server $Domain | Sort-Object HostName

$results = foreach ($dc in $dcs) {
    try {
        $u = Get-ADUser -Identity $SamAccountName -Server $dc.HostName -Properties LastLogon, UserPrincipalName, DisplayName
        $dt = $null
        if ($u.LastLogon -and $u.LastLogon -gt 0) {
            $dt = [DateTime]::FromFileTime($u.LastLogon)
        }

        [PSCustomObject]@{
            Domain        = $Domain
            DomainController = $dc.HostName
            SamAccountName = $u.SamAccountName
            DisplayName    = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            LastLogonRaw   = $u.LastLogon
            LastLogon      = $dt
            Result         = 'Success'
            Reason         = $null
        }
    }
    catch {
        [PSCustomObject]@{
            Domain        = $Domain
            DomainController = $dc.HostName
            SamAccountName = $SamAccountName
            DisplayName    = $null
            UserPrincipalName = $null
            LastLogonRaw   = $null
            LastLogon      = $null
            Result         = 'Failed'
            Reason         = $_.Exception.Message
        }
    }
}

$latest = $results |
    Where-Object { $_.Result -eq 'Success' -and $_.LastLogon } |
    Sort-Object LastLogon -Descending |
    Select-Object -First 1

[PSCustomObject]@{
    SamAccountName        = $SamAccountName
    Domain               = $Domain
    MostRecentLastLogon  = $latest.LastLogon
    MostRecentDC         = $latest.DomainController
    PerDC                = $results
}
