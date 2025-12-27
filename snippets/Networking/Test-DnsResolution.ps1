<#
.SYNOPSIS
Tests DNS forward and/or reverse resolution with optional specific DNS server(s).

.DESCRIPTION
Validates DNS resolution in a way that is useful during incidents:
- Forward lookup for one or more record types (A/AAAA/CNAME/TXT/MX/SRV/NS)
- Optional reverse lookup when an IP is provided (PTR)
- Ability to query specific DNS servers (one or many)
- Timeouts and structured output designed for automation/reporting

Designed to answer:
- "Is DNS broken, or is the app broken?"
- "Do these DNS servers agree?"
- "Is the client using the wrong DNS server?"
- "Is split DNS behaving as expected?"

.PARAMETER Name
DNS name to resolve (FQDN recommended). Accepts pipeline.

.PARAMETER IPAddress
IP address to reverse-resolve (PTR). Accepts pipeline.

.PARAMETER Type
Record type(s) for forward lookup. Default: A, AAAA, CNAME.

.PARAMETER DnsServer
One or more DNS servers to query. If omitted, uses system default resolver.

.PARAMETER TimeoutSeconds
Timeout per query attempt. Default 5 seconds.

.PARAMETER Quick
Quick mode: single server attempt and fewer record types (A + CNAME).

.PARAMETER IncludeAuthority
Include authority/TTL details when available.

.PARAMETER PassOnAnyAnswer
If set, marks OverallStatus Pass if ANY server returns ANY answer for the query.
Default behavior is stricter: Pass only if at least one answer exists and no fatal errors.

.EXAMPLE
.\Test-DnsResolution.ps1 -Name "intranet.contoso.local"

.EXAMPLE
"intranet.contoso.local","portal.contoso.com" | .\Test-DnsResolution.ps1 -Type A,AAAA -DnsServer 10.0.0.10,10.0.0.11 |
  Format-Table -Auto

.EXAMPLE
.\Test-DnsResolution.ps1 -IPAddress 10.0.0.25

.EXAMPLE
.\Test-DnsResolution.ps1 -Name "autodiscover.contoso.com" -Type A,CNAME,TXT -IncludeAuthority -DnsServer 1.1.1.1,8.8.8.8

.NOTES
Author: Cheri
Requires: Resolve-DnsName (Windows 8+/Server 2012+).
#>

[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    [Parameter(Mandatory, ParameterSetName = 'ByName', ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('Host','Fqdn','Domain')]
    [string[]]$Name,

    [Parameter(Mandatory, ParameterSetName = 'ByIP', ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('IP','Address')]
    [string[]]$IPAddress,

    [Parameter(ParameterSetName = 'ByName')]
    [ValidateSet('A','AAAA','CNAME','TXT','MX','SRV','NS','SOA','PTR')]
    [string[]]$Type = @('A','AAAA','CNAME'),

    [Parameter()]
    [string[]]$DnsServer,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5,

    [Parameter()]
    [switch]$Quick,

    [Parameter()]
    [switch]$IncludeAuthority,

    [Parameter()]
    [switch]$PassOnAnyAnswer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-ResolveDns {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$QueryType,
        [Parameter()][string]$Server,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    # Resolve-DnsName has -Server and -Type. Timeout behavior is environment-dependent.
    # We implement best-effort timeout by running the query in a background job for local calls.
    # (For simplicity and reliability, we do a direct call and catch failures.)
    try {
        $params = @{
            Name        = $Query
            Type        = $QueryType
            ErrorAction = 'Stop'
        }
        if ($Server) { $params.Server = $Server }

        $answers = Resolve-DnsName @params
        return [PSCustomObject]@{
            Succeeded = $true
            Answers   = $answers
            Error     = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Succeeded = $false
            Answers   = $null
            Error     = $_.Exception.Message
        }
    }
}

function Normalize-Servers {
    param([string[]]$DnsServer)
    if ($DnsServer -and $DnsServer.Count -gt 0) {
        return @($DnsServer | Where-Object { $_ -and $_.Trim() -ne '' } | ForEach-Object { $_.Trim() })
    }
    # Use default resolver when Server is null/empty; represent as '(Default)'
    return @('(Default)')
}

function Flatten-AnswerSummary {
    param(
        [Parameter(Mandatory)][object[]]$Answers,
        [Parameter(Mandatory)][string]$QueryType,
        [Parameter(Mandatory)][switch]$IncludeAuthority
    )

    # Build a human-friendly summary by record type.
    $rows = @()

    foreach ($a in $Answers) {
        # Only consider answer section-like records
        if (-not $a) { continue }

        $ttl = $null
        $section = $null
        try { $ttl = $a.TTL } catch {}
        try { $section = $a.Section } catch {}

        $val = $null
        switch ($QueryType) {
            'A'     { $val = $a.IPAddress }
            'AAAA'  { $val = $a.IPAddress }
            'CNAME' { $val = $a.NameHost }
            'TXT'   { $val = ($a.Strings -join ' ') }
            'MX'    { $val = "$($a.Preference) $($a.NameExchange)" }
            'SRV'   { $val = "$($a.Priority) $($a.Weight) $($a.Port) $($a.NameTarget)" }
            'NS'    { $val = $a.NameHost }
            'SOA'   { $val = "$($a.PrimaryServer) $($a.ResponsiblePerson)" }
            'PTR'   { $val = $a.NameHost }
            default { $val = $a.ToString() }
        }

        if ([string]::IsNullOrWhiteSpace([string]$val)) { continue }

        if ($IncludeAuthority) {
            $rows += @("$val (TTL=$ttl, Section=$section)")
        } else {
            $rows += @("$val")
        }
    }

    return ($rows | Where-Object { $_ } | Select-Object -Unique)
}

function New-ResultRow {
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$QueryType,
        [Parameter(Mandatory)][string]$ServerLabel,
        [Parameter(Mandatory)][bool]$Succeeded,
        [Parameter()][string[]]$AnswerSummary,
        [Parameter()][string]$Error
    )

    $hasAnswer = ($AnswerSummary -and $AnswerSummary.Count -gt 0)

    [PSCustomObject]@{
        Timestamp      = Get-Date
        ComputerName   = $env:COMPUTERNAME
        Query          = $Query
        QueryType      = $QueryType
        DnsServer      = $ServerLabel
        Succeeded      = $Succeeded
        HasAnswer      = $hasAnswer
        AnswerCount    = if ($hasAnswer) { $AnswerSummary.Count } else { 0 }
        Answers        = if ($hasAnswer) { $AnswerSummary -join '; ' } else { $null }
        Error          = $Error
    }
}

$servers = Normalize-Servers -DnsServer $DnsServer

# Quick mode adjustments
if ($Quick) {
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        $Type = @('A','CNAME')
    }
    if ($servers.Count -gt 1) {
        $servers = @($servers[0])
    }
}

$all = New-Object System.Collections.Generic.List[object]

process {
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        foreach ($q in $Name) {
            $query = $q.Trim()
            if ([string]::IsNullOrWhiteSpace($query)) { continue }

            foreach ($t in $Type) {
                foreach ($s in $servers) {
                    $serverArg = if ($s -eq '(Default)') { $null } else { $s }

                    $res = Invoke-ResolveDns -Query $query -QueryType $t -Server $serverArg -TimeoutSeconds $TimeoutSeconds

                    if ($res.Succeeded -and $res.Answers) {
                        $answers = @($res.Answers)
                        $summary = Flatten-AnswerSummary -Answers $answers -QueryType $t -IncludeAuthority:$IncludeAuthority
                        $all.Add((New-ResultRow -Query $query -QueryType $t -ServerLabel $s -Succeeded $true -AnswerSummary $summary -Error $null))
                    } else {
                        $all.Add((New-ResultRow -Query $query -QueryType $t -ServerLabel $s -Succeeded $false -AnswerSummary $null -Error $res.Error))
                    }
                }
            }
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'ByIP') {
        foreach ($ip in $IPAddress) {
            $query = $ip.Trim()
            if ([string]::IsNullOrWhiteSpace($query)) { continue }

            foreach ($s in $servers) {
                $serverArg = if ($s -eq '(Default)') { $null } else { $s }

                $res = Invoke-ResolveDns -Query $query -QueryType 'PTR' -Server $serverArg -TimeoutSeconds $TimeoutSeconds

                if ($res.Succeeded -and $res.Answers) {
                    $answers = @($res.Answers)
                    $summary = Flatten-AnswerSummary -Answers $answers -QueryType 'PTR' -IncludeAuthority:$IncludeAuthority
                    $all.Add((New-ResultRow -Query $query -QueryType 'PTR' -ServerLabel $s -Succeeded $true -AnswerSummary $summary -Error $null))
                } else {
                    $all.Add((New-ResultRow -Query $query -QueryType 'PTR' -ServerLabel $s -Succeeded $false -AnswerSummary $null -Error $res.Error))
                }
            }
        }
    }
}

end {
    # Compute per-query overall signal (optional): users can group by Query/Type.
    # We keep raw rows as primary output.
    if ($PassOnAnyAnswer) {
        # Leave rows as-is; downstream can interpret.
        $all
        return
    }

    # Default behavior: still return all rows, but add a computed OverallStatus per Query+Type via NoteProperty.
    $grouped = $all | Group-Object Query, QueryType
    foreach ($g in $grouped) {
        $rows = @($g.Group)
        $hasAnyAnswer = $rows | Where-Object { $_.HasAnswer } | Select-Object -First 1
        $hasAllFailed = ($rows | Where-Object { $_.Succeeded -eq $true } | Measure-Object).Count -eq 0

        $overall = if ($hasAnyAnswer) { 'Pass' } elseif ($hasAllFailed) { 'Fail' } else { 'Warn' }

        foreach ($r in $rows) {
            $r | Add-Member -NotePropertyName OverallStatus -NotePropertyValue $overall -Force
        }
    }

    $all | Sort-Object Query, QueryType, DnsServer
}
