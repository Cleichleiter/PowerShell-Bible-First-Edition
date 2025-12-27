<#
.SYNOPSIS
Gets health/status data for RDS Session Hosts / terminal servers.

.DESCRIPTION
Returns an operational health snapshot suitable for:
- Morning checks
- Pre-maintenance validation
- Troubleshooting "server slow" complaints
- Capacity and session-load visibility

Includes:
- Uptime / last boot time
- Pending reboot detection
- Key RDS service status
- Session counts via quser (Active/Disc/Total)
- CPU and memory quick snapshot
- Disk free (system drive default; optional all fixed drives)

.PARAMETER ComputerName
One or more servers to query. Defaults to the local computer.

.PARAMETER IncludeAllFixedDrives
If set, returns disk metrics for all fixed drives. Otherwise system drive only.

.PARAMETER TimeoutSeconds
CIM query timeout (best-effort). Default 10 seconds.

.PARAMETER SessionQueryTimeoutSeconds
Timeout for quser session query per host. Default 8 seconds.

.EXAMPLE
.\Get-RDHostStatus.ps1

.EXAMPLE
.\Get-RDHostStatus.ps1 -ComputerName RDSH01,RDSH02 | Format-Table -Auto

.EXAMPLE
.\Get-RDHostStatus.ps1 -ComputerName RDSH01 -IncludeAllFixedDrives |
  Export-Csv C:\Reports\RDS-HostStatus.csv -NoTypeInformation

.NOTES
Author: Cheri
Requires: CIM/WMI connectivity and rights; quser.exe locally available.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string[]]$ComputerName = @($env:COMPUTERNAME),

    [Parameter()]
    [switch]$IncludeAllFixedDrives,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$TimeoutSeconds = 10,

    [Parameter()]
    [ValidateRange(1, 300)]
    [int]$SessionQueryTimeoutSeconds = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# RDS-ish services you generally care about on Session Hosts.
# (Not all exist on all servers; missing is not automatically "bad".)
$ServiceNames = @(
    'TermService',      # Remote Desktop Services
    'UmRdpService',     # Remote Desktop Services UserMode Port Redirector
    'SessionEnv',       # Remote Desktop Configuration
    'TSpkg',            # Remote Desktop Session Host Server Security
    'RdsRpc'            # Remote Desktop Services UserMode Port Redirector (older variants differ)
) | Select-Object -Unique

function Invoke-QuserLines {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    $args = @()
    if ($Computer -and ($Computer -ne $env:COMPUTERNAME)) {
        $args += "/server:$Computer"
    }

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "quser.exe"
    $psi.Arguments = ($args -join ' ')
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi

    $null = $p.Start()
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        try { $p.Kill() } catch {}
        throw "quser timeout after $TimeoutSeconds seconds."
    }

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if (-not [string]::IsNullOrWhiteSpace($stderr) -and [string]::IsNullOrWhiteSpace($stdout)) {
        throw $stderr.Trim()
    }

    return ($stdout -split "`r?`n" | Where-Object { $_ -and $_.Trim() -ne '' })
}

function Get-SessionCounts {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][int]$TimeoutSeconds
    )

    try {
        $lines = Invoke-QuserLines -Computer $Computer -TimeoutSeconds $TimeoutSeconds
        $data = $lines | Where-Object { $_ -notmatch '^\s*USERNAME\s+' }

        $active = 0
        $disc   = 0
        $other  = 0

        foreach ($line in $data) {
            $raw = $line.Trim()
            if ($raw.StartsWith('>')) { $raw = $raw.TrimStart('>').TrimStart() }
            $cols = $raw -split '\s{2,}'
            if ($cols.Count -lt 5) { continue }

            # Determine which column is State (varies w/ session name presence)
            $state = if ($cols.Count -ge 6) { $cols[3] } else { $cols[2] }

            switch ($state) {
                'Active' { $active++ }
                'Disc'   { $disc++ }
                default  { $other++ }
            }
        }

        [PSCustomObject]@{
            TotalSessions       = ($active + $disc + $other)
            ActiveSessions      = $active
            DisconnectedSessions= $disc
            OtherSessions       = $other
            SessionQueryError   = $null
        }
    }
    catch {
        [PSCustomObject]@{
            TotalSessions        = $null
            ActiveSessions       = $null
            DisconnectedSessions = $null
            OtherSessions        = $null
            SessionQueryError    = $_.Exception.Message
        }
    }
}

function Test-PendingReboot {
    param(
        [Parameter(Mandatory)][string]$Computer
    )

    # We’ll query remote registry via StdRegProv (WMI) so it works without PSRemoting.
    # If that fails, we return Unknown with error.
    $hklm = 2147483650

    try {
        $reg = Get-CimInstance -ComputerName $Computer -ClassName StdRegProv -Namespace root\default -OperationTimeoutSec $TimeoutSeconds

        $indicators = [ordered]@{
            CBS_RebootPending                   = $false
            WindowsUpdate_RebootRequired        = $false
            PendingFileRenameOperations         = $false
            SCCM_PendingReboot                  = $false
            ComponentBasedServicing             = $false
            Error                               = $null
        }

        # 1) Component Based Servicing
        $r = Invoke-CimMethod -InputObject $reg -MethodName EnumKey -Arguments @{
            hDefKey     = $hklm
            sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
        }
        if ($r.ReturnValue -eq 0 -and $r.sNames -contains 'RebootPending') {
            $indicators.CBS_RebootPending = $true
            $indicators.ComponentBasedServicing = $true
        }

        # 2) Windows Update RebootRequired
        $r = Invoke-CimMethod -InputObject $reg -MethodName EnumKey -Arguments @{
            hDefKey     = $hklm
            sSubKeyName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        }
        if ($r.ReturnValue -eq 0 -and $r.sNames -contains 'RebootRequired') {
            $indicators.WindowsUpdate_RebootRequired = $true
        }

        # 3) PendingFileRenameOperations
        $r = Invoke-CimMethod -InputObject $reg -MethodName GetMultiStringValue -Arguments @{
            hDefKey     = $hklm
            sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager'
            sValueName  = 'PendingFileRenameOperations'
        }
        if ($r.ReturnValue -eq 0 -and $r.sValue -and $r.sValue.Count -gt 0) {
            $indicators.PendingFileRenameOperations = $true
        }

        # 4) SCCM / ConfigMgr pending reboot (common key)
        $r = Invoke-CimMethod -InputObject $reg -MethodName EnumKey -Arguments @{
            hDefKey     = $hklm
            sSubKeyName = 'SOFTWARE\Microsoft\CCM\ClientSDK'
        }
        if ($r.ReturnValue -eq 0) {
            # Presence doesn’t always mean pending; we’ll attempt common values
            $r2 = Invoke-CimMethod -InputObject $reg -MethodName GetDWORDValue -Arguments @{
                hDefKey     = $hklm
                sSubKeyName = 'SOFTWARE\Microsoft\CCM\ClientSDK'
                sValueName  = 'RebootPending'
            }
            if ($r2.ReturnValue -eq 0 -and $r2.uValue -eq 1) {
                $indicators.SCCM_PendingReboot = $true
            }
        }

        $pending = $indicators.CBS_RebootPending -or
                   $indicators.WindowsUpdate_RebootRequired -or
                   $indicators.PendingFileRenameOperations -or
                   $indicators.SCCM_PendingReboot

        [PSCustomObject]@{
            PendingReboot = $pending
            Indicators    = $indicators
        }
    }
    catch {
        [PSCustomObject]@{
            PendingReboot = $null
            Indicators    = [ordered]@{
                CBS_RebootPending                   = $null
                WindowsUpdate_RebootRequired        = $null
                PendingFileRenameOperations         = $null
                SCCM_PendingReboot                  = $null
                ComponentBasedServicing             = $null
                Error                               = $_.Exception.Message
            }
        }
    }
}

function Get-ServiceStatusMap {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string[]]$ServiceNames
    )

    $map = [ordered]@{}
    foreach ($svc in $ServiceNames) { $map[$svc] = 'NotFound' }

    try {
        $services = Get-Service -ComputerName $Computer -ErrorAction Stop |
            Where-Object { $ServiceNames -contains $_.Name }

        foreach ($s in $services) {
            $map[$s.Name] = $s.Status.ToString()
        }
    }
    catch {
        # If remote service query fails, reflect error in a special field
        $map['__Error'] = $_.Exception.Message
    }

    return $map
}

function Get-PerfQuick {
    param([Parameter(Mandatory)][string]$Computer)

    try {
        $os = Get-CimInstance -ComputerName $Computer -ClassName Win32_OperatingSystem -OperationTimeoutSec $TimeoutSeconds
        $cs = Get-CimInstance -ComputerName $Computer -ClassName Win32_ComputerSystem -OperationTimeoutSec $TimeoutSeconds

        $totalMemGB = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
        $freeMemGB  = [math]::Round(($os.FreePhysicalMemory * 1KB / 1GB), 2)
        $usedMemGB  = [math]::Round(($totalMemGB - $freeMemGB), 2)

        # CPU percent from Win32_Processor LoadPercentage (quick indicator)
        $cpu = Get-CimInstance -ComputerName $Computer -ClassName Win32_Processor -OperationTimeoutSec $TimeoutSeconds |
            Select-Object -First 1 -ExpandProperty LoadPercentage

        [PSCustomObject]@{
            CpuLoadPercent = $cpu
            TotalMemGB     = $totalMemGB
            UsedMemGB      = $usedMemGB
            FreeMemGB      = $freeMemGB
        }
    }
    catch {
        [PSCustomObject]@{
            CpuLoadPercent = $null
            TotalMemGB     = $null
            UsedMemGB      = $null
            FreeMemGB      = $null
        }
    }
}

function Get-DiskQuick {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][switch]$IncludeAllFixedDrives
    )

    try {
        $logical = Get-CimInstance -ComputerName $Computer -ClassName Win32_LogicalDisk -Filter "DriveType=3" -OperationTimeoutSec $TimeoutSeconds

        if (-not $IncludeAllFixedDrives) {
            # system drive heuristic: OS drive letter from environment or Win32_OperatingSystem
            $os = Get-CimInstance -ComputerName $Computer -ClassName Win32_OperatingSystem -OperationTimeoutSec $TimeoutSeconds
            $sys = ($os.SystemDrive ?? 'C:').ToUpperInvariant()
            $logical = $logical | Where-Object { $_.DeviceID.ToUpperInvariant() -eq $sys }
        }

        $drives = foreach ($d in $logical) {
            $sizeGB = if ($d.Size) { [math]::Round(($d.Size / 1GB), 2) } else { $null }
            $freeGB = if ($d.FreeSpace) { [math]::Round(($d.FreeSpace / 1GB), 2) } else { $null }
            $pctFree = if ($d.Size -and $d.FreeSpace -ne $null) {
                [math]::Round((($d.FreeSpace / $d.Size) * 100), 2)
            } else { $null }

            [PSCustomObject]@{
                Drive      = $d.DeviceID
                SizeGB     = $sizeGB
                FreeGB     = $freeGB
                PercentFree= $pctFree
            }
        }

        return $drives
    }
    catch {
        return @([PSCustomObject]@{
            Drive      = $null
            SizeGB     = $null
            FreeGB     = $null
            PercentFree= $null
            Error      = $_.Exception.Message
        })
    }
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($c in $ComputerName) {
    $computer = $c.Trim()
    if ([string]::IsNullOrWhiteSpace($computer)) { continue }

    Write-Verbose "Collecting host status for: $computer"

    try {
        $os = Get-CimInstance -ComputerName $computer -ClassName Win32_OperatingSystem -OperationTimeoutSec $TimeoutSeconds
        $cs = Get-CimInstance -ComputerName $computer -ClassName Win32_ComputerSystem -OperationTimeoutSec $TimeoutSeconds

        $lastBoot = $os.LastBootUpTime
        $uptime = (Get-Date) - $lastBoot

        $pending = Test-PendingReboot -Computer $computer
        $sessions = Get-SessionCounts -Computer $computer -TimeoutSeconds $SessionQueryTimeoutSeconds
        $perf = Get-PerfQuick -Computer $computer
        $svcMap = Get-ServiceStatusMap -Computer $computer -ServiceNames $ServiceNames
        $disks = Get-DiskQuick -Computer $computer -IncludeAllFixedDrives:$IncludeAllFixedDrives

        # Flatten disk info into a compact string for one-row reporting (CSV-friendly)
        $diskSummary = ($disks | ForEach-Object {
            if ($_.Drive) { "{0} Free={1}GB ({2}%)" -f $_.Drive, $_.FreeGB, $_.PercentFree }
        }) -join '; '

        # Flatten services too
        $serviceSummary = ($svcMap.GetEnumerator() | Where-Object { $_.Key -ne '__Error' } |
            ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '

        $results.Add([PSCustomObject]@{
            Timestamp                = Get-Date
            ComputerName             = $computer
            OS                       = $os.Caption
            OSVersion                = $os.Version
            LastBootTime             = $lastBoot
            UptimeDays               = [math]::Round($uptime.TotalDays, 2)
            PendingReboot            = $pending.PendingReboot
            PendingRebootIndicators  = ($pending.Indicators | ConvertTo-Json -Compress)
            CpuLoadPercent           = $perf.CpuLoadPercent
            TotalMemGB               = $perf.TotalMemGB
            UsedMemGB                = $perf.UsedMemGB
            FreeMemGB                = $perf.FreeMemGB
            TotalSessions            = $sessions.TotalSessions
            ActiveSessions           = $sessions.ActiveSessions
            DisconnectedSessions     = $sessions.DisconnectedSessions
            OtherSessions            = $sessions.OtherSessions
            SessionQueryError        = $sessions.SessionQueryError
            Services                 = $serviceSummary
            ServiceQueryError        = ($svcMap['__Error'])
            DiskSummary              = $diskSummary
        })
    }
    catch {
        $results.Add([PSCustomObject]@{
            Timestamp                = Get-Date
            ComputerName             = $computer
            OS                       = $null
            OSVersion                = $null
            LastBootTime             = $null
            UptimeDays               = $null
            PendingReboot            = $null
            PendingRebootIndicators  = $null
            CpuLoadPercent           = $null
            TotalMemGB               = $null
            UsedMemGB                = $null
            FreeMemGB                = $null
            TotalSessions            = $null
            ActiveSessions           = $null
            DisconnectedSessions     = $null
            OtherSessions            = $null
            SessionQueryError        = $null
            Services                 = $null
            ServiceQueryError        = $null
            DiskSummary              = $null
            Error                    = $_.Exception.Message
        })
    }
}

$results | Sort-Object ComputerName
