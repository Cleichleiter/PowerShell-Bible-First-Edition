````markdown
# RDS Snippets

Operational PowerShell snippets for RDS Session Hosts / terminal servers.

Design goals:
- Works without RD Connection Broker / RDMS modules (where possible)
- Uses built-in Windows tools (`quser`, `logoff`, `tsdiscon`) and CIM/WMI for portability
- Outputs structured objects suitable for reporting, automation, and Datto RMM logs
- Safe defaults (audit-first where deletion is involved)

## Scripts

- `Get-RDActiveSessions.ps1` — enumerate sessions (Active/Disc), normalize idle time
- `Disconnect-RDIdleSessions.ps1` — disconnect idle sessions (preserves session; does not log off)
- `Logoff-RDUsers.ps1` — log off sessions (ends session)
- `Get-RDHostStatus.ps1` — host health snapshot (uptime, reboot pending, services, sessions, CPU/mem, disk)
- `Get-RDLicenseStatus.ps1` — licensing configuration indicators (mode + license servers)
- `Clear-RDStaleProfiles.ps1` — report/remove stale local profiles (audit-first; safeguards)
- `Test-RDUserLogon.ps1` — end-to-end “likely to accept RDP logons” validation (DNS/port/services/quser)

---

## Get-RDActiveSessions.ps1

Enumerates active and disconnected RDS sessions using the built-in `quser` command.  
Outputs structured objects suitable for automation and reporting.

### Common Usage

**List sessions on the local server**
```powershell
.\Get-RDActiveSessions.ps1 | Format-Table -Auto
````

**Show disconnected sessions only**

```powershell
.\Get-RDActiveSessions.ps1 -ComputerName RDSH01 -State Disc | Format-Table -Auto
```

**Find active users idle more than 2 hours**

```powershell
.\Get-RDActiveSessions.ps1 -ComputerName RDSH01 -State Active -MinIdleMinutes 120 |
  Sort-Object IdleMinutes -Descending |
  Select-Object ComputerName, Username, SessionId, State, Idle, IdleMinutes, LogonTimeRaw
```

---

## Disconnect-RDIdleSessions.ps1

Disconnects sessions that are idle beyond a threshold.
Disconnecting preserves the session (does not log off). This is useful for nightly hygiene and reducing resource drag.

### Common Usage

**Disconnect disconnected sessions idle for 8+ hours (safe nightly hygiene)**

```powershell
.\Disconnect-RDIdleSessions.ps1 -MinIdleMinutes 480 -Verbose
```

**Disconnect active sessions idle for 2+ hours (more aggressive)**

```powershell
.\Disconnect-RDIdleSessions.ps1 -ComputerName RDSH01 -MinIdleMinutes 120 -IncludeActive -Force -Verbose
```

**Exclude admins/service accounts**

```powershell
.\Disconnect-RDIdleSessions.ps1 -MinIdleMinutes 240 -IncludeActive -ExcludeUsers 'admin*','svc_*' -Force
```

---

## Logoff-RDUsers.ps1

Logs off sessions that meet criteria.
Use this when you want sessions completely terminated (not just disconnected).

### Common Usage

**Log off all disconnected sessions nightly (simple + safe)**

```powershell
.\Logoff-RDUsers.ps1 -DisconnectedOnly -Force -Verbose
```

**Log off disconnected sessions idle more than 8 hours**

```powershell
.\Logoff-RDUsers.ps1 -DisconnectedOnly -MinIdleMinutes 480 -Force -Verbose
```

**Log off active sessions idle more than 12 hours (aggressive; exclude admins)**

```powershell
.\Logoff-RDUsers.ps1 -IncludeActive -MinIdleMinutes 720 -ExcludeUsers 'admin*','svc_*' -Force -Verbose
```

---

## Get-RDHostStatus.ps1

Returns an operational health snapshot for RDS hosts:

* Uptime / last boot
* Pending reboot indicators
* Core RDS services state
* Session counts
* CPU / memory quick snapshot
* Disk free summary (system drive by default; optional all fixed drives)

### Common Usage

**Quick check one host**

```powershell
.\Get-RDHostStatus.ps1 -ComputerName RDSH01 | Format-Table -Auto
```

**Export status for multiple hosts**

```powershell
.\Get-RDHostStatus.ps1 -ComputerName RDSH01,RDSH02 |
  Export-Csv C:\Reports\RDS-HostStatus.csv -NoTypeInformation
```

**Include all fixed drives**

```powershell
.\Get-RDHostStatus.ps1 -ComputerName RDSH01 -IncludeAllFixedDrives | Format-List
```

---

## Get-RDLicenseStatus.ps1

Reads Session Host licensing configuration indicators:

* Effective licensing mode (policy vs local)
* Configured license server list (policy preferred)
* Basic misconfiguration warnings (mode not set, no server configured)

### Common Usage

**Check licensing config across hosts**

```powershell
.\Get-RDLicenseStatus.ps1 -ComputerName RDSH01,RDSH02 | Format-Table -Auto
```

**Export for audit / ticket attachment**

```powershell
.\Get-RDLicenseStatus.ps1 -ComputerName RDSH01,RDSH02 |
  Export-Csv C:\Reports\RDS-LicenseStatus.csv -NoTypeInformation
```

---

## Clear-RDStaleProfiles.ps1

Finds and optionally removes stale local user profiles based on `LastUseTime`.
Default mode is report-only. Use `-Remove` to delete.

Important:

* Will not remove profiles that are currently loaded
* For FSLogix environments, this targets local Windows profiles, not VHD/VHDX containers

### Common Usage

**Report only (no deletion)**

```powershell
.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 60 | Format-Table -Auto
```

**Safe removal (prompts)**

```powershell
.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 90 -Remove -Verbose
```

**Automation removal (no prompts)**

```powershell
.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01,RDSH02 -StaleDays 120 -Remove -Confirm:$false -Verbose
```

**Target only large stale profiles (size estimate is slower)**

```powershell
.\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 120 -EstimateSize -MinProfileSizeMB 500
```

---

## Test-RDUserLogon.ps1

Validates that a host is likely to accept RDP logons by checking:

* DNS resolution
* RDP port reachability
* Core RDS services state
* Ability to query sessions (`quser`)
* Best-effort NLA and “deny connections” indicators

This does not perform an interactive login; it is an operational readiness test.

### Common Usage

**Quick check one host**

```powershell
.\Test-RDUserLogon.ps1 -ComputerName RDSH01 | Format-Table -Auto
```

**Check multiple hosts (skip ping if blocked)**

```powershell
.\Test-RDUserLogon.ps1 -ComputerName RDSH01,RDSH02 -SkipPing | Format-Table -Auto
```

**Treat any stopped core service as a hard fail**

```powershell
.\Test-RDUserLogon.ps1 -ComputerName RDSH01 -RequireAllCoreServicesRunning -SkipPing
```

```








