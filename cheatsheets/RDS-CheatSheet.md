````markdown

\# RDS Cheat Sheet



Quick-reference commands and scripts for \*\*Remote Desktop Services (RDS) / Terminal Services\*\* administration, troubleshooting, and operational triage.



This cheat sheet assumes a \*\*session-host–centric\*\* model (traditional RDSH, not AVD control plane management).



---



\## Core Concepts (Mental Model)



When troubleshooting RDS, always separate issues into:



1\. \*\*Connectivity\*\* (can users reach the host?)

2\. \*\*Authentication\*\* (can they log in?)

3\. \*\*Session State\*\* (are sessions stuck, idle, or orphaned?)

4\. \*\*Resource Pressure\*\* (CPU, RAM, disk, profile bloat)

5\. \*\*Licensing\*\* (CAL availability, grace period, server reachability)



Most “RDS is down” incidents fall into \*\*#3 or #4\*\*, not networking.



---



\## Session Enumeration (Built-in)



```powershell

\# Local sessions

quser



\# Remote host

quser /server:RDSH01



\# Query via WMI (fallback)

Get-CimInstance Win32\_LogonSession

````



---



\## Session Management (PowerShell Bible)



\### Get Active / Disconnected Sessions



```powershell

\# Local host

.\\Get-RDActiveSessions.ps1 | Format-Table -Auto



\# One server, disconnected only

.\\Get-RDActiveSessions.ps1 -ComputerName RDSH01 -State Disc |

&nbsp; Format-Table -Auto



\# Find users idle more than 2 hours

.\\Get-RDActiveSessions.ps1 -ComputerName RDSH01 -State Active -MinIdleMinutes 120 |

&nbsp; Sort-Object IdleMinutes -Descending |

&nbsp; Select-Object ComputerName,Username,SessionId,State,Idle,IdleMinutes,LogonTimeRaw

```



---



\## Idle Session Cleanup



\### Disconnect Idle Sessions (non-destructive)



```powershell

\# Disconnect idle sessions older than 8 hours

.\\Disconnect-RDIdleSessions.ps1 -MinIdleMinutes 480 -Verbose



\# Remote host, include active sessions (be careful)

.\\Disconnect-RDIdleSessions.ps1 -ComputerName RDSH01 -MinIdleMinutes 120 -IncludeActive -Force -Verbose



\# Exclude service/admin accounts

.\\Disconnect-RDIdleSessions.ps1 -MinIdleMinutes 240 -IncludeActive `

&nbsp; -ExcludeUsers 'admin\*','svc\_\*' -Force

```



---



\## User Logoff (Destructive)



```powershell

\# Log off disconnected users

.\\Logoff-RDUsers.ps1 -DisconnectedOnly -Force -Verbose



\# Log off users idle > 8 hours

.\\Logoff-RDUsers.ps1 -DisconnectedOnly -MinIdleMinutes 480 -Force -Verbose



\# Include active sessions (use extreme caution)

.\\Logoff-RDUsers.ps1 -IncludeActive -MinIdleMinutes 720 `

&nbsp; -ExcludeUsers 'admin\*','svc\_\*' -Force -Verbose

```



---



\## RDS Host Health



```powershell

\# Basic host health

.\\Get-RDHostStatus.ps1 -ComputerName RDSH01 | Format-Table -Auto



\# Multi-host report

.\\Get-RDHostStatus.ps1 -ComputerName RDSH01,RDSH02 |

&nbsp; Export-Csv C:\\Reports\\RDS-HostStatus.csv -NoTypeInformation



\# Include disk utilization

.\\Get-RDHostStatus.ps1 -ComputerName RDSH01 -IncludeAllFixedDrives |

&nbsp; Format-List

```



\*\*Signals to watch\*\*



\* Low free disk on profile volume

\* Excessive session count vs CPU/RAM

\* High reboot pending signals



---



\## RDS Licensing



```powershell

\# License status per host

.\\Get-RDLicenseStatus.ps1 -ComputerName RDSH01,RDSH02 |

&nbsp; Format-Table -Auto



\# Export for audit

.\\Get-RDLicenseStatus.ps1 -ComputerName RDSH01,RDSH02 |

&nbsp; Export-Csv C:\\Reports\\RDS-LicenseStatus.csv -NoTypeInformation

```



\*\*Common issues\*\*



\* Grace period expired

\* Licensing server unreachable

\* CAL type mismatch (Per User vs Per Device)



---



\## Profile Management



\### Identify and Clean Stale Profiles



```powershell

\# Preview stale profiles (>60 days)

.\\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 60 |

&nbsp; Format-Table -Auto



\# Remove stale profiles (>90 days)

.\\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 90 -Remove -Verbose



\# Multi-host forced cleanup (automation-safe)

.\\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01,RDSH02 `

&nbsp; -StaleDays 120 -Remove -Confirm:$false -Verbose



\# Estimate space reclaimed

.\\Clear-RDStaleProfiles.ps1 -ComputerName RDSH01 -StaleDays 120 `

&nbsp; -EstimateSize -MinProfileSizeMB 500

```



---



\## Login Validation



```powershell

\# Test interactive login prerequisites

.\\Test-RDUserLogon.ps1 -ComputerName RDSH01 | Format-Table -Auto



\# Skip ping (firewall-restricted environments)

.\\Test-RDUserLogon.ps1 -ComputerName RDSH01,RDSH02 -SkipPing |

&nbsp; Format-Table -Auto



\# Require all core services running

.\\Test-RDUserLogon.ps1 -ComputerName RDSH01 `

&nbsp; -RequireAllCoreServicesRunning -SkipPing

```



---



\## High-Signal Event Logs



```powershell

\# Terminal Services operational log

Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" |

&nbsp; Select-Object TimeCreated,Id,LevelDisplayName,Message



\# RDP authentication failures

Get-WinEvent -LogName Security |

&nbsp; Where-Object { $\_.Id -in 4625,4771,4776 } |

&nbsp; Select-Object TimeCreated,Id,Message

```



---



\## Common Failure Patterns



| Symptom                  | Likely Cause                         |

| ------------------------ | ------------------------------------ |

| Black screen after login | Profile corruption / disk full       |

| Immediate disconnect     | Licensing or auth failure            |

| Slow logon               | GPO processing / profile size        |

| Sessions won’t log off   | Hung user process                    |

| New logons fail          | Session limit or resource exhaustion |



---



\## Safety Notes



\* \*\*Disconnect ≠ Logoff\*\* (disconnect is always safer)

\* Always \*\*exclude admin/service accounts\*\*

\* Clean profiles \*\*before\*\* adding capacity

\* Capture a \*\*session inventory\*\* before mass actions

\* Prefer \*\*WhatIf / Preview\*\* modes first



---



\## Related Scripts



\* `Get-RDActiveSessions.ps1`

\* `Disconnect-RDIdleSessions.ps1`

\* `Logoff-RDUsers.ps1`

\* `Get-RDHostStatus.ps1`

\* `Get-RDLicenseStatus.ps1`

\* `Clear-RDStaleProfiles.ps1`

\* `Test-RDUserLogon.ps1`



---



\## Philosophy



RDS stability is about \*\*reducing entropy\*\*:



\* Fewer sessions

\* Smaller profiles

\* Predictable cleanup

\* Clear visibility



Most fixes are boring. That’s a good thing.



```



---



