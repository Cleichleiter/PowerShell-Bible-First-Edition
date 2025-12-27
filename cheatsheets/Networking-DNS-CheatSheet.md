\# PowerShell Bible  

\## RDS / Terminal Services Cheat Sheet



---



\## Purpose



This cheat sheet provides \*\*practical PowerShell and native command patterns\*\* for managing \*\*Remote Desktop Services (RDS) / Terminal Servers\*\*.



It is intended for:

\- Live troubleshooting

\- Session cleanup

\- Nightly automation

\- Validation during performance or lock issues



This is not a full RDS deployment guide — it focuses on \*\*operational control\*\*.



---



\## Core Assumptions



Before running RDS-related commands:

\- You are on an RDS / Terminal Server (or targeting one remotely)

\- You have sufficient privileges

\- You understand the impact of logging off users



Always validate context before execution.



---



\## Identify RDS / Terminal Server Role



\### Quick Role Validation



```powershell

Get-WindowsFeature RDS-RD-Server



