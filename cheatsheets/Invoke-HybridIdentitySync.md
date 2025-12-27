\# Invoke-HybridIdentitySync.ps1  

Hybrid Identity Sync Control (Entra Connect \& Cloud Sync)



---



\## Purpose



`Invoke-HybridIdentitySync.ps1` is a \*\*single operational control script\*\* for managing and troubleshooting \*\*hybrid identity synchronization\*\* between on-prem Active Directory and Microsoft Entra ID.



It consolidates the most common “I need this synced now” and “why isn’t this syncing” actions into \*\*one predictable tool\*\*.



Supported platforms:

\- \*\*Microsoft Entra Connect Sync (ADSync / Azure AD Connect)\*\*

\- \*\*Microsoft Entra Cloud Sync (Provisioning Agent)\*\*



This script is intended to be run \*\*directly on the sync server or agent host\*\*.



---



\## Supported Modes



\### EntraConnect

For environments using \*\*Microsoft Entra Connect Sync\*\* (classic ADSync).



Capabilities:

\- Trigger delta sync

\- Trigger full (initial) sync

\- Inspect scheduler state

\- Enable / disable scheduler

\- Stop a running sync cycle (when supported)



---



\### CloudSync

For environments using \*\*Microsoft Entra Cloud Sync\*\* (provisioning agent).



Capabilities:

\- Surface Cloud Sync trace log location

\- Open trace logs folder

\- Detect presence of AADCloudSyncTools

\- Provide local agent health signals



> Note: Cloud Sync job state is primarily managed via the Entra portal.  

> This script provides \*\*local triage\*\*, not full job control.



---



\## Parameters



\### `-Mode`

Specifies the sync platform.



Valid values:

\- `EntraConnect`

\- `CloudSync`



---



\### `-Action`

Specifies the operation to perform.



\#### EntraConnect actions

\- `GetScheduler`

\- `DeltaSync`

\- `FullSync`

\- `StopCurrentCycle`

\- `EnableScheduler`

\- `DisableScheduler`



\#### CloudSync actions

\- `ShowLogs`

\- `ListTools`

\- `ShowStatus`



---



\### `-OpenLogs`

When used with `CloudSync` + `ShowLogs`, opens the trace log folder in Explorer.



---



\## Common Usage Examples



\### Trigger a delta sync (most common)

```powershell

.\\Invoke-HybridIdentitySync.ps1 -Mode EntraConnect -Action DeltaSync



