\# Filesystem Snippets



Ops-focused PowerShell scripts for analyzing, troubleshooting, cleaning up, and reporting on filesystem usage and health.



These snippets are designed for \*\*real-world administration\*\*: safe defaults, object-based output, and compatibility with automation, RMM tooling, and reporting workflows.



This is not a tutorial section. Scripts are task-oriented and intended to be run directly or adapted into larger automation.



---



\## Included Scripts



\### Storage Analysis



\- \*\*Get-FolderSize.ps1\*\*  

&nbsp; Measure folder sizes with depth control, exclusions, and size thresholds.



\- \*\*Get-LargeFiles.ps1\*\*  

&nbsp; Identify large files by size, age, extension, and location to support cleanup and migration planning.



\- \*\*Find-OldFiles.ps1\*\*  

&nbsp; Locate stale files by age (and optionally size), with support for archiving or removal using guardrails.



---



\### File Access \& Locks



\- \*\*Get-FileLockStatus.ps1\*\*  

&nbsp; Best-effort detection of file locks and open handles using SMB sessions, `openfiles`, and optional Sysinternals `handle.exe`.



\- \*\*Test-FilePathAccess.ps1\*\*  

&nbsp; Validate whether the current execution context can read, write, or modify a given path.



---



\### Permissions \& Security



\- \*\*Get-NTFSPermissionsSummary.ps1\*\*  

&nbsp; Human-readable NTFS permission summaries with support for:

&nbsp; - Explicit-only ACLs

&nbsp; - Principal-focused views

&nbsp; - Recursive scans with depth limits



---



\### Cleanup \& Hygiene



\- \*\*Clear-TempDirectories.ps1\*\*  

&nbsp; Safely clean user and system temp locations based on age, file type, and scope.

&nbsp; Designed for unattended RMM execution with optional detailed output.



---



\### Capacity \& Trending



\- \*\*Get-DiskFreeSpaceTrend.ps1\*\*  

&nbsp; Capture disk free-space snapshots for:

&nbsp; - Capacity planning

&nbsp; - Trend analysis

&nbsp; - CSV-based historical comparison



&nbsp; Supports local and remote systems and append-only reporting.



---



\## Usage Notes



\- All scripts emit \*\*objects\*\*, not formatted text.  

&nbsp; Formatting (`Format-Table`, `Export-Csv`, etc.) is intentionally left to the caller.



\- Scripts that can modify or remove data support \*\*safe defaults\*\* and should be tested with `-WhatIf` when available.



\- Remote execution requires PowerShell remoting to be enabled and accessible.



---



\## Intended Use Cases



\- Incident response and rapid triage

\- Storage growth investigations

\- Migration readiness assessments

\- Permission audits

\- Scheduled cleanup and hygiene tasks

\- Capacity planning and reporting



---



\## Design Philosophy



\- Readability over cleverness  

\- Safety over speed  

\- Explicit behavior over assumptions  

\- Automation-friendly output over console formatting





