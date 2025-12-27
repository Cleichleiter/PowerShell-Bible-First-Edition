$RepoPath = "C:\\Users\\CheriLeichleiter\\Github Repos\\PowerShell-Bible"

$DocsPath = Join-Path $RepoPath "docs"



if (-not (Test-Path $DocsPath)) {

&nbsp;   throw "Docs folder not found at $DocsPath"

}



\# ==========================================================

\# Standards-Style-Guide.md

\# ==========================================================

$StandardsContent = @"

\# PowerShell Bible  

\## Standards \& Style Guide



---



\## Purpose



This document defines \*\*mandatory standards\*\* for scripts contained in the PowerShell-Bible repository.  

Its goal is consistency, readability, and safety in operational environments.



These standards are opinionated by design.



---



\## File Naming Conventions



\### Scripts

\- Use \*\*Verb-Noun\*\* format

\- PascalCase

\- Use hyphens, not underscores



Examples:

\- `Get-DnsClientState.ps1`

\- `Logoff-RDSSessions.ps1`

\- `Restore-TimeSkew.ps1`



\### Modules \& Functions

\- PascalCase

\- Singular nouns where possible



Examples:

\- `Write-Log`

\- `Resolve-PrimaryAdapter`

\- `Test-IsAdmin`



---



\## Folder Organization



\- `docs/` – Standards, philosophy, long-form guidance

\- `cheatsheets/` – Fast lookup references

\- `templates/` – Script and function scaffolding

\- `modules/` – Reusable tooling

\- `snippets/` – Task-focused scripts

\- `examples/` – Sample output and reports



Do not place production scripts at repo root.



---



\## Script Header Requirements



Every script must include \*\*comment-based help\*\*:



Required sections:

\- `.SYNOPSIS`

\- `.DESCRIPTION`

\- `.PARAMETER` (for each parameter)

\- `.EXAMPLE`

\- `.NOTES`



Scripts without help are considered incomplete.



---



\## CmdletBinding Usage



All scripts must use:



```powershell

\[CmdletBinding(SupportsShouldProcess = \\$true)]

param (...)



