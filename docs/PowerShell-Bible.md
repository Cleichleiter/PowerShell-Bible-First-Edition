$RepoPath = "C:\\Users\\CheriLeichleiter\\Github Repos\\PowerShell-Bible"

$DocPath  = Join-Path $RepoPath "docs\\PowerShell-Bible.md"



if (-not (Test-Path $RepoPath)) {

&nbsp;   throw "Repo path not found: $RepoPath"

}



if (-not (Test-Path (Split-Path $DocPath))) {

&nbsp;   throw "Docs folder not found. Run repo initialization first."

}



$Content = @"

\# PowerShell Bible  

\## Core Philosophy \& Operational Patterns



---



\## Purpose of This Document



This document defines the \*\*engineering philosophy\*\*, \*\*standards\*\*, and \*\*patterns\*\* used throughout the PowerShell-Bible repository.  

It exists to ensure scripts are:



\- Predictable under pressure

\- Safe to run in production environments

\- Readable by other engineers

\- Easy to troubleshoot during incidents

\- Reusable without re-learning intent



This is a \*field manual\*, not a tutorial.



---



\## Core Philosophy



\### 1. Operations First



Scripts are written for \*\*real environments\*\*, not demos.



Assumptions:

\- You may be running this during an outage

\- You may not remember how the script works

\- Someone else may need to read or reuse it later

\- Output may be copied directly into a ticket or incident report



Design accordingly.



---



\### 2. Clarity Over Cleverness



Avoid:

\- Overly compact one-liners

\- Obscure PowerShell tricks

\- Implicit behavior



Prefer:

\- Explicit variables

\- Step-by-step logic

\- Clear intent



If a script must be clever, it must also be documented.



---



\### 3. Object Output by Default



Scripts should output \*\*objects\*\*, not formatted text.



Rules:

\- Use objects for data processing and reporting

\- Only format output (`Format-Table`, `Format-List`) at the \*very end\*

\- Never format output that another script might consume



This preserves reusability and pipeline integrity.



---



\### 4. Fail Fast, Fail Loud



Silent failure is unacceptable in operational tooling.



Standards:

\- Use `$ErrorActionPreference = 'Stop'`

\- Wrap risky operations in `try/catch`

\- Include context in error messages (target, action, expectation)



If a script fails, it should be obvious \*\*what failed and where\*\*.



---



\### 5. Safety and Reversibility



Any script that \*\*changes state\*\* must answer:

\- What changed?

\- How do I undo it?



Examples:

\- Capture original settings before modification

\- Log previous values

\- Provide a paired \*restore\* script when appropriate



---



\## Standard Script Structure



Every operational script should include:



1\. Comment-based help

2\. Parameter validation

3\. Explicit error handling

4\. Logging

5\. Clear execution flow



High-level layout:



```powershell

\[CmdletBinding()]

param (...)



Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'



try {

&nbsp;   # validate environment

&nbsp;   # perform action

}

catch {

&nbsp;   # log and rethrow

}



