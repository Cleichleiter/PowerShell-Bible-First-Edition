\# PowerShell Bible  

\## Scheduled Tasks \& Job Execution Standards



---



\## Purpose



This document defines \*\*approved patterns and standards\*\* for using \*\*Windows Scheduled Tasks\*\* and \*\*PowerShell jobs\*\* within the PowerShell-Bible repository.



Automation that runs unattended must be:

\- Predictable

\- Observable

\- Recoverable

\- Safe to rerun



Poorly designed scheduled execution is a common source of silent failure and long-term instability. These standards exist to prevent that.



---



\## Core Principles



\### 1. Scheduled ≠ Fire and Forget



Anything that runs unattended must:

\- Log its execution

\- Surface failures

\- Be auditable after the fact



If you cannot tell whether a task ran successfully, it is not production-ready.



---



\### 2. Prefer Scheduled Tasks Over Background Jobs



For operational automation:

\- \*\*Scheduled Tasks\*\* are preferred

\- \*\*PowerShell jobs\*\* are limited to short-lived, interactive use



Scheduled Tasks provide:

\- Better reliability

\- Clear execution context

\- Built-in retry and history

\- Integration with Windows logging



---



\## When to Use Each Mechanism



\### Use Scheduled Tasks When:

\- Automation must run on a schedule

\- Execution must survive reboots

\- The task runs without user interaction

\- Logging and auditability are required

\- Used in RMM or server automation



\### Use PowerShell Jobs When:

\- Running short-lived parallel work

\- Executing interactive or exploratory tasks

\- Testing logic locally

\- Results are immediately consumed



Jobs are not a substitute for durable automation.



---



\## Scheduled Task Design Standards



\### Task Naming



Use clear, descriptive names:





