\# PowerShell Bible  

\## Logging \& Error Handling Standards



---



\## Purpose



This document defines the \*\*mandatory logging and error-handling standards\*\* used across the PowerShell-Bible repository.



The goals are to ensure that scripts:

\- Fail predictably

\- Provide actionable error information

\- Are debuggable during live incidents

\- Produce output suitable for ticketing and post-incident review



Logging and error handling are not optional implementation details — they are core operational requirements.



---



\## Guiding Principles



\### 1. Silent Failure Is Unacceptable



If a script fails, it must:

\- Surface the failure

\- Identify what failed

\- Provide enough context to troubleshoot quickly



Scripts that fail quietly are operational liabilities.



---



\### 2. Errors Should Be Actionable



An error message should answer:

\- What was attempted?

\- On what target?

\- Why did it fail (if known)?

\- What was expected instead?



Avoid generic messages such as:

\- “An error occurred”

\- “Operation failed”



---



\## Error Handling Strategy



\### Default Error Behavior



All operational scripts should include:



```powershell

$ErrorActionPreference = 'Stop'



