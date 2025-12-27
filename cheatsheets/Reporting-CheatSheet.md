\# PowerShell Bible  

\## Reporting \& Output Cheat Sheet



---



\## Purpose



This cheat sheet provides \*\*practical PowerShell patterns\*\* for generating reports and structured output that are:

\- Easy to consume

\- Safe for automation

\- Suitable for tickets and audits

\- Consistent across scripts



Reporting is about \*\*clarity\*\*, not just data volume.



---



\## Core Principles



\### 1. Objects First



Always build and manipulate \*\*objects\*\*, not formatted text.



Formatting (`Format-Table`, `Format-List`) should occur \*\*only at the final presentation step\*\*.



---



\### 2. Reports Must Be Reusable



Reports should:

\- Be readable by humans

\- Be parseable by tools

\- Be easy to export



Avoid output that only looks good in a console.



---



\## Creating Report Objects



\### Basic Custom Object



```powershell

$report = \[PSCustomObject]@{

&nbsp;   ComputerName = $env:COMPUTERNAME

&nbsp;   Timestamp    = Get-Date

&nbsp;   Status       = "OK"

}



