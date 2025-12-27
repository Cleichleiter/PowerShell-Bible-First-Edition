````markdown

\# Scheduled Tasks Snippets



Ops-focused PowerShell scripts for \*\*discovering\*\*, \*\*auditing\*\*, \*\*validating\*\*, and \*\*safely changing\*\* Windows Scheduled Tasks.



These scripts are designed for MSP/sysadmin workflows where scheduled tasks are frequently the root cause of:

\- silent failures (backups, sync jobs, maintenance tasks)

\- authentication issues (expired run-as credentials)

\- “it worked yesterday” drift

\- migration leftovers and dead automations



\## Design Goals



\- \*\*Object-first output\*\* (export-friendly: CSV/JSON/HTML)

\- \*\*Safe defaults\*\* (read-only unless explicitly opted in)

\- \*\*Remote-capable\*\* via PowerShell remoting

\- \*\*Consistent properties\*\* across scripts

\- \*\*Triage-ready\*\* (include principal + actions + triggers when needed)



\## Scripts in This Folder



\### Get-ScheduledTaskInventory.ps1

Baseline discovery. Enumerates tasks and returns normalized inventory fields (state, enabled, run-as, last run, next run, result).



Use this to build a \*\*snapshot\*\* before/after changes or to produce a client-facing inventory export.



\### Get-ScheduledTaskStatus.ps1

Health-focused status reporting. Flags tasks that are disabled, failing, running unexpectedly, or stale based on configurable recency thresholds.



Use this for \*\*daily health checks\*\* and \*\*RMM alerting\*\*.



\### Get-ScheduledTaskDefinition.ps1

Definition expansion for audits and triage. Extracts task principal, actions, triggers, and settings. Optional raw XML for deep auditing.



Use this when you need to answer: \*\*“What is this task actually doing?”\*\*



\### Find-StaleScheduledTasks.ps1

Identifies tasks that are stale (not run recently), never run, disabled (optional), or failing (optional). Useful for cleanup after migrations and long-lived environments.



\### Test-ScheduledTaskExecution.ps1

Readiness validation by default. Optional opt-in controlled start (`-Start`) with optional wait and post-run capture.



Use this for \*\*validation\*\* and \*\*troubleshooting\*\*, especially after permissions changes.



\### Disable-ScheduledTaskSafely.ps1

Controlled change script. Captures pre-change snapshot and disables tasks with strong guardrails. Supports WhatIf, confirmations, and export evidence.



This script \*\*does not delete tasks\*\*.



\## Common Usage



> Tip: Build a baseline inventory first, then move into status/definition validation.



\### Inventory (baseline discovery)



```powershell

\# Full inventory (lightweight)

.\\Get-ScheduledTaskInventory.ps1 | Format-Table -Auto



\# Exclude Microsoft + include action/trigger summaries

.\\Get-ScheduledTaskInventory.ps1 -ExcludeMicrosoft -IncludeActions -IncludeTriggers |

&nbsp; Export-Csv C:\\Reports\\ScheduledTaskInventory.csv -NoTypeInformation



\# Focus a subtree and name pattern

.\\Get-ScheduledTaskInventory.ps1 -TaskPath "\\Microsoft\\Windows\\\*" -TaskName "\*Update\*" |

&nbsp; Format-Table -Auto



\# Remote multi-host inventory

.\\Get-ScheduledTaskInventory.ps1 -ComputerName RDSH01,RDSH02 -ExcludeMicrosoft |

&nbsp; Export-Csv C:\\Reports\\TaskInventory.csv -NoTypeInformation

````



\### Definitions (actions, triggers, security context)



```powershell

\# Definitions for all non-Microsoft tasks (actions + triggers)

.\\Get-ScheduledTaskDefinition.ps1 -ExcludeMicrosoft |

&nbsp; Select-Object ComputerName,FullName,PrincipalUserId,RunLevel |

&nbsp; Format-Table -Auto



\# Focus a task name pattern

.\\Get-ScheduledTaskDefinition.ps1 -TaskName "Backup\*" | Format-List



\# Deep audit: include XML (heavier)

.\\Get-ScheduledTaskDefinition.ps1 -TaskPath "\\Microsoft\\Windows\\UpdateOrchestrator\\" -IncludeRawXml |

&nbsp; Export-Csv C:\\Reports\\TaskDefinitions-WithXml.csv -NoTypeInformation

```



\### Stale task identification (cleanup + drift detection)



```powershell

\# Default: inactive > 90 days (exclude Microsoft noise)

.\\Find-StaleScheduledTasks.ps1 -ExcludeMicrosoft | Format-Table -Auto



\# Include tasks that never ran (enabled)

.\\Find-StaleScheduledTasks.ps1 -ExcludeMicrosoft -IncludeNeverRun | Format-Table -Auto



\# Include failures even if recent (high-signal broken automations)

.\\Find-StaleScheduledTasks.ps1 -ExcludeMicrosoft -IncludeFailing |

&nbsp; Format-Table -Auto



\# Multi-host export for cleanup review

.\\Find-StaleScheduledTasks.ps1 -ComputerName RDSH01,RDSH02 -ExcludeMicrosoft -IncludeDisabled -IncludeFailing |

&nbsp; Export-Csv C:\\Reports\\StaleOrFailingTasks.csv -NoTypeInformation

```



\### Execution validation (readiness check + optional controlled start)



```powershell

\# Readiness check only (no changes)

.\\Test-ScheduledTaskExecution.ps1 -TaskName "NightlyBackup" -TaskPath "\\Backups\\" -RequireSingle |

&nbsp; Format-Table -Auto



\# Readiness check for a subtree (include definition signals)

.\\Test-ScheduledTaskExecution.ps1 -FullName "\\Vendor\\\*" -IncludeDefinitionSignals |

&nbsp; Format-Table -Auto



\# Controlled start + wait for completion (explicit opt-in)

.\\Test-ScheduledTaskExecution.ps1 -TaskName "NightlyBackup" -TaskPath "\\Backups\\" -Start -RequireSingle -Wait -WaitSeconds 300 |

&nbsp; Format-List



\# Remote controlled validation (be deliberate; -Start runs remotely)

.\\Test-ScheduledTaskExecution.ps1 -ComputerName RDSH01 -TaskName "Cleanup" -TaskPath "\\Ops\\" -Start -RequireSingle -Wait |

&nbsp; Format-List

```



\### Safe disable (controlled change + audit evidence)



```powershell

\# Preview changes (recommended)

.\\Disable-ScheduledTaskSafely.ps1 -FullName "\\Vendor\\\*" -ExcludeMicrosoft -WhatIf



\# Disable one task with guardrails

.\\Disable-ScheduledTaskSafely.ps1 -TaskName "NightlyBackup" -TaskPath "\\Backups\\" -RequireSingle -Force



\# Disable a set and export evidence

.\\Disable-ScheduledTaskSafely.ps1 -FullName "\\Ops\\Legacy\\\*" -ExcludeMicrosoft -Force `

&nbsp; -IncludeDefinition -ExportCsv C:\\Reports\\DisabledTasks.csv



\# Remote disable (be deliberate)

.\\Disable-ScheduledTaskSafely.ps1 -ComputerName RDSH01,RDSH02 -FullName "\\Ops\\Legacy\\\*" -Force -WhatIf

```



\## Safety Notes



\* \*\*Test-ScheduledTaskExecution.ps1\*\* is read-only unless `-Start` is provided.

\* \*\*Disable-ScheduledTaskSafely.ps1\*\* is a change script:



&nbsp; \* Always run `-WhatIf` first in unfamiliar environments.

&nbsp; \* Use `-RequireSingle` for high-impact targets.

&nbsp; \* Export evidence when working in regulated/audited environments.



\## Requirements



\* Windows PowerShell 5.1+ or PowerShell 7+ (best-effort compatibility)

\* ScheduledTasks module (available on most Windows systems)

\* PowerShell remoting enabled for `-ComputerName` scenarios



```







