Reporting Snippets

Ops-focused PowerShell scripts designed to collect, summarize, and export operational data for reporting, auditing, and automation workflows.

These scripts prioritize structured object output suitable for CSV, HTML, JSON, and downstream processing. Formatting is intentionally deferred to the caller.

Design Goals

Object-based output (no inline formatting)

Safe, read-only data collection

Automation- and RMM-friendly

Consistent property naming

Easy export, scheduling, and chaining

Common Use Cases

Daily / weekly health reports

Capacity and trend tracking

Audit preparation and evidence collection

Client-facing summaries

Baseline snapshots before changes

General Usage Patterns
# Export to CSV
.\Get-ServiceHealthReport.ps1 |
  Export-Csv C:\Reports\ServiceHealth.csv -NoTypeInformation

# Multi-host reporting
.\Get-SystemInventory.ps1 -ComputerName PC01,PC02 |
  Export-Csv C:\Reports\SystemInventory.csv -NoTypeInformation

# HTML reporting
.\Get-SystemInventory.ps1 -IncludeDisks |
  ConvertTo-Html -Title "System Inventory" |
  Out-File C:\Reports\Inventory.html

System Inventory
# Local inventory
.\Get-SystemInventory.ps1 | Format-Table -Auto

# Include disk + network summaries
.\Get-SystemInventory.ps1 -IncludeDisks -IncludeNetwork | Format-List

# Multi-host CSV export
.\Get-SystemInventory.ps1 -ComputerName PC01,PC02 |
  Export-Csv C:\Reports\SystemInventory.csv -NoTypeInformation

Service Health Reporting
# Full service inventory
.\Get-ServiceHealthReport.ps1 | Format-Table -Auto

# High-signal problems: auto-start services not running
.\Get-ServiceHealthReport.ps1 -StartMode Auto -OnlyProblems |
  Sort-Object ComputerName,Name |
  Format-Table -Auto

# RDS-focused expected services (critical if not running)
.\Get-ServiceHealthReport.ps1 -ComputerName RDSH01,RDSH02 `
  -ExpectedRunning TermService,UmRdpService -OnlyProblems |
  Export-Csv C:\Reports\ServiceHealth-RDS.csv -NoTypeInformation

# Filter by service name (include path for triage)
.\Get-ServiceHealthReport.ps1 -Name "MSSQL*" -IncludePath |
  Format-Table -Auto

Event Log Summary
# Default: System + Application, last 24 hours
.\Get-EventLogSummary.ps1 | Format-Table -Auto

# Last 6 hours, only critical + error
.\Get-EventLogSummary.ps1 -Hours 6 -Level Critical,Error |
  Format-Table -Auto

# Remote hosts + CSV summary
.\Get-EventLogSummary.ps1 -ComputerName RDSH01,RDSH02 -Hours 24 |
  Export-Csv C:\Reports\EventLogSummary.csv -NoTypeInformation

# Include sample rows for triage
.\Get-EventLogSummary.ps1 -Hours 12 -IncludeSamples -SampleCount 15 |
  Format-List

# Filter by provider wildcard
.\Get-EventLogSummary.ps1 -ProviderName "*Disk*","*Service Control Manager*" |
  Format-Table -Auto

Patch Compliance
# Local patch compliance snapshot
.\Get-PatchComplianceReport.ps1 | Format-Table -Auto

# SLA-style compliance (hotfix within last 30 days)
.\Get-PatchComplianceReport.ps1 -ComplianceDays 30 |
  Export-Csv C:\Reports\PatchCompliance.csv -NoTypeInformation

# Multi-host + pending reboot signals
.\Get-PatchComplianceReport.ps1 -ComputerName PC01,PC02 `
  -ComplianceDays 30 -IncludePendingRebootSignals |
  Export-Csv C:\Reports\PatchCompliance.csv -NoTypeInformation

# Include recent hotfix rows for audit evidence
.\Get-PatchComplianceReport.ps1 -IncludeHotfixes -TopHotfixes 15 |
  Format-List

Scheduled Task Health
# Full task inventory
.\Get-ScheduledTaskStatus.ps1 | Format-Table -Auto

# Only problems (warn / critical / error)
.\Get-ScheduledTaskStatus.ps1 -OnlyProblems |
  Sort-Object ComputerName,Health,FullName |
  Format-Table -Auto

# Focus a namespace (Microsoft built-in tasks)
.\Get-ScheduledTaskStatus.ps1 -TaskPath "\Microsoft\Windows\*" |
  Export-Csv C:\Reports\ScheduledTasks.csv -NoTypeInformation

# Remote problems export
.\Get-ScheduledTaskStatus.ps1 -ComputerName PC01,PC02 -OnlyProblems |
  Export-Csv C:\Reports\ScheduledTaskProblems.csv -NoTypeInformation

# Include actions and triggers for triage
.\Get-ScheduledTaskStatus.ps1 -OnlyProblems -IncludeDefinition |
  Format-List

User Login Activity
# Default: last 24 hours, interactive + RDP logons
.\Get-UserLoginActivity.ps1 | Format-Table -Auto

# Last 6 hours with sample events
.\Get-UserLoginActivity.ps1 -Hours 6 -IncludeSamples -SampleCount 20 |
  Format-List

# Multi-host export
.\Get-UserLoginActivity.ps1 -ComputerName RDSH01,RDSH02 -Hours 24 |
  Export-Csv C:\Reports\UserLoginActivity.csv -NoTypeInformation

Installed Software Inventory
# Full inventory (deduplicated)
.\Get-InstalledSoftwareReport.ps1 |
  Sort-Object DisplayName |
  Format-Table -Auto

# Focus common MSP / accounting apps
.\Get-InstalledSoftwareReport.ps1 `
  -Name "*QuickBooks*","*Thomson*","*UltraTax*","*Adobe*","*Java*" |
  Format-Table -Auto

# Only problematic / stale entries
.\Get-InstalledSoftwareReport.ps1 -OnlyProblems |
  Export-Csv C:\Reports\Software-Problems.csv -NoTypeInformation

# Include per-user installs (HKCU)
.\Get-InstalledSoftwareReport.ps1 -IncludeCurrentUser |
  Export-Csv C:\Reports\InstalledSoftware-WithHKCU.csv -NoTypeInformation

Notes

All scripts are read-only by default

No assumptions are made about output formatting

Designed to be chained, exported, and scheduled

Suitable for direct RMM execution