\# Reporting Snippets



Ops-focused PowerShell scripts designed to collect, summarize, and export

operational data for reporting, auditing, and automation workflows.



These scripts prioritize structured object output suitable for CSV, HTML,

JSON, and downstream processing.



\## Design Goals



\- Object-based output (no inline formatting)

\- Safe, read-only data collection

\- Automation- and RMM-friendly

\- Consistent property naming

\- Easy export and scheduling



\## Common Use Cases



\- Daily / weekly health reports

\- Capacity and trend tracking

\- Audit preparation

\- Client-facing summaries

\- Baseline snapshots before changes



\## Usage Patterns



```powershell

\# Export to CSV

.\\Get-ServiceHealthReport.ps1 |

&nbsp; Export-Csv C:\\Reports\\ServiceHealth.csv -NoTypeInformation



\# Multi-host reporting

.\\Get-DiskUsageReport.ps1 -ComputerName FS01,FS02 |

&nbsp; Export-Csv C:\\Reports\\DiskUsage.csv -NoTypeInformation



\# HTML reporting

.\\Get-SystemInventory.ps1 |

&nbsp; ConvertTo-Html -Title "System Inventory" |

&nbsp; Out-File C:\\Reports\\Inventory.html



\# Local inventory

.\\Get-SystemInventory.ps1 | Format-Table -Auto



\# Include disk + network summaries

.\\Get-SystemInventory.ps1 -IncludeDisks -IncludeNetwork | Format-List



\# Multi-host CSV export

.\\Get-SystemInventory.ps1 -ComputerName PC01,PC02 |

&nbsp; Export-Csv C:\\Reports\\SystemInventory.csv -NoTypeInformation



\# HTML report

.\\Get-SystemInventory.ps1 -IncludeDisks |

&nbsp; ConvertTo-Html -Title "System Inventory" |

&nbsp; Out-File C:\\Reports\\Inventory.html


# Full service inventory
.\Get-ServiceHealthReport.ps1 | Format-Table -Auto

# High-signal problems: Auto-start services not running
.\Get-ServiceHealthReport.ps1 -StartMode Auto -OnlyProblems |
  Sort-Object ComputerName,Name |
  Format-Table -Auto

# RDS-focused expected services (treat as critical if not running)
.\Get-ServiceHealthReport.ps1 -ComputerName RDSH01,RDSH02 -ExpectedRunning TermService,UmRdpService -OnlyProblems |
  Export-Csv C:\Reports\ServiceHealth-RDS.csv -NoTypeInformation

# Filter by service name pattern (include path for triage)
.\Get-ServiceHealthReport.ps1 -Name "MSSQL*" -IncludePath |
  Format-Table -Auto



