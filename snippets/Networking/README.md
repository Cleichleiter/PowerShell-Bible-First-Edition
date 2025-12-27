\## Networking Snippets



A practical, incident-focused set of PowerShell scripts for quickly validating network health, name resolution, routing, listening services, port reachability, Windows Firewall posture, and NIC error counters. All scripts are designed to output structured objects that work cleanly with `Format-\*`, `Export-Csv`, and downstream automation.



\### Quick Usage



\#### Get-NetworkInterfaceStatus.ps1



Enumerates network interfaces with link status, IP configuration, and high-signal fields for troubleshooting (up/down, DHCP/static, gateway/DNS presence). Supports filtering and multi-host collection.



```powershell

.\\Get-NetworkInterfaceStatus.ps1 | Format-Table -Auto



.\\Get-NetworkInterfaceStatus.ps1 -IncludeDown -ExcludeVirtual | Format-Table -Auto



.\\Get-NetworkInterfaceStatus.ps1 -ComputerName PC01,PC02 |

&nbsp; Export-Csv C:\\Reports\\NetIfStatus.csv -NoTypeInformation

```



\#### Test-DnsResolution.ps1



Validates forward and reverse DNS resolution with flexible query types and optional authoritative details. Useful for “is it DNS or networking?” triage, split-brain checks, and troubleshooting internal records (AD-integrated DNS) vs public resolvers.



```powershell

.\\Test-DnsResolution.ps1 -Name "www.microsoft.com" -Quick | Format-Table -Auto



.\\Test-DnsResolution.ps1 -Name "intranet.contoso.local" -Type A,CNAME -DnsServer 10.0.0.10,10.0.0.11 |

&nbsp; Format-Table -Auto



.\\Test-DnsResolution.ps1 -Name "autodiscover.contoso.com" -Type A,CNAME,TXT |

&nbsp; Format-Table -Auto



.\\Test-DnsResolution.ps1 -IPAddress 10.0.0.25 | Format-Table -Auto



.\\Test-DnsResolution.ps1 -Name "portal.contoso.com" -Type A,CNAME -IncludeAuthority -DnsServer 1.1.1.1,8.8.8.8 |

&nbsp; Format-Table -Auto

```



\#### Test-NetworkPath.ps1



End-to-end network path validation combining reachability signals and optional port checks and traceroute. Useful for isolating where a failure occurs (local host, gateway, WAN, target network, target host).



```powershell

.\\Test-NetworkPath.ps1 -Target "fileserver01" | Format-List



.\\Test-NetworkPath.ps1 -Target "sql01" -Port 1433 | Format-List



.\\Test-NetworkPath.ps1 -Target "rds.contoso.local" -TraceRoute -SkipPing | Format-List



.\\Test-NetworkPath.ps1 -Target "rds.contoso.local" -TraceRoute -AsHops |

&nbsp; Format-Table -Auto



.\\Test-NetworkPath.ps1 -Target "8.8.8.8" -TraceRoute -IncludeReverseLookup -AsHops |

&nbsp; Format-Table -Auto

```



\#### Get-RoutingTable.ps1



Displays effective routing information, including default routes and filtered prefix views. Useful for diagnosing asymmetric routing, incorrect default gateways, and missing static routes.



```powershell

.\\Get-RoutingTable.ps1 | Format-Table -Auto



.\\Get-RoutingTable.ps1 -DefaultOnly | Format-Table -Auto



.\\Get-RoutingTable.ps1 -AddressFamily IPv4 -Prefix "10.\*" | Format-Table -Auto



.\\Get-RoutingTable.ps1 -ComputerName RDSH01,RDSH02 -DefaultOnly |

&nbsp; Export-Csv C:\\Reports\\Routing-Defaults.csv -NoTypeInformation

```



\#### Get-ListeningPorts.ps1



Enumerates listening TCP (and optional UDP) ports, including owning process context. Useful for confirming whether a service is actually bound and available locally, and for verifying unexpected listeners.



```powershell

.\\Get-ListeningPorts.ps1 | Format-Table -Auto



.\\Get-ListeningPorts.ps1 -Port 3389,443,80,445 | Format-Table -Auto



.\\Get-ListeningPorts.ps1 -ExcludeLoopback | Format-Table -Auto



.\\Get-ListeningPorts.ps1 -IncludeUDP | Format-Table -Auto



.\\Get-ListeningPorts.ps1 -ProcessName "sqlservr" -IncludePath | Format-List



.\\Get-ListeningPorts.ps1 -ComputerName RDSH01,RDSH02 -Port 3389 |

&nbsp; Export-Csv C:\\Reports\\ListeningPorts-3389.csv -NoTypeInformation

```



\#### Test-PortConnectivity.ps1



Bulk TCP connectivity testing (with optional UDP best-effort probe) across many targets and ports. Designed for firewall validation and service reachability proof, with export-friendly output.



```powershell

.\\Test-PortConnectivity.ps1 -Target RDSH01,RDSH02 -Port 3389,445,443 | Format-Table -Auto



.\\Test-PortConnectivity.ps1 -Target "sql01","sql02" -Port 1433 -ResolveDNS -IncludePing |

&nbsp; Format-Table -Auto



.\\Test-PortConnectivity.ps1 -TargetFile .\\targets.txt -PortFile .\\ports.txt -Parallel -ThrottleLimit 30 |

&nbsp; Export-Csv C:\\Reports\\PortTest.csv -NoTypeInformation



.\\Test-PortConnectivity.ps1 -Target dc01 -Port 53 -Protocol UDP -TimeoutSeconds 2 | Format-Table -Auto

```



\#### Get-FirewallProfileStatus.ps1



Reports Windows Firewall profile posture (Domain/Private/Public), default inbound/outbound policy, logging signals, and optional high-signal rule indicators. Useful for diagnosing “wrong profile” problems and unexpected blocking/allow behavior.



```powershell

.\\Get-FirewallProfileStatus.ps1 | Format-List



.\\Get-FirewallProfileStatus.ps1 -IncludeRuleSignals | Format-List



.\\Get-FirewallProfileStatus.ps1 -ComputerName RDSH01,RDSH02 -IncludeRuleSignals |

&nbsp; Format-Table -Auto



.\\Get-FirewallProfileStatus.ps1 -ComputerName RDSH01,RDSH02 |

&nbsp; Export-Csv C:\\Reports\\FirewallProfiles.csv -NoTypeInformation

```



\#### Get-NetworkAdapterErrors.ps1



Collects NIC error/discard counters and link state to identify cabling/switch/duplex/driver symptoms. Supports driver enrichment and multi-host export.



```powershell

.\\Get-NetworkAdapterErrors.ps1 |

&nbsp; Format-Table ComputerName,InterfaceAlias,Status,LinkSpeed,ReceivedErrors,SentErrors,ReceivedDiscards,SentDiscards,HasAnyErrorsOrDiscards -Auto



.\\Get-NetworkAdapterErrors.ps1 | Format-Table -Auto



.\\Get-NetworkAdapterErrors.ps1 -IncludeVirtual -IncludeDriverInfo | Format-List



.\\Get-NetworkAdapterErrors.ps1 -ComputerName RDSH01,RDSH02 -IncludeDriverInfo |

&nbsp; Export-Csv C:\\Reports\\NIC-Errors.csv -NoTypeInformation

```



\#### Get-FirewallRuleSummary.ps1



Condensed, high-signal summary of Windows Firewall rules for troubleshooting and risk detection. Includes enabled rule counts (direction/action/profile), optional inbound allow port breakdown, and optional focus checks (RDP/WinRM/SMB).



```powershell

.\\Get-FirewallRuleSummary.ps1 | Format-List



.\\Get-FirewallRuleSummary.ps1 -IncludePortBreakdown -TopPorts 20 | Format-List



.\\Get-FirewallRuleSummary.ps1 -Focus RDP,WinRM,SMB | Format-List



.\\Get-FirewallRuleSummary.ps1 -ComputerName RDSH01,RDSH02 -IncludePortBreakdown |

&nbsp; Export-Csv C:\\Reports\\FirewallRuleSummary.csv -NoTypeInformation

```





