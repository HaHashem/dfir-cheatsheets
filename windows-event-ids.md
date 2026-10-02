# Windows event IDs for investigations

Logs live in `C:\Windows\System32\winevt\Logs\`. Many events need the matching audit policy enabled, so a missing event may mean the logging was off, not that nothing happened.

## Security log

### Logons and authentication
| ID | Meaning | Look for |
|---|---|---|
| 4624 | Logon success | `LogonType` (2 interactive, 3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 new credentials, 10 remote interactive, 11 cached), source IP, account |
| 4625 | Logon failure | Many failures (brute force, spray). `SubStatus` gives the reason |
| 4634 / 4647 | Logoff | Session length |
| 4648 | Logon with explicit credentials | `runas`, lateral movement tools, pass-the-hash variants |
| 4672 | Special privileges assigned | Admin logons. Useful to separate privileged sessions |
| 4768 | Kerberos TGT requested | Source of the initial ticket request |
| 4769 | Kerberos service ticket requested | RC4 (`0x17`) in volume suggests Kerberoasting |
| 4771 | Kerberos pre-authentication failed | Password guessing against Kerberos |
| 4776 | NTLM credential validation | NTLM use, possible pass-the-hash and spraying |
| 4740 | Account locked out | Source of the lockout |

### Accounts and groups
| ID | Meaning |
|---|---|
| 4720 / 4722 / 4725 / 4726 | User created / enabled / disabled / deleted |
| 4723 / 4724 | Password change attempt / password reset |
| 4728 / 4732 / 4756 | Member added to global / local / universal group |
| 4738 | User account changed |

### Persistence and execution
| ID | Meaning |
|---|---|
| 4688 | Process creation. Needs "Include command line in process creation events" for the command line |
| 4697 | Service installed |
| 4698 / 4699 / 4702 | Scheduled task created / deleted / updated |

### Defense evasion and domain
| ID | Meaning |
|---|---|
| 1102 | Security log cleared |
| 4719 | Audit policy changed |
| 4662 | Directory object access. Replication GUIDs here indicate DCSync |
| 5136 / 5137 / 5141 | Directory object changed / created / deleted (GPO changes, for example) |
| 5140 / 5145 | Network share accessed / detailed file share access (admin shares) |

## System log
| ID | Meaning |
|---|---|
| 7045 | New service installed (key for PsExec-style spread) |
| 7036 | Service entered running or stopped state |
| 7040 | Service start type changed |
| 104 | An event log was cleared |
| 6005 / 6006 / 41 | Event log started (boot) / stopped (shutdown) / unexpected reboot |

## Sysmon (`Microsoft-Windows-Sysmon/Operational`)
Requires Sysmon installed and configured. Coverage depends on your configuration.

| ID | Meaning |
|---|---|
| 1 | Process creation (with hashes, parent, command line) |
| 3 | Network connection |
| 5 | Process terminated |
| 7 | Image (DLL) loaded |
| 8 | CreateRemoteThread (injection indicator) |
| 10 | Process access (LSASS access shows here) |
| 11 | File created |
| 12 / 13 / 14 | Registry object created or deleted / value set / key or value renamed |
| 15 | File stream created (downloaded-from-internet marker) |
| 17 / 18 | Pipe created / connected (C2 framework indicators) |
| 19 / 20 / 21 | WMI filter / consumer / binding |
| 22 | DNS query |
| 23 / 26 | File delete archived / delete logged |
| 25 | Process tampering |

## PowerShell
| Log | ID | Meaning |
|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | 4104 | Script block logging (deobfuscated code) |
| same | 4103 | Module logging |
| `Windows PowerShell` | 400 / 800 | Engine start / pipeline execution detail |
| `Microsoft-Windows-WinRM/Operational` | various | Remote session activity. Check the log directly, and look for `wsmprovhost.exe` in process events |

Script block logging and module logging must be enabled by policy.

## Remote Desktop
| Log | ID | Meaning |
|---|---|---|
| `TerminalServices-RemoteConnectionManager/Operational` | 1149 | Successful network authentication for RDP, with the source address |
| `TerminalServices-LocalSessionManager/Operational` | 21 / 22 / 23 / 24 / 25 | Logon / shell start / logoff / disconnect / reconnect |
| `RemoteDesktopServices-RdpCoreTS/Operational` | 131 | Connection accepted, with client address |

## Task Scheduler (`Microsoft-Windows-TaskScheduler/Operational`)
| ID | Meaning |
|---|---|
| 106 | Task registered |
| 140 / 141 | Task updated / deleted |
| 200 / 201 | Action started / completed |

## Microsoft Defender (`Microsoft-Windows-Windows Defender/Operational`)
| ID | Meaning |
|---|---|
| 1116 / 1117 | Malware detected / action taken |
| 5001 | Real-time protection disabled |
| 5007 | Configuration changed (exclusions added, for example) |
| 5010 / 5012 | Scanning for malware / scanning for viruses disabled |

## WMI (`Microsoft-Windows-WMI-Activity/Operational`)
| ID | Meaning |
|---|---|
| 5857 / 5860 / 5861 | Provider loaded / temporary event consumer registered / permanent event subscription created |

## Fast pivots
- **New admin appeared?** 4720, then 4728/4732/4756.
- **Lateral movement?** 4624 type 3 or 10 from a workstation, 7045 or 4697 on the target, 5145 for admin shares.
- **Hiding tracks?** 1102, 104, 4719, Defender 5001 and 5007.
- **Ransomware prep?** Shadow copy deletion shows in process creation (4688 or Sysmon 1), then service stops in 7036.
