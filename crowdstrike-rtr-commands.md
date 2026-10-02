# CrowdStrike Falcon Real Time Response (RTR): useful commands and workflow

Real Time Response gives analysts a remote command line on a Falcon-protected host. This sheet covers the built-in commands, `runscript` snippets for common DFIR questions, and a workflow that pairs RTR with Falcon Advanced Event Search.

> **Read this first.**
> - Which commands you can run depends on your **RTR role** (Read-Only Analyst, Active Responder, Real Time Responder Admin), your sensor version and the host OS. Type `help` in the session for the commands available to you, and `help <command>` for syntax. Treat the syntax here as a guide and confirm it with `help`.
> - RTR sessions and commands are **audited**. Use RTR only on hosts and cases you are authorized to work on, and follow your organization's rules for evidence handling.
> - Commands marked **[changes system]** alter the host. Collect first, change later, and record who approved it.
> - Examples use invented names and documentation-range IPs. Nothing here comes from any employer.

## 1. Built-in commands (Windows)

Roles: **RO** = Read-Only Analyst, **AR** = Active Responder, **ADM** = Admin. A higher role includes the lower role's commands.

### Look around (RO)
| Command | Use |
|---|---|
| `help` / `help <cmd>` | List commands, show syntax |
| `ls <path>` | List a directory. Use it for `C:\Users`, `C:\Windows\Temp`, startup folders, `C:\Windows\Prefetch` |
| `cd <path>` | Change directory |
| `cat <file>` | Print a (small) text file: hosts file, PowerShell history, scripts |
| `ps` | Running processes with PIDs and command lines |
| `netstat` | Network connections and listeners |
| `ipconfig` | Network configuration |
| `filehash <file>` | MD5 and SHA256 of a file. Hash a suspect file, then check intelligence |
| `reg query <key> [<value>]` | Read registry keys: Run keys, services, RunMRU |
| `eventlog list` | List event logs |
| `eventlog view <log> [count]` | Read recent events from a log |
| `eventlog export <log>` / `eventlog backup` | Save an event log for download |
| `getsid` | Show the SID of the current user |
| `env` | Environment variables |
| `history` | Your session's command history |
| `mount` | Mounted volumes and shares |
| `clear` | Clear the console screen |

### Collect and respond (AR)
| Command | Use |
|---|---|
| `get <path>` | **Retrieve a file** from the host to the Falcon cloud, for download from the session. Files arrive in a protected archive, and the console shows how to open it |
| `zip <source> <destination>` | Compress a file or folder on the host before you `get` it |
| `memdump <pid>` | Dump the memory of one process |
| `mkdir <path>`, `cp`, `mv` | File operations (write to a clean path, not over evidence) |
| `kill <pid>` | **[changes system]** Stop a process. This destroys its memory, so dump it first |
| `rm <path>` | **[changes system]** Delete a file. Retrieve a copy first |
| `reg set`, `reg delete` | **[changes system]** Change or remove registry values (persistence cleanup) |
| `restart`, `shutdown` | **[changes system]** Power control. Prefer network containment to shutdown |

### Run your own tooling (ADM)
| Command | Use |
|---|---|
| `put <file>` | Copy a file from the Falcon cloud file library to the host |
| `run <path> [args]` | Run an executable already on the host |
| `put-and-run <file>` | Copy and run in one step |
| `runscript` | Run a script with PowerShell (Windows). See below |

`runscript` forms:
````
runscript -Raw=```Get-Process | Select Name, Id, Path | Format-Table -Auto```
runscript -CloudFile="Triage-Processes" -CommandLine="-Hours 24"
runscript -HostPath="C:\Tools\collect.ps1" -Timeout=120
````
`-Raw` runs inline code, `-CloudFile` runs a script you have uploaded to the Falcon library, and `-HostPath` runs a script already on the host. Use `-Timeout` for long jobs. Test scripts on one lab host before using them on a production one or a batch of hosts.

## 2. `runscript -Raw` snippets for DFIR questions

Keep output small. RTR has output limits, so filter and select columns. Each snippet below is the code that goes between the triple backticks of a `-Raw=` argument, as in the first example above.

**Process tree with command lines**
```
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine | Format-Table -Auto -Wrap
```

**Processes running from user-writable locations**
```
Get-CimInstance Win32_Process | ? { $_.ExecutablePath -match '\\(Users|ProgramData|Temp|AppData)\\' } | Select ProcessId,Name,ExecutablePath,CommandLine | Format-List
```

**Connections with owning process names**
```
Get-NetTCPConnection -State Established | Select LocalPort,RemoteAddress,RemotePort,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Format-Table -Auto
```

**Scheduled tasks (enabled) and their actions**
```
Get-ScheduledTask | ? State -ne 'Disabled' | Select TaskName,TaskPath,@{n='Action';e={($_.Actions|%{$_.Execute+' '+$_.Arguments}) -join ' | '}} | Format-Table -Auto -Wrap
```

**Services from odd locations**
```
Get-CimInstance Win32_Service | ? { $_.PathName -match 'Users|Temp|ProgramData|cmd\.exe|powershell' } | Select Name,State,StartName,PathName | Format-List
```

**Run keys**
```
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | % { "== $_"; Get-ItemProperty $_ -EA 0 | Format-List }
```

**Win+R history (ClickFix check)** (this can be run per user with `reg query` where the user hive is loaded)
```
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -EA 0 | Format-List
```
RTR often runs as `SYSTEM`, so `HKCU` is not the logged-in user. To read a specific user, load their `NTUSER.DAT` or read `HKU:\<SID>`:
```
Get-ChildItem Registry::HKEY_USERS | Select Name
Get-ItemProperty 'Registry::HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -EA 0 | Format-List
```

**Recently changed executables and scripts in user areas**
```
Get-ChildItem C:\Users,C:\ProgramData,C:\Windows\Temp -Recurse -Force -EA 0 -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js,*.hta | ? LastWriteTime -gt (Get-Date).AddDays(-2) | Select FullName,Length,LastWriteTime | Sort LastWriteTime -Desc | Select -First 50 | Format-Table -Auto
```

**Hash a file and check its signature**
```
$f='C:\Users\asmith\AppData\Local\Temp\svc_update.exe'; Get-FileHash $f -Algorithm SHA256; Get-AuthenticodeSignature $f | Select Status,SignerCertificate
```

**Downloaded-from-internet marker**
```
Get-Content 'C:\Users\asmith\Downloads\invoice.exe' -Stream Zone.Identifier
```

**PowerShell history for every user**
```
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -EA 0 | % { "== $($_.FullName)"; Get-Content $_ -Tail 40 }
```

**Local administrators and logged-on sessions**
```
Get-LocalGroupMember Administrators; query user
```

**Defender exclusions and status**
```
Get-MpPreference | Select ExclusionPath,ExclusionProcess,ExclusionExtension; Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
```

**Shadow copies still present (ransomware check)**
```
vssadmin list shadows
```

**Security log: logons from the last day**
```
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 40 | Select TimeCreated,Id | Format-Table -Auto
```
More on these in [windows-powershell-cmd-commands.md](windows-powershell-cmd-commands.md).

## 3. Linux and macOS hosts
Available commands differ from Windows, and `runscript` uses a shell (bash) instead of PowerShell. Use `help` on the host first. Typical read-only examples with `runscript -Raw`:
```
ps auxwwf
ss -tulpan
last -aF | head -30
crontab -l; ls -la /etc/cron*
systemctl list-unit-files --state=enabled
find / -xdev -type f -mtime -2 2>/dev/null | head -100
```
The full command list is in [linux-dfir-commands.md](linux-dfir-commands.md).

## 4. Workflow: Falcon query to RTR to evidence

1. **Find the host and process in Advanced Event Search.** Example for a suspicious PowerShell download:
   ```
   #event_simpleName=ProcessRollup2 event_platform=Win
   | FileName=/^(powershell|pwsh)\.exe$/i
   | CommandLine=/(downloadstring|downloadfile|invoke-webrequest|\biwr\b)/i
   | table([@timestamp, aid, ComputerName, UserName, TargetProcessId, ParentBaseFileName, SHA256HashData, CommandLine])
   ```
   Keep `ComputerName`, `aid` and `TargetProcessId`.
2. **Check what else the process did** with `NewExecutableWritten`, `DnsRequest` and `NetworkConnectIP4` events that share `ContextProcessId` = that `TargetProcessId`. See [powershell-download-hunting.md](https://github.com/HaHashem/soc-hunting-queries/blob/main/crowdstrike-falcon/powershell-download-hunting.md).
3. **Open an RTR session** on that host from the console (host management or the detection).
4. **Confirm and collect:**
   ```
   ps
   netstat
   filehash C:\Users\asmith\AppData\Local\Temp\svc_update.exe
   ls C:\Users\asmith\AppData\Local\Temp
   cat C:\Users\asmith\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
   reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
   eventlog export Security
   zip C:\Users\asmith\AppData\Local\Temp\svc_update.exe C:\Windows\Temp\evidence.zip
   get C:\Windows\Temp\evidence.zip
   ```
5. **Contain** with the Falcon **network containment** action in the console (not by ad hoc commands). RTR still works on a contained host.
6. **Scope** the hash, domain and file name fleet-wide with Advanced Event Search.
7. **Remediate last:** `kill` the process (after `memdump`), remove persistence with `reg delete` and `rm` (after retrieving copies), then verify with a second pass of the checks above.
8. **Write it up:** timeline, commands you ran (the session history), files collected with hashes, and who approved changes.

## 5. Batch RTR (many hosts)
Batch sessions run one command on many hosts at once. Use them carefully:
- Start with a **read-only** command on a **small, representative group**.
- Prefer scoping with Advanced Event Search first, so you only touch hosts that match.
- Never run `kill`, `rm`, `reg set`, `restart` or `shutdown` in batch unless you have tested on one host and have approval.
- Check output size. A command that prints thousands of lines on every host is slow and hard to read.

## 6. Good practice
- Collect volatile data (`ps`, `netstat`, `memdump`) **before** anything that changes state.
- Write files to a dedicated folder such as `C:\Windows\Temp\IR\`, and delete your staging files when done, if the case allows, and say so in your notes.
- Use `filehash` and record hashes before and after copying.
- Keep your command history from the session with the case record.
- If a command fails, check your role, the path quoting (paths with spaces need quotes), and the sensor version.
- Do not paste scripts from the internet into production RTR without reading and testing them.

## Related
[windows-powershell-cmd-commands.md](windows-powershell-cmd-commands.md) · [linux-dfir-commands.md](linux-dfir-commands.md) · [triage-first-30-minutes.md](triage-first-30-minutes.md) · [CrowdStrike hunting queries](https://github.com/HaHashem/soc-hunting-queries/tree/main/crowdstrike-falcon)
