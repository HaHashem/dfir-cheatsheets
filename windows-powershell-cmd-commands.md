# Windows PowerShell and CMD commands for DFIR

Commands for collecting evidence and scoping an incident on a Windows host.

> **Safety first.**
> - Every command here only **reads** unless marked **[changes system]**. Reading still changes some timestamps and leaves traces, so record what you ran and when.
> - On a suspected compromised host, the system's own tools may be tampered with. Prefer trusted tools run from external media or your EDR's remote shell.
> - Write output to an evidence location, not to the suspect disk, when you can. Hash everything you collect.
> - Use administrator rights where a command needs them (marked **admin**).
> - `wmic` is deprecated in current Windows. This sheet uses `Get-CimInstance` instead.

## 0. Start a record
```powershell
Start-Transcript -Path E:\evidence\ps-session.txt      # logs everything you type and see
Get-Date -Format o; [System.TimeZoneInfo]::Local.Id    # time and time zone, for your notes
hostname; whoami /all
systeminfo
w32tm /query /status                                   # is the clock in sync?
```

## 1. Processes
```powershell
# Process list with parent, command line and owner path
Get-CimInstance Win32_Process |
  Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
  Sort-Object ParentProcessId | Format-Table -AutoSize -Wrap

# Start times and paths
Get-Process | Select-Object Name, Id, StartTime, Path | Sort-Object StartTime -Descending

# Services hosted by each svchost
tasklist /svc /fo table

# Processes running from user-writable locations
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '\\(Users|ProgramData|Temp|AppData)\\' } |
  Select-Object ProcessId, Name, ExecutablePath, CommandLine
```
Look for: Office or browsers with script-host children, `powershell` with encoded commands, binaries in `Temp` or `AppData`, processes with no path.

## 2. Network
```powershell
# Connections mapped to process names
Get-NetTCPConnection -State Established, Listen |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
  Sort-Object State, RemoteAddress

netstat -ano                      # classic view with PIDs
netstat -anob                     # admin: adds executable names (slow)
Get-DnsClientCache | Select-Object Entry, Name, Data      # recently resolved names
ipconfig /displaydns              # CMD equivalent
arp -a
route print
Get-Content C:\Windows\System32\drivers\etc\hosts        # tampered hosts file?
netsh winhttp show proxy
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
  Select-Object DisplayName, Profile, @{n='Program';e={($_ | Get-NetFirewallApplicationFilter).Program}}
```

## 3. Accounts and sessions
```powershell
query user                        # logged-on users and sessions (CMD: qwinsta)
qwinsta
net user                          # local accounts
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
Get-LocalGroupMember -Group Administrators
net localgroup administrators
net session                       # admin: inbound SMB sessions to this host
Get-SmbSession                    # admin: who is connected to shares
Get-SmbShare                      # shares exposed by this host
Get-SmbOpenFile                   # admin: files opened over SMB right now
cmdkey /list                      # stored credentials (targets only)
```

## 4. Persistence
```powershell
# Run keys
$keys = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
foreach ($k in $keys) { "== $k"; Get-ItemProperty $k -ErrorAction SilentlyContinue }

Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User

# Scheduled tasks (not disabled), with their actions
Get-ScheduledTask | Where-Object State -ne 'Disabled' |
  Select-Object TaskName, TaskPath,
    @{n='Action';e={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | '}}
schtasks /query /fo LIST /v

# Services running from odd paths
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -match 'Users|Temp|ProgramData|cmd\.exe|powershell' } |
  Select-Object Name, State, StartMode, StartName, PathName

# WMI event subscriptions
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding

Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -Force
```

## 5. Files and timelines
```powershell
# Executables and scripts changed in the last 3 days in user areas
Get-ChildItem C:\Users, C:\ProgramData, C:\Windows\Temp -Recurse -Force -ErrorAction SilentlyContinue `
  -Include *.exe,*.dll,*.ps1,*.bat,*.vbs,*.js,*.hta,*.lnk |
  Where-Object LastWriteTime -gt (Get-Date).AddDays(-3) |
  Select-Object FullName, Length, CreationTime, LastWriteTime | Sort-Object LastWriteTime -Descending

# Hash a file
Get-FileHash -Algorithm SHA256 C:\path\file.exe
certutil -hashfile C:\path\file.exe SHA256                 # CMD

# Signature and publisher
Get-AuthenticodeSignature C:\path\file.exe | Select-Object Status, SignerCertificate

# Alternate data streams and Mark of the Web
Get-Item C:\path\file.exe -Stream *
dir /r C:\path                                              # CMD, shows streams
Get-Content C:\path\file.exe -Stream Zone.Identifier        # ZoneId=3 means downloaded from the internet

# Files in a folder, newest first, with hidden items
dir C:\Users\<user>\Downloads /a /o-d                       # CMD

# Hunt a string in files (can be slow)
Select-String -Path C:\Users\*\*.ps1 -Pattern 'DownloadString' -ErrorAction SilentlyContinue
```

## 6. Event logs
```powershell
# Logon successes and failures in the last day
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-1)} |
  Select-Object TimeCreated, Id, Message -First 50

# New services (System) and scheduled tasks (Security)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 | Format-List TimeCreated, Message
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} -MaxEvents 20 | Format-List TimeCreated, Message

# PowerShell script blocks (4104)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 50 |
  Select-Object TimeCreated, @{n='Script';e={$_.Properties[2].Value}}

# Log cleared?
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -ErrorAction SilentlyContinue

# CMD: query one event type as text
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /rd:true /f:text

# Export a log as evidence (admin). Copy, do not clear.
wevtutil epl Security E:\evidence\Security.evtx
wevtutil epl System   E:\evidence\System.evtx
wevtutil epl "Microsoft-Windows-PowerShell/Operational" E:\evidence\PS-Operational.evtx
wevtutil epl "Microsoft-Windows-Sysmon/Operational" E:\evidence\Sysmon.evtx
```
Check whether the logging you need is on: `auditpol /get /category:*` (admin) and `Get-ItemProperty HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`.

## 7. PowerShell and command history
```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath          # current user's history file
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue
doskey /history                                              # CMD, current console only
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"     # Win+R history (ClickFix)
```

## 8. Execution and presence artifacts
```powershell
Get-ChildItem C:\Windows\Prefetch -Filter *.pf | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime -First 30
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object InstallDate -Descending
```
Parse Prefetch, Amcache and ShimCache with dedicated tools from a collected copy. See [windows-artifacts.md](windows-artifacts.md).

## 9. Defender and security tooling
```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension       # added exclusions?
Get-MpThreatDetection | Select-Object InitialDetectionTime, ProcessName, Resources
Get-Service | Where-Object { $_.Name -match 'Sense|WinDefend|CSFalcon|csagent|Sysmon' }
```

## 10. Ransomware and recovery checks
```powershell
vssadmin list shadows                                        # shadow copies still present?
vssadmin list shadowstorage
bcdedit /enum                                                # recovery settings
Get-Volume
fsutil usn readjournal C: csv > E:\evidence\usn.csv          # admin: file change journal (large)
```
For mass encryption, look for new extensions and ransom notes:
```powershell
Get-ChildItem D:\ -Recurse -Force -ErrorAction SilentlyContinue -Include *readme*.txt,*decrypt*.txt,*restore*.txt |
  Select-Object FullName, LastWriteTime -First 50
```

## 11. Remote collection from another host (admin, authorized)
```powershell
Invoke-Command -ComputerName HOST01 -ScriptBlock { Get-Process | Select-Object Name, Id, Path } -Credential (Get-Credential)
```
Remote commands create their own log entries and use your credentials on that host. Use accounts and methods approved for incident response.

## 12. Containment actions **[changes system]**
Do these only with approval, and record them:
```powershell
Disable-LocalUser -Name <name>
Stop-Process -Id <pid> -Force                               # destroys that process's memory
Stop-Service -Name <svc>; Set-Service -Name <svc> -StartupType Disabled
New-NetFirewallRule -DisplayName "IR block" -Direction Outbound -RemoteAddress <ip> -Action Block
```
Capture memory and the process details first. Prefer EDR host isolation over ad hoc firewall rules.

## Related
[windows-artifacts.md](windows-artifacts.md) · [windows-event-ids.md](windows-event-ids.md) · [persistence-locations.md](persistence-locations.md) · [triage-first-30-minutes.md](triage-first-30-minutes.md)
