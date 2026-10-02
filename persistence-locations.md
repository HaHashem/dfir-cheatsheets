# Windows persistence locations and how to hunt them

Persistence is how an attacker keeps access after a reboot or logoff. Check these locations on a suspect host, and hunt them fleet-wide for items that appear on only one or two machines.

| Technique (ATT&CK) | Where to look | What is suspicious | Hunt with |
|---|---|---|---|
| Registry Run keys (T1547.001) | `HKCU` and `HKLM` `\Software\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`; `...\Policies\Explorer\Run` | Scripts, `powershell`, `mshta`, or binaries in `AppData`, `Temp`, `ProgramData` | Sysmon 12/13, Falcon `AsepValueUpdate`, Defender `DeviceRegistryEvents` |
| Startup folders (T1547.001) | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`; `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` | Any new script, shortcut or executable | Sysmon 11, file creation events |
| Winlogon helpers (T1547.004) | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` (`Shell`, `Userinit`) | Values that add anything to `explorer.exe` or `userinit.exe` | Registry events |
| Scheduled tasks (T1053.005) | `C:\Windows\System32\Tasks`, registry `TaskCache`, `schtasks /query /xml` | Random names, run as `SYSTEM`, scripts or odd paths, frequent triggers | Security 4698, TaskScheduler 106, `schtasks /create` command lines |
| Services (T1543.003) | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` (`ImagePath`) | `cmd /c`, user-writable paths, services with no description or random names | System 7045, Security 4697 |
| WMI event subscriptions (T1546.003) | `root\subscription`: `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` | Any `CommandLineEventConsumer` or `ActiveScriptEventConsumer` | Sysmon 19/20/21, WMI-Activity 5861 |
| IFEO debugger (T1546.012) | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` (`Debugger`) | A `Debugger` value on accessibility or system tools | Registry events |
| Accessibility features (T1546.008) | `sethc.exe`, `utilman.exe`, `osk.exe` replaced or debugged | Hash or signature differs from the real binary | File integrity checks |
| AppInit and AppCert DLLs (T1546.010, T1546.009) | `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`; `...\Control\Session Manager\AppCertDLLs` | Any DLL listed | Registry events |
| DLL search-order hijack (T1574.001) | Application folders and `PATH` directories | A DLL that sits next to an executable but is unsigned or recently created | Sysmon 7 with signature checks |
| Office startup (T1137) | `%APPDATA%\Microsoft\Word\STARTUP`, `%APPDATA%\Microsoft\Excel\XLSTART`, Outlook rules and forms, add-ins | Macro templates or add-ins you did not deploy | File events, Office telemetry |
| Browser extensions (T1176) | Browser profile `Extensions` folder | Unknown extensions with broad permissions | Browser management tools |
| New accounts and keys (T1136, T1098) | Local users, `authorized_keys`, domain accounts | Unexpected admin accounts, hidden accounts ending in `$` | Security 4720, 4728, 4732 |
| Remote access tools (T1219) | Installed software, services | AnyDesk, ScreenConnect, Atera and similar that you did not approve | Proxy and process telemetry |
| Boot or firmware | Bootkits and UEFI implants | Rare. Suspect when disk and memory disagree | Specialist tooling |

## Quick manual checks on a live host
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
schtasks /query /fo LIST /v
sc query type= service state= all
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName, TaskPath
```
Sysinternals **Autoruns** lists nearly every one of these locations in one view. Use it with signature verification turned on and compare against a known-good host.

## How to judge an item
1. Who created it, and when? Match the time to a suspected intrusion window.
2. Is the binary signed, and by whom? Is it where this software normally lives?
3. Does it appear on many machines (probably software) or one or two (investigate)?
4. What does it run, and what does that process connect to?
