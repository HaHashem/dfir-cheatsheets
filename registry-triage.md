# Windows registry triage

A working reference for reading registry hives during an investigation, with Eric Zimmerman's free tools: **Registry Explorer** (GUI), **RECmd** (batch, command line) and **Timeline Explorer** (CSV viewer). Work on **copies** of the evidence and record hashes.

## Which hive holds what

| Hive | File | Holds |
|---|---|---|
| `SYSTEM` | `C:\Windows\System32\config\SYSTEM` | Services, ShimCache, BAM/DAM, USB devices, time zone, SafeBoot, RDP settings |
| `SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | Installed software, Run keys (machine), Defender settings, Winlogon, scheduled-task cache |
| `SAM` | `C:\Windows\System32\config\SAM` | Local accounts and logon counts |
| `SECURITY` | `C:\Windows\System32\config\SECURITY` | Policies and cached credentials (handle with care) |
| `NTUSER.DAT` | `C:\Users\<user>\NTUSER.DAT` | Per-user Run keys, RunMRU, UserAssist, RecentDocs, TypedPaths |
| `UsrClass.dat` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Shellbags (folders the user browsed) |
| `Amcache.hve` | `C:\Windows\appcompat\Programs\Amcache.hve` | Executables with path, size and SHA1 |

Always collect the `.LOG1` and `.LOG2` transaction logs beside each hive. Registry Explorer replays them on load and can show changes that are not yet merged into the hive.

## Artifacts: what they prove and what they do not

| Artifact | Location | Gives you | Limits |
|---|---|---|---|
| Run and RunOnce | `...\CurrentVersion\Run`, `RunOnce` (HKLM and HKCU) | Programs started at logon | Shows persistence, not that it ran |
| Services | `SYSTEM\ControlSet001\Services\<name>` | `ImagePath`, `Start`, `ObjectName` | `Start=2` is automatic, `ObjectName` is the account |
| ShimCache | `SYSTEM\...\AppCompatCache` | File paths seen by the system, with a timestamp | Not proof of execution on modern Windows |
| BAM/DAM | `SYSTEM\...\Services\bam\State\UserSettings\<SID>` | Last run time per executable and user | Limited history, newer Windows 10 and 11 |
| UserAssist | `NTUSER\...\Explorer\UserAssist` | GUI-launched programs, run count, last run (ROT13 names) | GUI launches only |
| RunMRU | `NTUSER\...\Explorer\RunMRU` | Commands typed into Win+R | Key for paste-a-command lures (ClickFix) |
| TypedPaths / RecentDocs | `NTUSER\...\Explorer\` | Paths typed and files opened | User activity, not malware proof |
| Shellbags | `UsrClass.dat` | Folders the user browsed, even deleted ones | Interpretation takes care |
| Amcache | `Amcache.hve` | SHA1, path and size of executables | Collect as a file, separate from `reg save` |
| USBSTOR | `SYSTEM\...\Enum\USBSTOR` | USB devices seen | Needs corroboration for exfiltration claims |

## Ransomware-related keys

| Key or value | Meaning |
|---|---|
| `SOFTWARE\Microsoft\Windows Defender\Exclusions\*` | Added exclusions hide staging folders |
| `SOFTWARE\Policies\Microsoft\Windows Defender` | `DisableAntiSpyware` and real-time protection switches |
| `SYSTEM\CurrentControlSet\Control\SafeBoot` | Safe-mode boot tampering |
| `...\Control\Terminal Server\fDenyTSConnections` | `0` means RDP enabled |
| `...\SecurityProviders\WDigest\UseLogonCredential` | `1` keeps credentials recoverable in memory |
| `...\Policies\System\LocalAccountTokenFilterPolicy` | `1` allows remote use of local admin accounts |
| `NTUSER\Control Panel\Desktop\Wallpaper` | Some families set the wallpaper to the ransom message |
| Winlogon `Shell` and `Userinit` | Extra programs started at logon |
| Image File Execution Options `Debugger` | Hijack of a program's start |

Key **last-write time** changes whenever any value under that key changes. It does not say which value or who changed it. Registry timestamps are UTC.

## Registry Explorer tips
- **File → Load hive**, then accept the offer to replay transaction logs.
- **Available bookmarks** jumps to the keys investigators check most and decodes them (ShimCache, UserAssist, BAM, Run keys, USB).
- **Find** (Ctrl+F) searches key names, value names, data, and last-write times.
- Use **Deleted** items view when you suspect cleanup. Recovery is not guaranteed.
- Export a view to CSV or Excel for the report.

## Eric Zimmerman command-line tools

```
# run a batch of rules over every hive in a folder
RECmd.exe -d C:\Case\hives --bn BatchExamples\Kroll_Batch.reb --csv C:\Case\out

# individual parsers
AppCompatCacheParser.exe -f C:\Case\hives\SYSTEM --csv C:\Case\out
AmcacheParser.exe -f C:\Case\hives\Amcache.hve --csv C:\Case\out
SBECmd.exe -d C:\Case\usrclass --csv C:\Case\out
PECmd.exe -d C:\Case\Prefetch --csv C:\Case\out
EvtxECmd.exe -d C:\Case\evtx --csv C:\Case\out
MFTECmd.exe -f C:\Case\$MFT --csv C:\Case\out
```
Open the CSV files in **Timeline Explorer** and sort by timestamp to build a timeline. Options vary by tool version, so check `<tool>.exe --help`.

## Quick collection from a lab or live machine (elevated)
```
reg save HKLM\SYSTEM   C:\Case\hives\SYSTEM.hiv   /y
reg save HKLM\SOFTWARE C:\Case\hives\SOFTWARE.hiv /y
```
For a real case, use a forensic image or a collection tool (such as KAPE) so you also get user hives, `Amcache.hve`, `UsrClass.dat` and the transaction logs.

## Workflow
1. Hash and copy the hives and logs. Work on the copy.
2. Load in Registry Explorer and replay the logs.
3. Check persistence: Run keys, services, Winlogon, tasks.
4. Check execution: ShimCache, BAM, UserAssist, RunMRU, Amcache.
5. Check what was disabled: Defender, SafeBoot, RDP, credential settings.
6. Run RECmd across all hives and sort the CSV in Timeline Explorer.
7. Combine with event logs, Prefetch and the file system. One artifact is a lead, not a conclusion.

See also [`persistence-locations.md`](persistence-locations.md), [`windows-artifacts.md`](windows-artifacts.md) and [`triage-first-30-minutes.md`](triage-first-30-minutes.md).
