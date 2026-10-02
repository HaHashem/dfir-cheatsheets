# Windows forensic artifacts

Paths assume a default install. `%USERPROFILE%` is the user's profile folder. Collect from a forensic copy, not by browsing the live system more than you must.

## Reading the tables
- **Proves** is the strongest honest claim. Many artifacts show presence or a user action, not proof of execution.
- Always confirm with a second, independent artifact before you state a conclusion.

## Program execution

| Artifact | Location | Proves | Notes and limits |
|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | A program ran, run count, last run times, files it loaded | Windows 8 and later keep up to 8 last-run times. Often disabled on servers. Can be disabled by policy |
| Amcache | `C:\Windows\appcompat\Programs\Amcache.hve` | A file was present, with path, first-seen time and SHA1 | Presence is not always execution. Useful for hashes of deleted files |
| ShimCache (AppCompatCache) | `SYSTEM` hive, `...\Control\Session Manager\AppCompatCache` | A file existed or was touched | On modern Windows it does not prove execution. Written on shutdown, so recent entries may only be in memory |
| BAM / DAM | `SYSTEM` hive, `...\Services\bam\State\UserSettings\<SID>` | Last execution time per user and executable | Entries are cleaned up after some days, and the exact retention varies by build |
| UserAssist | `NTUSER.DAT`, `...\Explorer\UserAssist` | GUI program launches by that user, with run count and last run | Values are ROT13 encoded. Misses command-line launches |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Per-application resource and network usage over roughly 30 to 60 days | Strong for "how much data did this process send". Needs parsing with a SRUM tool |
| RunMRU | `NTUSER.DAT`, `...\Explorer\RunMRU` | Commands typed or pasted into the Win+R Run dialog | Key to ClickFix investigations. Overwritten as new commands are run |
| PowerShell history | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Interactive PowerShell commands for that user | Not written by some hosts or when disabled. Easy to delete |
| Event logs | `C:\Windows\System32\winevt\Logs\*.evtx` | Depends on the log. See the event ID sheet | Logs roll over and attackers clear them (event 1102 and 104) |

## File and folder activity

| Artifact | Location | Proves | Notes and limits |
|---|---|---|---|
| `$MFT` | volume root | Every file record: names, timestamps, sizes, resident small files | Two sets of timestamps (`$STANDARD_INFORMATION` and `$FILE_NAME`). A mismatch can indicate timestomping |
| `$UsnJrnl:$J` | `\$Extend\$UsnJrnl` | A change journal of file creates, renames and deletes | Excellent for deleted or renamed files. Has a size limit and wraps around |
| `$LogFile` | volume root | Recent NTFS transactions | Short retention |
| Recycle Bin | `C:\$Recycle.Bin\<SID>\` | Deleted file: `$I` holds original path and deletion time, `$R` holds contents | Shift-delete skips it |
| LNK files | `%APPDATA%\Microsoft\Windows\Recent\` | A user opened a file, with target path, target timestamps and volume | Created on open, including from removable and network paths |
| Jump Lists | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\` | Files opened per application | Good for what a user opened in Office, Explorer and browsers |
| Shellbags | `NTUSER.DAT` and `UsrClass.dat`, `...\Shell\BagMRU` | A user browsed a folder, including since-deleted and network folders | Shows folders opened in Explorer |
| Open/Save MRU | `NTUSER.DAT`, `...\Explorer\ComDlg32\OpenSavePidlMRU` | Files chosen through Open and Save dialogs | |

## User and system activity

| Artifact | Location | Notes |
|---|---|---|
| Registry hives | `C:\Windows\System32\config\` (`SAM`, `SYSTEM`, `SOFTWARE`, `SECURITY`), `%USERPROFILE%\NTUSER.DAT`, `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` | Copy transaction logs (`.LOG1`, `.LOG2`) with each hive, or recent changes can be missed |
| Browser history | Chrome and Edge: `%LOCALAPPDATA%\<Google\Chrome or Microsoft\Edge>\User Data\<Profile>\History` (SQLite). Firefox: `places.sqlite` | Downloads, visited URLs, search terms. Look at the downloads table for payload sources |
| Windows Search index and Activity History | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb`; `%LOCALAPPDATA%\ConnectedDevicesPlatform\<id>\ActivitiesCache.db` | Can add file and application activity. Availability varies by Windows version and settings |
| Scheduled tasks | `C:\Windows\System32\Tasks\` and the registry under `...\Schedule\TaskCache` | XML definitions keep the command and creator |
| Services | `SYSTEM` hive, `...\Services\<name>` | `ImagePath`, `Start`, `ObjectName` |
| USB devices | `SYSTEM` hive `...\Enum\USBSTOR` and `...\Enum\USB`; `SOFTWARE` `...\Windows Portable Devices\Devices` | Device make, serial number, first and last connection |

## Remote access evidence

| Artifact | Where | Shows |
|---|---|---|
| RDP client history | `NTUSER.DAT`, `...\Terminal Server Client\Default` and `\Servers` | Hosts this user connected out to |
| RDP bitmap cache | `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\` | Screen fragments from outbound RDP sessions |
| RDP inbound logons | Security 4624 type 10 (and 7 for reconnect), `TerminalServices-RemoteConnectionManager/Operational` 1149, `TerminalServices-LocalSessionManager/Operational` 21 to 25 | Who connected in, from where, and when |
| Network shares | Security 5140 and 5145, `SYSTEM` hive `...\MountPoints2` | Admin share use (`C$`, `ADMIN$`) |
| WinRM and PowerShell remoting | `Microsoft-Windows-WinRM/Operational`, `wsmprovhost.exe` in process events | Remote PowerShell sessions |

## Memory and volatile data
Memory holds what disk does not: injected code, decrypted payloads, network connections, running processes and credentials. Capture it **before** a reboot when you can, and note that capture tools change the system. Collect in order of volatility: memory, network connections and process list, then disk.

## Timestomping checks
- Compare `$STANDARD_INFORMATION` and `$FILE_NAME` timestamps in the MFT.
- Check the USN journal for the real creation time.
- A creation time later than the modified time is unusual and worth a look.

## Tools often used with these artifacts
KAPE (collection and parsing), Eric Zimmerman's tools (MFTECmd, PECmd, AmcacheParser, SBECmd, Registry Explorer, Timeline Explorer), Volatility 3 for memory, plaso (log2timeline) for timelines, Velociraptor for live collection. Follow your organization's approved tooling and chain-of-custody rules.
