# dfir-cheatsheets

Quick-reference sheets for incident response and digital forensics: where Windows keeps evidence, which event IDs matter, where attackers persist, and what to do in the first minutes of an investigation. Written as a working analyst's notes, kept short enough to use mid-investigation.

> **Read this first.** These are reference notes from public documentation and general practice, not a substitute for vendor documentation or your organization's procedures. Artifact behavior varies by Windows version, configuration and logging policy, so confirm on your own systems. Nothing here comes from any employer.

| Sheet | Use it for |
|---|---|
| [`windows-artifacts.md`](windows-artifacts.md) | What each artifact proves, where it lives, and its limits |
| [`windows-event-ids.md`](windows-event-ids.md) | Security, System, Sysmon, PowerShell, RDP, Task Scheduler and Defender event IDs |
| [`registry-triage.md`](registry-triage.md) | Reading registry hives with Registry Explorer and RECmd: persistence, execution evidence, ransomware-related keys |
| [`persistence-locations.md`](persistence-locations.md) | Where attackers keep access on Windows, with the hunt for each |
| [`triage-first-30-minutes.md`](triage-first-30-minutes.md) | Scoping, containment decisions, what to collect and in what order |
| [`linux-triage.md`](linux-triage.md) | The same questions for a Linux host |
| [`windows-powershell-cmd-commands.md`](windows-powershell-cmd-commands.md) | PowerShell and CMD commands to collect evidence and scope an incident on Windows |
| [`linux-dfir-commands.md`](linux-dfir-commands.md) | Linux commands for processes, network, persistence, files, logs and acquisition |
| [`crowdstrike-rtr-commands.md`](crowdstrike-rtr-commands.md) | CrowdStrike Real Time Response: built-in commands, `runscript` snippets, and a Falcon-to-RTR workflow |

Related: [soc-hunting-queries](https://github.com/HaHashem/soc-hunting-queries) · [sigma-rules](https://github.com/HaHashem/sigma-rules) · [dfir-toolkit](https://github.com/HaHashem/dfir-toolkit) · [portfolio](https://hahashem.github.io)

Spotted an error or an artifact that behaves differently on your version? Open an issue with the version and what you saw.

## License
[MIT](LICENSE)
