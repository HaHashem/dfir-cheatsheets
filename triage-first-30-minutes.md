# Triage: the first 30 minutes

A checklist for when an alert looks real. The goal is not to finish the investigation. It is to **decide quickly**, **avoid destroying evidence**, and **hand over a clear picture**.

## 0 to 5 minutes: understand the alert
- What exactly fired, on which host and account, and when?
- What does the detection assume? Read the rule logic, not only the title.
- Is this a known test, a scheduled task or an approved admin action? Check the change calendar and ask the owner.
- Write down the **time zone** of every timestamp you will use. Mismatched time zones ruin timelines.

## 5 to 15 minutes: scope
Answer these in order. Write each answer down.
1. **Who** is the user or account, and what access do they have?
2. **What** happened: process, command line, parent process, files written, hashes.
3. **Where** did it come from: URL, domain, IP, email, USB, remote logon?
4. **When** did it start, and what happened just before and after?
5. **Who else**? Search the hash, file name, domain, IP and account across the environment.
6. **What next**: is there persistence, credential access or movement to other hosts?

Useful first searches: the parent and child processes, network connections from the process, files created by it, and the account's logons in the last 24 hours.

## 15 to 25 minutes: decide on containment
Contain **now** if any of these is true:
- credential theft tooling or LSASS access
- shadow copy deletion, backups touched, or mass file changes
- a command-and-control connection that is still active
- the account is privileged, or movement to other hosts is visible
- data is leaving the network

Containment options, from least to most disruptive:
1. Isolate the host with the EDR (keeps the sensor connected, and memory intact).
2. Disable or reset the compromised account and revoke its sessions and tokens.
3. Block the indicators (domain, IP, hash) at proxy, DNS, firewall and EDR.
4. Quarantine the email and remove it from all mailboxes.
5. Disconnect the host from the network or power it down. **Prefer isolation over powering off**, because shutdown loses memory.

Say who approved the action and when. Containment that breaks a business service needs the owner told.

## 25 to 30 minutes: preserve and hand off
**Collect in order of volatility**, as far as you are authorized to:
1. Memory image
2. Running processes, network connections, logged-on users
3. Triage collection from disk: event logs, registry hives, Prefetch, Amcache, `$MFT`, browser data, scheduled tasks, relevant user folders
4. Full disk image if the case needs it

Record for each item: what, from where, when, who collected it, and the hash. Store it read-only. Do not analyze on the original.

**Handoff note** (write it even if you are the only analyst):
- Summary in two sentences
- Timeline of confirmed events with sources
- Indicators: hashes, IPs, domains, file names, accounts, command lines
- Hosts and accounts affected, and containment taken
- What you have **not** checked yet
- What you need from others (owner, IT, legal, management)

## Habits that prevent mistakes
- Separate **facts** (a log line shows X) from **assumptions** (so the attacker did Y). Label each.
- Do not rely on one artifact. Confirm with a second source.
- Keep a running timeline as you go. It is far harder to rebuild afterward.
- Do not run unknown files on a work machine, and handle samples in an isolated environment.
- Do not search confidential indicators on public sites.
- If you are unsure whether to isolate a host, escalate and ask. A short disruption costs less than a missed spread.

## Questions to ask the business
- Is this host critical? When is its next maintenance window?
- Does the user normally do this?
- Were there recent changes, new software or travel?
- Who is the right contact if we have to disrupt the service?

## Related
- [windows-artifacts.md](windows-artifacts.md) · [windows-event-ids.md](windows-event-ids.md) · [persistence-locations.md](persistence-locations.md)
- [Ransomware hunting queries](https://github.com/HaHashem/soc-hunting-queries/tree/main/ransomware)
