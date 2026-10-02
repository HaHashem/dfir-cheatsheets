# Linux triage

The same questions as for Windows: what ran, how did it get in, how does it persist, what did it touch. Commands assume a typical distribution, and log paths vary (Debian and Ubuntu versus RHEL and similar).

> Work on a copy or with a trusted, read-only toolset where you can. Commands you run on a live compromised host can be tampered with by a rootkit and also change timestamps.

## Quick live snapshot
```
date -u; uname -a; uptime
who; w; last -aF | head -50; lastb 2>/dev/null | head -30
ps auxwwf
ss -tulpan                       # listening and established connections with processes
lsof -nP -i                      # network files per process
ip a; ip route; cat /etc/resolv.conf
```
Look for processes running from `/tmp`, `/dev/shm` or a deleted binary:
```
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted|/tmp|/dev/shm"
```

## Logs
| What | Debian / Ubuntu | RHEL / CentOS / Fedora |
|---|---|---|
| Authentication, sudo, SSH | `/var/log/auth.log` | `/var/log/secure` |
| General system | `/var/log/syslog` | `/var/log/messages` |
| Kernel | `dmesg`, `/var/log/kern.log` | `dmesg` |
| Package changes | `/var/log/dpkg.log`, `/var/log/apt/` | `/var/log/dnf.log` or `yum.log` |
| Audit (if auditd installed) | `/var/log/audit/audit.log` | `/var/log/audit/audit.log` |
| Journal | `journalctl -u ssh`, `journalctl --since "2026-10-01"` | same |
| Web servers | `/var/log/apache2/`, `/var/log/nginx/` | `/var/log/httpd/`, `/var/log/nginx/` |

Useful searches:
```
grep -E "Accepted|Failed|Invalid user" /var/log/auth.log | tail -100
grep -i "sudo" /var/log/auth.log | tail -50
journalctl -u ssh --since "2 days ago" | grep -E "Accepted|Failed"
```

## Persistence
```
crontab -l; ls -la /etc/cron* /var/spool/cron* 2>/dev/null
cat /etc/crontab
systemctl list-unit-files --state=enabled
ls -la /etc/systemd/system /usr/lib/systemd/system | head -50
find / -newer /etc/hostname -name "*.service" 2>/dev/null | head
cat /etc/rc.local 2>/dev/null
ls -la /etc/init.d
cat /etc/ld.so.preload 2>/dev/null          # should normally not exist
```
Per-user persistence: `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.ssh/authorized_keys`, `~/.config/autostart/`. Also check `/etc/profile.d/`, `/etc/sudoers` and `/etc/sudoers.d/`, and new users:
```
awk -F: '$3==0 {print}' /etc/passwd       # more than one UID 0 is suspicious
awk -F: '$7 !~ /nologin|false/ {print $1,$3,$7}' /etc/passwd
find / -name authorized_keys 2>/dev/null -exec ls -la {} \;
```

## Files and execution
```
find / -xdev -type f -mtime -3 -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -100
find / -xdev -perm -4000 -type f 2>/dev/null          # SUID files: compare with a baseline
find /tmp /var/tmp /dev/shm -type f -exec ls -la {} \; 2>/dev/null
```
Shell history can be cleared or never written: `~/.bash_history` and `~/.zsh_history` for each user, including root. An empty or missing history on an active account is itself a clue.

## Containers and cloud hosts
Check `docker ps -a`, `docker images`, and mounted volumes. A container with the host filesystem or `/var/run/docker.sock` mounted can reach the host. On cloud hosts, check the instance metadata use and IAM role permissions, since stolen role credentials are a common impact path.

## Common attacker signs
- SSH keys added to `authorized_keys`, or `PermitRootLogin` changed in `sshd_config`
- A cron job fetching a script with `curl` or `wget` piped to `sh`
- Cryptominer processes with high CPU, or `kworker`-like names that run from odd paths
- Web shells in web roots: recently modified `.php`, `.jsp`, `.aspx` files
- Reverse shell patterns in process lists (`bash -i >& /dev/tcp/...`, `nc -e`, `python -c 'import socket...'`)
- Log files truncated or missing for a period

## Related
[triage-first-30-minutes.md](triage-first-30-minutes.md) for the order of work and evidence handling.
