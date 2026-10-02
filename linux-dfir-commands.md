# Linux commands for DFIR

A command reference for collecting evidence and scoping an incident on a Linux host. For the investigation order and what attackers commonly leave behind, see [linux-triage.md](linux-triage.md).

> **Safety first.**
> - Commands run on a live compromised host can be subverted by a rootkit or altered binaries, and they change access times. Where possible use a trusted static toolset from external media, or collect with your EDR or a forensic agent.
> - Write output to an evidence location (external disk or remote share), not the suspect disk. Hash what you collect.
> - Most commands need `root`. Commands that change the system are marked **[changes system]**.
> - Flags differ a little between distributions and versions. Check `man` if a command errors.

## 0. Start a record
```
date -u; date; timedatectl                  # time, time zone, NTP sync
hostname; uname -a; cat /etc/os-release
uptime; who -b                              # boot time
id; whoami
script -a /evidence/session.log             # logs your terminal session (exit to stop)
```

## 1. Processes
```
ps auxwwf                                   # tree view with full command lines
ps -eo pid,ppid,user,lstart,cmd --sort=start_time
pstree -aps
top -b -n1 | head -30                       # busy processes (miners show high CPU)

# Details for one PID
ls -l /proc/<pid>/exe                       # real binary path (shows "(deleted)" if removed)
ls -l /proc/<pid>/cwd
tr '\0' ' ' < /proc/<pid>/cmdline; echo
tr '\0' '\n' < /proc/<pid>/environ          # environment variables
ls -l /proc/<pid>/fd                        # open files and sockets
cat /proc/<pid>/maps | head -50

# Processes running from a deleted file or odd location
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted|/tmp/|/dev/shm/|/var/tmp/"
```
Recover a deleted running binary (copy it before it is lost):
```
cp /proc/<pid>/exe /evidence/pid-<pid>.bin
sha256sum /evidence/pid-<pid>.bin
```

## 2. Network
```
ss -tulpan                                  # listening and established, with process (needs root)
ss -tnp state established
lsof -nP -i                                 # network files by process
ip addr; ip route; ip neigh
cat /etc/resolv.conf; cat /etc/hosts
iptables -S; nft list ruleset 2>/dev/null   # firewall rules
ip link | grep -i promisc                   # promiscuous mode (sniffing)
resolvectl status 2>/dev/null
```
Find processes with outbound connections to public addresses:
```
ss -tnp state established | grep -vE "127\.0\.0\.1|\[::1\]|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\."
```

## 3. Users, logons and authentication
```
who; w; last -aF | head -50                 # logons
lastb -aF 2>/dev/null | head -30            # failed logons
lastlog | grep -v "Never logged in"
cat /etc/passwd; cat /etc/group
awk -F: '$3==0 {print}' /etc/passwd         # more than one UID 0 account is suspicious
awk -F: '($2=="" ) {print $1}' /etc/shadow  # accounts with empty passwords (root)
getent group sudo wheel admin 2>/dev/null
cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null
find / -name authorized_keys 2>/dev/null -exec ls -la {} \; -exec cat {} \;
```
Auth log searches:
```
grep -E "Accepted|Failed|Invalid user" /var/log/auth.log* 2>/dev/null | tail -100        # Debian and Ubuntu
grep -E "Accepted|Failed|Invalid user" /var/log/secure* 2>/dev/null | tail -100          # RHEL family
grep -i sudo /var/log/auth.log /var/log/secure 2>/dev/null | tail -50
journalctl -u ssh -u sshd --since "2 days ago" | grep -E "Accepted|Failed"
# Failed logins by source address
grep "Failed password" /var/log/auth.log* /var/log/secure* 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -rn | head
```

## 4. Persistence
```
crontab -l; for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u $u 2>/dev/null | sed "s/^/$u: /"; done
ls -la /etc/cron* /var/spool/cron* 2>/dev/null; cat /etc/crontab
systemctl list-unit-files --state=enabled
systemctl list-timers --all
find /etc/systemd /usr/lib/systemd /lib/systemd ~/.config/systemd -name "*.service" -mtime -14 2>/dev/null
ls -la /etc/init.d /etc/rc*.d 2>/dev/null; cat /etc/rc.local 2>/dev/null
cat /etc/ld.so.preload 2>/dev/null; echo "LD_PRELOAD=$LD_PRELOAD"      # preload libraries hide malware
ls -la /etc/profile.d; tail -n 20 /etc/profile ~/.bashrc ~/.profile 2>/dev/null
ls -la /etc/pam.d | head; ls -la /lib/security /lib64/security 2>/dev/null
find / -xdev -name "*.so" -mtime -7 -not -path "/proc/*" 2>/dev/null | head -50
```
Also check `~/.ssh/config`, `/etc/ssh/sshd_config` (`PermitRootLogin`, `AuthorizedKeysFile`), and `at -l` for scheduled jobs.

## 5. Files and timelines
```
# Recently changed files (adjust the date)
find / -xdev -type f -newermt "2026-10-01" ! -newermt "2026-10-03" -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -200
find / -xdev -type f -mtime -3 -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort -r | head -100

stat <file>                                 # birth (if supported), access, modify, change times
file <file>; strings -n 8 <file> | head -50
sha256sum <file>; md5sum <file>

# Risky locations
ls -laR /tmp /var/tmp /dev/shm 2>/dev/null | head -100
find / -xdev \( -name ".*" -a -type f \) -path "/tmp/*" 2>/dev/null          # hidden files in /tmp
find /var/www /srv -type f \( -name "*.php" -o -name "*.jsp" -o -name "*.aspx" \) -mtime -7 2>/dev/null   # possible web shells

# Privilege-bearing files: compare with a baseline
find / -xdev -perm -4000 -type f 2>/dev/null     # SUID
find / -xdev -perm -2000 -type f 2>/dev/null     # SGID
getcap -r / 2>/dev/null                          # file capabilities
find / -xdev -type f -perm -0002 -not -path "/proc/*" 2>/dev/null | head      # world-writable files
```
The change time (`ctime`) cannot be set directly by common tools, so a file whose modify time is older than its change time may have been timestomped.

Check package integrity for modified system binaries:
```
rpm -Va 2>/dev/null | head -50                   # RHEL family; "5" in the output means the checksum changed
debsums -c 2>/dev/null | head -50                # Debian and Ubuntu (install debsums from trusted media)
dpkg -S /usr/bin/<binary>; rpm -qf /usr/bin/<binary>     # which package owns this file?
```

## 6. Shell history and user activity
```
for h in /root /home/*; do echo "== $h"; tail -n 50 $h/.bash_history $h/.zsh_history 2>/dev/null; done
history | tail -50
find / -xdev -name ".*_history" -o -name ".viminfo" -o -name ".lesshst" 2>/dev/null
```
Empty or missing history for an active account is itself a clue, as is `HISTFILE` set to `/dev/null`.

## 7. Logs
```
ls -la /var/log
journalctl --since "2026-10-01" --until "2026-10-03" | less
journalctl -p err --since "1 day ago"
journalctl _COMM=sshd --since "2 days ago"
dmesg | tail -50
tail -n 200 /var/log/syslog /var/log/messages 2>/dev/null
last -f /var/log/wtmp; last -f /var/log/btmp 2>/dev/null
# auditd, if present
ausearch -m EXECVE -ts yesterday 2>/dev/null | head -100
ausearch -k <key> 2>/dev/null
# web server
grep -E "POST .*\.(php|jsp|asp)|cmd=|/bin/sh|union select" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null | tail -50
```
Look for log gaps and truncated files: `ls -la /var/log` where a log is zero bytes or much smaller than its neighbors.

## 8. Containers and cloud
```
docker ps -a; docker images; docker network ls
docker inspect <container> | grep -iE "Privileged|Binds|Mounts|CapAdd"
docker logs --tail 100 <container>
ls -la /var/run/docker.sock                      # access to the socket means control of the host
crictl ps 2>/dev/null; kubectl get pods -A 2>/dev/null
curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null | head      # reachable instance metadata service (AWS-style)
```
A container with the host filesystem or Docker socket mounted, or run `--privileged`, can reach the host.

## 9. Acquisition: memory and disk
```
# Memory: use a purpose-built tool, and note it changes the system
# AVML (Microsoft) or LiME produce a memory image you analyze with Volatility 3
avml /evidence/mem.lime                          # [changes system] copies the tool onto the host

# Disk: image a block device (from a live system or a rescue environment)
lsblk -f
dd if=/dev/sda of=/evidence/sda.img bs=4M conv=noerror,sync status=progress
sha256sum /evidence/sda.img > /evidence/sda.img.sha256
```
Imaging a mounted, running disk gives an inconsistent copy. Prefer a snapshot, a write-blocked image, or booting from a rescue disk. Follow your organization's evidence handling rules, and record who collected what and when.

## 10. Quick triage bundle (read-only)
```
OUT=/evidence/$(hostname)-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $OUT
{ date -u; uname -a; uptime; who; last -aF | head -100; } > $OUT/system.txt
ps auxwwf > $OUT/ps.txt
ss -tulpan > $OUT/ss.txt
lsof -nP > $OUT/lsof.txt 2>/dev/null
systemctl list-unit-files > $OUT/units.txt
crontab -l > $OUT/crontab-current.txt 2>&1; cp -a /etc/cron* $OUT/ 2>/dev/null
cp -a /etc/passwd /etc/group /etc/hosts /etc/resolv.conf $OUT/
find / -xdev -type f -mtime -7 2>/dev/null > $OUT/changed-7d.txt
tar czf $OUT.tgz -C /var/log . 2>/dev/null
sha256sum $OUT/* $OUT.tgz > $OUT/SHA256SUMS
```
Review `ps.txt` and `ss.txt` first.

## 11. Containment **[changes system]**
Only with approval, and record each step:
```
kill -STOP <pid>                                 # pause a process without destroying its memory
usermod -L <user>; passwd -l <user>              # lock an account
iptables -I OUTPUT -d <ip> -j DROP               # block an address
systemctl disable --now <unit>
```
Collect memory and the process details before you kill anything. Prefer network isolation with your EDR over ad hoc firewall rules.

## Related
[linux-triage.md](linux-triage.md) · [triage-first-30-minutes.md](triage-first-30-minutes.md) · [windows-powershell-cmd-commands.md](windows-powershell-cmd-commands.md)
