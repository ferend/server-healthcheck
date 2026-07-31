#!/bin/bash
# =============================================================
# Server Audit Script v2
# Usage:  sudo bash server_audit_v2.sh            (standard run)
#         sudo bash server_audit_v2.sh --deep     (adds slow full-disk scans)
#         sudo bash server_audit_v2.sh --quick    (skips disk walk & find scans)
# Output is echoed to stdout AND saved to ./audit_<host>_<date>.txt
# =============================================================

MODE="standard"
[ "$1" = "--deep" ]  && MODE="deep"
[ "$1" = "--quick" ] && MODE="quick"

OUTFILE="./audit_$(hostname)_$(date +%Y%m%d_%H%M).txt"
exec > >(tee "$OUTFILE") 2>&1

# Findings collector — populated as checks run, printed as a summary at the end
FINDINGS=()
note()  { FINDINGS+=("[INFO]  $1"); }
warn()  { FINDINGS+=("[WARN]  $1"); }
crit()  { FINDINGS+=("[CRIT]  $1"); }

have() { command -v "$1" >/dev/null 2>&1; }
hr()   { echo; echo "=====  $1  ====="; }

if [ "$EUID" -ne 0 ]; then
  echo "!! Not running as root — many checks will be incomplete. Re-run with sudo."
  echo
fi

echo "############################################"
echo "# SERVER AUDIT v2 — $(hostname) — $(date)"
echo "# Mode: $MODE   Output: $OUTFILE"
echo "############################################"

# -------------------------------------------------------------
hr "1. SYSTEM"
uname -a
uptime
echo "--- distro ---"
[ -f /etc/os-release ] && grep -E "^(PRETTY_NAME|VERSION)=" /etc/os-release
echo "--- virtualization ---"
have systemd-detect-virt && systemd-detect-virt || echo "(unknown)"
echo "--- reboot required? ---"
if [ -f /var/run/reboot-required ]; then
  echo "YES"; cat /var/run/reboot-required.pkgs 2>/dev/null
  warn "Reboot required (pending kernel/libc update)"
else
  echo "No"
fi

# -------------------------------------------------------------
hr "2. MEMORY & SWAP"
free -h
echo "--- swappiness: $(cat /proc/sys/vm/swappiness) ---"
echo "--- vmstat (si/so = active swapping; 0 means healthy) ---"
vmstat 1 5

SWAP_USED=$(free -m | awk '/Swap:/{print $3}')
SWAP_TOTAL=$(free -m | awk '/Swap:/{print $2}')
MEM_AVAIL_PCT=$(free | awk '/Mem:/{printf "%d", $7/$2*100}')
if [ "$SWAP_TOTAL" -gt 0 ] && [ "$SWAP_USED" -gt 0 ]; then
  SI=$(vmstat 1 2 | tail -1 | awk '{print $7}')
  SO=$(vmstat 1 2 | tail -1 | awk '{print $8}')
  if [ "$SI" -gt 0 ] || [ "$SO" -gt 0 ]; then
    crit "ACTIVE swapping detected (si=$SI so=$SO) — real memory pressure"
  else
    note "Swap holds ${SWAP_USED}MB but si/so=0 — stale pages, not active pressure"
  fi
fi
[ "$MEM_AVAIL_PCT" -lt 15 ] && warn "Only ${MEM_AVAIL_PCT}% memory available"

# -------------------------------------------------------------
hr "3. CPU & TOP PROCESSES"
echo "cores: $(nproc)   load:$(cut -d' ' -f1-3 /proc/loadavg)"
LOAD1=$(cut -d' ' -f1 /proc/loadavg | cut -d. -f1)
CORES=$(nproc)
[ "$LOAD1" -gt "$CORES" ] && warn "Load average ($LOAD1) exceeds core count ($CORES)"
echo "--- top by CPU (excluding this script) ---"
ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%cpu | grep -v "ps -eo" | head -12
echo "--- top by MEM ---"
ps -eo pid,ppid,user,%cpu,%mem,cmd --sort=-%mem | head -12

# -------------------------------------------------------------
hr "4. DISK"
df -h -x tmpfs -x devtmpfs
ROOT_PCT=$(df / | awk 'NR==2{print $5}' | tr -d '%')
[ "$ROOT_PCT" -ge 85 ] && crit "Root filesystem ${ROOT_PCT}% full"
[ "$ROOT_PCT" -ge 70 ] && [ "$ROOT_PCT" -lt 85 ] && warn "Root filesystem ${ROOT_PCT}% full"
echo "--- inode usage (often overlooked; full inodes break writes) ---"
df -i -x tmpfs -x devtmpfs
INODE_PCT=$(df -i / | awk 'NR==2{print $5}' | tr -d '%')
[ "$INODE_PCT" -ge 80 ] && warn "Inode usage at ${INODE_PCT}%"

if [ "$MODE" != "quick" ]; then
  echo "--- top-level usage ---"
  du -h --max-depth=1 / 2>/dev/null | sort -rh | head -12
  echo "--- /var breakdown ---"
  du -h --max-depth=2 /var 2>/dev/null | sort -rh | head -12
  echo "--- largest files >500M (host only, excludes container layers) ---"
  find / -xdev -type f -size +500M \
       -not -path "/var/lib/docker/*" \
       -not -path "/var/lib/containerd/*" \
       -not -path "/var/lib/rancher/*" 2>/dev/null \
       -exec du -h {} \; | sort -rh | head -10
  echo "--- container/image storage totals ---"
  for d in /var/lib/docker /var/lib/containerd /var/lib/rancher /var/lib/snapd; do
    [ -d "$d" ] && echo "$(du -sh $d 2>/dev/null)"
  done
fi

echo "--- journal size ---"
have journalctl && journalctl --disk-usage
echo "--- old kernels (only the running one + 1 fallback are needed) ---"
echo "running: $(uname -r)"
dpkg -l 'linux-image-[0-9]*' 2>/dev/null | grep ^ii | awk '{print $2}'
echo "--- disk I/O ---"
if have iostat; then iostat -x 1 2 | grep -vE "^loop|^$"; else echo "(sysstat not installed)"; fi
echo "--- SMART ---"
if have smartctl; then
  for disk in $(lsblk -dno NAME | grep -vE "^loop|^sr"); do
    echo "/dev/$disk: $(smartctl -H /dev/$disk 2>/dev/null | grep -iE "overall-health|SMART Health" || echo 'n/a')"
  done
else
  echo "(smartctl not installed — apt install smartmontools)"
fi

# -------------------------------------------------------------
hr "5. CONTAINERS (docker)"
if have docker && docker info >/dev/null 2>&1; then
  docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
  echo "--- live stats ---"
  docker stats --no-stream
  echo "--- storage ---"
  docker system df
  echo "--- restart counts & exit codes ---"
  for c in $(docker ps -aq); do
    docker inspect --format='{{.Name}}: restarts={{.RestartCount}} status={{.State.Status}} exit={{.State.ExitCode}}' "$c"
  done
  # flag unhealthy / crash-looping / OOM-killed containers
  UNHEALTHY=$(docker ps --filter health=unhealthy -q | wc -l)
  [ "$UNHEALTHY" -gt 0 ] && crit "$UNHEALTHY container(s) reporting unhealthy"
  for c in $(docker ps -aq); do
    RC=$(docker inspect --format='{{.RestartCount}}' "$c")
    EC=$(docker inspect --format='{{.State.ExitCode}}' "$c")
    NM=$(docker inspect --format='{{.Name}}' "$c")
    [ "$RC" -gt 5 ] && warn "Container$NM has restarted $RC times"
    [ "$EC" = "137" ] && note "Container$NM exited 137 (OOM-kill or force-stop)"
  done
  RECLAIM=$(docker system df --format '{{.Reclaimable}}' 2>/dev/null | head -1)
  [ -n "$RECLAIM" ] && note "Docker reclaimable space: $RECLAIM (docker image prune -a)"
else
  echo "(docker not installed or not running — section skipped)"
fi

# -------------------------------------------------------------
hr "6. KUBERNETES (k3s)"
if have k3s && systemctl is-active --quiet k3s 2>/dev/null; then
  K="k3s kubectl"
  $K get nodes -o wide
  echo "--- pods ---"
  $K get pods -A -o wide
  echo "--- pod images ---"
  $K get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}'
  echo "--- resource usage ---"
  $K top nodes 2>/dev/null || echo "(metrics-server unavailable)"
  $K top pods -A 2>/dev/null
  echo "--- pods NOT in Running state ---"
  $K get pods -A --field-selector=status.phase!=Running 2>/dev/null
  echo "--- pods with restarts ---"
  $K get pods -A --no-headers 2>/dev/null | awk '$5>0 {print $1"/"$2" restarts="$5}'
  echo "--- recent warning events ---"
  $K get events -A --field-selector type=Warning --sort-by='.lastTimestamp' 2>/dev/null | tail -15
  NOTRUN=$($K get pods -A --field-selector=status.phase!=Running --no-headers 2>/dev/null | wc -l)
  [ "$NOTRUN" -gt 0 ] && warn "$NOTRUN pod(s) not in Running state"
  echo "--- DNS resolution test (use FQDN; busybox short names give false NXDOMAIN) ---"
  echo "run manually: k3s kubectl run -it --rm dnstest --image=busybox:1.36 --restart=Never -- nslookup kubernetes.default.svc.cluster.local"
else
  echo "(k3s not installed or not active — section skipped)"
fi

# -------------------------------------------------------------
hr "7. WEB SERVER"
WEBSVC=""
have nginx && WEBSVC="nginx"
have apache2 && WEBSVC="$WEBSVC apache2"
if [ -z "$WEBSVC" ]; then
  echo "(no host web server installed — may be containerized; section skipped)"
else
  if have nginx; then
    echo "--- nginx config test ---"
    nginx -t 2>&1
    nginx -t >/dev/null 2>&1 || crit "nginx config test FAILS — reload would break the service"
    systemctl status nginx --no-pager 2>/dev/null | head -6
    echo "--- configured server_names ---"
    nginx -T 2>/dev/null | grep -E "^\s*server_name" | sort -u | head -20
  fi
  ALOG=$(ls -1t /var/log/nginx/access.log 2>/dev/null | head -1)
  if [ -n "$ALOG" ]; then
    echo "--- status codes (last 2000 requests) ---"
    tail -2000 "$ALOG" | awk '{print $9}' | sort | uniq -c | sort -rn | head
    echo "--- top paths ---"
    tail -2000 "$ALOG" | awk '{print $7}' | sort | uniq -c | sort -rn | head -10
    echo "--- top client IPs ---"
    tail -2000 "$ALOG" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
    ERR404=$(tail -2000 "$ALOG" | awk '$9==404' | wc -l)
    [ "$ERR404" -gt 1000 ] && note "$ERR404/2000 requests are 404 — typical bot/.env scanning, harmless if app returns 404"
    echo "--- recent errors ---"
    tail -20 /var/log/nginx/error.log 2>/dev/null
  fi
fi

# -------------------------------------------------------------
hr "8. FIREWALL  (read this BEFORE judging open ports below)"
if have ufw && ufw status >/dev/null 2>&1; then
  ufw status verbose
  ufw status | grep -q "Status: active" || warn "ufw is installed but INACTIVE"
elif have firewall-cmd; then
  firewall-cmd --list-all
else
  echo "(no ufw/firewalld — showing raw iptables INPUT chain)"
  iptables -L INPUT -n -v --line-numbers 2>/dev/null | head -30
  POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1)
  echo "$POLICY" | grep -q "policy ACCEPT" && \
    warn "iptables INPUT policy is ACCEPT with no ufw — every listening port is internet-reachable"
fi

# -------------------------------------------------------------
hr "9. LISTENING SERVICES"
echo "NOTE: a socket bound to 0.0.0.0/* is NOT necessarily internet-exposed."
echo "      Cross-reference against the firewall rules in section 8."
ss -tulnp
echo
echo "--- sockets bound to all interfaces (verify each against firewall) ---"
ss -tulnp | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\])/ {print $1, $5, $7}'
echo "--- docker daemon TCP exposure (should be EMPTY) ---"
ss -tulnp | grep -E ":2375|:2376" && crit "Docker daemon exposed over TCP — root-equivalent access" || echo "clean"
echo "--- docker socket perms ---"
ls -la /var/run/docker.sock 2>/dev/null
echo "--- kubelet auth (expect 'Unauthorized') ---"
if ss -tuln | grep -q ":10250"; then
  RESP=$(curl -sk --max-time 5 https://localhost:10250/pods 2>&1 | head -c 100)
  echo "$RESP"
  echo "$RESP" | grep -qi "unauthorized\|forbidden" || crit "kubelet on :10250 may not require auth — verify manually"
else
  echo "(kubelet not listening)"
fi
echo "--- established connections: $(ss -t state established 2>/dev/null | tail -n +2 | wc -l) ---"

# -------------------------------------------------------------
hr "10. CRON"
echo "--- root crontab ---"
crontab -l -u root 2>&1
echo "--- all user crontabs ---"
for u in $(cut -f1 -d: /etc/passwd); do
  OUT=$(crontab -l -u "$u" 2>/dev/null | grep -vE "^\s*#|^\s*$")
  [ -n "$OUT" ] && { echo "--- $u ---"; echo "$OUT"; }
done
echo "--- /etc/crontab & cron dirs ---"
grep -vE "^\s*#|^\s*$" /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null | grep -vE "placeholder|^total|^d"
echo "--- systemd timers (the modern cron; often missed) ---"
systemctl list-timers --all --no-pager 2>/dev/null | head -20
echo "--- suspicious pattern scan (rkhunter help-text matches are FALSE POSITIVES) ---"
SUSP=$(grep -rEn "curl|wget|base64 -d|base64 --decode|/dev/tcp|nc -e|\|\s*(ba)?sh" \
  /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ \
  /var/spool/cron/crontabs/ /etc/crontab 2>/dev/null | grep -v rkhunter)
if [ -n "$SUSP" ]; then
  echo "$SUSP"
  warn "Cron entries matched download+execute patterns — review each above"
else
  echo "clean (no matches outside rkhunter's own help text)"
fi

# -------------------------------------------------------------
hr "11. SSH & FAIL2BAN"
echo "--- sshd effective config ---"
grep -E "^\s*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups)" \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
grep -qiE "^\s*PermitRootLogin\s+yes" /etc/ssh/sshd_config 2>/dev/null && crit "PermitRootLogin is enabled"
grep -qiE "^\s*PasswordAuthentication\s+yes" /etc/ssh/sshd_config 2>/dev/null && \
  note "Password auth enabled — key-only auth is stronger if practical"
echo "--- fail2ban ---"
if have fail2ban-client && systemctl is-active --quiet fail2ban; then
  fail2ban-client status
  for j in $(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,//g'); do
    echo "--- jail: $j ---"
    fail2ban-client status "$j"
  done
  # warn about internet-exposed services with no jail protecting them
  JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://')
  echo "$JAILS" | grep -q sshd || warn "No sshd jail in fail2ban"
else
  warn "fail2ban not installed or not running"
fi
echo "--- failed logins (last 15) ---"
grep "Failed password" /var/log/auth.log* 2>/dev/null | grep -v "COMMAND=" | tail -15
echo "--- successful logins (last 10) — verify every source IP is yours ---"
grep "Accepted" /var/log/auth.log* 2>/dev/null | grep -v "COMMAND=" | tail -10
echo "--- accounts with shell access ---"
awk -F: '$7 !~ /(nologin|false|sync)/ {print $1" uid="$3" shell="$7}' /etc/passwd
echo "--- UID 0 accounts (should be root ONLY) ---"
awk -F: '$3==0 {print $1}' /etc/passwd
UID0=$(awk -F: '$3==0' /etc/passwd | wc -l)
[ "$UID0" -gt 1 ] && crit "More than one UID-0 account exists — possible backdoor"
echo "--- passwordless sudo entries ---"
grep -rE "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null

# -------------------------------------------------------------
hr "12. UPDATES"
apt update 2>&1 | grep -vE "^(Hit|Get|Reading|Building)" | tail -8
echo "--- security updates ---"
SECCOUNT=$(apt list --upgradable 2>/dev/null | grep -ci security)
apt list --upgradable 2>/dev/null | grep -i security
echo "--- total upgradable: $(apt list --upgradable 2>/dev/null | tail -n +2 | wc -l) ---"
[ "$SECCOUNT" -gt 0 ] && warn "$SECCOUNT security update(s) pending — apt upgrade"
echo "--- unattended-upgrades enabled? ---"
systemctl is-enabled unattended-upgrades 2>/dev/null || echo "not enabled"
echo "--- duplicate apt sources (causes repeated warnings) ---"
grep -rh "^deb " /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null \
  | awk '{print $2, $3}' | sort | uniq -d

# -------------------------------------------------------------
hr "13. SYSTEMD HEALTH"
systemctl --failed --no-pager
FAILED=$(systemctl --failed --no-legend --no-pager 2>/dev/null | wc -l)
[ "$FAILED" -gt 0 ] && warn "$FAILED failed systemd unit(s)"
echo "--- stuck activating/deactivating (crash-loop indicator) ---"
systemctl list-units --state=activating,deactivating --no-pager
echo "--- units restarting frequently ---"
journalctl -u '*' --since "24 hours ago" 2>/dev/null | grep -c "Scheduled restart job" | \
  xargs -I{} echo "{} scheduled-restart events in last 24h"

# -------------------------------------------------------------
hr "14. LEFTOVER PANELS & STALE INSTALLS"
echo "NOTE: cpanel_json_xs is a Perl JSON library, NOT cPanel — ignore it."
echo "--- filesystem footprints ---"
for p in btpanel bt-panel aapanel dokku coolify casaos plesk cyberpanel virtualmin webmin froxlor ispconfig; do
  HITS=$(find / -maxdepth 4 -iname "*${p}*" -not -path "/proc/*" -not -path "*/containerd/*" \
         -not -path "/var/lib/docker/*" 2>/dev/null | grep -v cpanel_json | head -5)
  [ -n "$HITS" ] && { echo "[$p]"; echo "$HITS"; }
done
echo "--- panel-ish dirs at root ---"
ls -d /www /data /opt/bt /usr/local/bt /home/dokku 2>/dev/null
echo "--- panel-related systemd units ---"
systemctl list-unit-files 2>/dev/null | grep -iE "btpanel|dokku|coolify|casaos|plesk|panel|site_total"
echo "--- immutable files (chattr +i — panels use it, so does malware) ---"
if [ "$MODE" = "deep" ]; then
  lsattr -R /etc /www /home 2>/dev/null | grep -E "^-{4}i" | head -20
else
  echo "(run with --deep to scan)"
fi

# -------------------------------------------------------------
hr "15. INTEGRITY & PRIVILEGE SURFACE"
echo "--- OOM kills ---"
dmesg -T 2>/dev/null | grep -i "killed process" | tail -10
journalctl --since "7 days ago" 2>/dev/null | grep -i "out of memory" | tail -5
dmesg -T 2>/dev/null | grep -qi "killed process" && warn "OOM killer has fired — check memory sizing"
echo "--- world-writable files (host only; container layers excluded as noise) ---"
find / -xdev -type f -perm -0002 \
     -not -path "/proc/*" -not -path "/tmp/*" -not -path "/var/tmp/*" \
     -not -path "/var/lib/docker/*" -not -path "/var/lib/containerd/*" \
     -not -path "/var/lib/rancher/*" -not -path "/var/lib/casaos/*" 2>/dev/null | head -15
echo "--- SUID/SGID on HOST only (container copies are expected, filtered out) ---"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
     -not -path "/var/lib/docker/*" -not -path "/var/lib/containerd/*" \
     -not -path "/var/lib/rancher/*" 2>/dev/null | sort
echo "--- non-standard SUID (anything here deserves a second look) ---"
find / -xdev -type f -perm -4000 \
     -not -path "/var/lib/docker/*" -not -path "/var/lib/containerd/*" \
     -not -path "/var/lib/rancher/*" 2>/dev/null | \
  grep -vE "/(sudo|su|mount|umount|passwd|chsh|chfn|newgrp|gpasswd|chage|expiry|at|crontab|ssh-agent|ssh-keysign|pkexec|fusermount3|unix_chkpwd|pam_extrausers_chkpwd|dotlockfile|postqueue|postdrop|utempter|dbus-daemon-launch-helper|polkit-agent-helper-1|chrome-sandbox|Xorg.wrap)$"
echo "--- recently modified files in system bin dirs (last 7 days) ---"
find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null | head -10
echo "--- listening processes running from unusual paths ---"
ss -tulnp 2>/dev/null | grep -oP 'users:\(\("\K[^"]+' | sort -u | while read -r p; do
  BIN=$(command -v "$p" 2>/dev/null)
  [ -n "$BIN" ] && echo "$BIN" | grep -qvE "^/(usr/)?(s)?bin|^/usr/local|^/usr/libexec" && echo "unusual: $p -> $BIN"
done

# -------------------------------------------------------------
hr "16. TLS CERTIFICATES (auto-discovered)"
DOMAINS=$(nginx -T 2>/dev/null | grep -E "^\s*server_name" | \
          sed 's/.*server_name//;s/;//' | tr ' ' '\n' | \
          grep -vE "^$|_|localhost|^\*" | sort -u | head -5)
if [ -n "$DOMAINS" ]; then
  for d in $DOMAINS; do
    EXP=$(echo | timeout 5 openssl s_client -servername "$d" -connect "$d:443" 2>/dev/null | \
          openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
    [ -n "$EXP" ] && echo "$d expires: $EXP"
  done
else
  echo "(no nginx server_names found)"
fi
echo "--- local certbot certificates ---"
have certbot && certbot certificates 2>/dev/null | grep -E "Certificate Name|Expiry" || echo "(certbot not installed)"

# -------------------------------------------------------------
hr "17. DNS"
echo "--- resolv.conf ---"
cat /etc/resolv.conf 2>/dev/null | grep -vE "^#|^$"
if have resolvectl; then
  echo "--- resolvectl ---"
  resolvectl status 2>/dev/null | grep -E "Link|DNS Server|Current DNS" | head -20
  NSCOUNT=$(resolvectl status 2>/dev/null | grep -A2 "DNS Servers:" | tr ' ' '\n' | grep -cE "^[0-9a-f:.]+$")
  [ "$NSCOUNT" -gt 3 ] && note "$NSCOUNT nameservers configured; k8s caps pods at 3 (causes DNSConfigForming warnings — cosmetic)"
fi
echo "--- resolution test ---"
timeout 5 getent hosts github.com >/dev/null 2>&1 && echo "external DNS OK" || warn "external DNS resolution failing"

# -------------------------------------------------------------
hr "SUMMARY"
if [ ${#FINDINGS[@]} -eq 0 ]; then
  echo "No automated findings. Review sections above for anything unexpected."
else
  printf '%s\n' "${FINDINGS[@]}" | sort
fi
echo
echo "Counts: CRIT=$(printf '%s\n' "${FINDINGS[@]}" | grep -c CRIT)  WARN=$(printf '%s\n' "${FINDINGS[@]}" | grep -c WARN)  INFO=$(printf '%s\n' "${FINDINGS[@]}" | grep -c INFO)"
echo
echo "Reminders learned the hard way:"
echo " * An open socket is not an open port — check section 8 (firewall) first."
echo " * busybox nslookup on a short name returns NXDOMAIN even when DNS works; test the FQDN."
echo " * Give CoreDNS ~30s after a restart before testing; startup 503s are normal."
echo " * SUID/world-writable hits inside container layers are image contents, not host issues."
echo
echo "############################################"
echo "# COMPLETE — $(hostname) — $(date)"
echo "# Saved to: $OUTFILE"
echo "############################################"
