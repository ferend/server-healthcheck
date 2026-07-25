sudo bash -s <<'AUDIT_EOF'
audit_main() {
LC_ALL=C; export LC_ALL
DEEP="${DEEP:-0}"          # DEEP=1 -> slow filesystem-wide checks
DAYS="${DAYS:-7}"          # lookback window for "recent" checks

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[36m'; D=$'\e[2m'; W=$'\e[1m'; N=$'\e[0m'
else R=; Y=; G=; B=; D=; W=; N=; fi

nC=0; nW=0; nO=0; FIND=()
line(){ printf '%s\n' "${D}$(printf '%.0s-' $(seq 1 72))${N}"; }
sec(){ printf '\n%s\n' "${B}${W}== $* ${N}"; line; }
crit(){ nC=$((nC+1)); FIND+=("${R}CRIT${N} $*"); printf '  %s[CRIT]%s %s\n' "$R" "$N" "$*"; }
warn(){ nW=$((nW+1)); FIND+=("${Y}WARN${N} $*"); printf '  %s[WARN]%s %s\n' "$Y" "$N" "$*"; }
ok(){   nO=$((nO+1));  printf '  %s[ OK ]%s %s\n' "$G" "$N" "$*"; }
inf(){  printf '  %s[info]%s %s\n' "$D" "$N" "$*"; }
sub(){  printf '        %s%s%s\n' "$D" "$*" "$N"; }
have(){ command -v "$1" >/dev/null 2>&1; }
authlog(){ if [ -r /var/log/auth.log ]; then cat /var/log/auth.log /var/log/auth.log.1 2>/dev/null
           elif [ -r /var/log/secure ]; then cat /var/log/secure /var/log/secure.1 2>/dev/null
           elif have journalctl; then journalctl --since "${DAYS} days ago" --no-pager 2>/dev/null
           fi; }

printf '\n%s\n' "${W}##############  FULL SYSTEM / SECURITY AUDIT  ##############${N}"
printf '%s\n' "${D}host: $(hostname -f 2>/dev/null || hostname)   time: $(date -Is)   deep=${DEEP}${N}"
[ "$(id -u)" -ne 0 ] && warn "Not running as root - many checks will be incomplete. Re-run with sudo."

# ─────────────────────────────────────────── 1. HOST
sec "1. HOST IDENTITY"
inf "OS      : $(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")"
inf "Kernel  : $(uname -r)  ($(uname -m))"
inf "Virt    : $(have systemd-detect-virt && systemd-detect-virt || echo unknown)"
inf "Uptime  : $(uptime -p 2>/dev/null)  since $(uptime -s 2>/dev/null)"
inf "Boots   : $(have last && last -x reboot 2>/dev/null | head -3 | tr '\n' '|')"
if have timedatectl; then
  timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes \
    && ok "Time synchronised ($(timedatectl show -p Timezone --value 2>/dev/null))" \
    || warn "Clock NOT NTP-synchronised - breaks TLS, logs, tokens"
fi
UPS=$(cut -d. -f1 /proc/uptime); [ "$UPS" -lt 900 ] && warn "System rebooted <15 min ago - unexpected reboots can indicate a crash or compromise"

# ─────────────────────────────────────────── 2. RESOURCES
sec "2. RESOURCES & CAPACITY"
CORES=$(nproc); L1=$(cut -d' ' -f1 /proc/loadavg)
inf "Load: $(cat /proc/loadavg | cut -d' ' -f1-3)  cores: $CORES"
awk -v l="$L1" -v c="$CORES" 'BEGIN{exit !(l > c*2)}' && crit "Load $L1 is >2x core count - runaway process, miner, or DoS" || ok "Load within range"
MT=$(awk '/MemTotal/{print $2}' /proc/meminfo); MA=$(awk '/MemAvailable/{print $2}' /proc/meminfo)
MP=$(( (MT-MA)*100/MT )); inf "Memory used: ${MP}%  ($(( (MT-MA)/1024 ))MB / $(( MT/1024 ))MB)"
[ "$MP" -ge 92 ] && crit "Memory pressure ${MP}%" || { [ "$MP" -ge 80 ] && warn "Memory ${MP}%" || ok "Memory healthy"; }
SW=$(awk '/SwapTotal/{print $2}' /proc/meminfo); [ "$SW" -eq 0 ] && inf "No swap configured"
df -PT -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{gsub("%","",$6); print $7" "$6" "$3}' | while read -r mnt pct sz; do
  if [ "$pct" -ge 90 ]; then printf '  %s[CRIT]%s Disk %s at %s%%\n' "$R" "$N" "$mnt" "$pct"
  elif [ "$pct" -ge 80 ]; then printf '  %s[WARN]%s Disk %s at %s%%\n' "$Y" "$N" "$mnt" "$pct"
  else printf '  %s[ OK ]%s Disk %s at %s%%\n' "$G" "$N" "$mnt" "$pct"; fi; done
df -Pi -x tmpfs -x devtmpfs 2>/dev/null | awk 'NR>1{gsub("%","",$5); if($5+0>85) print "  inode pressure: "$6" "$5"%"}'
[ "$DEEP" = 1 ] && { inf "Largest dirs under /var and /opt:"; du -xhd2 /var /opt 2>/dev/null | sort -rh | head -8 | sed 's/^/        /'; }

# ─────────────────────────────────────────── 3. PATCH LEVEL
sec "3. PATCH LEVEL & UPDATES"
if have apt-get; then
  UPD=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst ')
  SECU=$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep '^Inst ' | grep -ci security)
  [ "$SECU" -gt 0 ] && crit "$SECU SECURITY updates pending (of $UPD total)" || { [ "$UPD" -gt 30 ] && warn "$UPD updates pending" || ok "$UPD updates pending, none security-flagged"; }
  [ "$UPD" -gt 0 ] && apt-get -s upgrade 2>/dev/null | grep '^Inst ' | grep -i security | awk '{print $2}' | head -12 | sed 's/^/        /'
  LASTUPD=$(stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null | cut -d' ' -f1)
  [ -n "$LASTUPD" ] && inf "Last apt index update: $LASTUPD"
fi
[ -f /var/run/reboot-required ] && crit "REBOOT REQUIRED: $(cat /var/run/reboot-required.pkgs 2>/dev/null | tr '\n' ' ')" || ok "No pending reboot"
RUNK=$(uname -r); NEWK=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|.*vmlinuz-||' | sort -V | tail -1)
[ -n "$NEWK" ] && [ "$RUNK" != "$NEWK" ] && crit "Running kernel $RUNK but $NEWK is installed - unpatched kernel in memory" || ok "Running newest installed kernel"
if have systemctl; then systemctl is-enabled unattended-upgrades >/dev/null 2>&1 && ok "unattended-upgrades enabled" || inf "unattended-upgrades not enabled"; fi

# ─────────────────────────────────────────── 4. ACCOUNTS
sec "4. ACCOUNTS, PASSWORDS, SUDO, SSH KEYS"
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do printf '  %s[CRIT]%s UID-0 account besides root: %s\n' "$R" "$N" "$u"; done
awk -F: '$3==0 && $1!="root"' /etc/passwd | grep -q . || ok "root is the only UID 0 account"
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do printf '  %s[CRIT]%s EMPTY PASSWORD: %s\n' "$R" "$N" "$u"; done
awk -F: '($2 ~ /^\$/){print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ' | sed 's/^/        accounts with a password hash: /'
echo
LOGINABLE=$(awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1}' /etc/passwd | tr '\n' ' ')
inf "Shell-capable accounts: $LOGINABLE"
NEWU=$(find /home -maxdepth 1 -mtime -"$DAYS" -type d 2>/dev/null | tail -n +2)
[ -n "$NEWU" ] && warn "Home dirs created/modified in last $DAYS days: $(echo "$NEWU" | tr '\n' ' ')"
authlog | grep -E 'new user|useradd|groupadd|usermod' | tail -5 | sed 's/^/        /'
inf "sudo/admin group members: $(getent group sudo admin wheel 2>/dev/null | cut -d: -f4 | tr '\n' ' ')"
NOPW=$( { cat /etc/sudoers; cat /etc/sudoers.d/* ; } 2>/dev/null | grep -v '^#' | grep -c NOPASSWD)
[ "$NOPW" -gt 0 ] && warn "$NOPW NOPASSWD sudo rule(s) present" || ok "No NOPASSWD sudo rules"
{ cat /etc/sudoers; cat /etc/sudoers.d/*; } 2>/dev/null | grep -v '^#' | grep -E 'ALL\s*=' | grep -v '^\s*$' | head -8 | sed 's/^/        /'
for h in /root $(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd); do
  ak="$h/.ssh/authorized_keys"
  [ -f "$ak" ] || continue
  cnt=$(grep -cE '^(ssh|ecdsa|sk-)' "$ak"); perm=$(stat -c %a "$ak")
  inf "$ak : $cnt key(s), perms $perm"
  ssh-keygen -lf "$ak" 2>/dev/null | sed 's/^/        /'
  [ "$perm" -gt 600 ] && warn "$ak is too permissive ($perm)"
  [ "$h" = /root ] && [ "$cnt" -gt 0 ] && warn "root has $cnt SSH key(s) - prefer a sudo user"
done
for f in /etc/passwd:644 /etc/shadow:640 /etc/group:644 /etc/sudoers:440; do
  p=${f%:*}; e=${f#*:}; a=$(stat -c %a "$p" 2>/dev/null)
  [ -n "$a" ] && [ "$a" != "$e" ] && warn "$p perms $a (expected $e)"
done
for h in /root $(awk -F: '$3>=1000 && $3<65534 {print $6}' /etc/passwd); do
  [ -L "$h/.bash_history" ] && crit "$h/.bash_history is a SYMLINK ($(readlink "$h/.bash_history")) - history is being destroyed"
  [ -f "$h/.bash_history" ] && [ ! -s "$h/.bash_history" ] && warn "$h/.bash_history is empty"
done
inf "Currently logged in:"; who 2>/dev/null | sed 's/^/        /'
inf "Last 8 logins:"; last -n 8 -w 2>/dev/null | head -8 | sed 's/^/        /'

# ─────────────────────────────────────────── 5. SSH DAEMON
sec "5. SSH DAEMON CONFIGURATION"
if have sshd; then SSHD=$(sshd -T 2>/dev/null); else SSHD=$(/usr/sbin/sshd -T 2>/dev/null); fi
g(){ echo "$SSHD" | awk -v k="$1" '$1==k{print $2}' | head -1; }
if [ -n "$SSHD" ]; then
  inf "Port(s)          : $(echo "$SSHD" | awk '$1=="port"{print $2}' | tr '\n' ' ')"
  case "$(g permitrootlogin)" in yes) crit "PermitRootLogin yes - root can log in directly";;
    no) ok "PermitRootLogin no";; *) warn "PermitRootLogin $(g permitrootlogin)";; esac
  [ "$(g passwordauthentication)" = yes ] && warn "PasswordAuthentication yes - brute-forceable; prefer keys only" || ok "PasswordAuthentication disabled"
  [ "$(g permitemptypasswords)" = yes ] && crit "PermitEmptyPasswords yes"
  [ "$(g x11forwarding)" = yes ] && inf "X11Forwarding enabled (usually unnecessary on a server)"
  inf "MaxAuthTries=$(g maxauthtries)  LoginGraceTime=$(g logingracetime)  AllowUsers=$(g allowusers) AllowGroups=$(g allowgroups)"
  [ -z "$(g allowusers)$(g allowgroups)" ] && inf "No AllowUsers/AllowGroups restriction set"
else inf "sshd -T unavailable, skipping"; fi

# ─────────────────────────────────────────── 6. NETWORK
sec "6. NETWORK EXPOSURE"
inf "Listening sockets:"
ss -tulpnH 2>/dev/null | awk '{printf "        %-6s %-24s %s\n", $1, $5, $7}' | sort -u
PUB=$(ss -tulpnH 2>/dev/null | awk '$5 ~ /^(0\.0\.0\.0|\*|\[::\]|::):/ {print $5" "$7}' | sort -u)
if [ -n "$PUB" ]; then warn "Sockets bound to ALL interfaces (verify each is firewalled):"; echo "$PUB" | sed 's/^/        /'
else ok "Nothing bound to 0.0.0.0 / [::]"; fi
inf "Established outbound connections (non-private peers):"
ss -tnpH state established 2>/dev/null | awk '{print $4" -> "$5" "$6}' \
 | grep -vE '(127\.0\.0\.1|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.)' \
 | head -20 | sed 's/^/        /'
OUTN=$(ss -tnH state established 2>/dev/null | wc -l); [ "$OUTN" -gt 200 ] && warn "$OUTN established connections - possible botnet/scan activity"
inf "Default route: $(ip route show default 2>/dev/null | head -1)"
inf "DNS servers  : $(grep ^nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
ip -br link 2>/dev/null | grep -i promisc && crit "Interface in PROMISCUOUS mode - packet sniffer may be running" || ok "No promiscuous interfaces"
HOSTSX=$(grep -vE '^\s*#|^\s*$|127\.0\.0\.1|::1|127\.0\.1\.1' /etc/hosts 2>/dev/null)
[ -n "$HOSTSX" ] && { inf "/etc/hosts custom entries (verify none redirect update/security domains):"; echo "$HOSTSX" | sed 's/^/        /'; }
if have tailscale; then
  tailscale status --peers=false >/dev/null 2>&1 && ok "Tailscale up: $(tailscale ip -4 2>/dev/null | tr '\n' ' ')" || warn "Tailscale installed but not connected"
fi

# ─────────────────────────────────────────── 7. FIREWALL
sec "7. FIREWALL & PACKET FILTER"
if have ufw; then
  US=$(ufw status verbose 2>/dev/null)
  echo "$US" | grep -q 'Status: active' && ok "UFW active" || crit "UFW is INACTIVE"
  echo "$US" | sed 's/^/        /' | head -30
  echo "$US" | grep -q 'deny (incoming)' || warn "UFW default incoming policy is not deny"
else inf "ufw not installed"; fi
if have nft; then inf "nftables rules: $(nft list ruleset 2>/dev/null | wc -l) lines"; fi
if have iptables; then
  for c in INPUT FORWARD; do
    pol=$(iptables -S "$c" 2>/dev/null | head -1 | awk '{print $3}')
    [ "$pol" = ACCEPT ] && inf "iptables $c policy ACCEPT (normal when UFW/k3s manage the chains)" || inf "iptables $c policy $pol"
  done
  KC=$(iptables -S 2>/dev/null | grep -c 'KUBE-')
  [ "$KC" -gt 0 ] && inf "$KC kube-proxy rules present - remember these BYPASS UFW; internal apps must use hostPort+hostIP on the Tailscale IP"
  iptables -S 2>/dev/null | grep -E '^-A INPUT .* -j ACCEPT' | grep -vE 'lo|ctstate|ufw|KUBE|cali' | head -10 | sed 's/^/        suspect-accept: /'
fi
if have fail2ban-client; then
  JAILS=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p')
  [ -n "$JAILS" ] && { ok "fail2ban running - jails: $JAILS"
    for j in $(echo "$JAILS" | tr -d ',' ); do
      b=$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:\s*//p'); sub "$j: $b currently banned"; done; }
else inf "fail2ban not installed (recommended if SSH is exposed publicly)"; fi

# ─────────────────────────────────────────── 8. PROCESSES
sec "8. RUNNING PROCESSES"
inf "Top 5 by CPU:"; ps -eo pcpu,pmem,pid,user,comm --sort=-pcpu 2>/dev/null | head -6 | sed 's/^/        /'
inf "Top 5 by MEM:"; ps -eo pcpu,pmem,pid,user,comm --sort=-pmem 2>/dev/null | head -6 | sed 's/^/        /'
BADEXE=0
for p in /proc/[0-9]*; do
  pid=${p#/proc/}; ex=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$ex" in
    /tmp/*|/dev/shm/*|/var/tmp/*|/run/*|/home/*/.*)
      crit "Process running from suspicious path: PID $pid ($ex) cmd=$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-80)"; BADEXE=1;;
  esac
  case "$ex" in *"(deleted)"*)
      warn "PID $pid runs a DELETED binary: $ex  (normal right after upgrades, otherwise investigate)";;
  esac
  if grep -qa 'LD_PRELOAD' "$p/environ" 2>/dev/null; then
    crit "PID $pid has LD_PRELOAD set: $(tr '\0' '\n' <"$p/environ" | grep LD_PRELOAD)"
  fi
done
[ "$BADEXE" = 0 ] && ok "No processes executing from /tmp, /dev/shm, /var/tmp or /run"
IOC='xmrig|kdevtmpfsi|kinsing|minerd|cryptonight|stratum|masscan|zmap|\bnc -l|ncat -l|socat .*EXEC|/dev/tcp/'
ps -eo pid,user,args 2>/dev/null | grep -aEi "$IOC" | grep -v grep | while read -r l; do printf '  %s[CRIT]%s Malware/IOC pattern in process: %s\n' "$R" "$N" "${l:0:120}"; done
ps -eo args 2>/dev/null | grep -aEi "$IOC" | grep -qv grep || ok "No known miner/scanner/reverse-shell patterns in process list"
HID=0
for p in /proc/[0-9]*; do pid=${p#/proc/}
  if ! ps -p "$pid" >/dev/null 2>&1 && [ -d "$p" ]; then HID=$((HID+1)); sub "possible hidden PID: $pid ($(cat "$p/comm" 2>/dev/null))"; fi; done
[ "$HID" -gt 0 ] && warn "$HID PID(s) in /proc but not in ps output (often a race; if it persists, suspect a rootkit)" || ok "No hidden PIDs detected"
ps -eo ppid,pid,user,comm 2>/dev/null | awk '$1==1 && $4 ~ /^(bash|sh|dash|python.*|perl|nc|ncat)$/ {print "        orphan shell: PID "$2" "$3" "$4}'

# ─────────────────────────────────────────── 9. PERSISTENCE
sec "9. PERSISTENCE MECHANISMS"
[ -f /etc/ld.so.preload ] && crit "/etc/ld.so.preload EXISTS - classic rootkit hook: $(cat /etc/ld.so.preload)" || ok "/etc/ld.so.preload absent"
for u in $(cut -d: -f1 /etc/passwd); do
  ct=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*#|^\s*$')
  [ -n "$ct" ] && { inf "crontab for $u:"; echo "$ct" | sed 's/^/        /'; }
done
CRONIOC=$( { for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null; done; cat /etc/crontab /etc/cron.d/* 2>/dev/null; } | grep -Ei 'curl|wget|base64|/dev/tcp|python -c|perl -e|\|\s*(sh|bash)' | grep -v '^#')
[ -n "$CRONIOC" ] && { crit "Cron entries that download or pipe to a shell:"; echo "$CRONIOC" | sed 's/^/        /'; } || ok "No download-and-execute cron entries"
inf "Recently modified cron/systemd units (last $DAYS days):"
find /etc/cron* /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -mtime -"$DAYS" -type f 2>/dev/null | head -25 | sed 's/^/        /'
have systemctl && { inf "Enabled non-vendor units:"; systemctl list-unit-files --state=enabled --no-legend --no-pager 2>/dev/null | awk '{print $1}' | head -40 | tr '\n' ' ' | fold -sw 100 | sed 's/^/        /'; echo; }
UNITIOC=$(grep -rlEi 'ExecStart=.*(curl|wget|/tmp/|/dev/shm|base64)' /etc/systemd/system /lib/systemd/system 2>/dev/null)
[ -n "$UNITIOC" ] && { crit "systemd units executing from tmp or downloading:"; echo "$UNITIOC" | sed 's/^/        /'; }
have systemctl && { inf "Active timers:"; systemctl list-timers --no-pager --no-legend 2>/dev/null | head -12 | sed 's/^/        /'; }
ls -1 /var/spool/cron/atjobs 2>/dev/null | grep -q . && warn "Pending 'at' jobs exist: $(ls /var/spool/cron/atjobs)"
[ -s /etc/rc.local ] && { inf "/etc/rc.local content:"; grep -vE '^\s*#|^\s*$|^exit 0' /etc/rc.local | sed 's/^/        /'; }
for f in /root/.bashrc /root/.profile /etc/profile /etc/bash.bashrc /etc/profile.d/*; do
  [ -f "$f" ] || continue
  grep -EHn 'curl|wget|base64|/dev/tcp|nc -e|alias (ps|ls|netstat|ss|top)=' "$f" 2>/dev/null | head -3 | sed 's/^/        SUSPECT: /'
done
find /etc /root -maxdepth 3 -mtime -"$DAYS" -type f 2>/dev/null | grep -vE '/etc/(mtab|resolv.conf|ld.so.cache|adjtime)' | head -30 | sed 's/^/        recent /etc change: /'
if have lsmod; then
  inf "Loaded modules: $(lsmod | tail -n +2 | wc -l)"
  lsmod | tail -n +2 | awk '{print $1}' | while read -r m; do
    modinfo "$m" >/dev/null 2>&1 || printf '  %s[CRIT]%s Kernel module with no modinfo (possible rootkit LKM): %s\n' "$R" "$N" "$m"; done
  T=$(cat /proc/sys/kernel/tainted); [ "$T" -ne 0 ] && inf "Kernel taint flag: $T (out-of-tree/unsigned modules loaded)"
fi

# ─────────────────────────────────────────── 10. FILE INTEGRITY
sec "10. FILE INTEGRITY & PERMISSIONS"
if have dpkg; then
  inf "Verifying installed packages (this takes a moment)..."
  MOD=$(dpkg -V 2>/dev/null | grep -v '^..5......   c ' | head -30)
  [ -n "$MOD" ] && { warn "Package files differ from what the distro shipped:"; echo "$MOD" | sed 's/^/        /'; } || ok "No unexpected package file modifications"
fi
inf "SUID/SGID binaries not on the standard baseline:"
BASE='/usr/bin/(su|sudo|passwd|chsh|chfn|gpasswd|newgrp|mount|umount|fusermount3?|pkexec|at|crontab|ssh-agent|expiry|wall|write|dotlockfile|bsd-write|screen|staprun)$|/usr/sbin/(unix_chkpwd|pam_extrausers_chkpwd|mount.nfs|postdrop|postqueue|exim4)$|/usr/lib/(dbus-1.0/dbus-daemon-launch-helper|openssh/ssh-keysign|policykit-1/polkit-agent-helper-1|snapd/snap-confine|eject/dmcrypt-get-device|xorg/Xorg.wrap|utempter/utempter)$|/bin/(su|mount|umount|ping|fusermount)$'
SUS=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | grep -vE "$BASE")
[ -n "$SUS" ] && { echo "$SUS" | while read -r f; do printf '  %s[WARN]%s SUID/SGID: %s  %s\n' "$Y" "$N" "$f" "$(stat -c '%A %U:%G %y' "$f" 2>/dev/null | cut -d. -f1)"; done; } || ok "No unexpected SUID/SGID binaries"
for d in /tmp /dev/shm /var/tmp; do
  E=$(find "$d" -maxdepth 3 -type f -executable 2>/dev/null | head -10)
  [ -n "$E" ] && { crit "Executable files in $d:"; echo "$E" | sed 's/^/        /'; }
done
find /tmp /dev/shm /var/tmp -maxdepth 3 -type f -executable 2>/dev/null | grep -q . || ok "No executables in world-writable temp dirs"
RECBIN=$(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -mtime -"$DAYS" 2>/dev/null | head -20)
[ -n "$RECBIN" ] && { warn "System binaries modified in last $DAYS days (expected only if you ran apt upgrade):"; echo "$RECBIN" | sed 's/^/        /'; } || ok "No recently modified system binaries"
if have lsattr; then
  IMM=$(lsattr -R /etc 2>/dev/null | grep -E '^....i' | head -5)
  [ -n "$IMM" ] && { warn "Immutable (chattr +i) files under /etc - malware uses this to protect itself:"; echo "$IMM" | sed 's/^/        /'; }
fi
if [ "$DEEP" = 1 ]; then
  inf "World-writable files outside temp dirs (deep scan):"
  find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null | head -20 | sed 's/^/        /'
  inf "Directories writable by all without sticky bit:"
  find / -xdev -type d -perm -0002 ! -perm -1000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -20 | sed 's/^/        /'
  inf "Files owned by no valid user/group:"
  find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -20 | sed 's/^/        /'
fi

# ─────────────────────────────────────────── 11. LOGS
sec "11. LOG ANALYSIS"
if have journalctl; then
  ERRN=$(journalctl -p err --since "${DAYS} days ago" --no-pager -q 2>/dev/null | wc -l)
  [ "$ERRN" -gt 500 ] && warn "$ERRN error-level journal lines in $DAYS days" || inf "$ERRN error-level journal lines in $DAYS days"
  inf "Most frequent errors:"
  journalctl -p err --since "${DAYS} days ago" --no-pager -q 2>/dev/null | sed 's/^[A-Z][a-z][a-z] [0-9 ]*[0-9:]* [^ ]* //' | sed 's/[0-9]\{3,\}/N/g' | sort | uniq -c | sort -rn | head -8 | sed 's/^/        /'
  SEG=$(journalctl --since "${DAYS} days ago" --no-pager -q 2>/dev/null | grep -ci 'segfault\|general protection')
  [ "$SEG" -gt 0 ] && warn "$SEG segfaults logged - crashing service or exploitation attempt"
  OOM=$(journalctl --since "${DAYS} days ago" --no-pager -q 2>/dev/null | grep -ci 'Out of memory\|oom-kill')
  [ "$OOM" -gt 0 ] && warn "$OOM OOM-kill events"
  IOE=$(journalctl -k --since "${DAYS} days ago" --no-pager -q 2>/dev/null | grep -ciE 'I/O error|ata[0-9]+.*failed|EXT4-fs error|blk_update_request')
  [ "$IOE" -gt 0 ] && crit "$IOE disk/filesystem I/O errors in kernel log - check the disk NOW" || ok "No disk I/O errors in kernel log"
fi
FAILED=$(authlog | grep -c 'Failed password'); INVAL=$(authlog | grep -c 'Invalid user')
inf "SSH failed passwords: $FAILED   invalid users: $INVAL"
[ "$FAILED" -gt 500 ] && warn "High volume of SSH brute force. Top sources:"
authlog | grep -E 'Failed password|Invalid user' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/        /'
inf "Successful SSH logins (last 10):"
authlog | grep 'Accepted ' | tail -10 | sed 's/^/        /'
inf "sudo commands (last 10):"
authlog | grep -E 'sudo:.*COMMAND=' | tail -10 | sed 's/.*sudo:/        sudo:/' | cut -c1-150
SUDOFAIL=$(authlog | grep -c 'authentication failure.*sudo\|incorrect password attempt')
[ "$SUDOFAIL" -gt 0 ] && warn "$SUDOFAIL failed sudo attempts"
for lf in /var/log/auth.log /var/log/syslog /var/log/wtmp /var/log/btmp; do
  [ -f "$lf" ] || continue
  [ ! -s "$lf" ] && warn "$lf is ZERO BYTES - possible log wiping"
done
have last && LASTW=$(last -x -w 2>/dev/null | tail -3 | head -1) && inf "Oldest wtmp entry: $LASTW"

# ─────────────────────────────────────────── 12. WEB / TLS
sec "12. NGINX, TLS CERTIFICATES, WEB LOGS"
if have nginx; then
  nginx -t >/dev/null 2>&1 && ok "nginx -t: configuration valid" || { crit "nginx configuration INVALID:"; nginx -t 2>&1 | sed 's/^/        /'; }
  systemctl is-active nginx >/dev/null 2>&1 && ok "nginx service active" || crit "nginx service NOT active"
  inf "server_name entries: $(grep -rhE '^\s*server_name' /etc/nginx/conf.d /etc/nginx/sites-enabled 2>/dev/null | tr -s ' ' | tr '\n' ' ')"
  grep -rhE 'proxy_pass' /etc/nginx/conf.d /etc/nginx/sites-enabled 2>/dev/null | tr -s ' ' | sed 's/^/        /'
fi
if [ -d /etc/letsencrypt/live ]; then
  for c in /etc/letsencrypt/live/*/fullchain.pem; do
    [ -f "$c" ] || continue
    n=$(basename "$(dirname "$c")")
    e=$(openssl x509 -enddate -noout -in "$c" 2>/dev/null | cut -d= -f2)
    d=$(( ( $(date -d "$e" +%s) - $(date +%s) ) / 86400 ))
    if [ "$d" -lt 0 ]; then crit "Certificate $n EXPIRED $((0-d)) days ago"
    elif [ "$d" -lt 10 ]; then crit "Certificate $n expires in $d days - renewal is failing"
    elif [ "$d" -lt 21 ]; then warn "Certificate $n expires in $d days"
    else ok "Certificate $n valid for $d more days"; fi
    sub "SANs: $(openssl x509 -noout -text -in "$c" 2>/dev/null | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' ')"
  done
fi
if have systemctl; then
  systemctl is-active certbot.timer >/dev/null 2>&1 && ok "certbot.timer active" || \
  { systemctl list-timers --all --no-pager 2>/dev/null | grep -q certbot && ok "certbot timer present" || warn "No active certbot renewal timer"; }
fi
AL=$(ls -1 /var/log/nginx/*access*.log 2>/dev/null | head -3)
if [ -n "$AL" ]; then
  inf "HTTP status distribution (current logs):"
  cat $AL 2>/dev/null | awk '{print $9}' | sort | uniq -c | sort -rn | head -8 | sed 's/^/        /'
  inf "Top 10 client IPs:"
  cat $AL 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/        /'
  ATK=$(cat $AL 2>/dev/null | grep -aciE '\.\./|/wp-(login|admin|content)|/\.env|/\.git|phpmyadmin|/vendor/phpunit|union.*select|base64_decode|/actuator|/config\.json|\?XDEBUG|cgi-bin')
  [ "$ATK" -gt 0 ] && warn "$ATK scanner/exploit-probe requests in access logs. Sample:" && \
    cat $AL 2>/dev/null | grep -aiE '\.\./|/wp-|/\.env|/\.git|phpmyadmin|union.*select|cgi-bin' | tail -6 | cut -c1-140 | sed 's/^/        /'
  S5=$(cat $AL 2>/dev/null | awk '$9 ~ /^5/' | wc -l); [ "$S5" -gt 50 ] && warn "$S5 HTTP 5xx responses - backend is erroring"
fi
[ -f /var/log/nginx/error.log ] && { inf "Recent nginx errors:"; tail -6 /var/log/nginx/error.log | cut -c1-150 | sed 's/^/        /'; }

# ─────────────────────────────────────────── 13. DOCKER
sec "13. DOCKER"
if have docker && docker info >/dev/null 2>&1; then
  ok "Docker running: $(docker info --format '{{.ServerVersion}}' 2>/dev/null), $(docker ps -q 2>/dev/null | wc -l) container(s) up"
  docker ps --format '        {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null
  EX=$(docker ps -a --filter 'status=exited' --format '{{.Names}} ({{.Status}})' 2>/dev/null | head -5)
  [ -n "$EX" ] && warn "Exited containers: $(echo "$EX" | tr '\n' ' ')"
  docker ps -q 2>/dev/null | while read -r cid; do
    nm=$(docker inspect -f '{{.Name}}' "$cid" 2>/dev/null | tr -d /)
    [ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null)" = true ] && printf '  %s[CRIT]%s Container %s runs PRIVILEGED\n' "$R" "$N" "$nm"
    [ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null)" = host ] && printf '  %s[WARN]%s Container %s uses host networking\n' "$Y" "$N" "$nm"
    docker inspect -f '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null | grep -q 'docker.sock' && printf '  %s[CRIT]%s Container %s mounts docker.sock = root on host\n' "$R" "$N" "$nm"
    rc=$(docker inspect -f '{{.RestartCount}}' "$cid" 2>/dev/null); [ "${rc:-0}" -gt 5 ] && printf '  %s[WARN]%s Container %s restarted %s times\n' "$Y" "$N" "$nm" "$rc"
    docker port "$cid" 2>/dev/null | grep -q '0.0.0.0' && printf '  %s[WARN]%s Container %s publishes a port on 0.0.0.0: %s\n' "$Y" "$N" "$nm" "$(docker port "$cid" | tr '\n' ' ')"
  done
  inf "Image ages:"; docker images --format '        {{.Repository}}:{{.Tag}}  {{.CreatedSince}}' 2>/dev/null | head -10
  inf "Disk used by Docker: $(docker system df --format '{{.Type}}={{.Size}}' 2>/dev/null | tr '\n' ' ')"
else inf "Docker not present or not running"; fi

# ─────────────────────────────────────────── 14. KUBERNETES / K3S
sec "14. K3S / KUBERNETES"
[ -f /etc/rancher/k3s/k3s.yaml ] && export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
if have kubectl && kubectl version >/dev/null 2>&1 && kubectl get nodes >/dev/null 2>&1; then
  systemctl is-active k3s >/dev/null 2>&1 && ok "k3s service active" || warn "k3s service not active (agent-only node?)"
  kubectl get nodes -o wide --no-headers 2>/dev/null | sed 's/^/        /'
  kubectl get nodes --no-headers 2>/dev/null | grep -qv ' Ready' && crit "A node is NOT Ready" || ok "All nodes Ready"
  BAD=$(kubectl get pods -A --no-headers 2>/dev/null | awk '$4!="Running" && $4!="Completed"')
  [ -n "$BAD" ] && { crit "Pods not healthy:"; echo "$BAD" | sed 's/^/        /'; } || ok "All pods Running/Completed"
  kubectl get pods -A --no-headers 2>/dev/null | awk '$5+0>5 {print "        high restarts: "$1"/"$2" = "$5}'
  inf "Services exposed via NodePort/LoadBalancer (remember: kube-proxy bypasses UFW):"
  kubectl get svc -A --no-headers 2>/dev/null | awk '$3=="NodePort"||$3=="LoadBalancer"{print "        "$1"/"$2" "$3" "$6}'
  inf "Pods using hostNetwork / privileged / hostPath:"
  kubectl get pods -A -o json 2>/dev/null | grep -q . && \
  kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"|hostNet="}{.spec.hostNetwork}{"|priv="}{range .spec.containers[*]}{.securityContext.privileged}{" "}{end}{"|hostPath="}{range .spec.volumes[*]}{.hostPath.path}{" "}{end}{"\n"}{end}' 2>/dev/null \
    | grep -Ei 'hostNet=true|priv=true|hostPath=/' | head -15 | sed 's/^/        /'
  inf "cluster-admin bindings to non-system subjects:"
  kubectl get clusterrolebindings -o json 2>/dev/null | grep -B0 -A0 'cluster-admin' >/dev/null 2>&1 && \
  kubectl get clusterrolebindings -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{" -> "}{range .subjects[*]}{.kind}/{.name}{" "}{end}{"\n"}{end}' 2>/dev/null | grep -vE 'system:|kube-system' | head -10 | sed 's/^/        /'
  inf "Warning events (last hour):"
  kubectl get events -A --field-selector type=Warning --no-headers 2>/dev/null | tail -10 | cut -c1-150 | sed 's/^/        /'
  inf "Images in use:"; kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' 2>/dev/null | sort -u | head -15 | sed 's/^/        /'
else inf "kubectl/k3s not available on this host"; fi

# ─────────────────────────────────────────── 15. ROOTKIT / AV TOOLING
sec "15. ROOTKIT & MALWARE TOOLING"
for t in rkhunter chkrootkit clamscan aide lynis auditctl; do
  have "$t" && inf "$t installed" || sub "$t not installed"
done
have auditctl && { auditctl -s 2>/dev/null | head -2 | sed 's/^/        /'; }
if [ "$DEEP" = 1 ]; then
  have chkrootkit && { inf "Running chkrootkit..."; chkrootkit -q 2>/dev/null | head -20 | sed 's/^/        /'; }
  have rkhunter && { inf "Running rkhunter..."; rkhunter --check --sk --nocolors --rwo 2>/dev/null | head -30 | sed 's/^/        /'; }
  have clamscan && { inf "Running clamscan on /tmp /var/tmp /dev/shm /root..."; clamscan -ri /tmp /var/tmp /dev/shm /root 2>/dev/null | tail -12 | sed 's/^/        /'; }
fi

# ─────────────────────────────────────────── 16. SUMMARY
sec "16. SUMMARY"
printf '  %sCRITICAL: %d%s   %sWARNINGS: %d%s   %sPASSED: %d%s\n\n' "$R" "$nC" "$N" "$Y" "$nW" "$N" "$G" "$nO" "$N"
if [ "${#FIND[@]}" -gt 0 ]; then
  printf '  %sEverything that needs your attention, in order:%s\n' "$W" "$N"
  i=1; for f in "${FIND[@]}"; do printf '   %2d. %s\n' "$i" "$f"; i=$((i+1)); done
fi
if [ "$nC" -gt 0 ]; then printf '\n  %sVERDICT: investigate the CRITICAL items before anything else.%s\n' "$R" "$N"
elif [ "$nW" -gt 0 ]; then printf '\n  %sVERDICT: no critical findings; review the warnings.%s\n' "$Y" "$N"
else printf '\n  %sVERDICT: clean run - nothing anomalous detected.%s\n' "$G" "$N"; fi
printf '%s\n' "${D}Finished $(date -Is). Nothing was written to disk.${N}"
}
audit_main </dev/null
AUDIT_EOF
