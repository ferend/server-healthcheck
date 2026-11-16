sudo bash -c "$(cat <<'EOF'
set -u
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---- CONFIG: edit before pasting -------------------------------------------
AUTO_REBOOT=1        # 1 = reboot when required, 0 = only report
RESTART_SERVICES=0   # 1 = needrestart restarts services using outdated libraries
INSTALL_TOOLS=1      # 1 = install fail2ban/needrestart/debsums if missing, 0 = use only what exists
JOURNAL_KEEP_DAYS=30
JOURNAL_MAX_SIZE=500M
LOG_KEEP_DAYS=14     # rotated logs (*.gz, *.1, *.old) older than this are deleted
TMP_KEEP_DAYS=10     # files in /tmp and /var/tmp untouched for this long are deleted
CACHE_KEEP_DAYS=30   # files in ~/.cache unused for this long are deleted
DOCKER_PRUNE=1       # 0 = off, 1 = dangling images + build cache,
                     # 2 = ALL unused images + stopped containers + unused networks (never volumes)
DISK_WARN_PCT=85
# -----------------------------------------------------------------------------

FAILED=(); WARNINGS=()
section() { echo; echo "==================== $1  [$(date +%H:%M:%S)] ===================="; }
warn()    { WARNINGS+=("$1"); echo "!! WARNING: $1"; }
have()    { command -v "$1" >/dev/null 2>&1; }
run()     { local label=$1; shift; "$@" || { FAILED+=("$label"); echo "!! FAILED: $label"; }; }
APT_OPTS=(-y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef)
need()    { # need <command> <packages...>: install only if missing and allowed
  local cmd=$1; shift
  have "$cmd" && return 0
  [ "$INSTALL_TOOLS" = 1 ] || { echo "($cmd not installed - skipped)"; return 1; }
  run "install $*" apt-get install "${APT_OPTS[@]}" --no-install-recommends "$@"
  have "$cmd"
}
proc_exes() { # pid, name and executable path of every process
  local p exe
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    printf '%s %s %s\n' "${p#/proc/}" "$(cat "$p/comm" 2>/dev/null)" "$exe"
  done
}

echo "=== SERVER MAINTENANCE started: $(date) on $(hostname) ==="
DISK_BEFORE=$(df -h / | awk 'NR==2{print $4}')
# Snapshot BEFORE the upgrade, otherwise every upgraded program shows up as "deleted binary".
PROCS_PRE=$(proc_exes)

section "1. SYSTEM UPDATES"
run "dpkg --configure -a" dpkg --configure -a
run "apt fix-broken"      apt-get -f install "${APT_OPTS[@]}"
run "apt-get update"      apt-get update -qq
# Installs new dependencies (e.g. kernels) but never REMOVES a package, unlike dist-upgrade.
run "apt-get upgrade"     apt-get upgrade --with-new-pkgs "${APT_OPTS[@]}"
HELD=$(apt-get -s dist-upgrade 2>/dev/null | awk '/^Inst /{print $2}' | xargs)
[ -n "$HELD" ] && warn "not upgraded (needs package removals - run 'apt-get dist-upgrade' by hand): $HELD"
have snap    && run "snap refresh"   snap refresh
have flatpak && run "flatpak update" flatpak update -y --noninteractive
if need needrestart needrestart; then
  if [ "$RESTART_SERVICES" = 1 ]; then run "needrestart" needrestart -r a
  else echo "--- Services using outdated libraries (listed only):"; run "needrestart" needrestart -r l; fi
fi

section "2. CLEANUP"
USED_BEFORE=$(df -kP / | awk 'NR==2{print $3}')
removed() { echo "    removed $(wc -l) file(s)"; }

echo "--- apt: unused packages, old kernels, package cache, leftover configs"
run "apt autoremove" apt-get autoremove --purge -y
run "apt clean"      apt-get clean
dpkg -l | awk '/^rc/{print $2}' | xargs -r apt-get purge -y

echo "--- systemd journal (keep ${JOURNAL_KEEP_DAYS}d / $JOURNAL_MAX_SIZE)"
journalctl --rotate   # close the active file so vacuum can also trim it
journalctl --vacuum-time="${JOURNAL_KEEP_DAYS}d" --vacuum-size="$JOURNAL_MAX_SIZE"

echo "--- rotated logs older than $LOG_KEEP_DAYS days (live logs are not touched)"
find /var/log -xdev -type f -not -path '/var/log/journal/*' -mtime +"$LOG_KEEP_DAYS" \
  \( -name '*.gz' -o -name '*.xz' -o -name '*.bz2' -o -name '*.[0-9]' -o -name '*.old' \) -print -delete | removed

echo "--- crash reports and core dumps"
find /var/crash /var/lib/systemd/coredump -mindepth 1 -print -delete 2>/dev/null | removed

echo "--- temp files untouched for $TMP_KEEP_DAYS days"
systemd-tmpfiles --clean 2>/dev/null   # the system's own temp-file rules
# mtime AND atime must both be old; private dirs of running services and JVM stats are skipped
find /tmp /var/tmp -xdev -mindepth 1 -type f -mtime +"$TMP_KEEP_DAYS" -atime +"$TMP_KEEP_DAYS" \
  -not -path '*/systemd-private-*' -not -path '*/hsperfdata_*' -print -delete 2>/dev/null | removed

echo "--- user caches unused for $CACHE_KEEP_DAYS days, and trash"
for home in /root /home/*; do
  [ -d "$home/.cache" ] && find "$home/.cache" -xdev -type f -atime +"$CACHE_KEEP_DAYS" -print -delete 2>/dev/null
  find "$home/.local/share/Trash" -mindepth 2 -print -delete 2>/dev/null
done | removed

if have snap; then
  echo "--- snap: old revisions and download cache"
  snap set system refresh.retain=2
  snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' |
    while read -r name rev; do snap remove "$name" --revision="$rev" </dev/null; done
  rm -rf /var/lib/snapd/cache/* 2>/dev/null
fi
if have flatpak; then
  echo "--- flatpak: unused runtimes"
  run "flatpak uninstall --unused" flatpak uninstall --unused -y --noninteractive
fi

USED_AFTER=$(df -kP / | awk 'NR==2{print $3}')
echo "Cleanup freed $(( (USED_BEFORE - USED_AFTER) / 1024 )) MB on /"

section "3. BRUTE-FORCE PROTECTION (fail2ban)"
if need fail2ban-server fail2ban python3-systemd; then
  # No /var/log/auth.log (Debian 12+) means the sshd jail must read the journal.
  F2B_DROPIN=/etc/fail2ban/jail.d/sshd-systemd.conf
  if [ "$INSTALL_TOOLS" = 1 ] && [ ! -f /var/log/auth.log ] && [ ! -f "$F2B_DROPIN" ]; then
    printf '[sshd]\nenabled = true\nbackend = systemd\n' > "$F2B_DROPIN"
    echo "Created $F2B_DROPIN"
    systemctl restart fail2ban 2>/dev/null
  fi
  run "enable fail2ban" systemctl enable --now fail2ban
  sleep 2
  fail2ban-client status sshd 2>/dev/null || warn "fail2ban sshd jail is not active - check /etc/fail2ban/"
fi

section "4. SSH REPORT (last 24h)"
SSHLOG=$(journalctl -u ssh -u sshd --since "24 hours ago" -o cat 2>/dev/null)
echo "--- Top 10 source IPs of failed logins:"
echo "$SSHLOG" | grep -Ei 'failed password|invalid user|authentication failure' |
  grep -oP 'from \K[0-9a-fA-F:.]+' | sort | uniq -c | sort -rn | head -10
echo "--- Top 10 invalid usernames tried:"
echo "$SSHLOG" | grep -oiP 'invalid user \K\S+' | sort | uniq -c | sort -rn | head -10
echo "--- Successful logins (count, method, user, source):"
echo "$SSHLOG" | awk '/^Accepted /{print $2, $4, $6}' | sort | uniq -c | sort -rn
if have last; then echo "--- Last 15 sessions:"; last -a -n 15; fi
echo "--- Effective sshd settings:"
SSHD_CONF=$(sshd -T 2>/dev/null)
echo "$SSHD_CONF" | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication) '
echo "$SSHD_CONF" | grep -q '^passwordauthentication yes' &&
  echo "NOTE: password logins are enabled; key-only login stops brute force completely."
echo "--- authorized_keys per user (check that you know every key):"
while IFS=: read -r user _ _ _ _ home _; do
  for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
    [ -f "$f" ] && ssh-keygen -lf "$f" 2>/dev/null | sed "s|^|[$user] |"
  done
done < /etc/passwd

section "5. PACKAGE INTEGRITY"
if need debsums debsums; then
  # -s prints only problems; config files are skipped, so each line is a changed program/library.
  DEBSUMS_OUT=$(debsums -s 2>&1)
  if [ -n "$DEBSUMS_OUT" ]; then
    echo "$DEBSUMS_OUT"
    warn "debsums: $(echo "$DEBSUMS_OUT" | wc -l) file(s) differ from their package"
  else
    echo "OK: all package files match their checksums."
  fi
fi

section "6. SUSPICIOUS ACTIVITY AUDIT"
echo "--- UID 0 accounts (only 'root' expected):"
awk -F: '$3==0{print $1}' /etc/passwd
[ "$(awk -F: '$3==0' /etc/passwd | wc -l)" -gt 1 ] && warn "more than one UID 0 account"
echo "--- Accounts with EMPTY passwords:"
EMPTY_PW=$(awk -F: '$2==""{print $1}' /etc/shadow | xargs)
if [ -n "$EMPTY_PW" ]; then warn "accounts with empty password: $EMPTY_PW"; else echo "None - OK"; fi
echo "--- Processes running from /tmp, /dev/shm, /var/tmp:"
TMP_PROCS=$(echo "$PROCS_PRE" | grep -E ' /(tmp|dev/shm|var/tmp|run/shm)/')
if [ -n "$TMP_PROCS" ]; then echo "$TMP_PROCS"; warn "processes running from a temp directory"; else echo "None - OK"; fi
echo "--- Processes running from DELETED binaries (state before the upgrade):"
DEL_PROCS=$(echo "$PROCS_PRE" | grep '(deleted)')
if [ -n "$DEL_PROCS" ]; then echo "$DEL_PROCS"; warn "processes running from deleted binaries"; else echo "None - OK"; fi
echo "--- Listening sockets (TCP + UDP):"
ss -tulpn
echo "--- SUID/SGID files modified in the last 7 days (updates are a normal cause):"
find / -xdev -perm /6000 -type f -mtime -7 2>/dev/null
echo "--- User crontabs:"
while IFS=: read -r user _; do
  crontab -l -u "$user" 2>/dev/null | grep -vE '^\s*(#|$)' | sed "s/^/[$user] /"
done < /etc/passwd
echo "--- System cron files:"
ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
echo "--- systemd timers:"
systemctl list-timers --all --no-pager
echo "--- Failed systemd units:"
FAILED_UNITS=$(systemctl --failed --no-legend --plain | awk '{print $1}' | xargs)
if [ -n "$FAILED_UNITS" ]; then warn "failed systemd units: $FAILED_UNITS"; else echo "None - OK"; fi
echo "--- Top 5 CPU consumers:"
ps aux --sort=-%cpu | head -6

section "7. DISK & HEALTH"
while read -r pct mnt; do warn "disk $mnt is $pct full"; done < <(
  df -P -x tmpfs -x devtmpfs -x squashfs -x overlay | awk -v t="$DISK_WARN_PCT" 'NR>1 && $5+0>=t {print $5, $6}')
while read -r pct mnt; do warn "inodes on $mnt are $pct used"; done < <(
  df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay | awk -v t="$DISK_WARN_PCT" 'NR>1 && $5+0>=t {print $5, $6}')
uptime
free -h
# What the cleanup can't decide for you: the biggest remaining space users.
echo "--- Biggest directories under /var:"
du -xh --max-depth=2 /var 2>/dev/null | sort -rh | head -10
echo "--- Files over 200 MB on /:"
find / -xdev -type f -size +200M -not -path '/var/lib/docker/*' -not -path '/var/lib/containerd/*' \
  -exec ls -lh {} + 2>/dev/null | awk '{print $5, $9}' | sort -rh | head -15
if have docker && docker info >/dev/null 2>&1; then echo "--- Docker disk usage:"; docker system df; fi
echo "Disk free on / before: $DISK_BEFORE | after: $(df -h / | awk 'NR==2{print $4}')"

section "8. SUMMARY"
REBOOT=0
[ -f /run/reboot-required ] && REBOOT=1
if have needrestart; then   # KSTA > 1 = a newer kernel is installed than the one running
  KSTA=$(needrestart -b -k 2>/dev/null | awk '/NEEDRESTART-KSTA/{print $2}')
  [ "${KSTA:-1}" -gt 1 ] 2>/dev/null && REBOOT=1
fi
if [ ${#WARNINGS[@]} -gt 0 ]; then echo "WARNINGS (${#WARNINGS[@]}):"; printf '  - %s\n' "${WARNINGS[@]}"; else echo "Warnings: none"; fi
if [ ${#FAILED[@]} -gt 0 ]; then echo "FAILED STEPS (${#FAILED[@]}):"; printf '  - %s\n' "${FAILED[@]}"; else echo "Failed steps: none"; fi
if [ "$REBOOT" = 1 ] && [ "$AUTO_REBOOT" = 1 ]; then
  echo "*** Reboot required - rebooting in 1 minute (cancel: sudo shutdown -c) ***"
  shutdown -r +1 "Rebooting after maintenance"
elif [ "$REBOOT" = 1 ]; then
  echo "*** Reboot required (AUTO_REBOOT=0, not done) ***"
else
  echo "No reboot required."
fi
echo; echo "=== FINISHED: $(date) ==="
EOF
)"
