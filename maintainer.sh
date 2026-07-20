sudo tee /usr/local/bin/server-maint.sh >/dev/null <<'EOF'
#!/bin/bash
set -u
export DEBIAN_FRONTEND=noninteractive
LOG=/var/log/server-maint-$(date +%F).log
exec > >(tee -a "$LOG") 2>&1

echo "==================================================="
echo "=== SERVER MAINTENANCE: $(hostname) | $(date) ==="
echo "==================================================="
DISK_BEFORE=$(df -h / | awk 'NR==2{print $4}')

# ---------- 1. UPDATES ----------
echo "--- [1/4] Updates ---"
dpkg --configure -a
apt-get -f install -y
apt-get update
apt-get dist-upgrade -y \
  -o Dpkg::Options::="--force-confold" \
  -o Dpkg::Options::="--force-confdef"
command -v snap >/dev/null && snap refresh
command -v flatpak >/dev/null && flatpak update -y --noninteractive
command -v needrestart >/dev/null || apt-get install -y needrestart
needrestart -r a

# ---------- 2. CLEANUP ----------
echo "--- [2/4] Cleanup ---"
apt-get autoremove --purge -y
apt-get clean
dpkg -l | awk '/^rc/{print $2}' | xargs -r apt-get purge -y
journalctl --vacuum-time=7d --vacuum-size=200M
find /var/log -type f \( -name "*.gz" -o -name "*.[0-9]" -o -name "*.old" \) -mtime +30 -delete
rm -rf /var/crash/* 2>/dev/null
if command -v snap >/dev/null; then
  snap set system refresh.retain=2
  snap list --all | awk '/disabled/{print $1, $3}' | while read -r name rev; do
    snap remove "$name" --revision="$rev"
  done
fi
command -v flatpak >/dev/null && flatpak uninstall --unused -y --noninteractive
find /tmp -type f -atime +10 -delete 2>/dev/null
find /var/tmp -type f -atime +30 -delete 2>/dev/null
# OPTIONAL: docker cleanup - uncomment only if you are sure
# command -v docker >/dev/null && docker system prune -af

# ---------- 3. MAINTENANCE ----------
echo "--- [3/4] Maintenance ---"

# SSD TRIM (safe on all mounts, skips non-SSD automatically)
fstrim -av 2>/dev/null || true

# SSL cert renewal
command -v certbot >/dev/null && certbot renew --quiet

# ---------- 4. HEALTH REPORT ----------
echo "--- [4/4] Health Report ---"
WARNINGS=0

echo "* Uptime/load: $(uptime)"

echo "* Disk usage:"
df -h --output=target,pcent,avail -x tmpfs -x devtmpfs | tail -n +2 | while read -r mount pct avail; do
  usage=${pct%\%}
  if [ "$usage" -ge 85 ]; then
    echo "  WARNING: $mount at $pct (only $avail free)"
  else
    echo "  OK: $mount at $pct"
  fi
done

echo "* Memory:"
free -h | awk 'NR<=3{print "  "$0}'

echo "* RAID status:"
if [ -f /proc/mdstat ] && grep -q ^md /proc/mdstat; then
  if grep -q '\[.*_.*\]' /proc/mdstat; then
    echo "  WARNING: DEGRADED RAID ARRAY DETECTED:"; cat /proc/mdstat
    WARNINGS=$((WARNINGS+1))
  else
    echo "  OK: all arrays healthy"
  fi
else
  echo "  (no software RAID)"
fi

echo "* SMART disk health:"
if command -v smartctl >/dev/null; then
  for disk in $(lsblk -dno NAME,TYPE | awk '$2=="disk"{print $1}'); do
    status=$(smartctl -H /dev/"$disk" 2>/dev/null | grep -iE "overall-health|result" || echo "not supported")
    echo "  /dev/$disk: $status"
  done
else
  echo "  (smartctl not installed - fine for VMs; on physical: apt install smartmontools)"
fi

echo "* Failed services:"
FAILED=$(systemctl --failed --no-legend | wc -l)
if [ "$FAILED" -gt 0 ]; then
  echo "  WARNING: $FAILED failed unit(s):"
  systemctl --failed --no-legend | sed 's/^/    /'
else
  echo "  OK: none"
fi

echo "* Time sync: $(timedatectl show -p NTPSynchronized --value 2>/dev/null | sed 's/yes/OK: synchronized/;s/no/WARNING: NOT synchronized/')"

SSH_FAILS=$(journalctl --since "24 hours ago" 2>/dev/null | grep -c "Failed password" || echo 0)
echo "* Failed SSH logins (24h): $SSH_FAILS"
[ "$SSH_FAILS" -gt 100 ] && echo "  WARNING: heavy brute-force activity - consider fail2ban + key-only auth"

ZOMBIES=$(ps aux | awk '$8 ~ /Z/' | wc -l)
echo "* Zombie processes: $ZOMBIES"

# ---------- SUMMARY & REBOOT ----------
DISK_AFTER=$(df -h / | awk 'NR==2{print $4}')
echo "==================================================="
echo "=== Disk free: $DISK_BEFORE -> $DISK_AFTER"
if [ -f /var/run/reboot-required ]; then
  echo "=== REBOOT REQUIRED - rebooting in 1 min (cancel: sudo shutdown -c)"
  shutdown -r +1 "Rebooting for security updates"
else
  echo "=== No reboot required"
fi
echo "=== Done: $(date) | Log: $LOG"
EOF
sudo chmod +x /usr/local/bin/server-maint.sh
sudo /usr/local/bin/server-maint.sh
