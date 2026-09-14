sudo tee /usr/local/bin/server-maint.sh >/dev/null <<'EOF'
#!/bin/bash
set -u
export DEBIAN_FRONTEND=noninteractive
LOG=/var/log/server-maint-$(date +%F).log
exec > >(tee -a "$LOG") 2>&1
section(){ echo; echo "==================== $1  [$(date +%H:%M:%S)] ===================="; }
APTI="apt-get install -y --no-install-recommends"

echo "=== SERVER MAINTENANCE started: $(date) on $(hostname) ==="
DISK_BEFORE=$(df -h / | awk 'NR==2{print $4}')

section "1. SYSTEM UPDATES"
dpkg --configure -a
apt-get -f install -y
apt-get update -qq
apt-get dist-upgrade -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef"
command -v snap >/dev/null && snap refresh
command -v flatpak >/dev/null && flatpak update -y --noninteractive
command -v needrestart >/dev/null || $APTI needrestart
needrestart -r a

section "2. CLEANUP"
apt-get autoremove --purge -y
apt-get clean
dpkg -l | awk '/^rc/{print $2}' | xargs -r apt-get purge -y
journalctl --vacuum-time=7d --vacuum-size=200M
find /var/log -type f \( -name "*.gz" -o -name "*.[0-9]" -o -name "*.old" \) -mtime +30 -delete
rm -rf /var/crash/* 2>/dev/null
find /tmp -type f -atime +10 -delete 2>/dev/null
find /var/tmp -type f -atime +30 -delete 2>/dev/null
if command -v snap >/dev/null; then
  snap set system refresh.retain=2
  snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' | while read -r n r; do snap remove "$n" --revision="$r"; done
fi

section "3. BRUTE-FORCE PROTECTION (fail2ban)"
command -v fail2ban-server >/dev/null || $APTI fail2ban
systemctl enable --now fail2ban
sleep 2
fail2ban-client status sshd 2>/dev/null || echo "sshd jail not active - check /etc/fail2ban/"

section "4. SSH ATTACK REPORT (last 24h)"
echo "--- Top 10 attacking IPs (failed passwords):"
journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | grep -i "failed password" \
  | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -10
echo "--- Invalid usernames tried:"
journalctl -u ssh -u sshd --since "24 hours ago" 2>/dev/null | grep -i "invalid user" \
  | grep -oP 'invalid user \K\S+' | sort | uniq -c | sort -rn | head -10
echo "--- Recent successful logins:"
last -a -n 15

section "5. PACKAGE INTEGRITY (tampered system binaries)"
command -v debsums >/dev/null || $APTI debsums
if debsums -s 2>&1 | grep -q .; then
  echo "^^ Files above differ from their package. Config edits are normal; changed BINARIES are not."
else
  echo "OK: all package files match their official checksums."
fi

section "6. SUSPICIOUS ACTIVITY AUDIT"
echo "--- UID 0 accounts (ONLY 'root' should be listed):"
awk -F: '$3==0{print $1}' /etc/passwd
echo "--- Accounts with EMPTY passwords:"
awk -F: '($2==""){print $1}' /etc/shadow
echo "--- Processes running from /tmp, /dev/shm, /var/tmp (classic malware sign):"
ls -l /proc/*/exe 2>/dev/null | grep -E '/(tmp|dev/shm|var/tmp)/' || echo "None - OK"
echo "--- Processes running from DELETED binaries:"
ls -l /proc/*/exe 2>/dev/null | grep -i deleted || echo "None - OK"
echo "--- Listening ports:"
ss -tulpn | grep LISTEN
echo "--- SUID binaries modified in last 7 days:"
find / -xdev -perm -4000 -type f -mtime -7 2>/dev/null
echo "--- Cron jobs per user:"
for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null | grep -v '^\s*#' | sed "s/^/[$u] /"; done
echo "--- Failed systemd units:"
systemctl --failed --no-legend
echo "--- Top 5 CPU consumers:"
ps aux --sort=-%cpu | head -6

section "7. DISK & HEALTH"
df -h | awk '$5+0 > 85 {print "WARNING: "$6" is "$5" full"}'
uptime
echo "Disk free before: $DISK_BEFORE | after: $(df -h / | awk 'NR==2{print $4}')"

section "8. REBOOT CHECK"
if [ -f /var/run/reboot-required ]; then
  echo "*** Reboot required - in 1 minute (cancel: shutdown -c) ***"
  shutdown -r +1 "Rebooting after maintenance"
else
  echo "No reboot required."
fi
echo; echo "=== FINISHED: $(date) | Full log: $LOG ==="
EOF
sudo chmod +x /usr/local/bin/server-maint.sh
sudo /usr/local/bin/server-maint.sh
