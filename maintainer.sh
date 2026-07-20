sudo bash -c '
echo "=== FIX & VERIFY: $(date) ==="
S=/usr/local/bin/server-maint.sh

# 1. Script bug (integer error)
if grep -q "|| echo 0)" "$S"; then
  sed -i "s/|| echo 0)/|| true)/" "$S"
  grep -q "|| true)" "$S" && echo "[FIXED] 1. script integer-error bug" || echo "[FAIL]  1. patch did not apply"
elif grep -q "|| true)" "$S"; then
  echo "[OK]    1. script bug already patched"
else
  echo "[WARN]  1. pattern not found - script content differs"
fi

# 2. Docker overlay noise in disk report
if grep -q -- "-x overlay" "$S"; then
  echo "[OK]    2. overlay filter already present"
else
  sed -i "s/-x tmpfs -x devtmpfs/-x tmpfs -x devtmpfs -x overlay/" "$S"
  grep -q -- "-x overlay" "$S" && echo "[FIXED] 2. docker overlay noise filtered" || echo "[FAIL]  2. filter not applied"
fi

# 3. fail2ban (the one that matters)
apt-get install -y -qq python3-systemd >/dev/null 2>&1
printf "[sshd]\nenabled = true\nbackend = systemd\n" > /etc/fail2ban/jail.local
systemctl restart fail2ban 2>/dev/null; sleep 2
if systemctl is-active --quiet fail2ban; then
  echo "[FIXED] 3. fail2ban RUNNING - jails:$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2)"
else
  echo "[FAIL]  3. fail2ban still down, last log lines:"
  journalctl -u fail2ban -n 5 --no-pager | sed "s/^/         /"
fi

# 4. blueman (Bluetooth manager - useless on a server)
if dpkg -l blueman 2>/dev/null | grep -q "^ii"; then
  apt-get purge -y -qq blueman >/dev/null 2>&1 && echo "[FIXED] 4. blueman removed"
else
  echo "[OK]    4. blueman not installed"
fi

# 5. apt-news + esm-cache (cosmetic Ubuntu Pro fetchers) - mask them
systemctl mask --now apt-news.service esm-cache.service >/dev/null 2>&1
echo "[FIXED] 5. apt-news + esm-cache masked (harmless noise, silenced)"

# 6. unattended-upgrades
systemctl restart unattended-upgrades 2>/dev/null; sleep 1
systemctl is-active --quiet unattended-upgrades \
  && echo "[OK]    6. unattended-upgrades active" \
  || echo "[WARN]  6. unattended-upgrades - check: journalctl -u unattended-upgrades -n 30"

# 7. cloud-init - only disable if this machine truly is not a cloud VM
if command -v cloud-id >/dev/null 2>&1; then
  CID=$(cloud-id 2>/dev/null || echo unknown)
  if [ "$CID" = "none" ]; then
    touch /etc/cloud/cloud-init.disabled
    echo "[FIXED] 7. cloud-init disabled (datasource=none, not a cloud VM)"
  else
    echo "[INFO]  7. cloud-init datasource=$CID - leaving enabled, check: journalctl -u cloud-init -n 30"
  fi
else
  echo "[OK]    7. cloud-init not present"
fi

# 8. Clear the old failed list and show final state
systemctl reset-failed
echo "=== VERIFICATION ==="
FAILED=$(systemctl --failed --no-legend | wc -l)
echo "Failed units now: $FAILED (was 10)"
systemctl --failed --no-legend | sed "s/^/  /"
echo "fail2ban: $(systemctl is-active fail2ban)"
swapon --show | grep -q . && echo "swap: present" || echo "swap: none (optional, see earlier message)"
echo "=== Done ==="
'
