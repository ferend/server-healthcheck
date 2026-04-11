#!/usr/bin/env bash
# ==========================================================================
# Smart Server Healthcheck v9.0 — Ferhat
# ==========================================================================
# CHANGES in v9.0:
#   - Compact Slack-friendly output: summary-first, only problems listed
#   - External exposure scan: public IP open port check
#   - Docker/K8s port audit: 0.0.0.0 binds, host network mode, exposed ports
#   - Intrusion detection: reverse shells, suspicious outbound, crypto miners,
#     unauthorized cron jobs, unusual ESTABLISHED connections, auth anomalies
#   - ~40% shorter output — OK items counted, not listed individually
# ==========================================================================
# Exit codes: 0=OK  1=WARNINGs  2=CRITICALs
# ==========================================================================
set -u -o pipefail
IFS=$' \t\n'
export LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin

SCRIPT_START="$(date +%s)"

# ══════════════════════════════════════════════════════════════
# ── SETTINGS
# ══════════════════════════════════════════════════════════════
HOST_ALIAS="${HOST_ALIAS:-$(hostname -s 2>/dev/null || echo unknown)}"
PUBLIC_IP_HINT="${PUBLIC_IP_HINT:-}"

REPORT_DIR="${REPORT_DIR:-/var/log/healthcheck}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
REPORT="${REPORT_DIR}/$(date +%F)_health.txt"
DATE="$(date +"%Y-%m-%d %H:%M:%S")"

CHECK_MODE="${CHECK_MODE:-AUTO}"
SLOW_MODE="${SLOW_MODE:-true}"
SECTION_DELAY="${SECTION_DELAY:-0.3}"
NETWORK_DELAY="${NETWORK_DELAY:-0.5}"

DOMAINS="${DOMAINS:-}"
EXTRA_SERVICES="${EXTRA_SERVICES:-}"
BASELINE_DIR="${BASELINE_DIR:-${REPORT_DIR}/baselines}"
KNOWN_PORTS="${KNOWN_PORTS:-}"
KNOWN_PORTS_FILE="${BASELINE_DIR}/known_ports.txt"

# ── Slack output mode: COMPACT (default) or VERBOSE (old style)
OUTPUT_MODE="${OUTPUT_MODE:-COMPACT}"

# ── External scan: set to false to skip public IP port scan
EXTERNAL_SCAN="${EXTERNAL_SCAN:-true}"

# ── Ports that are EXPECTED to be reachable from outside
# e.g. "22 80 443"  — anything else triggers a warning
EXPECTED_PUBLIC_PORTS="${EXPECTED_PUBLIC_PORTS:-22 80 443}"

# ══════════════════════════════════════════════════════════════
# ── HARDENING / RUNTIME
# ══════════════════════════════════════════════════════════════
umask 077
mkdir -p "$REPORT_DIR" "$BASELINE_DIR" 2>/dev/null || true
find "$REPORT_DIR" -maxdepth 1 -type f -name "*_health.txt" \
  -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true

LOCKFILE="/home/admin/healthcheck_${HOST_ALIAS}.lock"
exec 9>"$LOCKFILE" 2>/dev/null || true
if command -v flock >/dev/null 2>&1; then
  flock -n 9 || { echo "Another healthcheck running. Exiting."; exit 0; }
fi

exec > >(tee "$REPORT") 2>&1

# ══════════════════════════════════════════════════════════════
# ── HELPERS
# ══════════════════════════════════════════════════════════════
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

WARN_COUNT=0; CRIT_COUNT=0; SKIP_COUNT=0; OK_COUNT=0
WARNINGS=(); CRITICALS=()

ok() {
  OK_COUNT=$((OK_COUNT+1))
  [[ "$OUTPUT_MODE" == "VERBOSE" ]] && printf "%b\n" "  ${GREEN}✅${NC} $1"
}
warn()   { WARN_COUNT=$((WARN_COUNT+1)); WARNINGS+=("$1");
           printf "%b\n" "  ${YELLOW}⚠️${NC}  $1"; }
crit()   { CRIT_COUNT=$((CRIT_COUNT+1)); CRITICALS+=("$1");
           printf "%b\n" "  ${RED}🔴${NC} $1"; }
info()   { printf "%b\n" "  ${CYAN}ℹ${NC}  $1"; }
skipped(){ SKIP_COUNT=$((SKIP_COUNT+1)); }
detail() { printf "%b\n" "  ${DIM}   $1${NC}"; }

section() {
  printf "\n%b\n" "${BOLD}━━ $1 ━━${NC}"
}

cmd_exists()    { command -v "$1" >/dev/null 2>&1; }
cmp_float()     { awk "BEGIN{exit !($1 $2 $3)}"; }
sleep_s()       { [[ "$SLOW_MODE" == "true" ]] && sleep "$SECTION_DELAY" 2>/dev/null || true; }
sleep_net()     { [[ "$SLOW_MODE" == "true" ]] && sleep "$NETWORK_DELAY"  2>/dev/null || true; }
is_root()       { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
maybe_sudo()    { is_root && "$@" || sudo "$@" 2>/dev/null || return 127; }
is_interactive(){ [[ -t 1 ]]; }

cleanup_files=()
cleanup() { for f in "${cleanup_files[@]:-}"; do rm -f "$f" 2>/dev/null; done; }
trap cleanup EXIT

unit_exists() {
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q "^${svc}[[:space:]]"
}

add_service_if_unit_exists() {
  local svc="$1"
  unit_exists "$svc" && _AUTO_SERVICES+=("$svc")
}

if [[ "$CHECK_MODE" == "AUTO" ]]; then
  is_interactive && CHECK_MODE="FULL" || CHECK_MODE="FAST"
fi

# ══════════════════════════════════════════════════════════════
# ── CAPABILITY DETECTION (same as v8.1, condensed)
# ══════════════════════════════════════════════════════════════
HAS_NGINX=false;   cmd_exists nginx   && HAS_NGINX=true
HAS_APACHE=false;  (cmd_exists apache2 || cmd_exists httpd) && HAS_APACHE=true
HAS_MYSQL=false;   (cmd_exists mysql || cmd_exists mysqladmin) && HAS_MYSQL=true
HAS_POSTGRES=false; (cmd_exists psql || cmd_exists pg_isready) && HAS_POSTGRES=true
HAS_REDIS=false;   cmd_exists redis-cli && HAS_REDIS=true
HAS_MEMCACHED=false; cmd_exists memcached && HAS_MEMCACHED=true
HAS_MONGO=false;   cmd_exists mongosh && HAS_MONGO=true

HAS_PHP=false; PHP_BIN=""
for _php in php php8.3 php8.2 php8.1 php8.0 php7.4; do
  cmd_exists "$_php" && { HAS_PHP=true; PHP_BIN="$_php"; break; }
done

HAS_NODE=false;    cmd_exists node    && HAS_NODE=true
HAS_PYTHON=false;  (cmd_exists python3 || cmd_exists python) && HAS_PYTHON=true
HAS_DOCKER=false;  cmd_exists docker  && HAS_DOCKER=true
HAS_COMPOSE=false; ($HAS_DOCKER && docker compose version >/dev/null 2>&1) && HAS_COMPOSE=true
HAS_PODMAN=false;  cmd_exists podman  && HAS_PODMAN=true
HAS_K8S=false;     cmd_exists kubectl && HAS_K8S=true

HAS_UFW=false;     cmd_exists ufw           && HAS_UFW=true
HAS_NFTABLES=false; cmd_exists nft          && HAS_NFTABLES=true
HAS_IPTABLES=false; cmd_exists iptables     && HAS_IPTABLES=true
HAS_FAIL2BAN=false; cmd_exists fail2ban-client && HAS_FAIL2BAN=true
HAS_WG=false;      cmd_exists wg            && HAS_WG=true
HAS_RKHUNTER=false; cmd_exists rkhunter     && HAS_RKHUNTER=true
HAS_CHKROOTKIT=false; cmd_exists chkrootkit && HAS_CHKROOTKIT=true

HAS_JOURNALCTL=false; cmd_exists journalctl && HAS_JOURNALCTL=true
HAS_SYSTEMCTL=false;  cmd_exists systemctl  && HAS_SYSTEMCTL=true
HAS_SS=false;         cmd_exists ss         && HAS_SS=true
HAS_NETSTAT=false;    cmd_exists netstat    && HAS_NETSTAT=true
HAS_OPENSSL=false;    cmd_exists openssl    && HAS_OPENSSL=true
HAS_CURL=false;       cmd_exists curl       && HAS_CURL=true
HAS_NMAP=false;       cmd_exists nmap       && HAS_NMAP=true

HAS_LE=false
[[ -d /etc/letsencrypt/live ]] && ls /etc/letsencrypt/live/*/fullchain.pem \
  >/dev/null 2>&1 && HAS_LE=true

# Domain auto-discovery
if [[ -z "$DOMAINS" ]]; then
  _found_domains=""
  if $HAS_NGINX && [[ -d /etc/nginx ]]; then
    _found_domains="$(grep -rh 'server_name' /etc/nginx/sites-enabled/ \
      /etc/nginx/conf.d/ 2>/dev/null \
      | grep -v '#' | awk '{for(i=2;i<=NF;i++) print $i}' \
      | tr -d ';' | grep '\.' | grep -v '_' | sort -u | tr '\n' ' ' || true)"
  fi
  if [[ -z "$_found_domains" ]] && $HAS_APACHE && [[ -d /etc/apache2 ]]; then
    _found_domains="$(grep -rh 'ServerName\|ServerAlias' \
      /etc/apache2/sites-enabled/ 2>/dev/null \
      | awk '{print $2}' | grep '\.' | sort -u | tr '\n' ' ' || true)"
  fi
  DOMAINS="${_found_domains:-}"
fi
# shellcheck disable=SC2206
DOMAINS_ARR=($DOMAINS)
HAS_DOMAINS=false; [[ ${#DOMAINS_ARR[@]} -gt 0 ]] && HAS_DOMAINS=true

# Service auto-detection
_AUTO_SERVICES=()
if $HAS_SYSTEMCTL; then
  $HAS_NGINX    && add_service_if_unit_exists nginx
  $HAS_APACHE   && { unit_exists apache2 && _AUTO_SERVICES+=(apache2); unit_exists httpd && _AUTO_SERVICES+=(httpd); }
  $HAS_MYSQL    && { unit_exists mysql && _AUTO_SERVICES+=(mysql); unit_exists mariadb && _AUTO_SERVICES+=(mariadb); }
  $HAS_POSTGRES && add_service_if_unit_exists postgresql
  $HAS_REDIS    && { unit_exists redis-server && _AUTO_SERVICES+=(redis-server); unit_exists redis && _AUTO_SERVICES+=(redis); }
  $HAS_DOCKER   && add_service_if_unit_exists docker
  $HAS_WG       && add_service_if_unit_exists wg-quick@wg0
  $HAS_FAIL2BAN && add_service_if_unit_exists fail2ban
  for _pfpm in php8.3-fpm php8.2-fpm php8.1-fpm php8.0-fpm php7.4-fpm php-fpm; do
    unit_exists "$_pfpm" && _AUTO_SERVICES+=("$_pfpm")
  done
fi
# shellcheck disable=SC2206
[[ -n "$EXTRA_SERVICES" ]] && _AUTO_SERVICES+=($EXTRA_SERVICES)
if [[ ${#_AUTO_SERVICES[@]} -gt 0 ]]; then
  mapfile -t _AUTO_SERVICES < <(printf '%s\n' "${_AUTO_SERVICES[@]}" | awk '!seen[$0]++')
fi

# ══════════════════════════════════════════════════════════════
# ── BASELINE HELPERS (same logic, condensed)
# ══════════════════════════════════════════════════════════════
check_file_baseline() {
  local label="$1" file="$2"
  [[ -f "$file" ]] || { skipped; return; }
  local store="${BASELINE_DIR}/$(echo "$label" | tr ' /' '__').sha256"
  local cur; cur="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')" || return
  if [[ ! -f "$store" ]]; then
    echo "$cur" > "$store"; info "$label: baseline stored"
  else
    local prev; prev="$(cat "$store")"
    if [[ "$cur" != "$prev" ]]; then
      crit "$label CHANGED since baseline! ($file)"; echo "$cur" > "$store"
    else ok "$label unchanged"; fi
  fi
}

check_dir_baseline() {
  local label="$1"; shift
  local store="${BASELINE_DIR}/$(echo "$label" | tr ' /' '__').sha256"
  local tmp; tmp="$(mktemp)"; cleanup_files+=("$tmp")
  for d in "$@"; do
    [[ -e "$d" ]] && find "$d" -type f -exec sha256sum {} \; 2>/dev/null >> "$tmp" || true
  done
  [[ -s "$tmp" ]] || { skipped; return; }
  local cur; cur="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
  if [[ ! -f "$store" ]]; then
    echo "$cur" > "$store"; info "$label: baseline stored"
  else
    local prev; prev="$(cat "$store")"
    if [[ "$cur" != "$prev" ]]; then
      crit "$label CHANGED since baseline!"; echo "$cur" > "$store"
    else ok "$label unchanged"; fi
  fi
}

# ══════════════════════════════════════════════════════════════
# ── SSL HELPERS (condensed)
# ══════════════════════════════════════════════════════════════
check_https() {
  local host="$1" code
  $HAS_CURL || { skipped; return; }
  code="$(curl -sSL -o /dev/null -I --max-time 8 \
    -w '%{http_code}' "https://$host" 2>/dev/null || echo 000)"
  if [[ "$code" =~ ^(200|204|301|302|307|308|401|403)$ ]]; then
    ok "$host → $code"
  else warn "$host HTTPS failed ($code)"; fi
}

check_live_ssl() {
  local host="$1" out enddate expiry_epoch now_epoch days_left
  $HAS_OPENSSL || { skipped; return; }
  out="$(timeout 8 openssl s_client -servername "$host" \
    -connect "$host:443" </dev/null 2>&1 || true)"
  grep -q "BEGIN CERTIFICATE" <<<"$out" || { warn "SSL $host: no cert"; return; }
  enddate="$(openssl x509 -noout -enddate 2>/dev/null <<<"$out" | cut -d= -f2 || true)"
  [[ -z "$enddate" ]] && { warn "SSL $host: no enddate"; return; }
  expiry_epoch="$(date -d "$enddate" +%s 2>/dev/null || true)"
  now_epoch="$(date +%s)"
  [[ -z "$expiry_epoch" ]] && { warn "SSL $host: parse error"; return; }
  days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  if   (( days_left <  0  )); then crit "SSL $host EXPIRED $((-days_left))d ago"
  elif (( days_left < 15  )); then warn "SSL $host expires in ${days_left}d"
  elif (( days_left < 30  )); then warn "SSL $host expires soon: ${days_left}d"
  else ok "SSL $host valid (${days_left}d)"; fi
}

# ══════════════════════════════════════════════════════════════
# ── GET PUBLIC IP
# ══════════════════════════════════════════════════════════════
get_public_ip() {
  local ip=""
  if $HAS_CURL; then
    ip="$(curl -s --max-time 5 https://ifconfig.me 2>/dev/null || true)"
    [[ -z "$ip" ]] && ip="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    [[ -z "$ip" ]] && ip="$(curl -s --max-time 5 https://icanhazip.com 2>/dev/null || true)"
  fi
  echo "$ip"
}

# ══════════════════════════════════════════════════════════════
# HEADER (compact)
# ══════════════════════════════════════════════════════════════
printf "%b\n" "${BOLD}══ ${HOST_ALIAS}${PUBLIC_IP_HINT:+ @ ${PUBLIC_IP_HINT}} ══${NC}"
printf "%b\n" "${DIM}Healthcheck v9.0 | ${DATE} | Mode: ${CHECK_MODE}${NC}"
sleep_s

# ══════════════════════════════════════════════════════════════
# 1) SYSTEM INFO (one-liner)
# ══════════════════════════════════════════════════════════════
section "System"
{
  _os="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)"
  _up="$(uptime -p 2>/dev/null || uptime)"
  _kern="$(uname -r)"
  printf "  %s | %s | %s\n" "$_os" "$_kern" "$_up"
}
sleep_s

# ══════════════════════════════════════════════════════════════
# 2) CPU + MEMORY + DISK (condensed block)
# ══════════════════════════════════════════════════════════════
section "Resources"

# CPU
if [[ -r /proc/loadavg ]]; then
  LOAD1="$(awk '{print $1}' /proc/loadavg)"
  CORES="$(nproc 2>/dev/null || echo 1)"
  WARN_T="$(awk "BEGIN{printf \"%.2f\",$CORES*1.20}")"
  if   cmp_float "$LOAD1" "<" "$(awk "BEGIN{printf \"%.2f\",$CORES*0.70}")"; then ok "CPU ${LOAD1}/${CORES}cores"
  elif cmp_float "$LOAD1" "<" "$WARN_T"; then warn "CPU HIGH ${LOAD1}/${CORES}cores"
  else crit "CPU CRITICAL ${LOAD1}/${CORES}cores"; fi
fi

# Memory
if [[ -r /proc/meminfo ]]; then
  MEM_TOTAL="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  MEM_AVAIL="$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
  MEM_PCT="$(awk "BEGIN{printf(\"%.0f\",(1-$MEM_AVAIL/$MEM_TOTAL)*100)}")"
  if   (( MEM_PCT < 70 )); then ok "Memory ${MEM_PCT}%"
  elif (( MEM_PCT < 90 )); then warn "Memory HIGH: ${MEM_PCT}%"
  else crit "Memory CRITICAL: ${MEM_PCT}%"; fi

  SWAP_TOTAL="$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
  SWAP_FREE="$(awk '/SwapFree/{print $2}' /proc/meminfo)"
  if [[ "$SWAP_TOTAL" -gt 0 ]]; then
    SWAP_PCT="$(awk "BEGIN{printf(\"%.0f\",(($SWAP_TOTAL-$SWAP_FREE)/$SWAP_TOTAL)*100)}")"
    (( SWAP_PCT >= 20 )) && crit "Swap HIGH: ${SWAP_PCT}%" || \
    (( SWAP_PCT >   0 )) && warn "Swap in use: ${SWAP_PCT}%" || ok "Swap 0%"
  fi
fi

# Disk
if cmd_exists df; then
  while IFS=' ' read -r pct mnt; do
    [[ -z "$pct" || -z "$mnt" ]] && continue
    u="${pct%\%}"; [[ "$u" =~ ^[0-9]+$ ]] || continue
    if   (( u < 70 )); then ok "Disk $mnt ${u}%"
    elif (( u < 90 )); then warn "Disk $mnt HIGH: ${u}%"
    else crit "Disk $mnt CRITICAL: ${u}%"; fi
  done < <(df -Ph --output=pcent,target -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)

  while IFS=' ' read -r pct mnt; do
    [[ -z "$pct" || -z "$mnt" ]] && continue
    u="${pct%\%}"; [[ "$u" =~ ^[0-9]+$ ]] || continue
    (( u >= 90 )) && crit "Inodes $mnt CRITICAL: ${u}%" || \
    (( u >= 70 )) && warn "Inodes $mnt HIGH: ${u}%" || ok "Inodes $mnt ${u}%"
  done < <(df -Pi --output=ipcent,target -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 3) SERVICES (compact)
# ══════════════════════════════════════════════════════════════
section "Services"
if $HAS_SYSTEMCTL && [[ ${#_AUTO_SERVICES[@]} -gt 0 ]]; then
  _svc_ok=0; _svc_fail=()
  for svc in "${_AUTO_SERVICES[@]}"; do
    unit_exists "$svc" || continue
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      _svc_ok=$((_svc_ok+1))
    else
      _svc_fail+=("$svc")
    fi
  done
  (( _svc_ok > 0 )) && ok "${_svc_ok} service(s) running"
  for svc in "${_svc_fail[@]:-}"; do
    [[ -n "$svc" ]] && crit "$svc is NOT active"
  done
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 4) SSH + AUTH SECURITY (condensed)
# ══════════════════════════════════════════════════════════════
section "SSH & Auth"
if $HAS_JOURNALCTL; then
  _ssh_log="$(journalctl --since '24 hours ago' -u ssh -u sshd --no-pager 2>/dev/null || true)"
  FAILED="$(echo "$_ssh_log" | grep -c 'Failed password' || true)"
  INVALID="$(echo "$_ssh_log" | grep -c 'Invalid user' || true)"
  [[ "$FAILED" =~ ^[0-9]+$ ]] || FAILED=0
  [[ "$INVALID" =~ ^[0-9]+$ ]] || INVALID=0

  if   (( FAILED == 0 )); then ok "SSH: 0 failed logins (24h)"
  elif (( FAILED <  5 )); then warn "SSH failed logins: $FAILED (invalid users: $INVALID)"
  else
    crit "SSH HIGH failed logins: $FAILED (invalid: $INVALID)"
    echo "$_ssh_log" | grep 'Failed password' \
      | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
      | sort | uniq -c | sort -nr | head -3 | sed 's/^/      Top IPs: /'
  fi

  # Sudo
  SUDO_COUNT="$(journalctl --since '24 hours ago' _COMM=sudo --no-pager 2>/dev/null \
    | grep -c 'COMMAND=' || true)"
  [[ "$SUDO_COUNT" =~ ^[0-9]+$ ]] || SUDO_COUNT=0
  (( SUDO_COUNT == 0 )) && ok "Sudo: 0 commands (24h)" || warn "Sudo commands: $SUDO_COUNT (24h)"
fi

# Users
if cmd_exists who; then
  COUNT="$(who 2>/dev/null | wc -l | tr -d ' ')"
  [[ "$COUNT" =~ ^[0-9]+$ ]] || COUNT=0
  (( COUNT <= 2 )) && ok "Logged-in users: $COUNT" || warn "Unusual logged-in users: $COUNT"
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 5) FIREWALL + FAIL2BAN (compact)
# ══════════════════════════════════════════════════════════════
section "Firewall"
FIREWALL_FOUND=false
if $HAS_UFW; then
  FIREWALL_FOUND=true
  STATUS="$(maybe_sudo ufw status 2>/dev/null || true)"
  echo "$STATUS" | grep -q "Status: active" && ok "UFW active" || warn "UFW NOT active"
fi
if $HAS_NFTABLES && ! $FIREWALL_FOUND; then
  FIREWALL_FOUND=true
  maybe_sudo nft list ruleset >/dev/null 2>&1 && ok "nftables active" || warn "nftables: cannot read"
fi
if $HAS_IPTABLES && ! $FIREWALL_FOUND; then
  FIREWALL_FOUND=true
  RULES="$(maybe_sudo iptables -L INPUT --line-numbers 2>/dev/null | wc -l || echo 0)"
  [[ "$RULES" =~ ^[0-9]+$ ]] || RULES=0
  (( RULES > 3 )) && ok "iptables active ($RULES rules)" || warn "iptables: no meaningful rules"
fi
$FIREWALL_FOUND || warn "No firewall detected!"

if $HAS_FAIL2BAN; then
  JAILS="$(maybe_sudo fail2ban-client status 2>/dev/null \
    | awk -F',' '/Jail list/{print $0}' | sed 's/.*Jail list://;s/^[[:space:]]*//' || true)"
  if [[ -n "$JAILS" ]]; then
    TOTAL_BANNED=0
    for j in $(echo "$JAILS" | tr ',' ' '); do
      j="$(echo "$j" | tr -d ' ')"; [[ -z "$j" ]] && continue
      B="$(maybe_sudo fail2ban-client status "$j" 2>/dev/null | awk '/Currently banned/{print $4}' || true)"
      [[ "$B" =~ ^[0-9]+$ ]] || B=0
      TOTAL_BANNED=$((TOTAL_BANNED + B))
      (( B > 0 )) && info "Fail2Ban '$j': $B banned"
    done
    (( TOTAL_BANNED == 0 )) && ok "Fail2Ban: 0 bans" || warn "Fail2Ban total bans: $TOTAL_BANNED"
  fi
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 6) OPEN PORTS + PORT BASELINE
# ══════════════════════════════════════════════════════════════
section "Open Ports"
if $HAS_SS; then
  PORTS_OUT="$(ss -tulpn 2>/dev/null | tail -n +2)"
  CURRENT_PORTS="$(echo "$PORTS_OUT" | awk '{print $5}' \
    | awk -F: '{print $NF}' | sort -un | tr '\n' ' ' | sed 's/ $//')"
  detail "Listening: $CURRENT_PORTS"

  if [[ -n "$KNOWN_PORTS" ]]; then
    _unexpected=""
    for p in $CURRENT_PORTS; do
      echo " $KNOWN_PORTS " | grep -q " $p " || _unexpected="${_unexpected} $p"
    done
    [[ -n "$_unexpected" ]] && warn "Unexpected port(s):${_unexpected}" || ok "Port baseline OK"
  elif [[ ! -f "$KNOWN_PORTS_FILE" ]]; then
    echo "$CURRENT_PORTS" > "$KNOWN_PORTS_FILE"
    info "Port baseline stored: $CURRENT_PORTS"
  else
    PREV_PORTS="$(cat "$KNOWN_PORTS_FILE")"
    NEW_PORTS=""
    for p in $CURRENT_PORTS; do
      echo " $PREV_PORTS " | grep -q " $p " || NEW_PORTS="${NEW_PORTS} $p"
    done
    [[ -n "$NEW_PORTS" ]] && warn "NEW port(s) since baseline:${NEW_PORTS}" || ok "No new ports"
    echo "$CURRENT_PORTS" > "$KNOWN_PORTS_FILE"
  fi
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 7) ★ NEW: EXTERNAL EXPOSURE SCAN
# ══════════════════════════════════════════════════════════════
section "🌐 External Exposure"
if [[ "$EXTERNAL_SCAN" == "true" ]]; then
  PUB_IP="$(get_public_ip)"
  if [[ -n "$PUB_IP" ]]; then
    detail "Public IP: $PUB_IP"

    # Method 1: nmap scan (preferred)
    if $HAS_NMAP; then
      OPEN_EXT="$(timeout 30 nmap -Pn -sT --top-ports 100 -T4 "$PUB_IP" 2>/dev/null \
        | awk '/^[0-9]+\/tcp.*open/{print $1}' | sed 's|/tcp||' || true)"
    # Method 2: curl/bash probe top ports
    elif $HAS_CURL; then
      OPEN_EXT=""
      for _p in 21 22 23 25 53 80 110 143 443 445 993 995 \
                3306 3389 5432 5900 6379 8080 8443 9090 9200 27017; do
        (echo >/dev/tcp/"$PUB_IP"/"$_p") 2>/dev/null && OPEN_EXT="${OPEN_EXT} $_p"
      done
      OPEN_EXT="$(echo "$OPEN_EXT" | xargs)"
    else
      OPEN_EXT=""
      skipped "External scan (no nmap/curl)"
    fi

    if [[ -n "$OPEN_EXT" ]]; then
      detail "Externally open: $OPEN_EXT"
      for ep in $OPEN_EXT; do
        if ! echo " $EXPECTED_PUBLIC_PORTS " | grep -q " $ep "; then
          crit "Port $ep open externally but NOT in expected list!"
          # Identify what's listening
          $HAS_SS && ss -tlpn "sport = :$ep" 2>/dev/null | tail -1 | sed 's/^/      /' || true
        fi
      done
      _unexpected_ext=false
      for ep in $OPEN_EXT; do
        echo " $EXPECTED_PUBLIC_PORTS " | grep -q " $ep " || _unexpected_ext=true
      done
      $_unexpected_ext || ok "All external ports expected"
    else
      ok "No unexpected externally open ports detected"
    fi
  else
    skipped "External scan (cannot determine public IP)"
  fi
else
  skipped "External scan (disabled)"
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 8) ★ NEW: DOCKER / K8S PORT EXPOSURE AUDIT
# ══════════════════════════════════════════════════════════════
if $HAS_DOCKER || $HAS_K8S; then
  section "🐳 Container Exposure Audit"

  if $HAS_DOCKER; then
    # Check containers bound to 0.0.0.0 (world-accessible)
    _wildcard_binds=""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      _cname="$(echo "$line" | awk '{print $NF}')"
      _ports="$(echo "$line" | awk '{print $(NF-1)}')"
      if echo "$_ports" | grep -qE '0\.0\.0\.0:[0-9]+->'; then
        _exposed="$(echo "$_ports" | grep -oE '0\.0\.0\.0:[0-9]+' | sed 's/0.0.0.0://' | tr '\n' ',' | sed 's/,$//')"
        _wildcard_binds="${_wildcard_binds}\n      ${_cname} → 0.0.0.0:${_exposed}"
        warn "Container '${_cname}' exposes port(s) ${_exposed} on 0.0.0.0 (world-accessible)"
      fi
    done < <(docker ps --format 'table {{.Ports}}\t{{.Names}}' 2>/dev/null | tail -n +2 || true)
    [[ -z "$_wildcard_binds" ]] && ok "No containers bound to 0.0.0.0"

    # Host network mode check
    _host_net=""
    while IFS= read -r cname; do
      [[ -z "$cname" ]] && continue
      _netmode="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$cname" 2>/dev/null || true)"
      if [[ "$_netmode" == "host" ]]; then
        crit "Container '${cname}' runs in HOST network mode (shares all host ports!)"
        _host_net="yes"
      fi
    done < <(docker ps --format '{{.Names}}' 2>/dev/null || true)
    [[ -z "$_host_net" ]] && ok "No containers in host network mode"

    # Privileged containers
    while IFS= read -r cname; do
      [[ -z "$cname" ]] && continue
      _priv="$(docker inspect -f '{{.HostConfig.Privileged}}' "$cname" 2>/dev/null || true)"
      [[ "$_priv" == "true" ]] && crit "Container '${cname}' is PRIVILEGED (full host access!)"
    done < <(docker ps --format '{{.Names}}' 2>/dev/null || true)

    # Docker daemon TCP exposure
    if ss -tlpn 2>/dev/null | grep -qE ':2375\s|:2376\s'; then
      crit "Docker daemon listening on TCP (possible remote exploitation!)"
    else
      ok "Docker daemon not exposed on TCP"
    fi

    # Container health & stats (condensed from v8.1)
    RUNNING="$(docker ps -q  2>/dev/null | wc -l | tr -d ' ')"
    EXITED="$(docker ps -aq -f status=exited 2>/dev/null | wc -l | tr -d ' ')"
    RESTART="$(docker ps -aq -f status=restarting 2>/dev/null | wc -l | tr -d ' ')"
    [[ "$RUNNING" =~ ^[0-9]+$ ]] || RUNNING=0
    [[ "$EXITED" =~ ^[0-9]+$ ]] || EXITED=0
    [[ "$RESTART" =~ ^[0-9]+$ ]] || RESTART=0
    ok "Containers: ${RUNNING} running"
    (( EXITED  > 0 )) && warn "Exited containers: $EXITED"
    (( RESTART > 0 )) && crit "Restarting containers: $RESTART"

    # Unhealthy
    while IFS= read -r cname; do
      [[ -z "$cname" ]] && continue
      h="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$cname" 2>/dev/null || echo n/a)"
      [[ "$h" == "unhealthy" ]] && crit "Container $cname UNHEALTHY"
    done < <(docker ps --format '{{.Names}}' 2>/dev/null || true)

    # Container log errors (30min)
    _cerr=0
    while IFS= read -r cname; do
      [[ -z "$cname" ]] && continue
      CERR="$(docker logs --since 30m "$cname" 2>&1 \
        | grep -iE '\b(error|fatal|panic|exception|oom)\b' \
        | grep -iv 'healthcheck\|debug\|loglevel' | tail -2 || true)"
      if [[ -n "$CERR" ]]; then
        _cerr=1; warn "Log errors: $cname"
        echo "$CERR" | head -2 | sed 's/^/      /'
      fi
    done < <(docker ps --format '{{.Names}}' 2>/dev/null || true)
    (( _cerr == 0 )) && ok "No container log errors (30min)"
  fi

  if $HAS_K8S; then
    detail "Kubernetes services (type=NodePort/LoadBalancer):"
    _k8s_exposed="$(kubectl get svc --all-namespaces -o wide 2>/dev/null \
      | awk '$3=="NodePort" || $3=="LoadBalancer" {print $1"/"$2, $3, $5}' || true)"
    if [[ -n "$_k8s_exposed" ]]; then
      warn "K8s externally exposed services:"
      echo "$_k8s_exposed" | sed 's/^/      /'
    else
      ok "No K8s NodePort/LoadBalancer services"
    fi

    # Pods in host network
    _k8s_hostnet="$(kubectl get pods --all-namespaces -o json 2>/dev/null \
      | python3 -c "
import json,sys
data=json.load(sys.stdin)
for p in data.get('items',[]):
  if p.get('spec',{}).get('hostNetwork'):
    ns=p['metadata']['namespace']; name=p['metadata']['name']
    print(f'  {ns}/{name}')
" 2>/dev/null || true)"
    if [[ -n "$_k8s_hostnet" ]]; then
      warn "K8s pods with hostNetwork=true:"
      echo "$_k8s_hostnet" | sed 's/^/      /'
    else
      ok "No K8s pods in host network"
    fi
  fi
  sleep_s
fi

# ══════════════════════════════════════════════════════════════
# 9) ★ NEW: INTRUSION / HACK DETECTION
# ══════════════════════════════════════════════════════════════
section "🔍 Intrusion Detection"

# ── Suspicious outbound connections (reverse shells, C2, exfil)
if $HAS_SS; then
  detail "Checking outbound connections..."

  # Common reverse shell / C2 ports
  _sus_outbound=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    _dst="$(echo "$line" | awk '{print $5}')"
    _proc="$(echo "$line" | awk '{print $7}')"
    _port="$(echo "$_dst" | awk -F: '{print $NF}')"
    # Flag unusual outbound: IRC (6667-6669), known C2 ports, high random ports from root processes
    if [[ "$_port" =~ ^(4444|4445|5555|6666|6667|6668|6669|1337|31337|9001|9002)$ ]]; then
      _sus_outbound="${_sus_outbound}\n      ${_dst} [${_proc}]"
    fi
  done < <(ss -tnp state established 2>/dev/null | tail -n +2 || true)

  if [[ -n "$_sus_outbound" ]]; then
    crit "Suspicious outbound connections (possible C2/reverse shell):"
    printf "%b\n" "$_sus_outbound"
  else
    ok "No suspicious outbound connections"
  fi

  # Unusual ESTABLISHED connections: non-standard ports with foreign IPs
  _est_count="$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
  [[ "$_est_count" =~ ^[0-9]+$ ]] || _est_count=0
  (( _est_count > 100 )) && warn "High number of ESTABLISHED connections: $_est_count" \
                          || ok "ESTABLISHED connections: $_est_count"
fi

# ── Crypto miner detection
_miner_procs="$(ps aux 2>/dev/null \
  | grep -iE 'xmrig|minerd|cpuminer|stratum|cryptonight|ethminer|nbminer|t-rex|phoenixminer|lolminer' \
  | grep -v grep || true)"
if [[ -n "$_miner_procs" ]]; then
  crit "Possible crypto miner process detected!"
  echo "$_miner_procs" | head -5 | sed 's/^/      /'
else
  ok "No crypto miners detected"
fi

# ── Reverse shell indicators in processes
_revshell=""
# Check for common reverse shell patterns in process list
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  if echo "$line" | grep -qiE 'bash -i.*>&.*/dev/tcp|nc -e|ncat -e|socat.*EXEC|python.*socket.*connect|perl.*socket.*INET|ruby.*TCPSocket|php.*fsockopen.*sh'; then
    _revshell="${_revshell}\n      $line"
  fi
done < <(ps auxww 2>/dev/null || true)

if [[ -n "$_revshell" ]]; then
  crit "Possible REVERSE SHELL detected in process list!"
  printf "%b\n" "$_revshell"
else
  ok "No reverse shell indicators"
fi

# ── Unauthorized cron jobs (non-root, non-system)
_sus_crons=""
if [[ -d /var/spool/cron/crontabs ]]; then
  for cronfile in /var/spool/cron/crontabs/*; do
    [[ -f "$cronfile" ]] || continue
    _user="$(basename "$cronfile")"
    while IFS= read -r cronline; do
      # Flag lines with downloads, pipes to shell, encoded data
      if echo "$cronline" | grep -qiE 'curl.*\|.*sh|wget.*\|.*sh|base64|/dev/tcp|python.*-c|perl.*-e'; then
        _sus_crons="${_sus_crons}\n      [${_user}] ${cronline}"
      fi
    done < <(grep -v '^#\|^$\|^[[:space:]]*$' "$cronfile" 2>/dev/null || true)
  done
fi
# Also check /etc/cron.d
if [[ -d /etc/cron.d ]]; then
  for cronfile in /etc/cron.d/*; do
    [[ -f "$cronfile" ]] || continue
    while IFS= read -r cronline; do
      if echo "$cronline" | grep -qiE 'curl.*\|.*sh|wget.*\|.*sh|base64|/dev/tcp|python.*-c|perl.*-e'; then
        _sus_crons="${_sus_crons}\n      [$(basename "$cronfile")] ${cronline}"
      fi
    done < <(grep -v '^#\|^$\|^[[:space:]]*$' "$cronfile" 2>/dev/null || true)
  done
fi

if [[ -n "$_sus_crons" ]]; then
  crit "Suspicious cron entries (download+execute / encoded):"
  printf "%b\n" "$_sus_crons"
else
  ok "No suspicious cron entries"
fi

# ── Recently modified files in sensitive dirs (last 24h)
if [[ "$CHECK_MODE" == "FULL" ]]; then
  _recent_mods="$(find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
    -type f -mtime -1 2>/dev/null | head -10 || true)"
  if [[ -n "$_recent_mods" ]]; then
    warn "Recently modified system binaries (24h):"
    echo "$_recent_mods" | sed 's/^/      /'
  else
    ok "No recently modified system binaries"
  fi
fi

# ── Unusual listening on all interfaces
if $HAS_SS; then
  _all_iface_listen=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    _addr="$(echo "$line" | awk '{print $5}')"
    _proc="$(echo "$line" | awk '{print $7}')"
    _port="$(echo "$_addr" | awk -F: '{print $NF}')"
    # Flag 0.0.0.0 listeners on non-standard ports
    if echo "$_addr" | grep -qE '^(\*|0\.0\.0\.0|:::)' ; then
      if ! echo " 22 80 443 53 25 $EXPECTED_PUBLIC_PORTS " | grep -q " $_port "; then
        _all_iface_listen="${_all_iface_listen}\n      :${_port} [${_proc}]"
      fi
    fi
  done < <(ss -tulpn 2>/dev/null | tail -n +2 || true)

  if [[ -n "$_all_iface_listen" ]]; then
    warn "Services bound to 0.0.0.0 on non-standard ports:"
    printf "%b\n" "$_all_iface_listen"
  else
    ok "No unexpected wildcard listeners"
  fi
fi

# ── Auth anomalies: brute force success detection
if $HAS_JOURNALCTL; then
  # Check if there were many failures followed by success from same IP
  _brute_ips="$(journalctl --since '24 hours ago' -u ssh -u sshd --no-pager 2>/dev/null \
    | grep 'Failed password' \
    | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' \
    | sort | uniq -c | sort -nr | awk '$1>=10{print $2}' || true)"
  if [[ -n "$_brute_ips" ]]; then
    for _bip in $_brute_ips; do
      _accepted="$(journalctl --since '24 hours ago' -u ssh -u sshd --no-pager 2>/dev/null \
        | grep 'Accepted' | grep "$_bip" || true)"
      if [[ -n "$_accepted" ]]; then
        crit "POSSIBLE BREACH: IP $_bip had 10+ failed attempts AND successful login!"
        echo "$_accepted" | tail -3 | sed 's/^/      /'
      fi
    done
  fi
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 10) CONNECTIVITY + SSL (condensed)
# ══════════════════════════════════════════════════════════════
section "Connectivity & SSL"
if cmd_exists ping && ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
  ok "Internet OK"
else crit "No internet!"; fi

if $HAS_DOMAINS; then
  for site in "${DOMAINS_ARR[@]}"; do
    check_https "$site"; sleep_net
    check_live_ssl "$site"; sleep_net
  done
fi

# Local LE certs
if $HAS_LE && $HAS_OPENSSL; then
  shopt -s nullglob
  for crt in /etc/letsencrypt/live/*/fullchain.pem; do
    domain="$(basename "$(dirname "$crt")")"
    enddate="$(openssl x509 -enddate -noout -in "$crt" 2>/dev/null | cut -d= -f2 || true)"
    [[ -z "$enddate" ]] && continue
    expiry_epoch="$(date -d "$enddate" +%s 2>/dev/null || true)"
    [[ -z "$expiry_epoch" ]] && continue
    days_left=$(( (expiry_epoch - $(date +%s)) / 86400 ))
    if   (( days_left < 0  )); then crit "LE cert $domain EXPIRED"
    elif (( days_left < 15 )); then warn "LE cert $domain: ${days_left}d left"
    else ok "LE cert $domain: ${days_left}d"; fi
  done
  shopt -u nullglob
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 11) UPDATES
# ══════════════════════════════════════════════════════════════
section "Updates"
[[ -f /var/run/reboot-required ]] && crit "Reboot required" || ok "No reboot needed"

if cmd_exists apt-get; then
  SEC_UPDATES=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst.*security/{c++} END{print c+0}')
  UPDATES=$(apt-get -s upgrade 2>/dev/null | awk '/^Inst /{c++} END{print c+0}')
  [[ "$SEC_UPDATES" =~ ^[0-9]+$ ]] || SEC_UPDATES=0
  [[ "$UPDATES" =~ ^[0-9]+$ ]] || UPDATES=0
  (( SEC_UPDATES > 0 )) && crit "$SEC_UPDATES security updates pending" || \
  (( UPDATES > 0 ))     && warn "$UPDATES packages upgradable" || ok "Packages up-to-date"
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 12) FILE INTEGRITY + SECURITY (condensed)
# ══════════════════════════════════════════════════════════════
section "File Integrity"
check_file_baseline "etc_passwd"   /etc/passwd
check_file_baseline "etc_shadow"   /etc/shadow
check_file_baseline "etc_group"    /etc/group
check_file_baseline "etc_hosts"    /etc/hosts
check_file_baseline "sshd_config"  /etc/ssh/sshd_config
check_file_baseline "etc_sudoers"  /etc/sudoers
check_dir_baseline  "sudoers_d"    /etc/sudoers.d
check_dir_baseline  "crontabs"     /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly \
  /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs
$HAS_NGINX  && check_dir_baseline "nginx_conf"  /etc/nginx
$HAS_APACHE && check_dir_baseline "apache_conf" /etc/apache2
sleep_s

# ══════════════════════════════════════════════════════════════
# 13) ACCOUNT SECURITY (condensed)
# ══════════════════════════════════════════════════════════════
section "Account Security"
ROOT_EXTRA="$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd 2>/dev/null || true)"
[[ -n "$ROOT_EXTRA" ]] && crit "Non-root UID-0: $ROOT_EXTRA" || ok "No extra UID-0"

NO_PASS="$(awk -F: '$2=="" && $7!="/usr/sbin/nologin" && $7!="/bin/false" {print $1}' /etc/shadow 2>/dev/null || true)"
[[ -n "$NO_PASS" ]] && crit "Empty password accounts: $NO_PASS" || ok "No empty passwords"
sleep_s

# ══════════════════════════════════════════════════════════════
# 14) ROOTKIT / MALWARE (condensed)
# ══════════════════════════════════════════════════════════════
section "Malware Scan"

# Executables in /tmp
TMP_EXE="$(find /tmp /var/tmp -type f -executable 2>/dev/null || true)"
[[ -z "$TMP_EXE" ]] && ok "No executables in /tmp" \
  || { crit "Executables in /tmp (possible malware):"; echo "$TMP_EXE" | head -5 | sed 's/^/      /'; }

# Known bad binaries
BAD_BINS="w0rm xpl0it r00tkit h4x r57shell c99shell backdoor"
BAD_FOUND=""
for b in $BAD_BINS; do cmd_exists "$b" && BAD_FOUND="${BAD_FOUND} $b"; done
[[ -n "$BAD_FOUND" ]] && crit "Suspicious binaries:$BAD_FOUND" || ok "No rootkit binaries"

# /dev regular files
DEV_FILES="$(find /dev -maxdepth 1 -type f 2>/dev/null | grep -v '\.d$' || true)"
[[ -n "$DEV_FILES" ]] && warn "Files in /dev: $DEV_FILES" || ok "Clean /dev"

# Suspicious processes
PROC_ALLOW="systemd|init|sshd|bash|sh|dash|nginx|apache2|httpd|ufw|cron|crond|dockerd|containerd|runc|mysqld|mariadbd|php-fpm|journald|rsyslogd|auditd|rpcbind|dbus|polkitd|NetworkManager|chronyd|ntpd|fail2ban|wg|wireguard|redis-server|postgres|memcached|node|python3|ruby|java|perl|atd|acpid|irqbalance|snapd|multipathd|systemd-|agetty|login|su|containerd-shim|docker-proxy|kworker|ksoftirqd|migration|rcu|lsmd|packagekit|tuned|accounts-daemon|udisksd|ModemManager|go.d.plugin|apps.plugin|traefik|soketi-server|tailscaled|smbd|nmbd|site_total|unattended-upgr"
SUSPICIOUS="$(ps -eo pid,user,comm --sort=-%mem 2>/dev/null \
  | awk -v allow="$PROC_ALLOW" 'NR>1 && $2=="root" && $3 !~ allow {print}' || true)"
[[ -z "$SUSPICIOUS" ]] && ok "No unexpected root processes" \
  || { warn "Unexpected root processes:"; echo "$SUSPICIOUS" | head -5 | sed 's/^/      /'; }

# Kernel dmesg quick scan
if cmd_exists dmesg && is_root; then
  _dmesg="$(dmesg --time-format reltime 2>/dev/null || true)"
  OOM="$(echo "$_dmesg" | grep -ciE 'oom.killer|out of memory' || true)"
  [[ "$OOM" =~ ^[0-9]+$ ]] || OOM=0
  (( OOM > 0 )) && crit "OOM killer events: $OOM" || ok "No OOM events"
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 15) NTP (one line)
# ══════════════════════════════════════════════════════════════
section "Time"
if cmd_exists timedatectl; then
  SYNC="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo no)"
  [[ "$SYNC" == "yes" ]] && ok "NTP synced" || warn "NTP NOT synced"
fi
sleep_s

# ══════════════════════════════════════════════════════════════
# 16) SUID + WORLD-WRITABLE (FULL mode only, condensed)
# ══════════════════════════════════════════════════════════════
if [[ "$CHECK_MODE" == "FULL" ]]; then
  section "Deep Scan"

  # SUID
  SUID_TMP="$(mktemp)"; cleanup_files+=("$SUID_TMP")
  find / \( -path /proc -o -path /sys -o -path /run -o -path /dev -o -path /snap \
    -o -path /var/lib/docker \) -prune -o -perm -4000 -type f -print 2>/dev/null | sort > "$SUID_TMP"
  SUID_STORE="${BASELINE_DIR}/suid_baseline.txt"
  if [[ ! -f "$SUID_STORE" ]]; then
    cp "$SUID_TMP" "$SUID_STORE"; info "SUID baseline stored"
  else
    _sdiff="$(comm -3 "$SUID_STORE" "$SUID_TMP" || true)"
    [[ -n "$_sdiff" ]] && { warn "SUID changes detected"; echo "$_sdiff" | head -5 | sed 's/^/      /'; } \
      || ok "SUID unchanged"
    cp "$SUID_TMP" "$SUID_STORE"
  fi

  # World-writable
  WW_COUNT="$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \
    -o -path /var/lib/docker -o -path /tmp \) -prune -o -perm -0002 -not -type l -print 2>/dev/null \
    | wc -l || echo 0)"
  [[ "$WW_COUNT" =~ ^[0-9]+$ ]] || WW_COUNT=0
  (( WW_COUNT == 0 )) && ok "No world-writable files" || warn "World-writable files: $WW_COUNT"

  # LD_PRELOAD scan
  if is_root; then
    _ldp=false
    for pid in /proc/[0-9]*/environ; do
      strings "$pid" 2>/dev/null | grep -q 'LD_PRELOAD' && { _ldp=true; break; }
    done
    $_ldp && crit "LD_PRELOAD found in running processes!" || ok "No LD_PRELOAD injection"
  fi

  # Kernel modules baseline
  KMOD_STORE="${BASELINE_DIR}/kmodules.txt"
  KMOD_CURRENT="$(lsmod 2>/dev/null | awk 'NR>1{print $1}' | sort || true)"
  if [[ ! -f "$KMOD_STORE" ]]; then
    echo "$KMOD_CURRENT" > "$KMOD_STORE"; info "Kernel module baseline stored"
  else
    KMOD_NEW="$(comm -13 "$KMOD_STORE" <(echo "$KMOD_CURRENT") || true)"
    [[ -n "$KMOD_NEW" ]] && warn "New kernel modules: $(echo "$KMOD_NEW" | tr '\n' ' ')" \
      || ok "Kernel modules unchanged"
    echo "$KMOD_CURRENT" > "$KMOD_STORE"
  fi
fi

# ══════════════════════════════════════════════════════════════
# FOOTER — COMPACT SUMMARY (Slack-optimized)
# ══════════════════════════════════════════════════════════════
SCRIPT_END="$(date +%s)"
RUNTIME=$(( SCRIPT_END - SCRIPT_START ))

printf "\n%b\n" "${BOLD}════════════════════════════════════════${NC}"
printf "%b\n" "${BOLD}📊 ${HOST_ALIAS} | $(date +%H:%M) | ${RUNTIME}s | ${CHECK_MODE}${NC}"

if (( CRIT_COUNT == 0 && WARN_COUNT == 0 )); then
  printf "%b\n" "${GREEN}✅ ALL OK — ${OK_COUNT} checks passed${NC}"
else
  if (( CRIT_COUNT > 0 )); then
    printf "%b\n" "${RED}🔴 CRITICAL: ${CRIT_COUNT}${NC}"
    for m in "${CRITICALS[@]}"; do printf "%b\n" "${RED}  • $m${NC}"; done
  fi
  if (( WARN_COUNT > 0 )); then
    printf "%b\n" "${YELLOW}⚠️  WARNING: ${WARN_COUNT}${NC}"
    for m in "${WARNINGS[@]}"; do printf "%b\n" "${YELLOW}  • $m${NC}"; done
  fi
  printf "%b\n" "${DIM}✅ ${OK_COUNT} checks passed | ⊘ ${SKIP_COUNT} skipped${NC}"
fi
printf "%b\n" "${BOLD}════════════════════════════════════════${NC}"

if   (( CRIT_COUNT > 0 )); then exit 2
elif (( WARN_COUNT > 0 )); then exit 1
else exit 0
fi
