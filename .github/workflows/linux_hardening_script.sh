#!/usr/bin/env bash
#
# CCDC Linux Hardening Bootstrap (Safe / Non-Disruptive)
# - Does NOT stop/disable services
# - Does NOT change existing firewall default policies
# - Focuses on:
#     * Inventory (users, groups, services, ports, suid, cron, web dirs)
#     * Enabling/confirming safe sysctl settings
#     * Enabling firewall logging where already active
#     * Searching for suspicious files / passwords
#

set -euo pipefail

DATE_TAG="$(date +%Y%m%d_%H%M%S)"
BASE_DIR="/root/ccdc_hardening"
LOG_DIR="$BASE_DIR/logs_$DATE_TAG"

mkdir -p "$LOG_DIR"

echo "[*] Output directory: $LOG_DIR"

# Ensure root
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[!] Run this script as root."
  exit 1
fi

# ---------------------------------
# 1. Baseline Inventory (Safe)
# ---------------------------------

echo "[*] Collecting user and group information..."
cp /etc/passwd "$LOG_DIR/passwd_$DATE_TAG"
cp /etc/group "$LOG_DIR/group_$DATE_TAG"
if [[ -f /etc/shadow ]]; then
  # permissions preserved by cp; content is for IR only
  cp /etc/shadow "$LOG_DIR/shadow_$DATE_TAG"
fi

echo "[*] Collecting sudoers configuration..."
cp /etc/sudoers "$LOG_DIR/sudoers_$DATE_TAG"
if [[ -d /etc/sudoers.d ]]; then
  tar czf "$LOG_DIR/sudoers.d_$DATE_TAG.tar.gz" -C /etc sudoers.d
fi

echo "[*] Collecting running services and processes..."
if command -v systemctl &>/dev/null; then
  systemctl --type=service --state=running > "$LOG_DIR/systemd_services_$DATE_TAG.txt"
fi
ps aux > "$LOG_DIR/ps_aux_$DATE_TAG.txt"

echo "[*] Collecting listening ports..."
if command -v ss &>/dev/null; then
  ss -tulpn > "$LOG_DIR/ss_tulpn_$DATE_TAG.txt"
elif command -v netstat &>/dev/null; then
  netstat -tulpn > "$LOG_DIR/netstat_tulpn_$DATE_TAG.txt"
fi

echo "[*] Collecting cron jobs..."
crontab -l 2>/dev/null > "$LOG_DIR/crontab_root_$DATE_TAG.txt" || true
for u in $(cut -d: -f1 /etc/passwd); do
  crontab -u "$u" -l 2>/dev/null > "$LOG_DIR/crontab_${u}_$DATE_TAG.txt" || true
done
cp /etc/crontab "$LOG_DIR/etc_crontab_$DATE_TAG"
if [[ -d /etc/cron.d ]]; then
  tar czf "$LOG_DIR/cron.d_$DATE_TAG.tar.gz" -C /etc cron.d
fi
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d "$d" ]]; then
    tar czf "$LOG_DIR/$(basename $d)_$DATE_TAG.tar.gz" -C "$(dirname "$d")" "$(basename "$d")"
  fi
done

echo "[*] Collecting firewall configuration..."
if command -v ufw &>/dev/null; then
  ufw status verbose > "$LOG_DIR/ufw_status_$DATE_TAG.txt" || true
fi
if command -v iptables &>/dev/null; then
  iptables -L -v -n > "$LOG_DIR/iptables_filter_$DATE_TAG.txt" || true
fi
if command -v ip6tables &>/dev/null; then
  ip6tables -L -v -n > "$LOG_DIR/ip6tables_filter_$DATE_TAG.txt" || true
fi

# ---------------------------------
# 2. Safe Sysctl Hardening (Non-breaking)
# ---------------------------------

echo "[*] Applying safe sysctl settings (ASLR, protected links/symlinks, tcp syncookies)..."

SYSCTL_BACKUP="$LOG_DIR/sysctl_before_$DATE_TAG.conf"
sysctl -a > "$SYSCTL_BACKUP" || true

# These are normally defaults on modern distros, but we enforce them safely
cat << 'EOF' > /etc/sysctl.d/99-ccdc-safe.conf
# Safe, non-disruptive hardening:
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
net.ipv4.tcp_syncookies = 1
EOF

sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-ccdc-safe.conf >/dev/null 2>&1 || true

echo "[+] Sysctl settings updated (safe)."

# ---------------------------------
# 3. Firewall Logging (Only If Active)
# ---------------------------------

echo "[*] Configuring firewall logging IF firewall already active..."

if command -v ufw &>/dev/null; then
  UFW_STATUS="$(ufw status 2>/dev/null | head -n1 || true)"
  if echo "$UFW_STATUS" | grep -qi "Status: active"; then
    # Turn on logging without changing rules/policies
    ufw logging medium || true
    echo "[+] UFW logging enabled (medium)."
  else
    echo "[*] UFW not active; not enabling or changing it."
  fi
fi

# iptables logging is heavily environment-specific; we won't add rules here
# to avoid interfering with grading.

# ---------------------------------
# 4. SUID/SGID and World-Writable Checks (No changes)
# ---------------------------------

echo "[*] Enumerating SUID/SGID binaries (no changes made)..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
  > "$LOG_DIR/suid_sgid_$DATE_TAG.txt" || true

echo "[*] Enumerating world-writable directories..."
find / -xdev -type d -perm -0002 2>/dev/null \
  > "$LOG_DIR/world_writable_dirs_$DATE_TAG.txt" || true

echo "[*] Enumerating world-writable files..."
find / -xdev -type f -perm -0002 2>/dev/null \
  > "$LOG_DIR/world_writable_files_$DATE_TAG.txt" || true

# ---------------------------------
# 5. Web Directory and Password String Hunting (No changes)
# ---------------------------------

# Web roots (adjust/add paths as needed for your environment)
WEB_ROOTS=(
  "/var/www"
  "/srv/www"
)

echo "[*] Searching for potential credentials in common web directories..."
for root in "${WEB_ROOTS[@]}"; do
  if [[ -d "$root" ]]; then
    grep -Rin --binary-files=without-match "password" "$root" 2>/dev/null \
      > "$LOG_DIR/web_password_strings_$(basename "$root")_$DATE_TAG.txt" || true
  fi
done

echo "[*] Searching for 'password' strings in /usr/bin (as requested)..."
if [[ -d /usr/bin ]]; then
  # This may be noisy, but it's good for offline review
  for f in /usr/bin/*; do
    if [[ -f "$f" && -x "$f" ]]; then
      strings "$f" 2>/dev/null | grep -i "password" 2>/dev/null && echo "---- $f" 
    fi
  done > "$LOG_DIR/usr_bin_password_strings_$DATE_TAG.txt" 2>/dev/null || true
fi

# ---------------------------------
# 6. Log Snapshots (Auth, Web, etc.) – No changes
# ---------------------------------

echo "[*] Snapshotting key log files (for IR / review)..."

# Authentication / SSH
if [[ -f /var/log/auth.log ]]; then
  tail -n 1000 /var/log/auth.log > "$LOG_DIR/authlog_tail_$DATE_TAG.txt"
fi
if [[ -f /var/log/secure ]]; then
  tail -n 1000 /var/log/secure > "$LOG_DIR/secure_tail_$DATE_TAG.txt"
fi

# Web logs (Apache / Nginx)
if [[ -d /var/log/apache2 ]]; then
  tail -n 1000 /var/log/apache2/access.log 2>/dev/null > "$LOG_DIR/apache2_access_tail_$DATE_TAG.txt" || true
  tail -n 1000 /var/log/apache2/error.log 2>/dev/null > "$LOG_DIR/apache2_error_tail_$DATE_TAG.txt" || true
fi
if [[ -d /var/log/nginx ]]; then
  tail -n 1000 /var/log/nginx/access.log 2>/dev/null > "$LOG_DIR/nginx_access_tail_$DATE_TAG.txt" || true
  tail -n 1000 /var/log/nginx/error.log 2>/dev/null > "$LOG_DIR/nginx_error_tail_$DATE_TAG.txt" || true
fi

echo
echo "[+] SAFE Linux baseline hardening complete."
echo "[+] No services were stopped/disabled, no firewall policies were tightened."
echo "[+] Review files under: $LOG_DIR"
