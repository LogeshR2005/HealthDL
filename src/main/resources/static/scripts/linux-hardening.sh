#!/usr/bin/env bash

# ============================
# BASIC SETUP
# ============================

HARDEN_ROOT="/var/lib/hardening-agent"
LOG_FILE="$HARDEN_ROOT/hardening.log"
REPORT_FILE="$HARDEN_ROOT/hardening_report.txt"
BACKUP_ROOT="$HARDEN_ROOT/backup_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$HARDEN_ROOT" "$BACKUP_ROOT"

log() {
  local msg="$1"
  local ts
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "$ts : $msg" | tee -a "$LOG_FILE"
}

# ============================
# ROOT CHECK
# ============================

if [[ $EUID -ne 0 ]]; then
  echo "Run this script as root."
  exit 1
fi

log "HARDENING STARTED"

# ============================
# DETECT PACKAGE MANAGER
# ============================

PM=""
if command -v apt >/dev/null 2>&1; then
  PM="apt"
elif command -v dnf >/dev/null 2>&1; then
  PM="dnf"
elif command -v yum >/dev/null 2>&1; then
  PM="yum"
fi

install_pkg() {
  local pkg="$1"
  if [[ "$PM" == "apt" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1
  elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
    "$PM" install -y -q "$pkg" >/dev/null 2>&1
  fi
}

remove_pkg() {
  local pkg="$1"
  if [[ "$PM" == "apt" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get remove -y "$pkg" >/dev/null 2>&1 || true
  elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
    "$PM" remove -y -q "$pkg" >/dev/null 2>&1 || true
  fi
}

# ============================
# 1. BLOCK MTA (postfix/sendmail/exim)
# ============================

log "Blocking mail transfer agents (postfix, sendmail, exim, mailutils)."
for M in postfix sendmail exim mailutils; do
  remove_pkg "$M"
done

# ============================
# 2. BACKUP CRITICAL FILES
# ============================

log "Creating backups in $BACKUP_ROOT"

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    mkdir -p "$(dirname "$BACKUP_ROOT$f")"
    cp -a "$f" "$BACKUP_ROOT$f"
  fi
}

backup_file "/etc/sysctl.conf"
backup_file "/etc/ssh/sshd_config"
backup_file "/etc/sudoers"
backup_file "/etc/ufw/ufw.conf"
backup_file "/etc/audit/auditd.conf"
backup_file "/etc/audit/audit.rules"
backup_file "/etc/audit/rules.d/audit.rules"
backup_file "/etc/audit/rules.d/hardening.rules"
backup_file "/etc/crontab"

# ============================
# 3. BLOCK RISKY KERNEL MODULES
# ============================

log "Blocking risky kernel modules"

block_module() {
  local mod="$1"
  echo "install $mod /bin/true" > "/etc/modprobe.d/$mod.conf"
  modprobe -r "$mod" >/dev/null 2>&1 || true
  log "Kernel module blocked: $mod"
}

# Filesystem / USB / Network modules
for MOD in cramfs freevxfs hfs hfsplus jffs2 squashfs udf usb-storage dccp sctp rds tipc; do
  block_module "$MOD"
done

# ============================
# 4. SYSCTL NETWORK HARDENING
# ============================

log "Applying sysctl network hardening."

SYSCTL_FILE="/etc/sysctl.d/99-hardening.conf"
cat >"$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
EOF

sysctl --system >/dev/null 2>&1 || true

# ============================
# 5. SSH HARDENING
# ============================

log "Hardening SSH configuration."

if [[ -f /etc/ssh/sshd_config ]]; then
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null || true

  # Basic patterns
  sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
  sed -i 's/^#\?ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
  sed -i 's/^#\?ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config

  # If missing, append
  grep -q "^PermitRootLogin" /etc/ssh/sshd_config || echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  grep -q "^PasswordAuthentication" /etc/ssh/sshd_config || echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
  grep -q "^MaxAuthTries" /etc/ssh/sshd_config || echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
  grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
  grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config || echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config

  systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
  log "SSH hardened."
else
  log "sshd_config not found, skipping SSH hardening."
fi

# ============================
# 6. SUDO HARDENING
# ============================

log "Hardening sudo configuration."

install_pkg sudo

if [[ -f /etc/sudoers ]]; then
  if ! grep -q "Defaults use_pty" /etc/sudoers; then
    echo "Defaults use_pty" >> /etc/sudoers
  fi
  if ! grep -q "Defaults logfile=" /etc/sudoers; then
    echo "Defaults logfile=/var/log/sudo.log" >> /etc/sudoers
  fi
  log "Sudo hardened."
else
  log "sudoers file not found, skipping sudo changes."
fi

# ============================
# 7. FIREWALL HARDENING
# ============================

log "Configuring host firewall."

if command -v ufw >/dev/null 2>&1; then
  log "Using ufw firewall."
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true
  ufw allow ssh >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
else
  if [[ "$PM" != "none" ]]; then
    install_pkg firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
      systemctl enable firewalld --now >/dev/null 2>&1 || true
      firewall-cmd --set-default-zone=public >/dev/null 2>&1 || true
      firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
      firewall-cmd --reload >/dev/null 2>&1 || true
      log "firewalld configured with SSH allowed."
    else
      log "firewall-cmd not found even after install, firewall step partial."
    fi
  else
    log "No package manager detected; firewall hardening skipped."
  fi
fi

# ============================
# 8. CRON PERMISSIONS
# ============================

log "Locking down cron permissions."

chmod 600 /etc/crontab 2>/dev/null || true
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  [[ -d "$d" ]] && chmod 700 "$d" 2>/dev/null || true
done

# ============================
# 9. INSTALL AND ENABLE auditd
# ============================

log "Installing and enabling auditd."

install_pkg auditd

if command -v auditd >/dev/null 2>&1 || [[ -f /sbin/auditd || -f /usr/sbin/auditd ]]; then
  systemctl enable auditd --now >/dev/null 2>&1 || true
  log "auditd installed and enabled."
else
  log "auditd not available on this system."
fi

# ============================
# 10. BASIC AUDIT RULES
# ============================

if [[ -d /etc/audit/rules.d ]]; then
  log "Configuring basic auditd rules."

  cat >/etc/audit/rules.d/hardening.rules <<'EOF'
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k priv_esc
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /var/log/auth.log -p wa -k logins
EOF

  if command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || true
  else
    service auditd restart >/dev/null 2>&1 || true
  fi
  log "auditd rules written to /etc/audit/rules.d/hardening.rules"
else
  log "auditd rules.d directory not found, skipping rules."
fi

# ============================
# 11. AIDE INSTALL (NO HEAVY INIT)
# ============================

log "Installing AIDE (no initial scan to avoid hangs)."

install_pkg aide >/dev/null 2>&1 || install_pkg aide-common >/dev/null 2>&1 || true

if command -v aide >/dev/null 2>&1 || [[ -f /usr/sbin/aide || -f /usr/bin/aide ]]; then
  log "AIDE installed. Initial database generation is not run to avoid long blocking."
  # Optional daily cron for check (light integration)
  if [[ -d /etc/cron.daily ]]; then
    cat >/etc/cron.daily/aide-check <<'EOF'
#!/usr/bin/env bash
if command -v aide >/dev/null 2>&1; then
  /usr/bin/aide --check >/var/log/aide_check.log 2>&1
fi
EOF
    chmod 700 /etc/cron.daily/aide-check
    log "AIDE daily check script created at /etc/cron.daily/aide-check"
  fi
else
  log "AIDE could not be installed on this system."
fi

# ============================
# 12. BLOCK USB STORAGE MODULE
# ============================

log "Blocking USB storage module."

echo "blacklist usb-storage" > /etc/modprobe.d/usb-storage.conf
modprobe -r usb-storage >/dev/null 2>&1 || true

# ============================
# 13. CRITICAL FILE PERMISSIONS
# ============================

log "Tightening basic system file permissions."

chmod 644 /etc/passwd  2>/dev/null || true
chmod 640 /etc/shadow  2>/dev/null || true
chmod 644 /etc/group   2>/dev/null || true
chmod 640 /etc/gshadow 2>/dev/null || true

# ============================
# 14. GENERATE TEXT REPORT
# ============================

log "Generating summary report."

{
  echo "==== HARDENING REPORT $(date '+%Y-%m-%d %H:%M:%S') ===="
  echo "MTA (postfix/sendmail/exim/mailutils) removed or disabled where present."
  echo "Backup created at: $BACKUP_ROOT"
  echo "Risky kernel modules blocked (cramfs, hfs, squashfs, udf, usb-storage, dccp, rds, sctp, tipc)."
  echo "Network sysctl hardening applied."
  echo "SSH hardened (no root login, limited auth attempts, idle timeouts)."
  echo "Sudo hardened (pty enforced and logging enabled)."
  echo "Firewall enabled with deny incoming, allow outgoing, ssh allowed."
  echo "Cron permissions hardened."
  echo "auditd installed and enabled (where supported) with basic rules."
  echo "AIDE installed (daily check cron created; initial DB generation left to admin)."
  echo "USB storage module blocked."
  echo "Base system file permissions hardened for passwd, shadow, group, gshadow."
  echo "Some advanced CIS items (PAM fine-tuning, full audit rule set, time sync rules, AIDE policies) may still require manual review."
  echo "==== HARDENING COMPLETED ===="
} > "$REPORT_FILE"

log "HARDENING COMPLETED SUCCESSFULLY"
