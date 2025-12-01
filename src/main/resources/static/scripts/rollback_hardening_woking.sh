#!/usr/bin/env bash

ROLLBACK_ROOT="/var/lib/hardening-agent"
LATEST_BACKUP=$(ls -dt $ROLLBACK_ROOT/backup_* 2>/dev/null | head -1)
LOGFILE="$ROLLBACK_ROOT/rollback.log"

echo "$(date '+%Y-%m-%d %H:%M:%S') : ROLLBACK STARTED" | tee -a "$LOGFILE"

if [ -z "$LATEST_BACKUP" ]; then
  echo "NO BACKUP FOUND. ROLLBACK ABORTED." | tee -a "$LOGFILE"
  exit 1
fi

echo "Using backup: $LATEST_BACKUP" | tee -a "$LOGFILE"

# ============================
# RESTORE CONFIG FILES
# ============================

restore_file() {
  SRC="$LATEST_BACKUP/$1"
  DST="/$1"
  if [ -f "$SRC" ]; then
    cp "$SRC" "$DST"
    echo "Restored $DST" | tee -a "$LOGFILE"
  fi
}

restore_file etc/ssh/sshd_config
restore_file etc/sudoers
restore_file etc/sysctl.conf
restore_file etc/ufw/user.rules
restore_file etc/crontab

# ============================
# SYSCTL RESET
# ============================
sysctl --system | tee -a "$LOGFILE"

# ============================
# FIREWALL RESET
# ============================
if command -v ufw >/dev/null; then
  ufw --force reset
  systemctl restart ufw
  echo "UFW RESET" | tee -a "$LOGFILE"
fi

# ============================
# RESTORE AUDITD
# ============================
if systemctl list-unit-files | grep auditd >/dev/null; then
  systemctl restart auditd
  echo "auditd restarted" | tee -a "$LOGFILE"
fi

# ============================
# REMOVE AIDE
# ============================
if command -v apt >/dev/null; then apt remove -y aide
elif command -v yum >/dev/null; then yum remove -y aide
elif command -v dnf >/dev/null; then dnf remove -y aide
fi

rm -rf /var/lib/aide
rm -f /etc/cron.daily/aide-check
echo "AIDE removed" | tee -a "$LOGFILE"

# ============================
# UNBLOCK USB & KERNEL MODULES
# ============================
rm -f /etc/modprobe.d/usb-storage.conf
rm -f /etc/modprobe.d/*.conf

for MOD in cramfs freevxfs hfs hfsplus jffs2 squashfs udf usb-storage dccp sctp rds tipc; do
  modprobe "$MOD" 2>/dev/null
done

echo "Kernel modules unblocked" | tee -a "$LOGFILE"

# ============================
# FILE PERMISSION ROLLBACK
# ============================
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow

echo "File permissions restored" | tee -a "$LOGFILE"

# ============================
# SERVICES RELOAD
# ============================
systemctl daemon-reload
systemctl restart ssh sshd 2>/dev/null
systemctl restart cron crond 2>/dev/null

# ============================
# FINAL MESSAGE
# ============================
echo "$(date '+%Y-%m-%d %H:%M:%S') : ROLLBACK COMPLETED SUCCESSFULLY" | tee -a "$LOGFILE"

echo ""
echo "ROLLBACK DONE"
echo "Log File: $LOGFILE"
echo ""