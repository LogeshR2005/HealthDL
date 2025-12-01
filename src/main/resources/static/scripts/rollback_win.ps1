<#
WINDOWS HARDENING ROLLBACK SCRIPT
Author: Security Automation
Purpose: Restore system to pre-hardening state using registry backups
Run As: Administrator
#>


# =========================
# GLOBAL PATHS
# =========================
$Root           = "C:\Hardening"
$Log            = Join-Path $Root "rollback.log"
$SystemBackup   = Join-Path $Root "system_backup.reg"
$PoliciesBackup = Join-Path $Root "policies_backup.reg"

# =========================
# LOG FUNCTION
# =========================
function Write-Log {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    $line | Out-File -Append -FilePath $Log -Encoding utf8
    Write-Host $line
}

# =========================
# ADMIN CHECK
# =========================
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "Run this rollback script as Administrator"
    exit 1
}

Write-Log "ROLLBACK STARTED"

# =========================
# VALIDATE BACKUPS
# =========================
if (!(Test-Path $SystemBackup)) {
    Write-Log "System registry backup NOT found. Rollback cannot continue."
    exit 1
}

if (!(Test-Path $PoliciesBackup)) {
    Write-Log "Policies registry backup NOT found. Rollback cannot continue."
    exit 1
}

Write-Log "Registry backups located successfully"

# =========================
# RESTORE REGISTRY
# =========================
try {
    reg import $SystemBackup | Out-Null
    Write-Log "SYSTEM registry restored successfully"

    reg import $PoliciesBackup | Out-Null
    Write-Log "POLICIES registry restored successfully"
} catch {
    Write-Log "Registry rollback failed: $_"
    exit 1
}

# =========================
# RE-ENABLE FIREWALL DEFAULT STATE (OPTIONAL SOFT RESET)
# =========================
try {
    netsh advfirewall reset | Out-Null
    Write-Log "Firewall reset to Windows defaults"
} catch {
    Write-Log "Firewall reset failed or skipped"
}

# =========================
# FINAL STATUS
# =========================
Write-Log "ROLLBACK COMPLETED SUCCESSFULLY"

Write-Host ""
Write-Host "System rollback completed successfully."
Write-Host "Rollback log file: $Log"
Write-Host ""
Write-Host "A SYSTEM RESTART IS REQUIRED TO FULLY APPLY ROLLBACK"
