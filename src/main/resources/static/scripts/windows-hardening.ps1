<#
WINDOWS ENTERPRISE HARDENING SCRIPT
Author: Security Automation
Run As: Administrator
Rollback Supported
#>

# =========================
# GLOBAL PATHS
# =========================
$Root           = "C:\Hardening"
$Log            = Join-Path $Root "hardening.log"
$SystemBackup   = Join-Path $Root "system_backup.reg"
$PoliciesBackup = Join-Path $Root "policies_backup.reg"

New-Item -ItemType Directory -Path $Root -Force | Out-Null

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
    Write-Host "Run this script as Administrator"
    exit 1
}

Write-Log "HARDENING STARTED"

# =========================
# REGISTRY BACKUP FOR ROLLBACK
# =========================
try {
    reg export "HKLM\SYSTEM" $SystemBackup /y | Out-Null
    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" $PoliciesBackup /y | Out-Null
    Write-Log "Registry backups created for rollback"
} catch {
    Write-Log "Registry backup failed: $_"
}

# =========================
# PASSWORD & LOCKOUT POLICY
# =========================
try {
    net accounts /uniquepw:24        | Out-Null
    net accounts /maxpwage:90        | Out-Null
    net accounts /minpwage:1         | Out-Null
    net accounts /minpwlen:12        | Out-Null
    net accounts /lockoutthreshold:5 | Out-Null
    net accounts /lockoutduration:15 | Out-Null

    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ClearTextPassword   /t REG_DWORD /d 0 /f | Out-Null

    Write-Log "Password and lockout policies applied"
} catch {
    Write-Log "Password/lockout policy section failed: $_"
}

# =========================
# SECURITY OPTIONS
# =========================
try {
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f | Out-Null

    Write-Log "Security options applied"
} catch {
    Write-Log "Security options section failed: $_"
}

# =========================
# INTERACTIVE LOGON
# =========================
$sys = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

try {
    reg add $sys /v DisableCAD           /t REG_DWORD /d 0   /f | Out-Null
    reg add $sys /v DontDisplayLastUserName /t REG_DWORD /d 1   /f | Out-Null
    reg add $sys /v InactivityTimeoutSecs   /t REG_DWORD /d 900 /f | Out-Null
    reg add $sys /v LegalNoticeText      /t REG_SZ    /d "Authorized access only." /f | Out-Null
    reg add $sys /v LegalNoticeCaption   /t REG_SZ    /d "Security Warning"        /f | Out-Null

    Write-Log "Interactive logon policies applied"
} catch {
    Write-Log "Interactive logon section failed: $_"
}

# =========================
# NETWORK SECURITY
# =========================
try {
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f | Out-Null

    $msv = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    reg add $msv /v NtlmMinClientSec /t REG_DWORD /d 537395200 /f | Out-Null
    reg add $msv /v NtlmMinServerSec /t REG_DWORD /d 537395200 /f | Out-Null

    Write-Log "Network security policies applied"
} catch {
    Write-Log "Network security section failed: $_"
}

# =========================
# UAC HARDENING
# =========================
try {
    reg add $sys /v FilterAdministratorToken   /t REG_DWORD /d 1 /f | Out-Null
    reg add $sys /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f | Out-Null
    reg add $sys /v ConsentPromptBehaviorUser  /t REG_DWORD /d 0 /f | Out-Null
    reg add $sys /v EnableInstallerDetection   /t REG_DWORD /d 1 /f | Out-Null
    reg add $sys /v EnableLUA                  /t REG_DWORD /d 1 /f | Out-Null
    reg add $sys /v PromptOnSecureDesktop      /t REG_DWORD /d 1 /f | Out-Null

    Write-Log "UAC hardened"
} catch {
    Write-Log "UAC section failed: $_"
}

# =========================
# FIREWALL
# =========================
try {
    netsh advfirewall set allprofiles state on                                   | Out-Null
    netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound | Out-Null
    netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound | Out-Null

    Write-Log "Firewall hardened"
} catch {
    Write-Log "Firewall section failed: $_"
}

# =========================
# ADVANCED AUDIT POLICIES
# =========================
try {
    auditpol /set /subcategory:"Process Creation"   /success:enable /failure:disable | Out-Null
    auditpol /set /subcategory:"Account Lockout"    /success:disable /failure:enable | Out-Null
    auditpol /set /subcategory:"File Share"         /success:enable /failure:enable  | Out-Null
    auditpol /set /subcategory:"Removable Storage"  /success:enable /failure:enable  | Out-Null
    auditpol /set /subcategory:"System Integrity"   /success:enable /failure:enable  | Out-Null

    Write-Log "Advanced audit policies applied"
} catch {
    Write-Log "Advanced audit section failed (possibly not supported on this edition): $_"
}

# =========================
# AUTOPLAY / AUTORUN
# =========================
try {
    $expl = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    reg add $expl /v NoAutoplayfornonVolume /t REG_DWORD /d 1   /f | Out-Null
    reg add $expl /v NoAutorun             /t REG_DWORD /d 1   /f | Out-Null
    reg add $expl /v NoDriveTypeAutoRun    /t REG_DWORD /d 255 /f | Out-Null

    Write-Log "Autoplay and autorun disabled"
} catch {
    Write-Log "Autoplay section failed: $_"
}

# =========================
# FINAL STATUS
# =========================
Write-Log "HARDENING COMPLETED SUCCESSFULLY"

Write-Host ""
Write-Host "Hardening Applied Successfully"
Write-Host "Log file: $Log"
Write-Host "Rollback backups:"
Write-Host $SystemBackup
Write-Host $PoliciesBackup
Write-Host ""
Write-Host "System restart is recommended"
