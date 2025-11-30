<#
WINDOWS ENTERPRISE HARDENING SCRIPT (CLEAN BASELINE)
Author: Security Automation
Run As: Administrator
#>

# =========================
# GLOBAL PATHS
# =========================
$Root = "C:\Hardening"
$Log  = "$Root\hardening.log"
$Backup = "$Root\registry_backup.reg"

New-Item -ItemType Directory -Path $Root -Force | Out-Null

# =========================
# LOG FUNCTION
# =========================
function Write-Log {
    param([string]$Message)
    "$((Get-Date).ToString("yyyy-MM-dd HH:mm:ss")) $Message" | Out-File -Append $Log
}

# =========================
# ADMIN CHECK
# =========================
$admin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")

if (-not $admin) {
    Write-Host "Run this script as Administrator"
    exit 1
}

Write-Log "Hardening started"

# =========================
# BACKUP REGISTRY (ROLLBACK)
# =========================
reg export HKLM\SYSTEM $Backup /y
Write-Log "Registry backup created"

# =========================
# PASSWORD & LOCKOUT POLICY
# =========================
net accounts /uniquepw:24
net accounts /maxpwage:90
net accounts /minpwage:1
net accounts /minpwlen:12
net accounts /lockoutthreshold:5
net accounts /lockoutduration:15

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordComplexity /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v ClearTextPassword /t REG_DWORD /d 0 /f

Write-Log "Password and lockout policies applied"

# =========================
# SECURITY OPTIONS
# =========================
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

Write-Log "Security options applied"

# =========================
# INTERACTIVE LOGON
# =========================
$sys = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

reg add $sys /v DisableCAD /t REG_DWORD /d 0 /f
reg add $sys /v DontDisplayLastUserName /t REG_DWORD /d 1 /f
reg add $sys /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
reg add $sys /v LegalNoticeText /t REG_SZ /d "Authorized access only." /f
reg add $sys /v LegalNoticeCaption /t REG_SZ /d "Security Warning" /f

Write-Log "Interactive logon policies applied"

# =========================
# NETWORK SECURITY
# =========================
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLMHash /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 1 /f

$msv = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
reg add $msv /v NtlmMinClientSec /t REG_DWORD /d 537395200 /f
reg add $msv /v NtlmMinServerSec /t REG_DWORD /d 537395200 /f

Write-Log "NTLM, LDAP, LM hash policies applied"

# =========================
# UAC HARDENING
# =========================
reg add $sys /v FilterAdministratorToken /t REG_DWORD /d 1 /f
reg add $sys /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add $sys /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f
reg add $sys /v EnableInstallerDetection /t REG_DWORD /d 1 /f
reg add $sys /v EnableLUA /t REG_DWORD /d 1 /f
reg add $sys /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f

Write-Log "UAC hardened"

# =========================
# FIREWALL (PRIVATE + PUBLIC)
# =========================
netsh advfirewall set allprofiles state on
netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound
netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound

Write-Log "Firewall enabled and hardened"

# =========================
# ADVANCED AUDIT POLICIES
# =========================
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
auditpol /set /subcategory:"Account Lockout" /success:disable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

Write-Log "Advanced audit enabled"

# =========================
# AUTOPLAY / AUTORUN
# =========================
$expl = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
reg add $expl /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add $expl /v NoAutorun /t REG_DWORD /d 1 /f
reg add $expl /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

Write-Log "Autoplay disabled"

# =========================
# FINAL MESSAGE
# =========================
Write-Log "Hardening completed successfully"

Write-Host ""
Write-Host "Hardening Applied Successfully"
Write-Host "Log file: $Log"
Write-Host "Rollback file: $Backup"
Write-Host ""
Write-Host "Restart is recommended"
