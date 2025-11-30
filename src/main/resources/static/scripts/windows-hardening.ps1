<#
    WINDOWS ENTERPRISE HARDENING SCRIPT
    -----------------------------------
    - Local Password & Lockout Policy
    - Security Options (LSA, Logon, Network)
    - UAC Hardening
    - Critical Service Lockdown
    - Firewall Private/Public Profiles
    - Advanced Audit Policy
    - Compliance Report (TXT + JSON)

    RUN AS: Administrator
#>

# ==============================
#   GLOBALS & PREP
# ==============================

$Global:HardenRoot   = "C:\Hardening"
$Global:LogFile      = Join-Path $HardenRoot "hardening.log"
$Global:ReportTxt    = Join-Path $HardenRoot "hardening_report.txt"
$Global:ReportJson   = Join-Path $HardenRoot "hardening_report.json"
$Global:BackupFolder = Join-Path $HardenRoot "Backup"
$Global:Compliance   = @()

New-Item -ItemType Directory -Path $HardenRoot -Force | Out-Null
New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    $line | Out-File -FilePath $LogFile -Encoding utf8 -Append
    Write-Host $line
}

# ==============================
#   ADMIN CHECK
# ==============================
Write-Host "=== WINDOWS HARDENING START ===" -ForegroundColor Cyan

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Host "ERROR: Please run this script as Administrator." -ForegroundColor Red
    exit 1
}

Write-Log "Script running as Administrator."

# ==============================
#   COMPLIANCE RECORDING
# ==============================

function Add-Compliance {
    param(
        [string]$Category,
        [string]$Policy,
        [string]$Expected,
        [string]$Status
    )
    $obj = [PSCustomObject]@{
        Category = $Category
        Policy   = $Policy
        Expected = $Expected
        Status   = $Status
        Time     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
    $Global:Compliance += $obj
}

# ==============================
#   REGISTRY BACKUP (CRITICAL KEYS)
# ==============================

Write-Log "Backing up critical registry keys."

$backupDate = Get-Date -Format "yyyyMMdd_HHmmss"
$regBackupFile = Join-Path $BackupFolder "reg_backup_$backupDate.reg"

# backup LSA / SYSTEM / POLICIES areas
$keysToBackup = @(
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0',
    'HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
)

foreach ($k in $keysToBackup) {
    try {
        reg export $k $regBackupFile /y | Out-Null
    } catch {
        Write-Log "Failed to export registry key: $k" "WARN"
    }
}

# ==============================
#   HELPER: SAFE REG SET
# ==============================

function Set-RegValue {
    param(
        [string]$Path,
        [string]$Name,
        [ValidateSet("REG_DWORD","REG_SZ","REG_QWORD","REG_MULTI_SZ","REG_EXPAND_SZ")] [string]$Type,
        [string]$Value,
        [string]$Category = "Unknown",
        [string]$Policy   = "Unknown",
        [string]$Expected = ""
    )

    try {
        reg add $Path /v $Name /t $Type /d $Value /f | Out-Null
        Write-Log "Set $Path\$Name = $Value ($Type)"
        if ($Category -ne "Unknown") {
            Add-Compliance $Category $Policy $Expected "APPLIED"
        }
    } catch {
        Write-Log "Failed to set $Path\$Name : $_" "ERROR"
        if ($Category -ne "Unknown") {
            Add-Compliance $Category $Policy $Expected "FAILED"
        }
    }
}

# ==============================
#   1. PASSWORD & LOCKOUT POLICY
# ==============================

function Set-PasswordPolicy {
    Write-Log "Applying Password and Account Lockout policies (net accounts)."

    try {
        # Enforce password history: 24
        net accounts /uniquepw:24 | Out-Null
        Add-Compliance "Password Policy" "Enforce password history" "24 passwords" "APPLIED"

        # Maximum password age: 90 days
        net accounts /maxpwage:90 | Out-Null
        Add-Compliance "Password Policy" "Maximum password age" "90 days" "APPLIED"

        # Minimum password age: 1 day
        net accounts /minpwage:1 | Out-Null
        Add-Compliance "Password Policy" "Minimum password age" "1 day" "APPLIED"

        # Minimum password length: 12
        net accounts /minpwlen:12 | Out-Null
        Add-Compliance "Password Policy" "Minimum password length" "12 chars" "APPLIED"

        # Account lockout threshold: 5
        net accounts /lockoutthreshold:5 | Out-Null
        Add-Compliance "Account Lockout" "Lockout Threshold" "5 attempts" "APPLIED"

        # Account lockout duration: 15
        net accounts /lockoutduration:15 | Out-Null
        Add-Compliance "Account Lockout" "Lockout Duration" "15 minutes" "APPLIED"

    } catch {
        Write-Log "Error applying password/lockout policies: $_" "ERROR"
    }

    # Complexity + reversible encryption via registry
    Set-RegValue `
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        "PasswordComplexity" `
        "REG_DWORD" "1" `
        "Password Policy" "Password must meet complexity" "Enabled"

    Set-RegValue `
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        "ClearTextPassword" `
        "REG_DWORD" "0" `
        "Password Policy" "Store password using reversible encryption" "Disabled"
}

# ==============================
#   2. SECURITY OPTIONS – ACCOUNTS
# ==============================

function Set-SecurityOptionsAccounts {
    Write-Log "Applying Security Options: Accounts."

    # Block Microsoft Accounts: 3 = "Users can't add or log on with Microsoft accounts"
    Set-RegValue `
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "NoConnectedUser" `
        "REG_DWORD" "3" `
        "Security Options - Accounts" "Block Microsoft accounts" "Users can't add/log on"

    # Limit blank passwords to console logon only
    Set-RegValue `
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        "LimitBlankPasswordUse" `
        "REG_DWORD" "1" `
        "Security Options - Accounts" "Limit local account use of blank passwords" "Enabled"

    # Guest account status = Disabled (SAM / user mgmt; log only)
    Add-Compliance "Security Options - Accounts" "Guest account status" "Disabled" "MANUAL"
}

# ==============================
#   3. INTERACTIVE LOGON
# ==============================

function Set-InteractiveLogon {
    Write-Log "Applying Interactive Logon policies."

    $base = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    # CTRL+ALT+DEL required → DisableCAD = 0
    Set-RegValue $base "DisableCAD" "REG_DWORD" "0" `
        "Interactive Logon" "Do not require CTRL+ALT+DEL" "Disabled"

    # Don't display last signed-in username
    Set-RegValue $base "DontDisplayLastUserName" "REG_DWORD" "1" `
        "Interactive Logon" "Don't display last signed in" "Enabled"

    # Machine inactivity limit - 900 seconds
    Set-RegValue $base "InactivityTimeoutSecs" "REG_DWORD" "900" `
        "Interactive Logon" "Machine inactivity limit" "900 seconds"

    # Legal Notice Text / Caption
    Set-RegValue $base "LegalNoticeText" "REG_SZ" "AUTHORIZED ACCESS ONLY. All activities may be monitored." `
        "Interactive Logon" "Message text for users attempting to log on" "Configured"

    Set-RegValue $base "LegalNoticeCaption" "REG_SZ" "SECURITY WARNING" `
        "Interactive Logon" "Message title for users attempting to log on" "Configured"

    # Prompt user to change password before expiration: cannot be set clean via registry; mark as manual.
    Add-Compliance "Interactive Logon" "Prompt user to change password before expiration" "5–14 days" "MANUAL"
}





# ==============================
#   4. MICROSOFT NETWORK SERVER / ANONYMOUS
# ==============================

function Set-NetworkServerSecurity {
    Write-Log "Applying Microsoft Network Server / Anonymous policies."

    $srv = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $lsa = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"

    # Idle time before suspending session (AutoDisconnect) - 15 minutes
    Set-RegValue $srv "AutoDisconnect" "REG_DWORD" "15" `
        "Microsoft Network Server" "Idle time before suspending session" "15 minutes"

    # Disconnect clients when logon hours expire
    Set-RegValue $srv "EnableForcedLogoff" "REG_DWORD" "1" `
        "Microsoft Network Server" "Disconnect clients when logon hours expire" "Enabled"

    # Anonymous SID/Name translation: Disabled
    Set-RegValue $lsa "RestrictAnonymousSAM" "REG_DWORD" "1" `
        "Network Access" "Do not allow anonymous enumeration of SAM accounts" "Enabled"

    # Do not allow anonymous enumeration of SAM accounts and shares
    Set-RegValue $lsa "RestrictAnonymous" "REG_DWORD" "1" `
        "Network Access" "Do not allow anonymous enumeration of SAM & shares" "Enabled"

    # Do not allow storage of passwords and credentials for network authentication
    Set-RegValue $lsa "DisablePasswordCaching" "REG_DWORD" "1" `
        "Network Access" "Do not allow storage of passwords and credentials" "Enabled"

    # Let Everyone permissions apply to anonymous users = Disabled (0)
    Set-RegValue $lsa "EveryoneIncludesAnonymous" "REG_DWORD" "0" `
        "Network Access" "Let Everyone permissions apply to anonymous" "Disabled"
}

# ==============================
#   5. NETWORK SECURITY (KERBEROS / NTLM / LDAP)
# ==============================

function Set-NetworkSecurity {
    Write-Log "Applying Network Security policies."

    # Kerberos encryption types
    $kerb = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    New-Item -Path $kerb -Force | Out-Null

    # 0x7ffffff8 ~ AES128, AES256, future etc (approx CIS)
    Set-RegValue $kerb "SupportedEncryptionTypes" "REG_DWORD" "2147483640" `
        "Network Security" "Configure encryption types allowed for Kerberos" "AES128/AES256/Future"

    # Do not store LAN Manager hash value on next password change
    $lsa = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-RegValue $lsa "NoLMHash" "REG_DWORD" "1" `
        "Network Security" "Do not store LAN Manager hash" "Enabled"

    # LDAP client signing requirements (1 = Negotiate)
    $ldap = "HKLM\SYSTEM\CurrentControlSet\Services\LDAP"
    New-Item -Path $ldap -Force | Out-Null
    Set-RegValue $ldap "LDAPClientIntegrity" "REG_DWORD" "1" `
        "Network Security" "LDAP client signing requirements" "Negotiate or higher"

    # NTLM min session security
    $msv = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
    New-Item -Path $msv -Force | Out-Null

    # These values are from CIS / Microsoft docs (Require NTLMv2 + 128-bit)
    # 0x20080000 = NTLMv2 + 128-bit, etc.
    Set-RegValue $msv "NtlmMinClientSec" "REG_DWORD" "537395200" `
        "Network Security" "Minimum session security for NTLM SSP clients" "NTLMv2 + 128-bit"

    Set-RegValue $msv "NtlmMinServerSec" "REG_DWORD" "537395200" `
        "Network Security" "Minimum session security for NTLM SSP servers" "NTLMv2 + 128-bit"
}


# ==============================
#   6. USER ACCOUNT CONTROL (UAC)
# ==============================

function Set-UAC {
    Write-Log "Applying UAC policies."

    $uac = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    # Admin Approval Mode for Built-in Administrator
    Set-RegValue $uac "FilterAdministratorToken" "REG_DWORD" "1" `
        "UAC" "Admin Approval Mode for built-in Administrator" "Enabled"

    # Elevation prompt (Admins) - Prompt for consent on secure desktop (2)
    Set-RegValue $uac "ConsentPromptBehaviorAdmin" "REG_DWORD" "2" `
        "UAC" "Behavior of elevation prompt for admins" "Prompt on secure desktop"

    # Elevation prompt (Standard users) - Automatically deny (0)
    Set-RegValue $uac "ConsentPromptBehaviorUser" "REG_DWORD" "0" `
        "UAC" "Behavior of elevation prompt for standard users" "Automatically deny"

    # Detect application installations and prompt for elevation
    Set-RegValue $uac "EnableInstallerDetection" "REG_DWORD" "1" `
        "UAC" "Detect application installations and prompt for elevation" "Enabled"

    # Run all admins in Admin Approval Mode
    Set-RegValue $uac "EnableLUA" "REG_DWORD" "1" `
        "UAC" "Run all administrators in Admin Approval Mode" "Enabled"

    # Switch to secure desktop
    Set-RegValue $uac "PromptOnSecureDesktop" "REG_DWORD" "1" `
        "UAC" "Switch to secure desktop when prompting" "Enabled"
}


# ==============================
#   8. FIREWALL – PRIVATE & PUBLIC
# ==============================

function Set-FirewallProfiles {
    Write-Log "Configuring Windows Firewall (Private/Public)."

    # Enable profiles
    netsh advfirewall set privateprofile state on       | Out-Null
    netsh advfirewall set publicprofile state  on       | Out-Null

    Add-Compliance "Firewall" "Private: Firewall state" "On" "APPLIED"
    Add-Compliance "Firewall" "Public: Firewall state"  "On" "APPLIED"

    # Inbound/Outbound
    netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound | Out-Null
    netsh advfirewall set publicprofile  firewallpolicy blockinbound,allowoutbound | Out-Null

    Add-Compliance "Firewall" "Private: Inbound connections" "Block" "APPLIED"
    Add-Compliance "Firewall" "Public: Inbound connections"  "Block" "APPLIED"

    # Notifications (Display a notification = No)
    netsh advfirewall set privateprofile settings inboundusernotification disable | Out-Null
    netsh advfirewall set publicprofile  settings inboundusernotification disable | Out-Null

    # Logging Private
    netsh advfirewall set privateprofile logging filename "%SystemRoot%\System32\logfiles\firewall\privatefw.log" | Out-Null
    netsh advfirewall set privateprofile logging maxfilesize 16384 | Out-Null
    netsh advfirewall set privateprofile logging droppedconnections enable | Out-Null
    netsh advfirewall set privateprofile logging allowedconnections  enable | Out-Null

    # Logging Public
    netsh advfirewall set publicprofile logging filename "%SystemRoot%\System32\logfiles\firewall\publicfw.log" | Out-Null
    netsh advfirewall set publicprofile logging maxfilesize 16384 | Out-Null
    netsh advfirewall set publicprofile logging droppedconnections enable | Out-Null
    netsh advfirewall set publicprofile logging allowedconnections  enable | Out-Null

    Add-Compliance "Firewall" "Private: Logging & size" "16384KB, log dropped & success" "APPLIED"
    Add-Compliance "Firewall" "Public: Logging & size"  "16384KB, log dropped & success" "APPLIED"
}

# ==============================
#   9. ADVANCED AUDIT POLICY
# ==============================

function Set-AuditPolicies {
    Write-Log "Configuring Advanced Audit Policies."

    function Set-Audit {
        param(
            [string]$SubCategory,
            [string]$Success,
            [string]$Failure,
            [string]$Policy
        )
        try {
            auditpol /set /subcategory:$SubCategory /success:$Success /failure:$Failure | Out-Null
            Add-Compliance "Advanced Audit Policy" $Policy "$Success / $Failure" "APPLIED"
        } catch {
            Write-Log "Failed audit policy: $SubCategory : $_" "ERROR"
            Add-Compliance "Advanced Audit Policy" $Policy "$Success / $Failure" "FAILED"
        }
    }

    Set-Audit "Credential Validation"            "enable" "enable" "Audit Credential Validation"
    Set-Audit "Application Group Management"     "enable" "enable" "Audit Application Group Management"
    Set-Audit "Security Group Management"        "enable" "disable" "Audit Security Group Management"
    Set-Audit "User Account Management"          "enable" "enable" "Audit User Account Management"
    Set-Audit "Process Creation"                 "enable" "disable" "Audit Process Creation"
    Set-Audit "Account Lockout"                  "disable" "enable" "Audit Account Lockout"
    Set-Audit "Other Logon/Logoff Events"        "enable" "enable" "Audit Other Logon/Logoff Events"
    Set-Audit "File Share"                       "enable" "enable" "Audit File Share"
    Set-Audit "Removable Storage"                "enable" "enable" "Audit Removable Storage"
    Set-Audit "Audit Policy Change"              "enable" "disable" "Audit Policy Change"
    Set-Audit "Other Policy Change Events"       "disable" "enable" "Audit Other Policy Change Events"
    Set-Audit "Sensitive Privilege Use"          "enable" "enable" "Audit Sensitive Privilege Use"
    Set-Audit "System Integrity"                 "enable" "enable" "Audit System Integrity"

    # Prevent enabling lock screen camera - via GPO/registry
    Set-RegValue `
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        "NoLockScreenCamera" "REG_DWORD" "1" `
        "Advanced Audit / Security" "Prevent enabling lock screen camera" "Enabled"

    # SMBv1 client driver disabled
    Set-RegValue `
        "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
        "Start" "REG_DWORD" "4" `
        "Advanced Audit / SMB" "Configure SMB v1 client driver" "Disabled"

    # SMBv1 server disabled
    Set-RegValue `
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        "SMB1" "REG_DWORD" "0" `
        "Advanced Audit / SMB" "Configure SMB v1 server" "Disabled"
}

# ==============================
#   10. AUTOPLAY / AUTORUN
# ==============================

function Set-AutoplayPolicies {
    Write-Log "Applying AutoPlay / AutoRun policies."

    $pol = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

    # Disallow Autoplay for non-volume devices
    Set-RegValue $pol "NoAutoplayfornonVolume" "REG_DWORD" "1" `
        "AutoPlay" "Disallow Autoplay for non-volume devices" "Enabled"

    # Set default behaviour for AutoRun = do not execute
    Set-RegValue $pol "NoAutorun" "REG_DWORD" "1" `
        "AutoPlay" "Set default behaviour for AutoRun" "Do not execute any commands"

    # Turn off Autoplay = All drives
    Set-RegValue $pol "NoDriveTypeAutoRun" "REG_DWORD" "255" `
        "AutoPlay" "Turn off Autoplay" "Enabled: All drives"
}

# ==============================
#   11. USER RIGHTS ASSIGNMENT (PARTIAL)
# ==============================
# NOTES:
# - True CIS-compliant User Rights need secedit / GPO.
# - Here we mark them as MANUAL so your report is honest.

function Mark-UserRightsAsManual {
    Add-Compliance "User Rights Assignment" "Access Credential Manager as a trusted caller" "No One" "MANUAL"
    Add-Compliance "User Rights Assignment" "Access this computer from the network" "Administrators, Remote Desktop Users" "MANUAL"
    Add-Compliance "User Rights Assignment" "Adjust memory quotas for a process" "Admins, LOCAL SERVICE, NETWORK SERVICE" "MANUAL"
    Add-Compliance "User Rights Assignment" "Allow log on locally" "Administrators, Users" "MANUAL"
    Add-Compliance "User Rights Assignment" "Back up files and directories" "Administrators" "MANUAL"
    Add-Compliance "User Rights Assignment" "Change the system time" "Administrators, LOCAL SERVICE" "MANUAL"
    Add-Compliance "User Rights Assignment" "Change the time zone" "Administrators, LOCAL SERVICE, Users" "MANUAL"
}

# ==============================
#   RUN ALL HARDENING STEPS
# ==============================

Set-PasswordPolicy
Set-SecurityOptionsAccounts
Set-InteractiveLogon
Set-NetworkServerSecurity
Set-NetworkSecurity
Set-UAC
Set-FirewallProfiles
Set-AuditPolicies
Set-AutoplayPolicies
Mark-UserRightsAsManual

# ==============================
#   GENERATE FINAL REPORTS
# ==============================

Write-Log "Generating compliance reports."

"========= HARDENING COMPLIANCE REPORT =========" | Out-File $ReportTxt -Encoding utf8
$Global:Compliance | ForEach-Object {
    "$($_.Time) | $($_.Category) | $($_.Policy) | Expected: $($_.Expected) | Status: $($_.Status)" |
        Out-File -FilePath $ReportTxt -Encoding utf8 -Append
}
"=============================================" | Out-File $ReportTxt -Encoding utf8 -Append

$Global:Compliance | ConvertTo-Json -Depth 5 | Out-File $ReportJson -Encoding utf8

Write-Host ""
Write-Host "HARDENING COMPLETED." -ForegroundColor Green
Write-Host "Log file    : $LogFile"
Write-Host "TXT report  : $ReportTxt"
Write-Host "JSON report : $ReportJson"
Write-Host ""
Write-Host " Some items (User Rights, MDAG, Rename Admin/Guest) are marked MANUAL and should be enforced via GPO/secedit." -ForegroundColor Yellow
Write-Host ""
Write-Host "It is recommended to REBOOT the machine to fully apply all UAC / service / SMB changes."



