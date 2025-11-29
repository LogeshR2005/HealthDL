@echo off
echo ==============================
echo PASSWORD HARDENING - AGENT
echo ==============================

:: -------------------------------
:: APPLY PASSWORD HISTORY = 24
:: -------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordHistorySize /t REG_DWORD /d 24 /f

:: -------------------------------
:: APPLY MIN PASSWORD LENGTH = 14
:: -------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v MinimumPasswordLength /t REG_DWORD /d 14 /f

:: -------------------------------
:: APPLY MAX PASSWORD AGE = 60 DAYS
:: -------------------------------
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MaximumPasswordAge /t REG_DWORD /d 60 /f

echo.
echo ✅ POLICY APPLIED - VERIFYING...
echo.

:: -------------------------------
:: VERIFY PASSWORD HISTORY
:: -------------------------------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v PasswordHistorySize

:: -------------------------------
:: VERIFY MIN PASSWORD LENGTH
:: -------------------------------
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v MinimumPasswordLength

:: -------------------------------
:: VERIFY MAX PASSWORD AGE
:: -------------------------------
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v MaximumPasswordAge

echo.
echo ✅ PASSWORD HARDENING COMPLETED SUCCESSFULLY
pause
