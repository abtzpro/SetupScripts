@echo off
echo Starting Windows 10 Hardening...

REM --- Ensure Windows Firewall is enabled (CIS 9.1.1) ---
echo Enabling Windows Firewall...
netsh advfirewall set allprofiles state on

REM --- Enable automatic updates (CIS 2.1.1) ---
echo Enabling Automatic Updates...
REG add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f

REM --- Disable SMB1 Protocol (NIST 3.1.7) ---
echo Disabling SMB1 Protocol...
dism /online /norestart /disable-feature /featurename:SMB1Protocol

REM --- Set UAC to Always Notify (CIS 2.3.1.1) ---
echo Setting User Account Control to Always Notify...
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f

REM --- Disable Guest Account (NIST 3.1.6) ---
echo Disabling Guest Account...
net user guest /active:no

REM --- Enable Bitlocker (NIST 3.1.8) ---
echo Enabling Bitlocker...
manage-bde -on C: -RecoveryPassword -RecoveryKey C:\

REM --- Disable Remote Desktop (NIST 2.2.2) ---
echo Disabling Remote Desktop...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f

REM --- Disable Remote Assistance ---
echo Disabling Remote Assistance...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

REM --- Set account lockout policy ---
echo Setting account lockout policy...
net accounts /lockoutduration:30
net accounts /lockoutthreshold:3
net accounts /lockoutwindow:30

REM --- Disable Autorun ---
echo Disabling Autorun...
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

REM --- Enable SmartScreen ---
echo Enabling SmartScreen...
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "RequireAdmin" /f

REM --- Disable PowerShell 2.0 ---
echo Disabling PowerShell 2.0...
dism /online /norestart /disable-feature /featurename:MicrosoftWindowsPowerShellV2Root

REM --- Disable unneeded services ---
echo Disabling unnecessary services...
sc config "Fax" start= disabled
sc config "stisvc" start= disabled
sc config "WMPNetworkSvc" start= disabled
sc config "XblGameSave" start= disabled
sc config "XboxNetApiSvc" start= disabled
sc config "XboxGipSvc" start= disabled
sc config "diagnosticshub.standardcollector.service" start= disabled
sc config "dmwappushsvc" start= disabled

REM --- Set password complexity requirements (CIS 1.1.1) ---
echo Setting password complexity requirements...
secedit /export /cfg c:\secpol.cfg
findstr /V "PasswordComplexity" c:\secpol.cfg > c:\secpolnew.cfg
echo "PasswordComplexity = 1" >> c:\secpolnew.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpolnew.cfg /areas SECURITYPOLICY
del c:\secpol.cfg
del c:\secpolnew.cfg

REM --- Set minimum password length (CIS 1.1.2) ---
echo Setting minimum password length...
secedit /export /cfg c:\secpol.cfg
findstr /V "MinimumPasswordLength" c:\secpol.cfg > c:\secpolnew.cfg
echo "MinimumPasswordLength = 14" >> c:\secpolnew.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpolnew.cfg /areas SECURITYPOLICY
del c:\secpol.cfg
del c:\secpolnew.cfg

REM --- Disable Windows Script Host ---
echo Disabling Windows Script Host...
REG ADD "HKCU\Software\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f

REM --- Disable unnecessary features (Windows Biometric Service, Camera) ---
echo Disabling unnecessary features...
sc config "WbioSrvc" start= disabled
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\camera" /v "Value" /t REG_SZ /d "Deny" /f

REM --- Set up audit policy ---
echo Setting up audit policy...
auditpol /set /category:"Logon/Logoff" /success:enable
auditpol /set /category:"Account Logon" /success:enable

REM --- Regularly update and patch ---
echo Regularly updating and patching...
wuauclt /detectnow /updatenow

echo Windows 10 Hardening Completed!
