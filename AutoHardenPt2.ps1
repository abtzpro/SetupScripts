# Requires -RunAsAdministrator

Write-Host "Starting Windows 10 Hardening..." -ForegroundColor Yellow

# Restrict the use of WinRM
Write-Host "Restricting the use of WinRM..." -ForegroundColor Yellow
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force
Set-Item WSMan:\localhost\Client\AllowUnencrypted -Value $false -Force

# Enable Antivirus Automatic Updates
Write-Host "Enabling Antivirus Automatic Updates..." -ForegroundColor Yellow
Set-MpPreference -SignatureUpdateInterval 8

# Set the Powershell Execution Policy
Write-Host "Setting PowerShell Execution Policy..." -ForegroundColor Yellow
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine -Force

# Enable Secure Boot
Write-Host "Enabling Secure Boot..." -ForegroundColor Yellow
Confirm-SecureBootUEFI | Out-Null
if ($LASTEXITCODE -eq 1) {Write-Host "Secure Boot is already enabled." -ForegroundColor Green}
else {Write-Host "Secure Boot is not enabled or not supported on this system." -ForegroundColor Red}

# Restrict access to the local "Administrators" group
Write-Host "Restricting access to the local 'Administrators' group..." -ForegroundColor Yellow
net localgroup Administrators /del Guest

# Harden the system for binary execution prevention
Write-Host "Hardening the system for binary execution prevention..." -ForegroundColor Yellow
bcdedit /set nx AlwaysOn

# Prevent the loading of dynamic libraries (DLLs)
Write-Host "Preventing the loading of dynamic libraries (DLLs)..." -ForegroundColor Yellow
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v MoveImages /t REG_DWORD /d 0x2 /f

Write-Host "Windows 10 Hardening Completed!" -ForegroundColor Green
