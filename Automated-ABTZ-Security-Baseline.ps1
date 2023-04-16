# Enable script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

# Set execution policy for PowerShell scripts to RemoteSigned

# Disable SMBv1 protocol
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart

# Disable guest account
Set-LocalUser -Name Guest -Enabled $false

# Enable Windows Defender Firewall and set default rules
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Disable unnecessary services
Get-Service -Name "Print Spooler","Remote Registry","Server","Telnet" | Set-Service -StartupType Disabled

# Disable remote assistance
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

# Enable User Account Control (UAC) to highest level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2

# Disable PowerShell script execution
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Restricted"

# Enable BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly

# Set strong password policy
$policy = Get-LocalUser | Where-Object {$_.Enabled -eq "True"}
$policy | Set-LocalUser -PasswordNeverExpires $true
$policy | Set-LocalUser -PasswordNotRequired $false
$policy | Set-LocalUser -UserMayNotChangePassword $true
$policy | Set-LocalUser -PasswordLength 12

# Disable auto-run for external media
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1

# Configure Windows Update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 3
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0

# Disable Windows Remote Management (WinRM)
Disable-PSRemoting -Force

# Disable SMBv2 and SMBv3 compression
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableCompression" -Value 1

# Disable NetBIOS over TCP/IP
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.TcpipNetbiosOptions -ne 2} | ForEach-Object { $_.SetTcpipNetbios(2) }

# Enable Secure Boot
Set-FirmwareType -UEFI
Set-ItemProperty -Path "HKLM:\SYSTEM\Current
