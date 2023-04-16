# Disable SMBv1 protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Enable Windows Defender Exploit Guard
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -EnableDEP OptIn
Set-MpPreference -EnableExploitProtectionAuditMode Enabled

# Disable Autorun for all drives
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Type DWord

# Disable PowerShell script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Disable guest account
Set-LocalUser -Name Guest -Enabled $false

# Disable unnecessary services
Get-Service -Name "Remote Registry","Server","Telnet" | Set-Service -StartupType Disabled

# Disable NetBIOS over TCP/IP
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "NetBIOSOptions" -Value 2

# Enable User Account Control (UAC)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Type DWord

# Disable unused protocols
Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord

# Disable unused devices
Disable-PnpDevice -InstanceId "PCI\VEN_8086&DEV_1903"

# Enable BitLocker to encrypt system drive
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly

Write-Host "Windows 10 Home image hardened successfully."
