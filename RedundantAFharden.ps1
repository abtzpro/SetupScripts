# Disable unused services
Get-Service -Name 'wsearch', 'MapsBroker', 'RetailDemo', 'shpamsvc' | Set-Service -StartupType Disabled

# Disable unused features
Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellISE', 'Printing-XPSServices-Features', 'Printing-InternetPrinting-Client', 'Printing-InternetPrinting-Server', 'Printing-Foundation-Features', 'SMB1Protocol', 'TelnetClient', 'TelnetServer', 'TFTP' -NoRestart

# Disable NTLMv1 authentication
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LMCompatibilityLevel' -Value 4

# Disable LM and NTLMv1 protocols for SMB
Set-SmbServerConfiguration -EnableSMB1Protocol $false
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'restrictnullsessaccess' -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'NullSessionShares' -Value ''

# Disable Guest account
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Value 1
New-LocalUser -Name 'Guest' -Description 'Built-in account for guest access to the computer/domain' -NoPassword | Out-Null
Disable-LocalUser -Name 'Guest'

# Configure User Account Control (UAC) settings
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Value 1

# Disable autorun for all devices
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1

# Disable the creation of LNK files on removable drives
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'DisableNTFSLastAccessUpdate' -Value 1

# Configure Internet Explorer security settings
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name '270C' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name '1406' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name '1407' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name '1408' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' -Name '2500' -Value 3

# Disable PowerShell remoting
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnablePSRemoting' -Value 0

# Disable unencrypted traffic over SMB
Set-SmbServerConfiguration -EncryptData $true

# Disable WinRM service
Stop-Service -Name WinRM
Set-Service -Name WinRM -StartupType Disabled

# Disable unencrypted traffic over RDP
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer' -Value 2

# Disable NetBIOS over TCP/IP
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*' -Name 'NetbiosOptions' -Value 2

# Disable LLMNR and NBT-NS
Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID ms_llmnr
Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID ms_nbt

# Disable the WebClient service
Stop-Service -Name WebClient
Set-Service -Name WebClient -StartupType Disabled

# Disable the WebClient service for non-Windows programs
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WebClient\Parameters' -Name 'BasicAuthLevel' -Value 2

# Enable secure LDAP (LDAPS)
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPServerIntegrity' -Value 2

# Enable automatic updates and schedule daily scans
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Value 4
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'ScheduledInstallDay' -Value 0
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'ScheduledInstallTime' -Value 3
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan' -Name 'ScheduleDay' -Value 7
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Scan' -Name 'ScheduleTime' -Value 3

# Restrict access to the PowerShell script execution policy
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -Value 'RemoteSigned'

# Disable the Windows Remote Management (WinRM) client
Disable-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -NoRestart

# Disable the SMBv1 protocol
Disable-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -NoRestart

# Disable unnecessary services
Get-Service | Where-Object {$_.Name -in ('Telnet', 'FTP', 'TFTP', 'WebClient')} | Set-Service -StartupType Disabled

# Enable User Account Control (UAC) and set it to the highest level
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1

# Disable autorun for removable devices
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoAutorun' -Value 1

# Restrict PowerShell script execution to signed scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Disable the guest account and rename the administrator account
Disable-LocalUser -Name Guest
Rename-LocalUser -Name Administrator -NewName HardenedAdmin

# Set up auditing for security events
wevtutil sl Security /ca:O:S-1-5-32-544
wevtutil sl Security /ca:O:S-1-5-32-544 /e:System

# Disable SMBv2 and SMBv3 compression to prevent the SMBleed vulnerability
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'DisableCompression' -Value 1

# Disable the NetBIOS protocol
Disable-NetAdapterBinding -Name 'Ethernet' -ComponentID ms_netbios
Disable-NetAdapterBinding -Name 'Wi-FI'
-ComponentID ms_netbios

# Disable IPv6 if it is not required
Set-NetIPv6Protocol -State Disabled

# Enable Windows Event Forwarding (WEF) to centralize security event logs
wevtutil im C:\Windows\security\Audit\WEC\Microsoft-Windows-EventCollector%4Operational.evtx

# Restrict access to PowerShell by removing the PowerShell ISE and the PowerShell Web Access roles
Remove-WindowsFeature PowerShell-ISE, PowerShellWebAccess

# Enable controlled folder access in Windows Defender to protect against ransomware
Set-MpPreference -EnableControlledFolderAccess Enabled

# Disable SMBv1 and RDP services
Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1

# Set strong passwords and enforce password complexity policies
Set-LocalUser -Name <UserName> -Password (ConvertTo-SecureString -AsPlainText '<NewPassword>' -Force)
Set-LocalGroupPolicy -Group 'Administrators' -PasswordComplexity 1

# Enable Windows Defender and configure it to scan all files and attachments
Set-MpPreference -ScanArchiveFiles 1
Set-MpPreference -DisablePrivacyMode 0

# Disable macros in Microsoft Office documents
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\<OfficeVersion>\Word\Security' -Name 'DisableAllMacrosWithoutNotification' -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\<OfficeVersion>\Excel\Security' -Name 'DisableAllMacrosWithoutNotification' -Value 1
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Office\<OfficeVersion>\PowerPoint\Security' -Name 'DisableAllMacrosWithoutNotification' -Value 1

# Configure Windows Firewall to block incoming traffic from suspicious IP addresses and ports
New-NetFirewallRule -DisplayName "Block suspicious traffic" -Direction Inbound -LocalAddress Any -Protocol TCP -RemoteAddress @('<IP1>', '<IP2>', '<IP3>', '<IP4>') -RemotePort @('<Port1>', '<Port2>', '<Port3>', '<Port4>') -Action Block

# Remove unnecessary software
Get-AppxPackage | Where-Object {$_.PublisherDisplayName -ne 'Microsoft Corporation'} | Remove-AppxPackage

# Enable BitLocker or any other disk encryption software to protect the data
Enable-BitLocker -MountPoint '<DriveLetter>:' -EncryptionMethod Aes256 -UsedSpaceOnly -TpmProtector

# Update Windows and other software to the latest versions
Get-WUInstall -AcceptAll -AutoReboot

# disable LSA anonymous enumeration 
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1

# disable windows remote management over http 
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Value 0

# Disable ping response
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CustomLocale' -Name '00000809' -Value '02 00 00 00'

# Disable LSA anonymousession 
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'everyoneincludesanonymous' -Value 0

# disable script host 
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0

# disable WMI
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Winmgmt' -Name 'Start' -Value 4

Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -Value 0 -Force
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -Value 0 -Force

Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting -Name value -Type DWORD -Value 0

Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search -Name CortanaConsent -Type DWORD -Value 0

# Install the most updated version of Firefox
$firefoxUrl = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US"
$firefoxPath = "$env:USERPROFILE\Downloads\firefox.exe"
Invoke-WebRequest -Uri $firefoxUrl -OutFile $firefoxPath
Start-Process -FilePath $firefoxPath -ArgumentList "/S"

# Install the most updated version of Chrome
$chromeUrl = "https://dl.google.com/chrome/install/standalone/enterprise/GoogleChromeEnterpriseBundle64.zip"
$chromePath = "$env:USERPROFILE\Downloads\chrome.zip"
Invoke-WebRequest -Uri $chromeUrl -OutFile $chromePath
Expand-Archive -Path $chromePath -DestinationPath "$env:ProgramFiles\Google\" -Force
$chromeInstallerPath = Get-ChildItem -Path "$env:ProgramFiles\Google\Google Chrome Enterprise" -Filter "GoogleChrome*.msi" -Recurse | Select-Object -First 1 -ExpandProperty FullName
Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$chromeInstallerPath`" /qn /norestart"

# Disable Microsoft Edge
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "AllowEdgeSwipe" -PropertyType DWord -Value 0 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventFirstRunPage" -PropertyType DWord -Value 1 -Force
New-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Edge" -Name "DisableWebViewCreation" -PropertyType DWord -Value 1 -Force

# Download and install the Microsoft Store app package
Invoke-WebRequest -Uri https://aka.ms/winget-cli -OutFile winget-cli.appxbundle
# Install the app package
Add-AppPackage .\winget-cli.appxbundle

# winget install the latest steam release because I got love for my fellow gamers
winget install Valve.Steam

# winget install microsoftdefenderATP
winget install MicrosoftDefenderATP

# winget install tweaking repair
winget install Tweaking.WindowsRepair

# winget install Autopsy forensic imager
winget install sleuthkit.Autopsy

# winget install windows media creation tool
winget install Microsoft.WindowsMediaCreationTool

# winget secondary debloat 
$packageList = Get-AppxPackage | Where-Object {($_.IsFramework -eq $false) -and ($_.PackageFullName -notlike "*store*")}
ForEach ($package in $packageList) {
    Remove-AppxPackage -Package $package.PackageFullName
}





