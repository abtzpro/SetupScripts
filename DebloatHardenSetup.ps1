# Debloating and Hardening script for Windows 10 Home - by Adam Rivers

# Enable system restore point creation 
Enable-ComputerRestore -Drive "C:\"

# Set a restore point
Checkpoint-Computer -Description "RiversHardeningBaseline" -RestorePointType "MODIFY_SETTINGS"

# Disable telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type DWord

# Remove bloatware apps
Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *bingfinance* | Remove-AppxPackage
Get-AppxPackage *bingnews* | Remove-AppxPackage
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *bingweather* | Remove-AppxPackage
Get-AppxPackage *gethelp* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *messaging* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *onenote* | Remove-AppxPackage
Get-AppxPackage *people* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *solitairecollection* | Remove-AppxPackage
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *windowsmaps* | Remove-AppxPackage
Get-AppxPackage *windowsstore* | Remove-AppxPackage
Get-AppxPackage *xbox* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage
Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Windows.Photos* | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage
Get-AppxPackage *Microsoft.HEIFImageExtension* | Remove-AppxPackage
Get-AppxPackage *Microsoft.People* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage
Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage
Get-AppxPackage *Microsoft.NET.Native.Framework.2.2* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage
Get-AppxPackage *Microsoft.NET.Native.Runtime.2.2* | Remove-AppxPackage
Get-AppxPackage *Microsoft.VP9VideoExtensions* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage
Get-AppxPackage *Microsoft.VCLibs.140.00.UWPDesktop* | Remove-AppxPackage
Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage
Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage
Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage
Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage
Get-AppxPackage *Microsoft.VCLibs.140.00* | Remove-AppxPackage
Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage

# Disable Windows tips and notifications
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value 1 -Type DWord

# Disable unnecessary services
Set-Service -Name "Diagnostics Tracking Service" -StartupType Disabled
Set-Service -Name "Connected User Experiences and Telemetry" -StartupType Disabled
Set-Service -Name "Windows Search" -StartupType Manual
Set-Service -Name "Superfetch" -StartupType Disabled
Set-Service -Name "Print Spooler" -StartupType Disabled
Set-Service -Name "Windows Insider Service" -StartupType Disabled
Set-Service -Name "DiagTrack" -StartupType Disabled
Set-Service -Name "edgeupdate" -StartupType Disabled
Set-Service -Name "iphlpsvc" -StartupType Disabled
Set-Service -Name "MapsBroker" -StartupType Disabled
Set-Service -Name "RasMan" -StartupType Disabled
Set-Service -Name "W3SVC" -StartupType Disabled
Set-Service -Name "TrkWks" -StartupType Disabled
Set-Service -Name "Wcmsvc" -StartupType Disabled
Set-Service -Name "AarSvc_4b611" -StartupType Disabled
Set-Service -Name "AJRouter" -StartupType Disabled
Set-Service -Name "ALG" -StartupType Disabled
Set-Service -Name "AppHostSvc" -StartupType Disabled
Set-Service -Name "AppIDSvc" -StartupType Disabled
Set-Service -Name "AxInstSV" -StartupType Disabled
Set-Service -Name "BcastDVRUserService" -StartupType Disabled
Set-Service -Name "BluetoothUserService" -StartupType Disabled
Set-Service -Name "bthserv" -StartupType Disabled
Set-Service -Name "BTAGService" -StartupType Disabled
Set-Service -Name "BthAvctpSvc" -StartupType Disabled
Set-Service -Name "CaptureService" -StartupType Disabled
Set-Service -Name "cbdhsvc" -StartupType Disabled
Set-Service -Name "dcsvc" -StartupType Disabled
Set-Service -Name "DevQueryBroker" -StartupType Disabled
Set-Service -Name "diagnosticshub.standardcollector.service" -StartupType Disabled
Set-Service -Name "DmEnrollmentSvc" -StartupType Disabled
Set-Service -Name "dmwappushservice" -StartupType Disabled
Set-Service -Name "DoSvc" -StartupType Disabled
Set-Service -Name "dot3svc" -StartupType Disabled
Set-Service -Name "DusmSvc" -StartupType Disabled
Set-Service -Name "Eaphost" -StartupType Disabled
Set-Service -Name "edgeupdatem" -StartupType Disabled
Set-Service -Name "embeddedmode" -StartupType Disabled
Set-Service -Name "EntAppSvc" -StartupType Disabled
Set-Service -Name "Fax" -StartupType Disabled
Set-Service -Name "FDResPub" -StartupType Disabled
Set-Service -Name "FrameServer" -StartupType Disabled
Set-Service -Name "HvHost" -StartupType Disabled
Set-Service -Name "icssvc" -StartupType Disabled
Set-Service -Name "KtmRm" -StartupType Disabled
Set-Service -Name "LanmanServer" -StartupType Disabled
Set-Service -Name "LanmanWorkstation" -StartupType Disabled
Set-Service -Name "lltdsvc" -StartupType Disabled
Set-Service -Name "lmhosts" -StartupType Disabled
Set-Service -Name "McpManagementService" -StartupType Disabled
Set-Service -Name "MessagingService" -StartupType Disabled
Set-Service -Name "MixedRealityOpenXRService" -StartupType Disabled
Set-Service -Name "MSiSCSI" -StartupType Disabled
Set-Service -Name "NaturalAuthSvc" -StartupType Disabled
Set-Service -Name "NcaSvc" -StartupType Disabled
Set-Service -Name "NcdAutoSetup" -StartupType Disabled
Set-Service -Name "p2pimsvc" -StartupType Disabled
Set-Service -Name "p2psvc" -StartupType Disabled
Set-Service -Name "PcaSvc" -StartupType Disabled
Set-Service -Name "perceptionsimulationsvc" -StartupType Disabled
Set-Service -Name "PerfHost" -StartupType Disabled
Set-Service -Name "PimIndexMaintenanceSvc" -StartupType Disabled
Set-Service -Name "PNRPAutoReg" -StartupType Disabled
Set-Service -Name "PNRPsvc" -StartupType Disabled
Set-Service -Name "PrintNotify" -StartupType Disabled
Set-Service -Name "PrintWorkflowUserSvc" -StartupType Disabled
Set-Service -Name "PushToInstall" -StartupType Disabled
Set-Service -Name "RasAuto" -StartupType Disabled
Set-Service -Name "RasMan" -StartupType Disabled
Set-Service -Name "RemoteAccess" -StartupType Disabled
Set-Service -Name "RemoteRegistry" -StartupType Disabled
Set-Service -Name "RetailDemo" -StartupType Disabled
Set-Service -Name "RmSvc" -StartupType Disabled
Set-Service -Name "RpcLocator" -StartupType Disabled
Set-Service -Name "SCardSvr" -StartupType Disabled
Set-Service -Name "ScDeviceEnum" -StartupType Disabled
Set-Service -Name "SCPolicySvc" -StartupType Disabled
Set-Service -Name "seclogon" -StartupType Disabled
Set-Service -Name "SensorDataService" -StartupType Disabled
Set-Service -Name "SensorService" -StartupType Disabled
Set-Service -Name "SensrSvc" -StartupType Disabled
Set-Service -Name "SessionEnv" -StartupType Disabled
Set-Service -Name "SharedAccess" -StartupType Disabled
Set-Service -Name "SharedRealitySvc" -StartupType Disabled
Set-Service -Name "ShellHWDetection" -StartupType Disabled
Set-Service -Name "shpamsvc" -StartupType Disabled
Set-Service -Name "smphost" -StartupType Disabled
Set-Service -Name "SmsRouter" -StartupType Disabled
Set-Service -Name "SNMPTRAP" -StartupType Disabled
Set-Service -Name "Spooler" -StartupType Disabled
Set-Service -Name "SSDPSRV" -StartupType Disabled
Set-Service -Name "ssh-agent" -StartupType Disabled
Set-Service -Name "SstpSvc" -StartupType Disabled
Set-Service -Name "stisvc" -StartupType Disabled
Set-Service -Name "TabletInputService" -StartupType Disabled
Set-Service -Name "TapiSrv" -StartupType Disabled
Set-Service -Name "TermService" -StartupType Disabled
Set-Service -Name "UmRdpService" -StartupType Disabled
Set-Service -Name "UnistoreSvc" -StartupType Disabled
Set-Service -Name "upnphost" -StartupType Disabled
Set-Service -Name "VacSvc" -StartupType Disabled
Set-Service -Name "vmicguestinterface" -StartupType Disabled
Set-Service -Name "vmicheartbeat" -StartupType Disabled
Set-Service -Name "vmickvpexchange" -StartupType Disabled
Set-Service -Name "vmicrdv" -StartupType Disabled
Set-Service -Name "vmicshutdown" -StartupType Disabled
Set-Service -Name "vmictimesync" -StartupType Disabled
Set-Service -Name "vmicvmsession" -StartupType Disabled
Set-Service -Name "vmicvss" -StartupType Disabled
Set-Service -Name "w3logsvc" -StartupType Disabled
Set-Service -Name "WarpJITSvc" -StartupType Disabled
Set-Service -Name "WAS" -StartupType Disabled
Set-Service -Name "WbioSrvc" -StartupType Disabled
Set-Service -Name "wcncsvc" -StartupType Disabled
Set-Service -Name "WFDSConMgrSvc" -StartupType Disabled
Set-Service -Name "WiaRpc" -StartupType Disabled
Set-Service -Name "WinHttpAutoProxySvc" -StartupType Disabled
Set-Service -Name "WinRM" -StartupType Disabled
Set-Service -Name "wisvc" -StartupType Disabled
Set-Service -Name "WlanSvc" -StartupType Disabled
Set-Service -Name "WManSvc" -StartupType Disabled
Set-Service -Name "WpcMonSvc" -StartupType Disabled
Set-Service -Name "WPDBusEnum" -StartupType Disabled
Set-Service -Name "WpnUserService" -StartupType Disabled
Set-Service -Name "WwanSvc" -StartupType Disabled

# Set up Windows Defender
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableIntrusionPreventionSystem $

# Set User Account Control to highest settings
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 2

# Disable Powershell 2 point 0 for security
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root"

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Disable SMBV1 protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Disable Guest Account
Disable-LocalUser -Name "Guest"

# Apply Strict Password Policy 
Set-ADDefaultDomainPasswordPolicy -Identity AD -ComplexityEnabled $true -LockoutDuration "0.12:00:00" -LockoutObservationWindow "0.00:30:00" -LockoutThreshold 10 -MaxPasswordAge "60.00:00:00" -MinPasswordAge "1.00:00:00" -MinPasswordLength 8 -PasswordHistoryCount 24 -ReversibleEncryptionEnabled $false

# Enable BitLocker (replace with your recovery key)
# Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes128 -UsedSpaceOnly -Pin "AyoStickYerKeyHere" -TPMandPinProtector 

# Prevent invalid signed software from running
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "CodeIntegrity" -Value 1

# Enable SmartScreen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 1

# Disable autorun malware vector
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255

# Disable Unrequired Features
Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage"
Disable-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client"
Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client"
Disable-WindowsOptionalFeature -Online -FeatureName "Xps-Foundation-Xps-Viewer"

# Disable script host to block .VBS malware vectors
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -PropertyType "DWord"

# Prevent windows media player from sharing media
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\MediaPlayer\Preferences\HME' -name "DisableMediaSharing" -Value 1

# Enable win defender realtime network monitoring
Set-MpPreference -NISScanningEnabled $true

# Block untrusted fonts
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\" -Name "MitigationOptions_FontBocking" -Value "1000000000000" -PropertyType "String"

# Disable the customer experience improvement program - for privacy
Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\SQMClient\Windows' -Name "CEIPEnable" -Value 0

# Disable AutoPlay on all devices
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoDriveTypeAutoRun" -Value 255

# Disable remote assistance
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name "fAllowToGetHelp" -Value 0

# Limit number of connections to smb share 
Set-SmbServerConfiguration -MaxSessionsPerUser 1

# Disable unneeded features on demand
Get-WindowsCapability -Online | ? State -eq 'Installed' | Remove-WindowsCapability -Online

# Disable NetBIOS over TCP/IP
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name "NetBiosOptions" -Value 2

# Disable administrative shares 
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name "AutoShareWks" -Value 0

# Restrict anonymous access to named pipes and shares
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name "restrictanonymous" -Value 1

# Enable firewall for all network profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Set audit policy to log failed events
AuditPol /Set /SubCategory:* /Failure:Enable

# Limit local use of blank passwords
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" LimitBlankPasswordUse -Type DWORD -Value 1 -Force

# Enable Network Access: Do not allow anonymous enumeration of SAM accounts
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" RestrictAnonymousSAM -Type DWORD -Value 1 -Force

# Disable automatic wifi sense connections
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\default\WiFi\AllowWiFiHotSpotReporting" value -Type DWORD -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\current\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" value -Type DWORD -Value 0 -Force

# Disable saved RDP creds
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Value 1 -Force

# Disable location tracking
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1 -Force

# Disable advertising ID
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Force

# Disable start menu app suggestions and ads
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1 -Force

# Disable lockscreen app notifs
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -Value 1 -Force

# Prevent the usage of onedrive for file storage
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1 -Force

# Disable shared experiences 
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableCdp" -Value 0 -Force

# Prevent automatic download of manufacturers' apps and icons for devices
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Force

# No handwriting personalation data sharing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Value 1 -Force

# Prevent cloud sync of settings
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Value 0 -Force

# Disable windows feedback requests
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Force

# Enable win defend PUA detection
Set-MpPreference -PUAProtection 1

# Set windows firewall to block outbound connections by default
Set-NetFirewallProfile -DefaultOutboundAction Block

# Enable audit process creation
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable windows defender exploit protection
Set-ProcessMitigation -System -Enable ExploitGuard

# Enable credential gaurd
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" -Name "LsaCfgFlags" -Value 1 -PropertyType "Dword"

# Block remote desktop connections
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1

# Enable SecureBoot
Confirm-SecureBootUEFI

# Disable SMB2 and SMB3 - might cause network file transfer issues
Set-SmbServerConfiguration -EnableSMB2Protocol $false

# Disable WebDAV
Disable-WebDAV -confirm:$false

# Disable AutoLogon
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0"

# Enable windodws defender behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $false

# Disable powershell remoting
Disable-PSRemoting -Force

# Disable unsecured guest logons, which can allow unauthenticated network access
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "RestrictGuestAccess" -Value 1

# Block remote access to plug n play - often abused by attackers
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PlugPlay" -Name "Start" -Value 4

# Enable audit for successful or failed logon events - for help in determining suspicious activity
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Disable OneDrive altogether - if you are using a different backup otion and dont want one drive
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1

# Block executables from running in AppData a common vector for malware
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "1" -Value "*.exe"

# Disable clipboard history
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Value 0

# Disable outdated Dynamic Data Exchange DDE
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDDE" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDDEAdvertise" -Value 1

# Disable Edge preloading
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value 0

# Set windows defender blocking level to sensitive af
Set-MpPreference -HighThreatDefaultAction Block -ModerateThreatDefaultAction Block -LowThreatDefaultAction Block

# Set internet explorer to high security level
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" -Name 1809 -Value 0

# Disable Windows Tips
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0

# Force UAC to use secure desktop
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

# Force the use of 128-bit encryption to secure Windows file sharing communications
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Redundant remote registry blocking
Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped

# Restrict powershell and cmd to admins only
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name "DisableCMD" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\PowerShell" -Name "DisableCommandLine" -Value 1

# Limit exposure to open network shares to local network
New-NetFirewallRule -DisplayName "Block Inbound Network Discovery" -Direction Inbound -Action Block -Profile Private -Service FDResPub

# Redundant disabling of inbound remote desktop services
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Enabled False

# Enable Address Space Layout Randomization (ASLR) to make it more difficult for an attacker to predict target address
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 0xFF

# Enable Network Access Protection Agent to help prevent network-based attacks
Set-Service napagent -StartupType Automatic

# Enable powershell logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1

# Enable script block logging
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Restrict NTLM authentication to reduce the risk of pass-the-hash attacks
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictReceivingNTLMTraffic" -Value 2

# Enable controlled folder access
Set-MpPreference -EnableControlledFolderAccess Enabled

# Enable powershell transcripts for tracing powershell commands backwards
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Transcripts"


