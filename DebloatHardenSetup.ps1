# Set up script for Windows 10 Home

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
