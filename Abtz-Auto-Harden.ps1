#Disable SMBv1 protocol
Set-SmbServerConfiguration -EnableSMB1Protocol $false

#Enable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

#Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value "0"

#Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false

#Disable Guest Account
Set-LocalUser -Name "Guest" -Enabled $false

#Disable Autorun
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value "1"

#Disable Remote Desktop Protocol (RDP)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value "1"

#Enable Secure Boot
Set-FirmwareEnvironmentVariable -Name "SecureBoot" -Value "Enabled"

#Disable unnecessary services
Get-Service | Where-Object {$_.StartType -eq "Auto" -and $_.DisplayName -notmatch "Windows Update|Windows Defender"} | Set-Service -StartupType Disabled

#Install Latest Patches
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", "C:\temp\wsusscn2.cab", 1)
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$UpdateSearchResult = $UpdateSearcher.Search("IsInstalled=0")
$Installer = New-Object -ComObject Microsoft.Update.Installer
$UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($Update in $UpdateSearchResult.Updates) {
    $UpdatesToInstall.Add($Update) | Out-Null
}
if ($UpdatesToInstall.Count -gt 0) {
    $Installer.Install($UpdatesToInstall)
}
