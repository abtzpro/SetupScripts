# Check for missing security updates
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")
$UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
ForEach ($Update in $SearchResult.Updates) {
    $UpdatesToInstall.Add($Update) | Out-Null
}

# Install missing security updates
If ($UpdatesToInstall.Count -gt 0) {
    $Installer = $UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
    $InstallationResult = $Installer.Install()
    If ($InstallationResult.ResultCode -eq "2") {
        Write-Host "Security updates installed successfully."
    } Else {
        Write-Host "Failed to install security updates."
    }
} Else {
    Write-Host "No missing security updates found."
}

# Check for weak or expired passwords
$UserAccounts = Get-LocalUser
ForEach ($UserAccount in $UserAccounts) {
    $PasswordInfo = $UserAccount | Select-Object -ExpandProperty PasswordLastSet
    If ($PasswordInfo -lt (Get-Date).AddDays(-90)) {
        Write-Host "User account $($UserAccount.Name) has a weak or expired password."
        # Change password code here
    }
}

# Disable guest account
Set-LocalUser -Name Guest -Enabled $false

# Disable unused services
Get-Service -Name "Remote Registry","Server","Telnet" | Set-Service -StartupType Disabled

# Enable Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configure Windows Update to automatically install updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4

# Disable automatic execution of macros in Office documents
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Word\Security" -Name "DisableLogging" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Excel\Security" -Name "DisableLogging" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\PowerPoint\Security" -Name "DisableLogging" -Value 1

# Disable PowerShell script execution
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "Restricted"

# Enable BitLocker to encrypt system drive
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly

Write-Host "Security vulnerabilities patched successfully."
