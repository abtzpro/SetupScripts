# Set execution policy to allow running of PowerShell scripts
Set-ExecutionPolicy Bypass -Scope Process -Force

# Create a function for the Windows Update process
function Start-WindowsUpdate {
    # Load the required Windows Update assemblies
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()

    # Search for updates
    Write-Host "Searching for updates..."
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

    # Check if there are any updates available
    if ($SearchResult.Updates.Count -eq 0) {
        Write-Host "No updates available."
        return
    }

    # Download updates
    Write-Host "Updates available: $($SearchResult.Updates.Count)"
    Write-Host "Downloading updates..."
    $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    $SearchResult.Updates | ForEach-Object { $UpdatesToDownload.Add($_) | Out-Null }
    $Downloader = $UpdateSession.CreateUpdateDownloader()
    $Downloader.Updates = $UpdatesToDownload
    $DownloadResult = $Downloader.Download()

    # Check if updates were downloaded successfully
    if ($DownloadResult.ResultCode -ne 2) {
        Write-Host "Failed to download updates."
        return
    }

    # Install updates
    Write-Host "Installing updates..."
    $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    $SearchResult.Updates | ForEach-Object {
        if ($_.IsDownloaded) {
            $UpdatesToInstall.Add($_) | Out-Null
        }
    }
    $Installer = $UpdateSession.CreateUpdateInstaller()
    $Installer.Updates = $UpdatesToInstall
    $InstallResult = $Installer.Install()

    # Check if updates were installed successfully
    if ($InstallResult.ResultCode -ne 2) {
        Write-Host "Failed to install updates."
    } else {
        Write-Host "Updates installed successfully."
    }
}

# Run the Windows Update function
Start-WindowsUpdate

# Set execution policy back to default
Set-ExecutionPolicy Default -Scope Process -Force
