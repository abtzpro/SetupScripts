# Hide PowerShell Window
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ConsoleUtils {
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
}
"@ 

$consolePtr = [ConsoleUtils]::GetConsoleWindow()
# Hide the console window
[ConsoleUtils]::ShowWindow($consolePtr, 0) 

# Get the path to the log file
$logFile = Join-Path -Path $PSScriptRoot -ChildPath "BootKit_Logging.txt"

# Create the log file if it doesn't exist
if (-not (Test-Path $logFile)) {
    New-Item -Path $logFile -ItemType File -Force
}

# Add a separator and the script start time to the log file
$separator = "=" * 80
$startTime = Get-Date
"$separator`nScript started at $startTime`n$separator" | Out-File -Append -FilePath $logFile

# Run the script indefinitely
while ($true) {
    try {
        # Get the current date and time
        $now = Get-Date

        # Trigger a quick scan with Windows Defender
        Start-Process "C:\Program Files\Windows Defender\MpCmdRun.exe" -ArgumentList "-Scan -ScanType 1" -Wait -WindowStyle Hidden

        # Check boot start drivers
        $drivers = Get-WmiObject -Query "Select * From Win32_SystemDriver WHERE StartMode = 'Boot'"
        foreach ($driver in $drivers) {
            if (-not(Get-AuthenticodeSignature -FilePath $driver.PathName)) {
                # Record the detection in the log file
                $detectionLog = @{
                    Time = $now
                    EventType = "Detection"
                    DisplayName = $driver.DisplayName
                    DriverName = $driver.Name
                    Description = $driver.Description
                    State = $driver.State
                    Status = $driver.Status
                    PathName = $driver.PathName
                    StartMode = $driver.StartMode
                } | Format-List | Out-String
                $detectionLog | Out-File -Append -FilePath $logFile

                # Attempt remediation by disabling the driver
                $driver.StopService()
                $driver.ChangeStartMode("Disabled")

                # Record the remediation in the log file
                $remediationLog = @{
                    Time = Get-Date
                    EventType = "Remediation"
                    DisplayName = $driver.DisplayName
                    DriverName = $driver.Name
                    Description = $driver.Description
                    State = $driver.State
                    Status = $driver.Status
                    PathName = $driver.PathName
                    StartMode = $driver.StartMode
                } | Format-List | Out-String
                $remediationLog | Out-File -Append -FilePath $logFile
            }
        }
    }
    catch {
        # Record the error in the log file
        $errorLog = @{
            Time = Get-Date
            EventType = "Error"
            ErrorDetails = $_
        } | Format-List | Out-String
        $errorLog | Out-File -Append -FilePath $logFile
    }

    # Wait 10 minutes before running again
    Start-Sleep -Seconds 600
}
