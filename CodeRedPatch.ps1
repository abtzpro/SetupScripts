# Block traffic to TCP port 80 (HTTP)
New-NetFirewallRule -DisplayName "Block CodeRed Worm" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block CodeRed Worm" -Direction Outbound -RemotePort 80 -Protocol TCP -Action Block

# Stop and disable the IIS Admin service
Stop-Service -Name IISADMIN
Set-Service -Name IISADMIN -StartupType Disabled

# Remove CodeRed worm and variants executable files
Remove-Item -Path C:\INETPUB\SCRIPTS\*.IDA -Force
Remove-Item -Path C:\WINNT\system32\inetsrv\*ida.dll -Force
Remove-Item -Path C:\WINNT\system32\inetsrv\*idq.dll -Force
Remove-Item -Path C:\WINNT\system32\cmd.exe -Force
Remove-Item -Path C:\WINNT\system32\root.exe -Force
Remove-Item -Path C:\WINNT\system32\services.exe -Force
Remove-Item -Path C:\WINNT\system32\svchosts.exe -Force
