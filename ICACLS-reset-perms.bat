@echo off
setlocal EnableDelayedExpansion

set "root=C:\"
icacls %root% /reset /t /c /l

for /f "delims=" %%d in ('dir %root% /ad /b /s') do (
  icacls "%%d" /reset /t /c /l
)

echo Done resetting permissions.
