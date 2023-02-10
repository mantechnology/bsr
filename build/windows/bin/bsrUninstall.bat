@echo off

setlocal

set DRIVER_PATH=.

if not (%1)==() set DRIVER_PATH=%1
cd %DRIVER_PATH%

rundll32.exe setupapi.dll,InstallHinfSection DefaultunInstall.NTamd64 0 .\bsrvflt.inf
rundll32.exe setupapi.dll,InstallHinfSection DefaultunInstall.NTamd64 0 .\bsrfsflt.inf

echo unstall finished. please reboot now.