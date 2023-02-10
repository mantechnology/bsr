@echo off

setlocal

set DRIVER_PATH=.

if not (%1)==() set DRIVER_PATH=%1

cd %DRIVER_PATH%

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 128 .\bsrfsflt.inf
sc config bsrfsflt start= boot binPath= \SystemRoot\system32\Drivers\bsrfsflt.sys

rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 0 .\bsrvflt.inf


rem echo reboot...