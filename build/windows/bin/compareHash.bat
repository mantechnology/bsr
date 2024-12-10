@echo off

if not exist %1 (
	echo "The file does not exist. (%1)" > hash.log
	exit /b -1
)
if not exist %2 (
	echo "The file does not exist. (%2)" > hash.log
	exit /b -1
)

set /p TEMP_HASH=<%1
set ORI_HASH=%TEMP_HASH: =%
set shell_cmd="bsrcon /md5 %2"
FOR /F "tokens=*" %%F IN ('%shell_cmd%') DO (set NEW_HASH=%%F)

if not "%ORI_HASH%" == "%NEW_HASH%" (
	setlocal enabledelayedexpansion
	set reg_path=HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager
	set "before_path="
	for /f "delims=" %%A in ('powershell -Command "Try { Get-ItemProperty -Path '!reg_path!' -Name PendingFileRenameOperations | Select-Object -ExpandProperty PendingFileRenameOperations } Catch { Write-Output 'No pending rename operations found.' }"') do (
		for %%i in ("%2") do (set target_filename=%%~nxi )
		set "path=%%A"
		set cleaned_path=!path:\??\=!
		for %%i in ("!cleaned_path!") do (set filename=%%~nxi )

		echo !target_filename! !filename!
		if "!target_filename!" == "!filename!" (	
			if defined before_path (
				set before_path=!before_path:\??\=!
				set wait_path=!before_path!
				set shell_temp_cmd="bsrcon /md5 !before_path!"
				FOR /F "tokens=*" %%F IN ('!shell_temp_cmd!') DO ( set WAIT_HASH=%%F )
				set WAIT_HASH=!WAIT_HASH: =!
				if "%ORI_HASH%" == "!WAIT_HASH!" (
					echo The hash of the source file and the file waiting to be installed matches. %ORI_HASH%,!WAIT_HASH! > hash.log
					endlocal
					exit /b 0
				)

			)
		)
		set "before_path=%%A"
	)	

	echo The hash of the source file and the installed file does not match. %ORI_HASH%,%NEW_HASH%,!WAIT_HASH! > hash.log
	endlocal
	exit /b -1
)

echo The hash of the source file and the installed file matches. %ORI_HASH%,%NEW_HASH% > hash.log
exit /b 0