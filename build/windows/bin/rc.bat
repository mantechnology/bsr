@echo off

REM 
REM bsr rc batch file
REM 

IF "%1" == "start" GOTO start
IF "%1" == "stop"  GOTO stop

@echo on
echo "Usage: rc.bat [start|stop] {vhd path for meta}"
goto :eof

REM ------------------------------------------------------------------------
:start

set log="%BSR_PATH%\..\log\rc_start.log"
echo [%date%_%time%] rc.bat start. > %log%

:bsr_attach_vhd


for /f "usebackq tokens=*" %%a in (`bsradm sh-md-idx all ^| findstr /C:".vhd"`) do (
	if %errorlevel% == 0 (
		call :sub_attach_vhd "%%a"
	)
)

REM for /f "usebackq tokens=*" %%a in (`bsradm sh-resources-list`) do (
REM	bsradm sh-dev %%a > tmp_vol.txt
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do bsrcon /letter %%b /init_thread
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do bsrcon /letter %%b /start_volume
REM	del tmp_vol.txt
REM )

REM linux! 
REM bsradm -c /etc/bsr.conf adjust-with-progress all
:bsr_start
::echo BSR Starting ...

setlocal EnableDelayedExpansion

set /a adj_retry=0
:adjust_retry
for /f "usebackq tokens=*" %%a in (`bsradm sh-resource all`) do (
	set ADJUST=0

	for /f "usebackq tokens=*" %%c in (`bsradm sh-resource-option -n svc_autostart %%a`) do (

		if /i "%%c" == "yes" (
			@(set ADJUST=1)
		) else if /i "%%c" == "no" (
			@(set ADJUST=0)
		) else (
			@(set ADJUST=1)
		)		
	)
	if !ADJUST! == 1 (
		echo [!date!_!time!] bsradm adjust %%a >> %log%
		bsradm -c /etc/bsr.conf adjust %%a
		if !errorlevel! gtr 0 (
			echo [!date!_!time!] Failed to bsradm adjust %%a. >> %log%
			set /a adj_retry=adj_retry+1
			REM Retry 10 times. If it fails more than 10 times, it may adjust fail.
			if %adj_retry% gtr 10 (
				echo [!date!_!time!] bsradm adjust %%a finally failed.>> %log%
			) else (
				timeout /t 3 /NOBREAK > nul
				goto adjust_retry
			)	
		) else (
			echo [!date!_!time!] bsradm adjust %%a success.>> %log%	
		)
		
		timeout /t 3 /NOBREAK > nul
	)
)
endlocal


REM User interruptible version of wait-connect all
::bsradm -c /etc/bsr.conf  wait-con-int 
::echo return code %errorlevel%

REM Become primary if configured
::bsradm -c /etc/bsr.conf  sh-b-pri all 
::echo return code %errorlevel%

::for /f "usebackq tokens=*" %%a in (`bsradm sh-resources-list`) do (
	REM MVL: check registered first!
	REM MVL: unlock volume 

	::bsradm sh-dev %%a > tmp_vol.txt

	REM : Edit mvl script please!!!
	REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /u %%b:	

	::del tmp_vol.txt
::)

goto :eof


REM ------------------------------------------------------------------------

:stop

@echo off

echo Stopping all BSR resources
bsradm down all
timeout /t 3 /NOBREAK > nul

REM linux
REM for res in $(bsrsetup all show | sed -ne 's/^resource \(.*\) {$/\1/p'); do
REM	  bsrsetup "$res" down
REM done

REM @echo on

REM for /f "usebackq tokens=*" %%a in (`bsradm sh-resource all`) do (
REM	bsradm sh-dev %%a > tmp_vol.txt
REM MVL
REM for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do ..\mvl\vollock /l %%b:
REM	for /f "usebackq tokens=*"  %%b in (tmp_vol.txt) do bsrcon /df %%b
REM	del tmp_vol.txt
REM	bsradm down %%a
REM	timeout /t 3 /NOBREAK > nul
REM )

goto :eof

:sub_attach_vhd
	if exist %1 (echo select vdisk file="%~f1" & echo attach vdisk) > _temp_attach
	if exist _temp_attach (diskpart /s _temp_attach  > nul & del _temp_attach )
	set /a retry=0
:check_vhd_status
	(echo select vdisk file="%~f1" & echo detail disk) > _check_volume	
	diskpart /s _check_volume | findstr /C:" ### " > nul
	if %errorlevel% gtr 0 (
		del _check_volume
		set /a retry=retry+1

		REM Retry 10 times. If it fails more than 10 times, it may become diskless state.
		if %retry% gtr 10 (
			echo [%date%_%time%] Failed to attach the %1 >> %log%
			goto :eof
		)

		echo [%date%_%time%] Waiting for %1 to attach... retry = %retry% >> %log%

		timeout /t 3 /NOBREAK > nul
		goto check_vhd_status
	)

	del _check_volume
	echo [%date%_%time%] %1 is mounted. >> %log%

	goto :eof