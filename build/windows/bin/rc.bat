@echo off

REM 
REM bsr rc batch file
REM 

REM BSR-1112
for /f "tokens=*" %%a in ('bsrcon /get_log_path') do set BSR_LOG_DIR=%%a

IF "%1" == "start" GOTO start
IF "%1" == "stop"  GOTO stop

@echo on
echo "Usage: rc.bat [start|stop] {vhd path for meta}"
goto :eof

REM ------------------------------------------------------------------------
:start

set start_log="%BSR_LOG_DIR%\rc_start.log"
echo [%date%_%time%] rc.bat start. > %start_log%


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
for /f "usebackq tokens=*" %%a in (`bsradm sh-resource all -T`) do (
	set ADJUST=0
	echo [%date%_%time%] check resource %%a >> %start_log%
	for /f "usebackq tokens=*" %%c in (`bsradm sh-node-option -n svc_auto_up %%a -T`) do (

		if /i "%%c" == "yes" (
			@(set ADJUST=1)
		) else if /i "%%c" == "no" (
			@(set ADJUST=0)
			echo [%date%_%time%] skip adjust %%a >> %start_log%
		) else (
			@(set ADJUST=1)
		)		
	)
	if !ADJUST! == 1 (
		echo [!date!_!time!] bsradm adjust %%a >> %start_log%
		bsradm -c /etc/bsr.conf adjust %%a -T
		if !errorlevel! gtr 0 (
			echo [!date!_!time!] Failed to bsradm adjust %%a. >> %start_log%
			set /a adj_retry=adj_retry+1
			REM Retry 10 times. If it fails more than 10 times, it may adjust fail.
			if %adj_retry% gtr 10 (
				echo [!date!_!time!] bsradm adjust %%a finally failed.>> %start_log%
			) else (
				waitfor bsrAdjust /t 3 > NUL 2>&1
				goto adjust_retry
			)	
		) else (
			echo [!date!_!time!] bsradm adjust %%a success.>> %start_log%	
		)
		
		waitfor bsrAdjust /t 3 > NUL 2>&1
	)
)

REM BSR-1138
:bsrmon_start
for /f "tokens=*" %%a in ('bsrmon /get run') do set bsrmon_enabled=%%a
for /f "tokens=3" %%b in ('bsrmon /get types') do set bsrmon_types=%%b
if !bsrmon_enabled! == 1 (
	bsrmon /start !bsrmon_types!
	echo [!date!_!time!] bsrmon start. >> %start_log%
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

set stop_log="%BSR_LOG_DIR%\rc_stop.log"
echo [%date%_%time%] rc.bat stop. > %stop_log%
echo [%date%_%time%] Stopping all BSR resources >> %stop_log%


setlocal EnableDelayedExpansion

REM BSR-1138
:bsrmon_stop
for /f "tokens=*" %%a in ('bsrmon /get run') do set bsrmon_enabled=%%a
if !bsrmon_enabled! == 1 (
	bsrmon /stop running
	echo [!date!_!time!] bsrmon stop. >> %stop_log%
)

REM BSR-593 auto-down by svc
for /f "usebackq tokens=*" %%a in (`bsradm sh-resource all`) do (
	set DOWN=0

	for /f "usebackq tokens=*" %%c in (`bsradm sh-node-option -n svc_auto_down %%a`) do (

		if /i "%%c" == "yes" (
			@(set DOWN=1)
		) else if /i "%%c" == "no" (
			@(set DOWN=0)
			echo [%date%_%time%] skip down %%a >> %stop_log%
		) else (
			@(set DOWN=1)
		)		
	)
	if !DOWN! == 1 (
		echo [!date!_!time!] bsradm down %%a >> %stop_log%
		bsradm down %%a
		if !errorlevel! gtr 0 (
			echo [!date!_!time!] Failed to bsradm down %%a. >> %stop_log%
		) else (
			echo [!date!_!time!] bsradm down %%a success.>> %stop_log%	
		)
	)
)
endlocal

waitfor bsrStop /t 3 > NUL 2>&1
		
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
			echo [%date%_%time%] Failed to attach the %1 >> %start_log%
			goto :eof
		)

		echo [%date%_%time%] Waiting for %1 to attach... retry = %retry% >> %start_log%

		waitfor bsrVhdStatus /t 3 > NUL 2>&1
		goto check_vhd_status
	)

	del _check_volume
	echo [%date%_%time%] %1 is mounted. >> %start_log%

	goto :eof