@rem ***************************************************************************
@rem Copyright(c)2007-2020 ManTechnology Co., LTD. All rights reserved.
@rem ***************************************************************************

@echo off

@rem BSR-1053
setlocal EnableDelayedExpansion

for /f "tokens=*" %%a in ('bsrcon /get_log_path') do set BSR_LOG_DIR=%%a
@rem BSR-1215
for /f "tokens=*" %%a in ('bsrmon /get file_path') do set BSRMON_DIR=%%a

@rem BSR-1260
set BSRMON_DIR=%BSRMON_DIR:path : =%

set bsrsupport_log="%BSR_LOG_DIR%\bsrsuupport.log"
echo [%date%_%time%] [bsrsupport] start. > %bsrsupport_log%

call :logging "[Check environments] start."
set OLDDIR=%CD%
set SUPPORT_HOME=%BSR_PATH%\..\support
set OUTPUT_HOME=%SUPPORT_HOME%\%COMPUTERNAME%

@rem BSR-976 add option to exclude system log collection to bsrsupport
@rem BSR-1117 add bsrsupport options --exclude-system-log, --exclude-perfmon
for %%x in (%*) do (
	if "%%x" == "-exclude_systemlog" (
		set EXCLUDE_SYSLOG=true
	) else if "%%x" == "--exclude-system-log" (
		set EXCLUDE_SYSLOG=true
	) else if "%%x" == "--exclude-perfmon" (
		set EXCLUDE_PERFMON=true
	) else (
		set CORE_FILE_PATH=%%x
	)
)
if exist "%OUTPUT_HOME%" (
	call :logging "remove exist file"
	rmdir /s "%OUTPUT_HOME%"
)
	
if not exist "%OUTPUT_HOME%" (
    mkdir "%OUTPUT_HOME%"
)

set | findstr BSR_PATH 1>NUL

if not %ERRORLEVEL% EQU 0 (
    call :logging "BSR not installed"
    exit -1
)

call :logging "[Check environments] complete."

if "%CORE_FILE_PATH%" == "" (
	call :logging "Skip collection of core file."
) else (
    call :logging "[GetCoreDumpFile] start."
	call :GetCoreDumpFile %CORE_FILE_PATH%
    call :logging "[GetCoreDumpFile] complete."
)

call :logging "[GetBSRInfo] start."
call :GetBSRInfo
call :logging "[GetBSRInfo] complete."

@rem BSR-976 add option to exclude system log collection to bsrsupport
if "%EXCLUDE_SYSLOG%" == "true" (
	call :logging "Skip collection of system log."
) else (
    call :logging "[GetDiskPart] start."
	call :GetDiskPart
    call :logging "[GetDiskPart] complete."
    call :logging "[GetSystemInfo] start."
	call :GetSystemInfo
    call :logging "[GetSystemInfo] complete."
)
call :logging "[GetBSRStatus] start."
call :GetBSRStatus
call :logging "[GetBSRStatus] complete."
call :logging "[GetBSRDebugInfo] start."
call :GetBSRDebugInfo
call :logging "[GetBSRDebugInfo] complete."

call :logging "[Archive] start."
call :Archive
call :logging "[Archive] complete."


echo [%date%_%time%] [bsrsupport] complete. >> %bsrsupport_log%
endlocal
exit /B %ERRORLEVEL%

@rem ##########################################################################################
@rem # Functions                                                                              #
@rem ##########################################################################################

:GetCoreDumpFile
	call :logging "Get Core Dump file..."

	for /f "delims=" %%a IN (%1) do @set core_filename=%%~nxa

    set CORE_ARCHIVE_NAME=%core_filename%.zip

    set BSR_DIR=%OUTPUT_HOME%\BSR
    if not exist "%BSR_DIR%" ( mkdir "%BSR_DIR%" )

    "%BSR_PATH%\..\support\zip" -9j "%BSR_DIR%\%CORE_ARCHIVE_NAME%" %1

    if %ERRORLEVEL% EQU 0 (
		call :logging  "core file has been compressed."
    ) else (
        call :logging  "core file compress failed. err(%ERRORLEVEL%)"
	)
exit /B 0

:GetDiskPart
    set DISKPART_DIR=%OUTPUT_HOME%\DiskPart
	
    if not exist "%DISKPART_DIR%" ( mkdir "%DISKPART_DIR%" )
	
	@rem ===================================================================
	@rem  Create a script file to be used by the for loops
	@rem ===================================================================
	echo list disk >> diskList.tmp
	echo list volume >> volumeList.tmp

	@rem ===================================================================
	@rem  Diskpart's  Total Volume List 
	@rem ===================================================================
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo --------------- Diskpart's total volume list information ------------  >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	diskpart /s volumeList.tmp >> "%DISKPART_DIR%\diskpartInfo.txt"
	IF EXIST volumeList.tmp DEL volumeList.tmp
    call :logging "total volume list"


	@rem ===================================================================
	@rem  Diskpart's Total Disk List 
	@rem ===================================================================
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo ---------------- Diskpart's total disk list information ------------ >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	diskpart /s diskList.tmp >> "%DISKPART_DIR%\diskpartInfo.txt"
	IF EXIST diskList.tmp DEL diskList.tmp
    call :logging "total disk list"

	@rem ===================================================================
	@rem  Get the total number of lines in the file(diskpartInfo.txt)
	@rem ===================================================================

	set diskpartLINES=1
	for /f "delims==" %%a in ('findstr /N .* "%DISKPART_DIR%\diskpartInfo.txt"') do ( 
		set /a diskpartLINES=diskpartLINES+1
	)

	@rem ===================================================================
	@rem  Print the last lines and Count disk drives
	@rem ===================================================================
	
	@rem Because of more commnad, the last number - 2 = Last disk count 
	set /a diskpartLINES=diskpartLINES-2 
	more +%diskpartLINES% < "%DISKPART_DIR%\diskpartInfo.txt" > diskListCount.txt

	for /f "tokens=2" %%b in (diskListCount.txt) do (
		set DiskCount=%%b 
	)	
	
	@rem ===================================================================
	@rem  As the number of disks, diskpart command is used
	@rem ===================================================================
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	for /l %%c in (0,1,%DiskCount%) do (
		echo select disk=%%c >> diskList.tmp
		echo detail disk >> diskList.tmp
		echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
		echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
		echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
		echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
		echo ---------------- Diskpart's %%c disk information ------------ >> "%DISKPART_DIR%\diskpartInfo.txt"
		echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
    
		diskpart /s diskList.tmp >> "%DISKPART_DIR%\diskpartInfo.txt"
		IF EXIST diskList.tmp DEL diskList.tmp
		echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	)
	IF EXIST diskListCount.txt DEL diskListCount.txt

	echo ---Complete dispart log collection--- >> "%DISKPART_DIR%\diskpartInfo.txt"

    call :logging "complete dispart log collection"
exit /B 0

:GetBSRInfo
    call :logging "Get BSR Information..."
    set BSR_DIR=%OUTPUT_HOME%\BSR

    if not exist "%BSR_DIR%" ( mkdir "%BSR_DIR%" )
    if not exist "%BSR_DIR%\etc" ( mkdir "%BSR_DIR%\etc" )
    if not exist "%BSR_DIR%\log" ( mkdir "%BSR_DIR%\log" )
    if not "%EXCLUDE_PERFMON%" == "true" (
        if not exist "%BSR_DIR%\perfmon" ( mkdir "%BSR_DIR%\perfmon" )
    )

    if not exist "%BSR_DIR%\bin" ( mkdir "%BSR_DIR%\bin" )

    xcopy "%BSR_PATH%\..\etc\*" "%BSR_DIR%\etc" /e /h /k
    call :logging "Get bsr config"

    @rem BSR-1117
    xcopy "%BSR_LOG_DIR%\bsr.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\bsradm.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\bsrsetup.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\bsrmeta.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\bsrapp.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\chkdsk*.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\rc_start.log*" "%BSR_DIR%\log" /k 2> nul
    xcopy "%BSR_LOG_DIR%\rc_stop.log*" "%BSR_DIR%\log" /k 2> nul
    call :logging "Get bsr log"
    if "%EXCLUDE_PERFMON%" == "true" (
        call :logging "Skip collection of perfmon log."
    ) else (
        xcopy "%BSRMON_DIR%\*" "%BSR_DIR%\perfmon" /e /h /k 2> nul
        call :logging "Get bsr perfmon log"
    )
    

    xcopy "%BSR_PATH%\..\bin\*.pdb" "%BSR_DIR%\bin" /e /h /k
    call :logging "Get bsr pdb"
exit /B 0

:GetSystemInfo
    call :logging "Get System information..."
    set SYSTEM_DIR=%OUTPUT_HOME%\System

    if not exist "%SYSTEM_DIR%" ( mkdir "%SYSTEM_DIR%" )

    @rem Event log
    cscript //Nologo "%BSR_PATH%\..\support\DumpEventLog.vbs" localhost Application > "%SYSTEM_DIR%\ApplicationLog.csv" 2> NUL
    call :logging "ApplicationLog.csv"
    cscript //Nologo "%BSR_PATH%\..\support\DumpEventLog.vbs" localhost System > "%SYSTEM_DIR%\SystemLog.csv" 2> NUL
    call :logging "SystemLog.csv"

    @rem System information
    systeminfo > "%SYSTEM_DIR%\systeminfo.txt"
     call :logging "systeminfo.txt"

    @rem Firewall setting
    netsh advfirewall show allprofiles > "%SYSTEM_DIR%\firewallpolicy.txt"
    netsh advfirewall firewall show rule name=all verbose >> "%SYSTEM_DIR%\firewallpolicy.txt"
    call :logging "firewallpolicy.txt"

    @rem Security Policy
    1>NUL secedit /export /cfg "%SYSTEM_DIR%\secPolicy.txt"
    call :logging "secPolicy.txt"

    @rem Service List
    wmic service list full /format:csv > "%SYSTEM_DIR%\svcList.csv"
    call :logging "svcList.csv"

	@rem Disk List
	wmic diskdrive > "%SYSTEM_DIR%\diskList.txt"
    call :logging "diskList.txt"
	
    @rem Running Process info
    tasklist /v > "%SYSTEM_DIR%\procList.txt"
    call :logging "procList.txt"

    @rem Network Configuration
    ipconfig /all > "%SYSTEM_DIR%\netconf.txt"
    call :logging "netconf.txt"

    @rem Device list
    cscript //Nologo "%BSR_PATH%\..\support\devlist.vbs" > "%SYSTEM_DIR%\devList.csv"
    call :logging "devList.csv"

    @rem Device Driver info
    1>NUL wmic sysdriver list full /format:csv > "%SYSTEM_DIR%\drvList.csv"
    call :logging "drvList.csv"

    @rem Windows'etc folder copy
    1>NUL copy /y %WINDIR%\System32\Drivers\etc\* "%SYSTEM_DIR%\System_etc"
    call :logging "System_etc"

    @rem Netsh
    set NETSHRESULT=%SYSTEM_DIR%\netshresult.txt

    echo ---------- Configuration ---------- > "%NETSHRESULT%"
    netsh interface ipv4 show config >> "%NETSHRESULT%"

    echo ---------- Interface Parameter ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show interfaces level=verbose >> "%NETSHRESULT%"

    echo ---------- Destination cache info ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show destinationcache >> "%NETSHRESULT%"

    echo ---------- Global Parameter ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show global >> "%NETSHRESULT%"

    echo ---------- ICMP stat ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show icmpstats >> "%NETSHRESULT%"

    echo ---------- IP Address ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show ipaddresses >> "%NETSHRESULT%"

    echo ---------- IP network mapping info ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show ipnettomedia >> "%NETSHRESULT%"

    echo ---------- IP stat ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show ipstats >> "%NETSHRESULT%"

    echo ---------- Neighbor cache ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show neighbors >> "%NETSHRESULT%"

    echo ---------- Offload ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show offload >> "%NETSHRESULT%"

    echo ---------- Route ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show route >> "%NETSHRESULT%"

    echo ---------- Subinterface ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show subinterfaces >> "%NETSHRESULT%"

    echo ---------- TCP connection ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show tcpconnections >> "%NETSHRESULT%"

    echo ---------- TCP stat ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show tcpstats >> "%NETSHRESULT%"

    echo ---------- UDP connection ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show udpconnections >> "%NETSHRESULT%"

    echo ---------- UDP stat ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show udpstats >> "%NETSHRESULT%"

    echo ---------- WINS server ---------- >> "%NETSHRESULT%"
    netsh interface ipv4 show winsservers >> "%NETSHRESULT%"

    call :logging "netshresult.txt"

    @rem Processes
    wmic /output:"%SYSTEM_DIR%\ProcInfo.html" process list full /format:htable
    call :logging "ProcInfo.html"

    @rem etc
    route print -4 > "%SYSTEM_DIR%\route4"
    call :logging "route4"
    route print -6 > "%SYSTEM_DIR%\route6"
    call :logging "route6"
    netstat -na > "%SYSTEM_DIR%\netstat"
    call :logging "netstat"
exit /B 0

:GetBSRStatus
    call :logging "Get BSR Status information..."
    set STATUS_DIR=%OUTPUT_HOME%\Status

    if not exist "%STATUS_DIR%" ( mkdir "%STATUS_DIR%" )
	
	bsradm show-gi all > "%STATUS_DIR%\gi.txt"
    call :logging "gi.txt"
    bsradm dump > "%STATUS_DIR%\dump.txt"
	call :logging "dump.txt"
	bsrsetup show > "%STATUS_DIR%\show.txt"
    call :logging "show.txt"
exit /b 0

@rem BSR-675 add debug info to support file
:GetBSRDebugInfo

setlocal EnableDelayedExpansion
    call :logging "Get BSR debug information..."
    set DEBUG_DIR=%OUTPUT_HOME%\Debuginfo

    if not exist "%DEBUG_DIR%" ( mkdir "%DEBUG_DIR%" )
	bsrmon /debug version > "%DEBUG_DIR%\version.txt"
	for /f "usebackq tokens=*" %%a in (`bsradm sh-resource all`) do (
		set res=%%a
		set res_dir=!DEBUG_DIR!\!res!
		if not exist "!res_dir!" ( mkdir "!res_dir!" )
		echo !res_dir!
		bsrmon /debug in_flight_summary %%a > "!res_dir!\in_flight_summary.txt" 2> nul
		bsrmon /debug state_twopc %%a > "!res_dir!\state_twopc.txt" 2> nul
		
		for /f "usebackq tokens=*" %%b in (`bsradm sh-peer-node-id !res!`) do (
			set conn=%%b
			set conn_dir=!res_dir!\connections\!conn!
			if not exist "!conn_dir!" ( mkdir "!conn_dir!" )
			bsrmon /debug callback_history !res! !conn! > "!conn_dir!\callback_history.txt" 2> nul
			bsrmon /debug debug !res! !conn! > "!conn_dir!\debug.txt" 2> nul
			bsrmon /debug conn_oldest_requests !res! !conn! > "!conn_dir!\conn_oldest_requests.txt" 2> nul
			bsrmon /debug transport !res! !conn! > "!conn_dir!\transport.txt" 2> nul
			for /f "usebackq tokens=*" %%c in (`bsradm bsradm sh-dev-vnr !res!`) do (
				set peer=%%c
				set peer_dir=!conn_dir!\!peer!
				if not exist "!peer_dir!" ( mkdir "!peer_dir!" )
				bsrmon /debug proc_bsr !res! !conn! !peer! > "!peer_dir!\proc_bsr.txt" 2> nul
				bsrmon /debug resync_extents !res! !conn! !peer! > "!peer_dir!\resync_extents.txt" 2> nul
				
			)
		
		)
		
		for /f "usebackq tokens=*" %%c in (`bsradm sh-dev-vnr !res!`) do (
			set vnr=%%c
			set vnr_dir=!res_dir!\volumes\!vnr!
			if not exist "!vnr_dir!" ( mkdir "!vnr_dir!" )
			bsrmon /debug act_log_extents !res! !vnr! > "!vnr_dir!\act_log_extents.txt" 2> nul
			bsrmon /debug data_gen_id !res! !vnr! > "!vnr_dir!\data_gen_id.txt" 2> nul
			bsrmon /debug ed_gen_id !res! !vnr! > "!vnr_dir!\ed_gen_id.txt" 2> nul
			bsrmon /debug io_frozen !res! !vnr! > "!vnr_dir!\io_frozen.txt" 2> nul
			bsrmon /debug dev_oldest_requests !res! !vnr! > "!vnr_dir!\dev_oldest_requests.txt" 2> nul
		)	
	)
endlocal
exit /b 0

:Archive
    call :logging "Archive files..."

    for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
    set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
    set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"
    set fullstamp=%YYYY%%MM%%DD%.%HH%%Min%%Sec%
    set ARCHIVE_NAME=%COMPUTERNAME%-%fullstamp%.zip

    @rem Archive gathered information.
    cd /d "%SUPPORT_HOME%"
    "%BSR_PATH%\..\support\zip" -r -m9 "%ARCHIVE_NAME%" "%COMPUTERNAME%"
    cd /d "%OLDDIR%"

    echo.
    call :logging "Saved to %SUPPORT_HOME%\%ARCHIVE_NAME%"
exit /B 0


:logging
    @rem BSR-1130
    echo %~1
    echo [%date%_%time%] %~1 >> %bsrsupport_log%
exit /B 0