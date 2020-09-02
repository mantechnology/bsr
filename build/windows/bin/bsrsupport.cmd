@rem ***************************************************************************
@rem Copyright(c)2007-2020 ManTechnology Co., LTD. All rights reserved.
@rem ***************************************************************************

@echo off

echo Check environments...
set OLDDIR=%CD%
set SUPPORT_HOME=%BSR_PATH%\..\support
set OUTPUT_HOME=%SUPPORT_HOME%\%COMPUTERNAME%
set ARGC=0
for %%x in (%*) do Set /A ARGC += 1

if exist "%OUTPUT_HOME%" (
	del "%OUTPUT_HOME%"
)
	
if not exist "%OUTPUT_HOME%" (
    mkdir "%OUTPUT_HOME%"
)

set | findstr BSR_PATH 1>NUL

if not %ERRORLEVEL% EQU 0 (
    echo BSR not installed
    exit -1
)

if %ARGC% == 0 (
	echo Skip collection of core file.
) else (
	call :GetCoreDumpFile %1
)
call :GetBSRInfo
call :GetDiskPart
call :GetSystemInfo
call :GetBSRStatus
call :Archive

exit /B %ERRORLEVEL%

@rem ##########################################################################################
@rem # Functions                                                                              #
@rem ##########################################################################################

:GetCoreDumpFile
	echo Get Core Dump file...

	for /f "delims=" %%a IN (%1) do @set core_filename=%%~nxa

    set CORE_ARCHIVE_NAME=%core_filename%.zip

    set BSR_DIR=%OUTPUT_HOME%\BSR
    if not exist "%BSR_DIR%" ( mkdir "%BSR_DIR%" )

    "%BSR_PATH%\..\support\zip" -9j "%BSR_DIR%\%CORE_ARCHIVE_NAME%" %1

    if %ERRORLEVEL% EQU 0 (
		echo core file has been compressed.
    ) else (
        echo core file compress failed. err(%ERRORLEVEL%)
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

	@rem ===================================================================
	@rem  Diskpart's Total Disk List 
	@rem ===================================================================
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo ---------------- Diskpart's total disk list information ------------ >> "%DISKPART_DIR%\diskpartInfo.txt"
	echo. >> "%DISKPART_DIR%\diskpartInfo.txt"
	diskpart /s diskList.tmp >> "%DISKPART_DIR%\diskpartInfo.txt"
	IF EXIST diskList.tmp DEL diskList.tmp

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
exit /B 0

:GetBSRInfo
    echo Get BSR Information...
    set BSR_DIR=%OUTPUT_HOME%\BSR

    if not exist "%BSR_DIR%" ( mkdir "%BSR_DIR%" )
    if not exist "%BSR_DIR%\etc" ( mkdir "%BSR_DIR%\etc" )
    if not exist "%BSR_DIR%\log" ( mkdir "%BSR_DIR%\log" )
    if not exist "%BSR_DIR%\bin" ( mkdir "%BSR_DIR%\bin" )

	xcopy "%BSR_PATH%\..\etc\*" "%BSR_DIR%\etc" /e /h /k
	xcopy "%BSR_PATH%\..\log\*" "%BSR_DIR%\log" /e /h /k
	xcopy "%BSR_PATH%\..\bin\*.pdb" "%BSR_DIR%\bin" /e /h /k
exit /B 0

:GetSystemInfo
    echo Get System information...
    set SYSTEM_DIR=%OUTPUT_HOME%\System

    if not exist "%SYSTEM_DIR%" ( mkdir "%SYSTEM_DIR%" )

    @rem Event log
    cscript //Nologo "%BSR_PATH%\..\support\DumpEventLog.vbs" localhost Application > "%SYSTEM_DIR%\ApplicationLog.csv" 2> NUL
    cscript //Nologo "%BSR_PATH%\..\support\DumpEventLog.vbs" localhost System > "%SYSTEM_DIR%\SystemLog.csv" 2> NUL

    @rem System information
    systeminfo > "%SYSTEM_DIR%\systeminfo.txt"

    @rem Firewall setting
    netsh advfirewall show allprofiles > "%SYSTEM_DIR%\firewallpolicy.txt"
    netsh advfirewall firewall show rule name=all verbose >> "%SYSTEM_DIR%\firewallpolicy.txt"

    @rem Security Policy
    1>NUL secedit /export /cfg "%SYSTEM_DIR%\secPolicy.txt"

    @rem Service List
    wmic service list full /format:csv > "%SYSTEM_DIR%\svcList.csv"

	@rem Disk List
	wmic diskdrive > "%SYSTEM_DIR%\diskList.txt"
	
    @rem Running Process info
    tasklist /v > "%SYSTEM_DIR%\procList.txt"

    @rem Network Configuration
    ipconfig /all > "%SYSTEM_DIR%\netconf.txt"

    @rem Device list
    cscript //Nologo "%BSR_PATH%\..\support\devlist.vbs" > "%SYSTEM_DIR%\devList.csv"

    @rem Device Driver info
    1>NUL wmic sysdriver list full /format:csv > "%SYSTEM_DIR%\drvList.csv"

    @rem Windows'etc folder copy
    1>NUL copy /y %WINDIR%\System32\Drivers\etc\* "%SYSTEM_DIR%\System_etc"

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

    @rem Processes
    wmic /output:"%SYSTEM_DIR%\ProcInfo.html" process list full /format:htable

    @rem etc
    route print -4 > "%SYSTEM_DIR%\route4"
    route print -6 > "%SYSTEM_DIR%\route6"
    netstat -na > "%SYSTEM_DIR%\netstat"
exit /B 0

:GetBSRStatus
    echo Get BSR Status information...
    set STATUS_DIR=%OUTPUT_HOME%\Status

    if not exist "%STATUS_DIR%" ( mkdir "%STATUS_DIR%" )
	
	bsradm show-gi all > "%STATUS_DIR%\gi.txt"
    bsradm dump > "%STATUS_DIR%\dump.txt"
	bsrsetup status --s --v all > "%STATUS_DIR%\status.txt"
	bsrsetup show > "%STATUS_DIR%\show.txt"
exit /b 0

:Archive
    echo Archive files...

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
    echo Saved to %SUPPORT_HOME%\%ARCHIVE_NAME%
exit /B 0
