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
FOR /F "tokens=*" %%F IN ('%shell_cmd%') DO (
set NEW_HASH=%%F
)

if not "%ORI_HASH%" == "%NEW_HASH%" (
	echo "The hash does not match the original file. original(%ORI_HASH%), new(%NEW_HASH%)" > hash.log
	exit /b -1
)

echo "The hash match the original file. original(%ORI_HASH%), new(%NEW_HASH%)" > hash.log

exit /b 0