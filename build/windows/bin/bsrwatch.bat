@echo off

@rem BSR-1112
for /f "tokens=*" %%a in ('bsrcon /get_log_path') do set BSR_LOG_DIR=%%a
@rem BSR-1680
Powershell.exe -command "Get-Content '%BSR_LOG_DIR%\bsr.log' -Wait -Tail 100"