@echo off

@rem BSR-1112
for /f "tokens=*" %%a in ('bsrcon /get_log_path') do set BSR_LOG_DIR=%%a
cd "%BSR_LOG_DIR%\"

Powershell.exe -command "Get-Content bsrlog.txt -Wait -Tail 100"