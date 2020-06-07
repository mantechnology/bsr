cd %BSR_PATH%/../log
Powershell.exe -command "Get-Content bsrlog.txt -Wait -Tail 100"