@echo off
cls

echo Disable Xbox Services?
echo.
echo Press "1" to Disable.
echo Press "2" to Enable.
echo.
set /P choice=:
if /I "%choice%"=="1" goto disable
if /I "%choice%" =="2" goto enable

:enable
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XblAuthManage" /v "Start" /t REG_DWORD /d "3" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f 
echo restart your pc
pause
exit /b

:disable
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XblAuthManage" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f 
echo restart your pc
pause
exit /b