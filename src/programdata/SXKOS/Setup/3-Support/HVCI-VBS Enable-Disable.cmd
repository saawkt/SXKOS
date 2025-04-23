@echo off
cls

echo Disable HVCI/VBS?
echo note: can improve performance at the cost of a layer of security
echo. 
echo --------------------------------
echo - 1. Disable HVCI/VBS -
echo - 2. Enable HVCI/VBS  -
echo --------------------------------
echo.
set /P choice=:
if /I "%choice%"=="1" goto disable
if /I "%choice%"=="2" goto enable
echo.

:disable
:: https://www.tomshardware.com/how-to/disable-vbs-windows-11
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
echo restart your pc
pause
exit /b

:enable
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "1" /f
echo restart your pc
pause
exit /b
