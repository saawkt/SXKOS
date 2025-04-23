@echo off
cls

echo Disable Windows Store?
echo.
echo Press "1" to Disable.
echo Press "2" to Enable.
Echo.
set /P choice=:
if /I "%choice%"=="2" goto enable
if /I "%choice%"=="1" goto disable
Echo.

:disable
for %%s in (
  iphlpsvc
  ClipSVC
  AppXSvc
  LicenseManager
  NgcSvc
  NgcCtnrSvc
  wlidsvc
  TokenBroker
  WalletService
  DoSvc
) do (
  Reg.exe add "HKLM\SYSTEM\ControlSet\Services%%s" /v "Start" /t REG_DWORD /d "4" /f
)

echo restart your pc
pause
exit /b

:enable
for %%s in (
  iphlpsvc
  ClipSVC
  AppXSvc
  LicenseManager
  NgcSvc
  NgcCtnrSvc
  wlidsvc
  TokenBroker
  WalletService
  DoSvc
) do (
  Reg.exe add "HKLM\SYSTEM\ControlSet\Services%%s" /v "Start" /t REG_DWORD /d "3" /f
)

echo restart your pc
pause
exit /b