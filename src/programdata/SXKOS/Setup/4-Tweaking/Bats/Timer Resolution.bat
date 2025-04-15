e@echo off
color a
title Timer Resolution
:home
cls
echo.
echo --------------------------------------
echo - 1. Disable TimerResolution         -
echo - 2. Enable  0.5ms TimerResolution   -
echo - 3. Set custom TimerResolution      -
echo --------------------------------------
set /p menu2=Enter an option:
if %menu2% EQU 1 goto d
if %menu2% EQU 2 goto e
if %menu2% EQU 3 goto c
goto home

:d
powershell.exe Stop-Process -Name str >NUL 2>&1
Reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "ForceResolution" /f
timeout /t 2 /nobreak >NUL 2>&1
exit

:e
powershell.exe Stop-Process -Name str >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ForceResolution" /t REG_SZ /d "C:\Windows\str.exe --resolution 5000 --no-console" /f
start "" "C:\bin\3\TimerResolution.exe.exe" --resolution 5000 --no-console
timeout /t 2 /nobreak >NUL 2>&1
exit

:c
echo You need to write int values, example, if you want 0.5ms resolution then put 5000.
set /p value=Enter custom value (integers):
powershell.exe Stop-Process -Name str >NUL 2>&1
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ForceResolution" /t REG_SZ /d "C:\Windows\str.exe --resolution %value% --no-console" /f
start "" "C:\bin\3\TimerResolution.exe" --resolution %value% --no-console
timeout /t 2 /nobreak >NUL 2>&1
exit
