@echo off
setlocal ENABLEDELAYEDEXPANSION
:: from ggos
:: CONFIRM ADMIN PRIVILEGES
dism >nul 2>&1 || exit

:: DISABLE THID PARTY SERVICES IF INSTALLED
sc config edgeupdate start=disabled >nul 2>&1
sc config edgeupdatem start=disabled >nul 2>&1
sc config gupdate start=disabled >nul 2>&1
sc config gupdatem start=disabled >nul 2>&1
sc config MozillaMaintenance start=disabled >nul 2>&1

:: STOP SERVICES
sc stop AppXSvc >nul 2>&1
sc stop BITS >nul 2>&1
sc stop ClipSvc >nul 2>&1
sc stop StorSvc >nul 2>&1
sc stop Wcmsvc >nul 2>&1

:: REMOVE OLD DEVICES
devicecleanup * -s -m:7d >nul 2>&1

:: LOWER PRIORITY OF SYSTEM PROCESSES -------------------------------------------------------------
:: values: "idle", "below normal", "normal", "above normal", "high priority", "realtime"
set /a CPU=%NUMBER_OF_CORES%*%MAX_CLOCK_SPEED%

wmic process where name="gamingservices.exe" call setpriority "below normal" >nul 2>&1
wmic process where name="searchindexer.exe" call setpriority "below normal" >nul 2>&1

if %CPU% GEQ 26000 goto:high
if %CPU% GEQ 19000 goto:mid
if %CPU% GEQ 12000 goto:low
exit

:high
wmic process where name="ctfmon.exe" call setpriority "normal" >nul 2>&1
wmic process where name="svchost.exe" call setpriority "below normal" >nul 2>&1
exit

:mid
wmic process where name="ctfmon.exe" call setpriority "above normal" >nul 2>&1
wmic process where name="svchost.exe" call setpriority "below normal" >nul 2>&1
exit

:low
wmic process where name="ctfmon.exe" call setpriority "above normal" >nul 2>&1
wmic process where name="svchost.exe" call setpriority "normal" >nul 2>&1
exit
