@echo off
setlocal ENABLEDELAYEDEXPANSION
:menu
cls
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo                      ===================================================================
echo                         [1] Close Explorer.exe             [2] Open Explorer.exe 
echo                      ===================================================================
set /p input=^>
if /i %input% == 1 goto DISABLE
if /i %input% == 2 goto ENABLE

:DISABLE
taskkill /im explorer.exe /f >nul 2>&1
taskkill /im runtimebroker.exe /f >nul 2>&1
taskkill /im SearchUI.exe /f >nul 2>&1
taskkill /im SearchApp.exe /f >nul 2>&1
taskkill /im SearchHost.exe /f >nul 2>&1
taskkill /im StartMenuExperienceHost.exe /f >nul 2>&1
taskkill /im ShellExperienceHost.exe /f >nul 2>&1
taskkill /im WmiPrvSE.exe /f >nul 2>&1
goto :menu

:ENABLE
start explorer.exe >nul 2>&1
goto :menu