@echo off
TITLE nvidia tweaker by sysnyxx

:: download files
echo downloading nvidia profile inspector and regs
powershell Invoke-WebRequest -Uri "https://github.com/wasynxyxxk/files/raw/refs/heads/main/nvidia/nvidiaProfileInspector.exe" -OutFile "C:\Windows\Temp\npi.exe"
powershell Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wasynxyxxk/files/refs/heads/main/nvidia/reg_nvidia.reg" -OutFile "C:\Windows\Temp\reg.reg"
cls

:: tweaks
regedit /s C:\Windows\Temp\reg.reg
cd /d C:\Windows\Temp >nul 2>&1
del /f /q reg.reg >nul 2>&1

for /f %%g in ('wmic path win32_videocontroller get PNPDeviceID ^| findstr /L "VEN_"') do (
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "0" /f 
)
schtasks /change /disable /tn "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NvDriverUpdateCheckDaily_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
schtasks /change /disable /tn "NVIDIA GeForce Experience SelfUpdate_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f 
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
	for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\ControlSet001\Enum\%%i" /v "Driver"') do (
		for /f %%i in ('echo %%a ^| findstr "{"') do (
		     Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f > nul 2>&1
                   )
                )
             )
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d "0" /f
cls

:menu
cls
echo Choose an option:
echo 1 - Basic Profile (Recommended)
echo 2 - Fps Average 
echo 3 - Advanced profiles
set /p input="Enter your choice (1 or 2): "

if "%input%"=="1" (
    goto basic
) else if "%input%"=="2" (
    goto fps
) else if "%input%"=="3" (
    goto adprofiles
) else (
    echo invalid choice. try again.
    pause
    goto menu
)

:basic
cls
powershell Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wasynxyxxk/files/refs/heads/main/nvidia/basic.nip" -OutFile "C:\Windows\Temp\basic.nip"
"C:\Windows\Temp\npi.exe" "C:\Windows\Temp\basic.nip" >nul 2>&1
cd /d C:\Windows\Temp >nul 2>&1
del /f /q npi.exe >nul 2>&1
del /f /q basic.nip >nul 2>&1
echo done
timeout /t 2 /nobreak >NUL 2>&1
exit /b

:fps
cls
powershell Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wasynxyxxk/files/refs/heads/main/nvidia/fps.nip" -OutFile "C:\Windows\Temp\fps.nip"
"C:\Windows\Temp\npi.exe" "C:\Windows\Temp\fps.nip" >nul 2>&1
cd /d C:\Windows\Temp >nul 2>&1
del /f /q npi.exe >nul 2>&1
del /f /q fps.nip >nul 2>&1
echo done
timeout /t 2 /nobreak >NUL 2>&1
exit /b

:adprofiles
cls
echo these profiles are still being tested, they may decrease the performance of your GPU and not work with all games
echo. 
echo Choose an option:
echo 1 - Advanced
echo 2 - Latency 
echo 3 - Main Profiles
set /p input="Enter your choice (1 or 2): "

if "%input%"=="1" (
    goto advanced
) else if "%input%"=="2" (
    goto latency
) else if "%input%"=="3" (
    goto menu
) else (
    echo invalid choice. try again.
    pause
    goto menu
)

:latency
cls
powershell Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wasynxyxxk/files/refs/heads/main/nvidia/latency.nip" -OutFile "C:\Windows\Temp\latency.nip"
"C:\Windows\Temp\npi.exe" "C:\Windows\Temp\latency.nip" >nul 2>&1
cd /d C:\Windows\Temp >nul 2>&1
del /f /q npi.exe >nul 2>&1
del /f /q latency.nip >nul 2>&1
echo done
timeout /t 2 /nobreak >NUL 2>&1
exit /b

:advanced
cls
powershell Invoke-WebRequest -Uri "https://raw.githubusercontent.com/wasynxyxxk/files/refs/heads/main/nvidia/advanced.nip" -OutFile "C:\Windows\Temp\advanced.nip"
"C:\Windows\Temp\npi.exe" "C:\Windows\Temp\advanced.nip" >nul 2>&1
cd /d C:\Windows\Temp >nul 2>&1
del /f /q npi.exe >nul 2>&1
del /f /q advanced.nip >nul 2>&1
echo done
timeout /t 2 /nobreak >NUL 2>&1
exit /b


