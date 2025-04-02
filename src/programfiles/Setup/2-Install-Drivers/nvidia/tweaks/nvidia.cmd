@echo off
TITLE profile nvidia by sysnyxx
echo profile nvidia

:: download files
echo downloading nvidia profile inspector
curl -g -k -L -# -o "C:\Windows\Temp\npi.exe" "https://cdn.discordapp.com/attachments/1342571971627585606/1342577845611794573/nvidiaProfileInspector.exe?ex=67ba248e&is=67b8d30e&hm=8caafccbc591968a9efe90da33abbb56977904e0ad06202497c219e00488bd11&" >NUL 2>&1

curl -g -k -L -# -o "C:\Windows\Temp\reg.reg" "https://cdn.discordapp.com/attachments/1342571971627585606/1342607325717860412/reg_nvidia.reg?ex=67ba4002&is=67b8ee82&hm=0fa5b18d44aaf83897dca70c86445d9913f13cf78995d5fec5268c1485f427d4&" >NUL 2>&1

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

:menu
cls
echo Escolha uma opção:
echo 1 - Basic Profile (Recommended) - Perfil Basico(Recomendado)
echo 2 - Fps Average Profile - Perfil para fps
set /p escolha="Digite sua escolha (1 ou 2): "

if "%escolha%"=="1" (
    goto basic
) else if "%escolha%"=="2" (
    goto fps
) else (
    echo Escolha inválida. Tente novamente.
    pause
    goto menu
)

:basic
curl -g -k -L -# -o "C:\Windows\Temp\basic.nip" "https://cdn.discordapp.com/attachments/1342571971627585606/1342577636169482312/basic.nip?ex=67ba245c&is=67b8d2dc&hm=943f947153ee87ac403f73bf0d2f93ca4e18788bf8931228a947f176239e52aa&" >NUL 2>&1
"C:\Windows\Temp\npi.exe" "C:\Windows\Temp\basic.nip" >nul 2>&1
cd /d C:\Windows\Temp >nul 2>&1
del /f /q npi.exe >nul 2>&1
del /f /q basic.nip >nul 2>&1
exit /b

:fps
curl -g -k -L -# -o "C:\Windows\Temp\fps.nip" "https://cdn.discordapp.com/attachments/1342571971627585606/1342577636592844861/fps_average.nip?ex=67ba245c&is=67b8d2dc&hm=746a2f9e79ec13312679f3eb8e7465962b429aa511ade61ff5126afc8223619d&" >NUL 2>&1
"C:\Windows\Temp\npi.exe" "C:\Windows\Temp\fps.nip" >nul 2>&1
cd /d C:\Windows\Temp >nul 2>&1
del /f /q npi.exe >nul 2>&1
del /f /q fps.nip >nul 2>&1
exit /b