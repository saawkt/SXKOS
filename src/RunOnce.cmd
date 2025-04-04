@echo off
@title "Post-Install W11"
SETLOCAL EnableDelayedExpansion

taskkill /im explorer.exe /f >nul 2>&1
reg add "HKCR\Directory\background\shell\Item2" /v "MUIVerb" /t REG_SZ /d "dev sysnyxx" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v "RegisteredOrganization" /t REG_SZ /d "dev sysnyxx" /f >NUL 2>&1
powercfg -import "C:\Windows\co.pow" b0a71852-3be4-43b1-9aff-70d3c8430794
powercfg /s b0a71852-3be4-43b1-9aff-70d3c8430794
powershell set-executionpolicy unrestricted -force >nul 2>&1
setx POWERSHELL_TELEMETRY_OPTOUT 1 >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /t REG_SZ /d "." /f >nul 2>&1
label C: SXKOS-23H2-2.0.0
bcdedit /set {current} description "SXKOS-23H2-2.0.0"
cls

:: installers
echo Installing Visual C++
start /b /wait "" "C:\bin\1\Visual-C-Runtimes-All-in-One-Nov-2023\install_all.bat" >nul 2>&1
cls

echo Installing DirectX
cd /d "C:\bin\1" >NUL 2>&1
start /min /wait DirectX\#install.bat >NUL 2>&1
timeout /t 5 /nobreak >NUL 2>&1

echo Installing 7z
start /b /wait "" "C:\bin\1\7z2401-x64.msi" /passive >nul 2>&1
rd /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip"

::lightshot
echo installing lightshot
call "C:\bin\1\lightshot.exe" /VERYSILENT /NORESTART
timeout /t 2 /nobreak >NUL 2>&1
rd /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Lightshot" >nul 2>&1
rd /s /q "C:\Program Files (x86)\Skillbrains\Updater" >nul 2>&1

:: 7zip settings
Reg.exe add "HKCU\Software\7-Zip\FM\Columns" /v "RootFolder" /t REG_BINARY /d "0100000000000000010000000400000001000000A0000000" /f
Reg.exe add "HKCU\Software\7-Zip\Options" /v "ContextMenu" /t REG_DWORD /d "3221230439" /f
Reg.exe add "HKCU\Software\Classes\.001" /ve /t REG_SZ /d "7-Zip.001" /f
Reg.exe add "HKCU\Software\Classes\.7z" /ve /t REG_SZ /d "7-Zip.7z" /f
Reg.exe add "HKCU\Software\Classes\.apfs" /ve /t REG_SZ /d "7-Zip.apfs" /f
Reg.exe add "HKCU\Software\Classes\.arj" /ve /t REG_SZ /d "7-Zip.arj" /f
Reg.exe add "HKCU\Software\Classes\.bz2" /ve /t REG_SZ /d "7-Zip.bz2" /f
Reg.exe add "HKCU\Software\Classes\.bzip2" /ve /t REG_SZ /d "7-Zip.bzip2" /f
Reg.exe add "HKCU\Software\Classes\.cab" /ve /t REG_SZ /d "7-Zip.cab" /f
Reg.exe add "HKCU\Software\Classes\.cpio" /ve /t REG_SZ /d "7-Zip.cpio" /f
Reg.exe add "HKCU\Software\Classes\.deb" /ve /t REG_SZ /d "7-Zip.deb" /f
Reg.exe add "HKCU\Software\Classes\.dmg" /ve /t REG_SZ /d "7-Zip.dmg" /f
Reg.exe add "HKCU\Software\Classes\.esd" /ve /t REG_SZ /d "7-Zip.esd" /f
Reg.exe add "HKCU\Software\Classes\.fat" /ve /t REG_SZ /d "7-Zip.fat" /f
Reg.exe add "HKCU\Software\Classes\.gz" /ve /t REG_SZ /d "7-Zip.gz" /f
Reg.exe add "HKCU\Software\Classes\.gzip" /ve /t REG_SZ /d "7-Zip.gzip" /f
Reg.exe add "HKCU\Software\Classes\.hfs" /ve /t REG_SZ /d "7-Zip.hfs" /f
Reg.exe add "HKCU\Software\Classes\.iso" /ve /t REG_SZ /d "7-Zip.iso" /f
Reg.exe add "HKCU\Software\Classes\.lha" /ve /t REG_SZ /d "7-Zip.lha" /f
Reg.exe add "HKCU\Software\Classes\.lzh" /ve /t REG_SZ /d "7-Zip.lzh" /f
Reg.exe add "HKCU\Software\Classes\.lzma" /ve /t REG_SZ /d "7-Zip.lzma" /f
Reg.exe add "HKCU\Software\Classes\.ntfs" /ve /t REG_SZ /d "7-Zip.ntfs" /f
Reg.exe add "HKCU\Software\Classes\.rar" /ve /t REG_SZ /d "7-Zip.rar" /f
Reg.exe add "HKCU\Software\Classes\.rpm" /ve /t REG_SZ /d "7-Zip.rpm" /f
Reg.exe add "HKCU\Software\Classes\.squashfs" /ve /t REG_SZ /d "7-Zip.squashfs" /f
Reg.exe add "HKCU\Software\Classes\.swm" /ve /t REG_SZ /d "7-Zip.swm" /f
Reg.exe add "HKCU\Software\Classes\.tar" /ve /t REG_SZ /d "7-Zip.tar" /f
Reg.exe add "HKCU\Software\Classes\.taz" /ve /t REG_SZ /d "7-Zip.taz" /f
Reg.exe add "HKCU\Software\Classes\.tbz" /ve /t REG_SZ /d "7-Zip.tbz" /f
Reg.exe add "HKCU\Software\Classes\.tbz2" /ve /t REG_SZ /d "7-Zip.tbz2" /f
Reg.exe add "HKCU\Software\Classes\.tgz" /ve /t REG_SZ /d "7-Zip.tgz" /f
Reg.exe add "HKCU\Software\Classes\.tpz" /ve /t REG_SZ /d "7-Zip.tpz" /f
Reg.exe add "HKCU\Software\Classes\.txz" /ve /t REG_SZ /d "7-Zip.txz" /f
Reg.exe add "HKCU\Software\Classes\.vhd" /ve /t REG_SZ /d "7-Zip.vhd" /f
Reg.exe add "HKCU\Software\Classes\.vhdx" /ve /t REG_SZ /d "7-Zip.vhdx" /f
Reg.exe add "HKCU\Software\Classes\.wim" /ve /t REG_SZ /d "7-Zip.wim" /f
Reg.exe add "HKCU\Software\Classes\.xar" /ve /t REG_SZ /d "7-Zip.xar" /f
Reg.exe add "HKCU\Software\Classes\.xz" /ve /t REG_SZ /d "7-Zip.xz" /f
Reg.exe add "HKCU\Software\Classes\.z" /ve /t REG_SZ /d "7-Zip.z" /f
Reg.exe add "HKCU\Software\Classes\.zip" /ve /t REG_SZ /d "7-Zip.zip" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.001" /ve /t REG_SZ /d "001 Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.001\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,9" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.001\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.001\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.001\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.7z" /ve /t REG_SZ /d "7z Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.7z\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,0" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.7z\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.7z\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.7z\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.apfs" /ve /t REG_SZ /d "apfs Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.apfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,25" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.apfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.apfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.apfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.arj" /ve /t REG_SZ /d "arj Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.arj\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,4" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.arj\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.arj\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.arj\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bz2" /ve /t REG_SZ /d "bz2 Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bz2\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bz2\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bz2\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bz2\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bzip2" /ve /t REG_SZ /d "bzip2 Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bzip2\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bzip2\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bzip2\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.bzip2\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cab" /ve /t REG_SZ /d "cab Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cab\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,7" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cab\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cab\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cab\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cpio" /ve /t REG_SZ /d "cpio Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cpio\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,12" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cpio\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cpio\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.cpio\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.deb" /ve /t REG_SZ /d "deb Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.deb\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,11" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.deb\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.deb\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.deb\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.dmg" /ve /t REG_SZ /d "dmg Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.dmg\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,17" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.dmg\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.dmg\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.dmg\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.esd" /ve /t REG_SZ /d "esd Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.esd\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.esd\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.esd\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.esd\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.fat" /ve /t REG_SZ /d "fat Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.fat\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,21" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.fat\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.fat\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.fat\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gz" /ve /t REG_SZ /d "gz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gzip" /ve /t REG_SZ /d "gzip Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gzip\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gzip\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gzip\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.gzip\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.hfs" /ve /t REG_SZ /d "hfs Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.hfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,18" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.hfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.hfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.hfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.iso" /ve /t REG_SZ /d "iso Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.iso\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,8" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.iso\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.iso\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.iso\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lha" /ve /t REG_SZ /d "lha Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lha\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,6" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lha\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lha\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lha\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzh" /ve /t REG_SZ /d "lzh Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzh\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,6" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzh\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzh\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzh\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzma" /ve /t REG_SZ /d "lzma Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzma\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,16" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzma\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzma\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.lzma\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.ntfs" /ve /t REG_SZ /d "ntfs Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.ntfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,22" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.ntfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.ntfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.ntfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rar" /ve /t REG_SZ /d "rar Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rar\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,3" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rar\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rar\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rar\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rpm" /ve /t REG_SZ /d "rpm Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rpm\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,10" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rpm\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rpm\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.rpm\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.squashfs" /ve /t REG_SZ /d "squashfs Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.squashfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,24" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.squashfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.squashfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.squashfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.swm" /ve /t REG_SZ /d "swm Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.swm\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.swm\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.swm\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.swm\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tar" /ve /t REG_SZ /d "tar Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tar\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,13" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tar\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tar\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tar\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.taz" /ve /t REG_SZ /d "taz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.taz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,5" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.taz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.taz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.taz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz" /ve /t REG_SZ /d "tbz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz2" /ve /t REG_SZ /d "tbz2 Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz2\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz2\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz2\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz2\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tbz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tgz" /ve /t REG_SZ /d "tgz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tgz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tgz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tgz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tgz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tpz" /ve /t REG_SZ /d "tpz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tpz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tpz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tpz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.tpz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.txz" /ve /t REG_SZ /d "txz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.txz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,23" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.txz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.txz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.txz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhd" /ve /t REG_SZ /d "vhd Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhd\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,20" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhd\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhd\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhd\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhdx" /ve /t REG_SZ /d "vhdx Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhdx\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,20" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhdx\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhdx\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.vhdx\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.wim" /ve /t REG_SZ /d "wim Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.wim\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.wim\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.wim\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.wim\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xar" /ve /t REG_SZ /d "xar Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xar\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,19" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xar\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xar\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xar\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xz" /ve /t REG_SZ /d "xz Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,23" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.xz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.z" /ve /t REG_SZ /d "z Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.z\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,5" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.z\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.z\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.z\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.zip" /ve /t REG_SZ /d "zip Archive" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.zip\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,1" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.zip\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.zip\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\7-Zip.zip\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\.001" /ve /t REG_SZ /d "7-Zip.001" /f
Reg.exe add "HKLM\Software\Classes\.7z" /ve /t REG_SZ /d "7-Zip.7z" /f
Reg.exe add "HKLM\Software\Classes\.apfs" /ve /t REG_SZ /d "7-Zip.apfs" /f
Reg.exe add "HKLM\Software\Classes\.arj" /ve /t REG_SZ /d "7-Zip.arj" /f
Reg.exe delete "HKLM\Software\Classes\.arj" /v "DontCompressInPackage" /f
Reg.exe add "HKLM\Software\Classes\.bz2" /ve /t REG_SZ /d "7-Zip.bz2" /f
Reg.exe add "HKLM\Software\Classes\.bzip2" /ve /t REG_SZ /d "7-Zip.bzip2" /f
Reg.exe add "HKLM\Software\Classes\.cab" /ve /t REG_SZ /d "7-Zip.cab" /f
Reg.exe delete "HKLM\Software\Classes\.cab" /v "PerceivedType" /f
Reg.exe delete "HKLM\Software\Classes\.cab\OpenWithProgids" /f
Reg.exe delete "HKLM\Software\Classes\.cab\PersistentHandler" /f
Reg.exe add "HKLM\Software\Classes\.cpio" /ve /t REG_SZ /d "7-Zip.cpio" /f
Reg.exe add "HKLM\Software\Classes\.deb" /ve /t REG_SZ /d "7-Zip.deb" /f
Reg.exe add "HKLM\Software\Classes\.dmg" /ve /t REG_SZ /d "7-Zip.dmg" /f
Reg.exe add "HKLM\Software\Classes\.esd" /ve /t REG_SZ /d "7-Zip.esd" /f
Reg.exe add "HKLM\Software\Classes\.fat" /ve /t REG_SZ /d "7-Zip.fat" /f
Reg.exe add "HKLM\Software\Classes\.gz" /ve /t REG_SZ /d "7-Zip.gz" /f
Reg.exe delete "HKLM\Software\Classes\.gz" /v "Content Type" /f
Reg.exe delete "HKLM\Software\Classes\.gz" /v "PerceivedType" /f
Reg.exe delete "HKLM\Software\Classes\.gz\PersistentHandler" /f
Reg.exe add "HKLM\Software\Classes\.gzip" /ve /t REG_SZ /d "7-Zip.gzip" /f
Reg.exe add "HKLM\Software\Classes\.hfs" /ve /t REG_SZ /d "7-Zip.hfs" /f
Reg.exe add "HKLM\Software\Classes\.iso" /ve /t REG_SZ /d "7-Zip.iso" /f
Reg.exe delete "HKLM\Software\Classes\.iso\OpenWithProgids" /f
Reg.exe add "HKLM\Software\Classes\.lha" /ve /t REG_SZ /d "7-Zip.lha" /f
Reg.exe add "HKLM\Software\Classes\.lzh" /ve /t REG_SZ /d "7-Zip.lzh" /f
Reg.exe delete "HKLM\Software\Classes\.lzh" /v "DontCompressInPackage" /f
Reg.exe add "HKLM\Software\Classes\.lzma" /ve /t REG_SZ /d "7-Zip.lzma" /f
Reg.exe add "HKLM\Software\Classes\.ntfs" /ve /t REG_SZ /d "7-Zip.ntfs" /f
Reg.exe add "HKLM\Software\Classes\.rar" /ve /t REG_SZ /d "7-Zip.rar" /f
Reg.exe add "HKLM\Software\Classes\.rpm" /ve /t REG_SZ /d "7-Zip.rpm" /f
Reg.exe add "HKLM\Software\Classes\.squashfs" /ve /t REG_SZ /d "7-Zip.squashfs" /f
Reg.exe add "HKLM\Software\Classes\.swm" /ve /t REG_SZ /d "7-Zip.swm" /f
Reg.exe delete "HKLM\Software\Classes\.tar" /v "PerceivedType" /f
Reg.exe delete "HKLM\Software\Classes\.tar" /v "Content Type" /f
Reg.exe add "HKLM\Software\Classes\.tar" /ve /t REG_SZ /d "7-Zip.tar" /f
Reg.exe delete "HKLM\Software\Classes\.tar\PersistentHandler" /f
Reg.exe add "HKLM\Software\Classes\.taz" /ve /t REG_SZ /d "7-Zip.taz" /f
Reg.exe add "HKLM\Software\Classes\.tbz" /ve /t REG_SZ /d "7-Zip.tbz" /f
Reg.exe add "HKLM\Software\Classes\.tbz2" /ve /t REG_SZ /d "7-Zip.tbz2" /f
Reg.exe delete "HKLM\Software\Classes\.tgz" /v "PerceivedType" /f
Reg.exe delete "HKLM\Software\Classes\.tgz" /v "Content Type" /f
Reg.exe add "HKLM\Software\Classes\.tgz" /ve /t REG_SZ /d "7-Zip.tgz" /f
Reg.exe delete "HKLM\Software\Classes\.tgz\PersistentHandler" /f
Reg.exe add "HKLM\Software\Classes\.tpz" /ve /t REG_SZ /d "7-Zip.tpz" /f
Reg.exe add "HKLM\Software\Classes\.txz" /ve /t REG_SZ /d "7-Zip.txz" /f
Reg.exe add "HKLM\Software\Classes\.vhd" /ve /t REG_SZ /d "7-Zip.vhd" /f
Reg.exe add "HKLM\Software\Classes\.vhdx" /ve /t REG_SZ /d "7-Zip.vhdx" /f
Reg.exe add "HKLM\Software\Classes\.wim" /ve /t REG_SZ /d "7-Zip.wim" /f
Reg.exe add "HKLM\Software\Classes\.xar" /ve /t REG_SZ /d "7-Zip.xar" /f
Reg.exe add "HKLM\Software\Classes\.xz" /ve /t REG_SZ /d "7-Zip.xz" /f
Reg.exe delete "HKLM\Software\Classes\.z" /v "Content Type" /f
Reg.exe delete "HKLM\Software\Classes\.z" /v "DontCompressInPackage" /f
Reg.exe add "HKLM\Software\Classes\.z" /ve /t REG_SZ /d "7-Zip.z" /f
Reg.exe delete "HKLM\Software\Classes\.z" /v "PerceivedType" /f
Reg.exe delete "HKLM\Software\Classes\.z\PersistentHandler" /f
Reg.exe add "HKLM\Software\Classes\.zip" /ve /t REG_SZ /d "7-Zip.zip" /f
Reg.exe delete "HKLM\Software\Classes\.zip" /v "Content Type" /f
Reg.exe delete "HKLM\Software\Classes\.zip" /v "DontCompressInPackage" /f
Reg.exe delete "HKLM\Software\Classes\.zip" /v "PerceivedType" /f
Reg.exe delete "HKLM\Software\Classes\.zip\CompressedFolder" /f
Reg.exe delete "HKLM\Software\Classes\.zip\OpenWithProgids" /f
Reg.exe delete "HKLM\Software\Classes\.zip\PersistentHandler" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.001" /ve /t REG_SZ /d "001 Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.001\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,9" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.001\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.001\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.001\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.7z" /ve /t REG_SZ /d "7z Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.7z\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,0" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.7z\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.7z\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.7z\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.apfs" /ve /t REG_SZ /d "apfs Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.apfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,25" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.apfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.apfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.apfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.arj" /ve /t REG_SZ /d "arj Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.arj\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,4" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.arj\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.arj\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.arj\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bz2" /ve /t REG_SZ /d "bz2 Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bz2\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bz2\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bz2\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bz2\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bzip2" /ve /t REG_SZ /d "bzip2 Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bzip2\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bzip2\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bzip2\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.bzip2\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cab" /ve /t REG_SZ /d "cab Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cab\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,7" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cab\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cab\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cab\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cpio" /ve /t REG_SZ /d "cpio Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cpio\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,12" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cpio\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cpio\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.cpio\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.deb" /ve /t REG_SZ /d "deb Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.deb\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,11" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.deb\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.deb\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.deb\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.dmg" /ve /t REG_SZ /d "dmg Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.dmg\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,17" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.dmg\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.dmg\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.dmg\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.esd" /ve /t REG_SZ /d "esd Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.esd\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.esd\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.esd\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.esd\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.fat" /ve /t REG_SZ /d "fat Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.fat\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,21" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.fat\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.fat\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.fat\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gz" /ve /t REG_SZ /d "gz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gzip" /ve /t REG_SZ /d "gzip Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gzip\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gzip\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gzip\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.gzip\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.hfs" /ve /t REG_SZ /d "hfs Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.hfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,18" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.hfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.hfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.hfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.iso" /ve /t REG_SZ /d "iso Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.iso\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,8" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.iso\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.iso\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.iso\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lha" /ve /t REG_SZ /d "lha Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lha\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,6" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lha\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lha\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lha\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzh" /ve /t REG_SZ /d "lzh Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzh\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,6" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzh\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzh\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzh\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzma" /ve /t REG_SZ /d "lzma Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzma\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,16" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzma\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzma\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.lzma\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.ntfs" /ve /t REG_SZ /d "ntfs Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.ntfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,22" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.ntfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.ntfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.ntfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rar" /ve /t REG_SZ /d "rar Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rar\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,3" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rar\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rar\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rar\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rpm" /ve /t REG_SZ /d "rpm Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rpm\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,10" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rpm\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rpm\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.rpm\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.squashfs" /ve /t REG_SZ /d "squashfs Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.squashfs\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,24" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.squashfs\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.squashfs\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.squashfs\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.swm" /ve /t REG_SZ /d "swm Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.swm\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.swm\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.swm\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.swm\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tar" /ve /t REG_SZ /d "tar Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tar\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,13" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tar\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tar\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tar\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.taz" /ve /t REG_SZ /d "taz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.taz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,5" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.taz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.taz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.taz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz" /ve /t REG_SZ /d "tbz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz2" /ve /t REG_SZ /d "tbz2 Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz2\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz2\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz2\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz2\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,2" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tbz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tgz" /ve /t REG_SZ /d "tgz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tgz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tgz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tgz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tgz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tpz" /ve /t REG_SZ /d "tpz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tpz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,14" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tpz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tpz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.tpz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.txz" /ve /t REG_SZ /d "txz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.txz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,23" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.txz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.txz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.txz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhd" /ve /t REG_SZ /d "vhd Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhd\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,20" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhd\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhd\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhd\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhdx" /ve /t REG_SZ /d "vhdx Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhdx\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,20" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhdx\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhdx\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.vhdx\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.wim" /ve /t REG_SZ /d "wim Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.wim\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,15" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.wim\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.wim\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.wim\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xar" /ve /t REG_SZ /d "xar Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xar\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,19" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xar\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xar\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xar\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xz" /ve /t REG_SZ /d "xz Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xz\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,23" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xz\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xz\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.xz\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.z" /ve /t REG_SZ /d "z Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.z\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,5" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.z\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.z\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.z\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.zip" /ve /t REG_SZ /d "zip Archive" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.zip\DefaultIcon" /ve /t REG_SZ /d "C:\Program Files\7-Zip\7z.dll,1" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.zip\shell" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.zip\shell\open" /ve /t REG_SZ /d "" /f
Reg.exe add "HKLM\Software\Classes\7-Zip.zip\shell\open\command" /ve /t REG_SZ /d "\"C:\Program Files\7-Zip\7zFM.exe\" \"%%1\"" /f
cls

start /b /wait "" "C:\bin\1\Visual-C-Runtimes-All-in-One-Nov-2023\install_all.bat" >nul 2>&1

::DWMEnableMMCSS
move "C:\bin\4\DWMEnableMMCSS.exe.lnk" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

::Eliminar cosas inutiles
cls
echo.
echo Deleting useless files...
PowerRun.exe /SW:0 taskkill.exe /im "HelpPane.exe" /t /f >NUL 2>&1
PowerRun.exe /SW:0 cmd.exe /c del /F /Q "%SYSTEMDRIVE%\Windows\HelpPane.exe"

::BCDEDIT SETTINGS
cls
echo.
echo Tweaking BCDedit...
bcdedit /timeout 10
bcdedit /set useplatformtick Yes
bcdedit /set disabledynamictick Yes
bcdedit /set bootmenupolicy Legacy
bcdedit /set quietboot On
bcdedit /set nx OptIn
timeout /t 3 /nobreak >NUL 2>&1

::Configurar Device Manager
::Nirsoft Software
cls
echo.
echo Setting up Device Manager...
dmv /disable "System Speaker"
dmv /disable "System Timer"
dmv /disable "High precision event timer"
dmv /disable "WAN Miniport (IKEv2)"
dmv /disable "WAN Miniport (IP)"
dmv /disable "WAN Miniport (IPv6)"
dmv /disable "WAN Miniport (L2TP)"
dmv /disable "WAN Miniport (Network Monitor)"
dmv /disable "WAN Miniport (PPPOE)"
dmv /disable "WAN Miniport (PPTP)"
dmv /disable "WAN Miniport (SSTP)"
dmv /disable "Direct memory access controller"
dmv /disable "System CMOS/real time clock"
dmv /disable "Unknown device"
dmv /disable "UMBus Root Bus Enumerator"
dmv /disable "Programmable Interrupt Controller"
dmv /disable "Composite Bus Enumerator"
dmv /disable "Numeric Data Processor"
dmv /disable "Legacy Device"
dmv /disable "PCI Memory Controller"
dmv /disable "PCI Simple Communications Controller"
dmv /disable "SM Bus Controller"
dmv /disable "PCI Data Acquisition and Signal Processing Controller"
dmv /disable "Base System Device"
timeout /t 3 /nobreak >NUL 2>&1

:{done}
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "0000000000" /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "0000000000" /F
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security" /V "DisableSecuritySettingsCheck" /T "REG_DWORD" /D "00000001" /F
cls
echo Please Wait...
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{6bdd1fc6-810f-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "LowerFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{71a27cdd-812a-11d0-bec7-08002be2092f}" /v "UpperFilters" /t REG_MULTI_SZ /d "" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dhcp" /v "DependOnService" /t REG_MULTI_SZ /d "NSI\0Afd" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache" /v "DependOnService" /t REG_MULTI_SZ /d "nsi" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v "InactivityShutdownDelay" /t REG_DWORD /d "4294967295" /f
for %%z in (
      DsmSvc
      autotimesvc
      W32Time
      DsSvc
      icssvc
      IKEEXT
      PcaSvc
      ShellHWDetection
      tzautoupdate
      OneSyncSvc
      Beep
      cdfs
      cdrom
      acpiex
      acpipagr
      acpipmi
      acpitime
      cnghwassist
      GpuEnergyDrv
      Telemetry
      VerifierExt
      udfs
      MsLldp
      lltdio
      NdisVirtualBus
      NDU
      luafv
      fvevol
      UsoSvc
      cbdhsvc
      BcastDVRUserService
      rdyboost
      rdpbus
      umbus
      vdrvroot
      CompositeBus
      rspndr
      NdisCap
      NetBIOS
      NetBT
      spaceport
      VaultSvc
      EventSystem
      bam
      bowser
      WarpJITSvc
      Wecsvc
      dmwappushservice
      GraphicsPerfSvc
      WMPNetworkSvc
      TermService
      UmRdpService
      PimIndexMaintenanceSvc
      UserDataSvc
      3ware
      arcsas
      buttonconverter
      circlass
      Dfsc
      ErrDev
      mrxsmb
      mrxsmb20
      PEAUTH
      QWAVEdrv
      srv
      SiSRaid2
      SiSRaid4
      Tcpip6
      tcpipreg
      vsmraid
      VSTXRAID
      wcnfs
      WindowsTrustedRTProxy
      SstpSvc
      SSDPSRV
      SmsRouter
      CldFlt
      DisplayEnhancementService
      iphlpsvc
      IpxlatCfgSvc
      NetTcpPortSharing
      KtmRm
      LanmanWorkstation
      LanmanServer
      lmhosts
      MSDTC
      QWAVE
      RmSvc
      RFCOMM
      BthEnum
      bthleenum
      BTHMODEM
      BthA2dp
      microsoft_bluetooth_avrcptransport
      BthHFEnum
      BTAGService
      bthserv
      BluetoothUserService
      BthAvctpSvc
      TsUsbFlt
      tsusbhub
      storflt
      RDPDR
      bttflt
      HidBth
      BthMini
      BTHPORT
      BTHUSB
      vmicrdv
      vmictimesync
      vmicvss
      hvservice
      HvHost
      lfsvc
      CldFlt
      defragsvc
      dispbrokerdesktopsvc
      dam
      FontCache
      FontCache3.0.0.0
      lfsvc
      lmhosts
      mslldp
      microsoft_bluetooth_avrcptransport
      Ndu
      NetTcpPortSharing
      UsoSvc
      PcaSvc
      PimIndexMaintenanceSvc
      printworkflowusersvc
      PhoneSvc
      rspndr
      rdyboost
      RmSvc
      RFCOMM
      SharedAccess
      SysMain
      spooler
      spaceport
      Themes
      TapiSrv
      tcpipreg
      UserDataSvc
      UnistoreSvc
      udfs
      vmickvpexchange
      vmicguestinterface
      vmicshutdown
      vmicheartbeat
      vmicvmsession
      vmicrdv
      vmictimesync
      vmicvss
      W32Time
      WaaSMedicSvc
      WSearch
      WPDBusEnum
      WMPNetworkSvc
) do (
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%z" /v "Start" /t REG_DWORD /d "4" /f
)
cls

:: Drivers
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdsvc" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lltdio" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsLldp" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Beep" /v "Start" /t REG_DWORD /d "4" /f

:{svcno}
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f
sc delete nvagent >NUL 2>&1
start /b /wait "" "C:\bin\4\drvset.bat" >NUL 2>&1
timeout /t 5 /nobreak >NUL 2>&1
del /F /Q "%SYSTEMDRIVE%\Windows\dmv.exe" >NUL 2>&1
del /F /Q "C:\bin\4\drvset.bat" >NUL 2>&1
rd /s /q %WINDIR%\Temp\ >NUL 2>&1
if exist "%SYSTEMDRIVE%\Program Files (x86)\Microsoft\Edge\Application" (
    for /f "delims=" %%a in ('where /r "%SYSTEMDRIVE%\Program Files (x86)\Microsoft\Edge\Application" *setup.exe*') do (
        if exist "%%a" (
            "%%a" --uninstall --system-level --verbose-logging --force-uninstall
        )
    )
)
sc delete edgeupdate >NUL 2>&1
sc delete edgeupdatem >NUL 2>&1

:: Disable SchTasks
:: From AtlasOS
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\MicrosoftEdgeUpdateTaskMachineCore" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\MicrosoftEdgeUpdateTaskMachineUA" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Autochk\Proxy" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\DiskFootprint\StorageSense" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\MicrosoftEdgeUpdateBrowserReplacementTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Report policies" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Work" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\UPnP\UPnPHostConfig" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\RetailDemo\CleanupOfflineContent" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\InstallService\SmartRetry" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\International\Synchronize Language Settings" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Multimedia\Microsoft\Windows\Multimedia" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Printing\EduPrintProv" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Ras\MobilityManager" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\PushToInstall\LoginCheck" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\SynchronizeTime" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Time Zone\SynchronizeTimeZone" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\WaaSMedic\PerformRemediation" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Wininet\CacheTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Device Setup\Metadata Refresh" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Shell\FamilySafetyUpload" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Application Experience\AitAgent" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Application Experience\StartupAppTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Autochk\Proxy" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /change /Disable /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\AppID\SmartScreenSpecific" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\PI\Sqm-Tasks" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\DiskFootprint\Diagnostics" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >NUL 2>&1
PowerRun.exe /SW:0 schtasks.exe /Change /Disable /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" >NUL 2>&1
timeout /t 10 /nobreak >NUL 2>&1
rd /s /q "%SYSTEMDRIVE%\Program Files (x86)\Microsoft" >NUL 2>&1

net accounts /maxpwage:unlimited
powercfg /hibernate off

:: BlitzOS Script (Spectre meltdown)
wmic cpu get name | findstr "Intel" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
move "C:\bin\3\xhci.cmd" "%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"
)
wmic cpu get name | findstr "AMD" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 64 /f
)

:: cleaner
rd /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\7-Zip"
rd /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Lightshot"
reg delete "HKLM\SOFTWARE\WOW6432Node\Skillbrains\Updater" /f
rd /s /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Open-Shell"
Reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Open-Shell Start Menu" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Open-Shell Start Menu" /f >nul 2>&1
for %%i in (pdate) do (for /f "tokens=1 delims=," %%a in ('schtasks /query /fo csv ^| findstr /v "TaskName" ^| findstr "%%~i" ^| findstr /v "Microsoft\\Windows"') do (schtasks /delete /tn %%a /f)) >nul 2>&1
rd /s /q "C:\Program Files (x86)\Skillbrains\Updater"

:: BlitzOS again
call NSudoLG.exe -ShowWindowMode:hide -U:S -P:E cmd /c "for /f "delims=" %%a in ('reg QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture"') do (reg add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t Reg_DWORD /d 0 /f & reg add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t Reg_DWORD /d 0 /f) & for /f "delims=" %%a in ('reg QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"') do (reg add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t Reg_DWORD /d 0 /f & reg add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t Reg_DWORD /d 0 /f)"
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >nul 2>&1

:: Keyboard and Mouse Settings
Echo "Configuring "Keyboard and Mouse Settings"
Reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Keyboard" /v "KeyboardSpeed" /t REG_SZ /d "31" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >nul 2>&1
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >nul 2>&1

:: visual effects
Echo "Visual Effects"
Reg.exe add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010000000" /f > NUL 2>&1
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f >nul 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Blur" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "Animations" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DWMA_TRANSITTIONS_FORCEDISABLED" /t REG_DWORD /d "1" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "DisallowAnimations" /t REG_DWORD /d "1" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DWM" /v "AnimationAttributionEnabled" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f > NUL 2>&1
Reg.exe Add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f > NUL 2>&1
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f > NUL 2>&1
Reg.exe delete "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /f >nul 2>&1
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /f >nul 2>&1

:: disable network adapters
Echo "Disabling network adapters"
powershell -NoProfile -Command "Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6, ms_msclient, ms_server, ms_rspndr, ms_lltdio, ms_implat, ms_lldp" >nul 2>&1
cls

:: netbios 
Echo "Disabling NetBIOS over TCP/IP"
for /f "delims=" %%u in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions" ^| findstr "HKEY"') do (
    reg add "%%u" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
)
cls

:: autologgers
Echo "Disabling AutoLoggers and Firewall Rules"
C:\Windows\PowerRun.exe "powershell.exe" Remove-AutologgerConfig -Name "autologger-diagtrack-listener", "cellcore", "cloudexperiencehostoobe", "lwtnetlog", "mellanox-Kernel", "microsoft-windows-assignedaccess-trace", "microsoft-windows-rdp-graphics-rdpidd-trace"
cls

:: dma remapping
Echo "Disabling DMA Remapping"
for %%a in (DmaRemappingCompatible) do for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f >nul 2>&1
cls

:: exclusive mode audio
Echo "Disabling Exclusive Mode On Audio Devices"
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do PowerRun.exe /SW:0 Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Capture') do PowerRun.exe /SW:0 Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do PowerRun.exe /SW:0 Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},3" /t REG_DWORD /d "0" /f >nul 2>&1
for /f "delims=" %%a in ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render') do PowerRun.exe /SW:0 Reg.exe add "%%a\Properties" /v "{b3f8fa53-0004-438e-9003-51a46e139bfc},4" /t REG_DWORD /d "0" /f >nul 2>&1
cls

:: power tweaks
powercfg -h off
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowHibernateOption" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t Reg_DWORD /d "0" /f  >nul 2>&1
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t Reg_DWORD /d "0" /f >nul 2>&1
wevtutil set-log "Microsoft-Windows-SleepStudy/Diagnostic" /e:false >nul 2>&1
wevtutil set-log "Microsoft-Windows-Kernel-Processor-Power/Diagnostic" /e:false >nul 2>&1
wevtutil set-log "Microsoft-Windows-UserModePowerService/Diagnostic" /e:false >nul 2>&1
cls

:: Scheduled Tasks
Echo "Optimizing Scheduled Tasks"
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Diagnosis\Scheduled" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\DiskFootprint\Diagnostics" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdates" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\InstallService\ScanForUpdatesAsUser" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Registry\RegIdleBackup" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\StateRepository\MaintenanceTasks" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\SystemRestore\SR" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\WDI\ResolutionHost" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\ApplicationData\appuriverifierdaily" >nul 2>&11
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Application Experience\StartupAppTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Application Experience\MareBackup" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Autochk\Proxy" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Device Information\Device User" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Device Information\Device" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Input\LocalUserSyncDataAvailable" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Input\MouseSyncDataAvailable" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Input\PenSyncDataAvailable" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Input\syncpensettings" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Input\TouchpadSyncDataAvailable" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Location\Notifications" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Location\WindowsActionDialog" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Maintenance\WinSAT" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\PI\Sqm-Tasks" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Maps\MapsToastTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\Maps\MapsUpdateTask" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" >nul 2>&1
powerrun "schtasks.exe" /change /disable /TN "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\TaskScheduler" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\WaaSMedic" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\WindowsUpdate" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work" >nul 2>&1
powerrun "schtasks.exe" /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work" >nul 2>&1
cls

:: Driver PowerSaving
Echo "Disable Driver PowerSaving"
%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"

Echo "Disabling PowerSaving Features"
for %%a in (
	EnhancedPowerManagementEnabled
	AllowIdleIrpInD3
	EnableSelectiveSuspend
	DeviceSelectiveSuspended
	SelectiveSuspendEnabled
	SelectiveSuspendOn
	WaitWakeEnabled
	D3ColdSupported
	WdfDirectedPowerTransitionEnable
	EnableIdlePowerManagement
	IdleInWorkingState
) do for /f "delims=" %%b in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum" /s /f "%%a" ^| findstr "HKEY"') do Reg.exe add "%%b" /v "%%a" /t REG_DWORD /d "0" /f > NUL 2>&1
cls

Echo "Configuring NIC"
for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}" /v "*SpeedDuplex" /s ^| findstr "HKEY"') do (
    for /f %%i in ('reg query "%%a" /v "*DeviceSleepOnDisconnect" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*DeviceSleepOnDisconnect" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*EEE" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*FlowControl" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*IPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*InterruptModeration" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*InterruptModeration" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*LsoV2IPv4" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*LsoV2IPv6" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*LsoV2IPv6" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*NumRssQueues" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*NumRssQueues" /t REG_SZ /d "2" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*PMARPOffload" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*PMARPOffload" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*PMNSOffload" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*PMNSOffload" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*PriorityVLANTag" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*PriorityVLANTag" /t REG_SZ /d "1" /f >nul 2>&1  
    )
    for /f %%i in ('reg query "%%a" /v "*RSS" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*RSS" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "*WakeOnPattern" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*ReceiveBuffers" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*ReceiveBuffers" /t REG_SZ /d "2048" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*TransmitBuffers" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*TransmitBuffers" /t REG_SZ /d "2048" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv4" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv6" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "DMACoalescing" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "DMACoalescing" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EEELinkAdvertisement" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "EeePhyEnable" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EeePhyEnable" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "ITR" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ITR" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "PowerDownPll" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PowerDownPll" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WaitAutoNegComplete" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WaitAutoNegComplete" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnLink" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnLink" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "WakeOnSlot" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnSlot" /t REG_SZ /d "0" /f >nul 2>&1
    )
	    for /f %%i in ('reg query "%%a" /v "WakeUpModeCap" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeUpModeCap" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "AdvancedEEE" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "GigaLite" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "PnPCapabilities" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PnPCapabilities" /t REG_DWORD /d "24" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "PowerSavingMode" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "S5WakeOnLan" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >nul 2>&1   
    )
	    for /f %%i in ('reg query "%%a" /v "SavePowerNowEnabled" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "SavePowerNowEnabled" /t REG_SZ /d "0" /f >nul 2>&1
    )
	    for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "ULPMode" /t REG_SZ /d "0" /f >nul 2>&1
    )
    for /f %%i in ('reg query "%%a" /v "WolShutdownLinkSpeed" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "LogLinkStateEvent" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "LogLinkStateEvent" /t REG_SZ /d "16" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "WakeOnMagicPacketFromS5" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "WakeOnMagicPacketFromS5" /t REG_SZ /d "0" /f >nul 2>&1   
	)
	for /f %%i in ('reg query "%%a" /v "Ultra Low Power Mode" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Ultra Low Power Mode" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "System Idle Power Saver" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "System Idle Power Saver" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "Selective Suspend" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Selective Suspend" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "Selective Suspend Idle Timeout" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Selective Suspend Idle Timeout" /t REG_SZ /d "60" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "Link Speed Battery Saver" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "Link Speed Battery Saver" /t REG_SZ /d "Disabled" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*SelectiveSuspend" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*SelectiveSuspend" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnablePME" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "TxIntDelay" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "TxIntDelay" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "TxDelay" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "TxDelay" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnableModernStandby" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableModernStandby" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*ModernStandbyWoLMagicPacket" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*ModernStandbyWoLMagicPacket" /t REG_SZ /d "0" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "EnableLLI" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "EnableLLI" /t REG_SZ /d "1" /f >nul 2>&1   
    )
    for /f %%i in ('reg query "%%a" /v "*SSIdleTimeout" ^| findstr "HKEY"') do (
        Reg.exe add "%%i" /v "*SSIdleTimeout" /t REG_SZ /d "60" /f >nul 2>&1   
    )
) >nul 2>&1
cls

Echo "Enabling MSI mode & set to undefined"
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
:: Probably will be reset by installing GPU driver
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f >nul 2>nul
cls

Echo "Remove Share from context menu"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f > nul
reg add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" /t REG_SZ /d "" /f > nul
cls

Echo "Removing Quick access"
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f >nul 2>&1
PowerRun.exe /SW:0 Reg.exe add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f >nul 2>&1
cls

Echo "Disable powerthorttling on laptop"
for /f "delims=:{}" %%a in ('wmic path Win32_SystemEnclosure get ChassisTypes ^| findstr [0-9]') do set "CHASSIS=%%a"
set "DEVICE_TYPE=PC"
for %%a in (8 9 10 11 12 13 14 18 21 30 31 32) do if "%CHASSIS%" == "%%a" (set "DEVICE_TYPE=LAPTOP")

if "%DEVICE_TYPE%" == "LAPTOP" (
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serenum" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sermouse" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\serial" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "0" /f
    cls
)
) else (
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
    Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f  >nul 2>&1
    cls
)

Echo "Fix explorer white bar bug"
cmd /c "start C:\Windows\explorer.exe"
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
taskkill /f /im explorer.exe >nul 2>&1
cmd /c "start C:\Windows\explorer.exe"
cls

Echo "Enabling legacy photo viewer"
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.bmp" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.dib" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.gif" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jxr" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jpe" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jpeg" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jpg" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.png" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts" /v "PhotoViewer.FileAssoc.Tiff_.jfif" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\UserChoice" /v "ProgId" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
cls

:: done
del "%HOMEPATH%\AppData\Local\updater.log" >nul 2>&1
del "%HOMEPATH%\AppData\Local\UserProducts.xml" >nul 2>&1
del "%SYSTEMROOT%\Logs\DirectX.log" >nul 2>&1
del "%SYSTEMROOT%\DirectX.log" >nul 2>&1
del "%SYSTEMROOT%\DtcInstall.log" >nul 2>&1
del "%SYSTEMROOT%\lsasetup.log" >nul 2>&1
del "%SYSTEMROOT%\setupact.log" >nul 2>&1
del "%SYSTEMROOT%\setuperr.log" >nul 2>&1
del "%SYSTEMROOT%\WindowsUpdate.log" >nul 2>&1
del /q /f /s %TEMP%\ >nul 2>&1
del /q/f/s %SYSTEMROOT%\Logs\* >nul 2>&1
del /q/f/s %SYSTEMROOT%\Temp\* >nul 2>&1
del /q/f/s %SYSTEMROOT%\SoftwareDistribution\* >nul 2>&1
del /s /f /q %windir%\temp\*.* >NUL 2>&1
rd /s /q %windir%\temp >NUL 2>&1
md %windir%\temp >NUL 2>&1
del /s /f /q %temp%\*.* >NUL 2>&1
rd /s /q %temp% >NUL 2>&1
md %temp% >NUL 2>&1
del /s /f /q %windir%\*.log >NUL 2>&1
for %%F in ("C:\Windows\SoftwareDistribution\Download\*") do (
    del "%%F" /q /f >NUL 2>&1
    rd "%%F" /s /q >NUL 2>&1
) >NUL 2>&1
for %%A in ("%localappdata%\Microsoft\Windows\INetCache\IE\*") do (
    del "%%A" /q /f >NUL 2>&1
    rd "%%A" /s /q >NUL 2>&1
) >NUL 2>&1
powershell Clear-RecycleBin -Force >NUL 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "Debugger" /f >nul 2>&1
shutdown /r /t 5 /c "restarting..."
start /b "" cmd /c del "%~f0"&exit /b