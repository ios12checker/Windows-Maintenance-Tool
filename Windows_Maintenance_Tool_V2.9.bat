@echo off
chcp 65001 >nul  REM Use UTF-8 encoding for better text display

:: Ensure the script runs with admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script requires administrator privileges.
    echo Please restart as administrator.
    pause
    exit /b
)

:menu
cls
color 07

echo ======================================================
echo           WINDOWS MAINTENANCE TOOL V2.9 - By Lil_Batti
echo ======================================================
echo.

echo      === WINDOWS UPDATES ===
echo   [1] Update Windows (Winget upgrade)

echo      === SYSTEM HEALTH CHECKS ===
echo   [2] Scan for corrupt files (SFC /scannow) [Admin]
echo   [3] Windows CheckHealth (DISM) [Admin]
echo   [4] Restore Windows Health (DISM /RestoreHealth) [Admin]

echo      === NETWORK TOOLS ===
echo   [5] DNS Options (Flush/Set/Reset)
echo   [6] Show network information (ipconfig /all)
echo   [7] Restart Network Adapters
echo   [8] Network Repair - Automatic Troubleshooter

echo      === CLEANUP ^& OPTIMIZATION ===
echo   [9] Disk Cleanup (cleanmgr)
echo  [10] Run Advanced Error Scan (CHKDSK) [Admin]
echo  [11] Perform System Optimization (Delete Temporary Files)
echo  [12] Advanced Registry Cleanup-Optimization

echo      === SUPPORT ===
echo  [13] Contact and Support information (Discord)

echo.
echo      === UTILITIES ^& EXTRAS ===
echo  [20] Show installed drivers
echo  [21] Windows Update Repair Tool
echo  [22] Generate Full System Report
echo  [23] Route Print

echo  [14] === EXIT ===
echo.
echo ------------------------------------------------------
set /p choice=Enter your choice: 
if "%choice%"=="22" goto choice22
if "%choice%"=="23" goto choice23

if "%choice%"=="20" goto choice20
if exist "%~f0" findstr /b /c:":choice%choice%" "%~f0" >nul || (
    echo Invalid choice, please try again.
    pause
    goto menu
)
goto choice%choice%

:choice1
cls
where winget >nul 2>nul || (
    echo Winget is not installed. Please install it from Microsoft Store.
    pause
    goto menu
)
echo Running Windows Update (Winget upgrade)...
winget upgrade --all --include-unknown
pause
goto menu

:choice2
cls
echo Scanning for corrupt files (SFC /scannow)...
sfc /scannow
pause
goto menu

:choice3
cls
echo Checking Windows health status (DISM /CheckHealth)...
dism /online /cleanup-image /checkhealth
pause
goto menu

:choice4
cls
echo Restoring Windows health status (DISM /RestoreHealth)...
dism /online /cleanup-image /restorehealth
pause
goto menu

:choice5
cls
echo ======================================================
echo Clearing DNS Cache...
ipconfig /flushdns
echo ======================================================
echo [1] Set DNS to Google (8.8.8.8 and 8.8.4.4).8 / 8.8.4.4)
echo [2] Set DNS to Cloudflare (1.1.1.1 / 1.0.0.1)
echo [3] Restore original DNS settings
echo [5] Use you're own DNS
echo [4] Return to menu
echo ======================================================
set /p dns_choice=Enter your choice: 

if "%dns_choice%"=="1" goto set_google_dns
if "%dns_choice%"=="2" goto set_cloudflare_dns
if "%dns_choice%"=="3" goto restore_dns

if \"%dns_choice%\"==\"5\" goto custom_dns
if "%dns_choice%"=="4" goto menu

echo Invalid choice, please try again.
pause
goto choice5

:: --- SET GOOGLE DNS ---
:set_google_dns
echo Saving current DNS settings...

:: Backup current DNS for Wi-Fi
netsh interface ip show config name="Wi-Fi" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\wifi_dns_backup.txt

:: Backup current DNS for Ethernet
netsh interface ip show config name="Ethernet" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\ethernet_dns_backup.txt

echo Applying Google DNS to Wi-Fi and Ethernet...

:: Set Google DNS for Wi-Fi
netsh interface ip set dns name="Wi-Fi" static 8.8.8.8 primary
netsh interface ip add dns name="Wi-Fi" 8.8.4.4 index=2

:: Set Google DNS for Ethernet
netsh interface ip set dns name="Ethernet" static 8.8.8.8 primary
netsh interface ip add dns name="Ethernet" 8.8.4.4 index=2

echo Google DNS applied successfully.
pause
goto menu

:: --- SET CLOUDFLARE DNS ---
:set_cloudflare_dns
echo Saving current DNS settings...

:: Backup current DNS for Wi-Fi
netsh interface ip show config name="Wi-Fi" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\wifi_dns_backup.txt

:: Backup current DNS for Ethernet
netsh interface ip show config name="Ethernet" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\ethernet_dns_backup.txt

echo Applying Cloudflare DNS to Wi-Fi and Ethernet...

:: Set Cloudflare DNS for Wi-Fi
netsh interface ip set dns name="Wi-Fi" static 1.1.1.1 primary
netsh interface ip add dns name="Wi-Fi" 1.0.0.1 index=2

:: Set Cloudflare DNS for Ethernet
netsh interface ip set dns name="Ethernet" static 1.1.1.1 primary
netsh interface ip add dns name="Ethernet" 1.0.0.1 index=2

echo Cloudflare DNS applied successfully.
pause
goto menu

:: --- RESTORE ORIGINAL DNS SETTINGS ---
:restore_dns
cls
echo Restoring original DNS settings...

:: Restore DNS for Wi-Fi
echo Setting Wi-Fi DNS to automatic (DHCP)...
netsh interface ip set dns name="Wi-Fi" source=dhcp
netsh interface ip set dns name="Wi-Fi" source=dhcp >nul 2>&1
if %errorlevel% neq 0 (
    echo Failed to restore Wi-Fi DNS. Please check manually.
) else (
    echo Wi-Fi DNS successfully restored to automatic mode.
)

:: Restore DNS for Ethernet
echo Setting Ethernet DNS to automatic (DHCP)...
netsh interface ip set dns name="Ethernet" source=dhcp
netsh interface ip set dns name="Ethernet" source=dhcp >nul 2>&1
if %errorlevel% neq 0 (
    echo Failed to restore Ethernet DNS. Please check manually.
) else (
    echo Ethernet DNS successfully restored to automatic mode.
)

pause
goto menu



:choice6
cls
echo Displaying Network Information...
ipconfig /all
pause
goto menu

:choice7
cls
echo Restarting network adapters...
netsh interface set interface "Wi-Fi" admin=disable
netsh interface set interface "Wi-Fi" admin=enable
echo Network adapters restarted.
pause
goto menu

:choice8
title Network Repair - Automatic Troubleshooter
cls
echo.
echo ================================
echo     Automatic Network Repair
echo ================================
echo.
echo Step 1: Renewing your IP address...
ipconfig /release >nul
ipconfig /renew >nul

echo Step 2: Refreshing DNS settings...
ipconfig /flushdns >nul

echo Step 3: Resetting network components...
netsh winsock reset >nul
netsh int ip reset >nul

echo.
echo Your network settings have been refreshed.
echo A system restart is recommended for full effect.
echo.

:askRestart
set /p restart=Would you like to restart now? (Y/N): 
if /I "%restart%"=="Y" (
    shutdown /r /t 5
) else if /I "%restart%"=="N" (
    goto menu
) else (
    echo Invalid input. Please enter Y or N.
    goto askRestart
)


:choice9
cls
echo Running Disk Cleanup...
cleanmgr
pause
goto menu

:choice10
cls
echo Running advanced error scan on all drives...
wmic logicaldisk get caption | findstr : > drives.txt
for /f %%d in (drives.txt) do chkdsk %%d /f /r /x
pause
goto menu

:choice11
cls

:confirm_loop
echo Do you want to delete temporary files and system cache? (Y/N)
set /p confirm=Type Y or N: 

IF /I "%confirm%"=="Y" (
    goto delete_temp
) ELSE IF /I "%confirm%"=="YES" (
    goto delete_temp
) ELSE IF /I "%confirm%"=="N" (
    echo Operation cancelled.
    pause
    goto menu
) ELSE IF /I "%confirm%"=="NO" (
    echo Operation cancelled.
    pause
    goto menu
) ELSE (
    echo Invalid input. Please type Y or N.
    goto confirm_loop
)

:delete_temp
echo Deleting temporary files and system cache...
del /s /f /q %temp%\*.*
del /s /f /q C:\Windows\Temp\*.*
del /s /f /q "C:\Users\%USERNAME%\AppData\Local\Temp\*.*"
echo Temporary files deleted.
pause
goto menu


:choice12
cls
echo ======================================================
echo Advanced Registry Cleanup ^& Optimization
echo ======================================================
setlocal enabledelayedexpansion

:: Opret backup-mappe
set backupFolder=%SystemRoot%\Temp\RegistryBackups
if not exist "%backupFolder%" mkdir "%backupFolder%"

:: Opret logfil
set logFile=%SystemRoot%\Temp\RegistryCleanupLog.txt
echo Registry Cleanup Log - %date% %time% > "%logFile%"

:: Initialize counter
set count=0
set safe_count=0

:: Dyb registry-analyse
echo Analyzing Windows Registry for errors and performance issues...
for /f "tokens=*" %%A in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall 2^>nul') do (
    set /a count+=1
    set entries[!count!]=%%A
    
    :: Check if the key is safe to delete
    echo %%A | findstr /I "IE40 IE4Data DirectDrawEx DXM_Runtime SchedulingAgent" >nul && (
        set /a safe_count+=1
        set safe_entries[!safe_count!]=%%A
    )
)

:: Hvis ingen entries findes, afslut
if %count%==0 (
    echo No unnecessary registry entries found.
    pause
    goto menu
)

:: Vis fundne registry entries til brugeren
echo Found %count% registry issues:
for /L %%i in (1,1,%count%) do echo [%%i] !entries[%%i]!
echo.
echo Safe to delete (%safe_count% entries detected):
for /L %%i in (1,1,%safe_count%) do echo [%%i] !safe_entries[%%i]!
echo.
echo [A] Delete only safe entries
if %safe_count% GTR 0 echo [B] Review safe entries before deletion
echo [C] Create Registry Backup
echo [D] Restore Registry Backup
echo [E] Scan for corrupt registry entries
echo [F] Defragment Registry
echo [0] Cancel
echo.
echo Enter your choice:
set /p user_choice=

:: Konverter input til store bogstaver for ensartethed
for %%A in (%user_choice%) do set user_choice=%%A
if /I "%user_choice%"=="0" goto menu
if /I "%user_choice%"=="A" goto delete_safe_entries
if /I "%user_choice%"=="B" goto review_safe_entries
if /I "%user_choice%"=="C" goto create_backup
if /I "%user_choice%"=="D" goto restore_backup
if /I "%user_choice%"=="E" goto scan_registry
if /I "%user_choice%"=="F" goto defrag_registry
if "%user_choice%"=="" goto menu

echo Invalid input, returning to menu.
pause
goto menu

:: Slet kun sikre registry-fejl
:delete_safe_entries
if %safe_count%==0 (
    echo No safe entries found for deletion.
    pause
    goto menu
)
echo Deleting all detected safe registry entries...
for /L %%i in (1,1,%safe_count%) do (
    echo Deleting !safe_entries[%%i]!...
    reg delete "!safe_entries[%%i]!" /f
    echo Deleted: !safe_entries[%%i]! >> "%logFile%"
)
echo All selected registry entries have been deleted.
pause
goto menu

:: Review secure entries before deletion
:review_safe_entries
cls
echo Safe to delete registry entries:
for /L %%i in (1,1,%safe_count%) do echo [%%i] !safe_entries[%%i]!
echo.
echo Do you want to delete them all? (Y/N)
set /p confirm=
for %%A in (%confirm%) do set confirm=%%A
if /I "%confirm%"=="Y" goto delete_safe_entries
echo Operation cancelled.
pause
goto menu

:: Opret en manuel backup af registreringsdatabasen
:create_backup
set backupName=RegistryBackup_%date:~-4,4%-%date:~-7,2%-%date:~-10,2%_%time:~0,2%-%time:~3,2%.reg
echo Creating registry backup: %backupFolder%\%backupName%...
reg export HKLM "%backupFolder%\%backupName%" /y
echo Backup successfully created.
pause
goto menu

:: Gendan backup af registreringsdatabase
:restore_backup
echo Available backups:
dir /b "%backupFolder%\*.reg"
echo Enter the name of the backup to restore:
set /p backupFile=
if exist "%backupFolder%\%backupFile%" (
    echo Restoring backup...
    reg import "%backupFolder%\%backupFile%"
    echo Backup successfully restored.
) else (
    echo Backup file not found. Please check the name and try again.
)
pause
goto menu

:: Scan for corrupt registry entries
:scan_registry
cls
echo Scanning for corrupt registry entries...
sfc /scannow
dism /online /cleanup-image /checkhealth
echo Registry scan complete. If errors were found, restart your PC.
pause
goto menu

:: Defragment Registry
:defrag_registry
cls
echo Defragmenting Windows Registry...
if exist "%SystemRoot%\System32\ntregopt.exe" (
    echo Running NT Registry Optimizer...
    start /wait ntregopt.exe
) else (
    echo NT Registry Optimizer not found. Download it from: https://www.larshederer.homepage.t-online.de/erunt/
)
echo Registry defragmentation complete. Restart recommended.
pause
goto menu

:choice13
cls
echo.
echo ==================================================
echo                CONTACT AND SUPPORT
echo ==================================================
echo Do you have any questions or need help?
echo You are always welcome to contact me.
echo.
echo Discord-Username: Lil_Batti
echo Support-server: https://discord.gg/bCQqKHGxja
echo.
echo Press ENTER to return to the main menu.
pause >nul
goto menu

:choice14
cls
echo Exiting script...
exit


:custom_dns
cls
echo ===============================================
echo           Enter your custom DNS
echo ===============================================

:get_dns
echo.
set /p customDNS1=Enter primary DNS: 
set /p customDNS2=Enter secondary DNS (optional): 

cls
echo ===============================================
echo           Validating DNS addresses...
echo ===============================================
ping -n 1 %customDNS1% >nul
if errorlevel 1 (
    cls
    echo ===============================================
    echo [!] ERROR: The primary DNS "%customDNS1%" is not reachable.
    echo ===============================================
    echo Please enter a valid DNS address.
    pause
    cls
    goto get_dns
)

if not "%customDNS2%"=="" (
    ping -n 1 %customDNS2% >nul
    if errorlevel 1 (
        cls
        echo ===============================================
        echo [!] ERROR: The secondary DNS "%customDNS2%" is not reachable.
        echo ===============================================
        echo Please enter a valid DNS address.
        pause
        cls
        goto get_dns
    )
)

cls
echo ===============================================
echo     Setting DNS for Wi-Fi and Ethernet...
echo ===============================================

netsh interface ip set dns name="Wi-Fi" static %customDNS1%
if errorlevel 1 (
    echo [!] Failed to set primary DNS on Wi-Fi adapter.
    pause
    goto choice5
)

if not "%customDNS2%"=="" (
    netsh interface ip add dns name="Wi-Fi" %customDNS2% index=2
    if errorlevel 1 (
        echo [!] Failed to set secondary DNS on Wi-Fi adapter.
        pause
        goto choice5
    )
)

netsh interface ip set dns name="Ethernet" static %customDNS1%
if errorlevel 1 (
    echo [!] Failed to set primary DNS on Ethernet adapter.
    pause
    goto choice5
)

if not "%customDNS2%"=="" (
    netsh interface ip add dns name="Ethernet" %customDNS2% index=2
    if errorlevel 1 (
        echo [!] Failed to set secondary DNS on Ethernet adapter.
        pause
        goto choice5
    )
)

echo.
echo ===============================================
echo      DNS has been successfully updated:
echo        Primary: %customDNS1%
if not "%customDNS2%"=="" echo        Secondary: %customDNS2%
echo ===============================================
pause
goto choice5:get_dns
set /p customDNS1=Enter primary DNS: 
set /p customDNS2=Enter secondary DNS (optional): 

echo Validating DNS addresses...
ping -n 1 %customDNS1% >nul
if errorlevel 1 (
    echo The primary DNS address "%customDNS1%" is not reachable.
    echo Please enter a valid DNS address.
    pause
    goto get_dns
)

if not "%customDNS2%"=="" (
    ping -n 1 %customDNS2% >nul
    if errorlevel 1 (
        echo The secondary DNS address "%customDNS2%" is not reachable.
        echo Please enter a valid DNS address.
        pause
        goto get_dns
    )
)

echo Setting DNS for Wi-Fi...
netsh interface ip set dns name="Wi-Fi" static %customDNS1%
if errorlevel 1 (
    echo Failed to set primary DNS on Wi-Fi adapter.
    pause
    goto choice5
)

if not "%customDNS2%"=="" (
    netsh interface ip add dns name="Wi-Fi" %customDNS2% index=2
    if errorlevel 1 (
        echo Failed to set secondary DNS on Wi-Fi adapter.
        pause
        goto choice5
    )
)

echo Setting DNS for Ethernet...
netsh interface ip set dns name="Ethernet" static %customDNS1%
if errorlevel 1 (
    echo Failed to set primary DNS on Ethernet adapter.
    pause
    goto choice5
)

if not "%customDNS2%"=="" (
    netsh interface ip add dns name="Ethernet" %customDNS2% index=2
    if errorlevel 1 (
        echo Failed to set secondary DNS on Ethernet adapter.
        pause
        goto choice5
    )
)

echo DNS has been successfully updated to:
echo Primary: %customDNS1%
if not "%customDNS2%"=="" echo Secondary: %customDNS2%
pause
goto choice5:retry_dns
set /p customDNS1=Enter primary DNS: 
ping -n 1 %customDNS1% >nul
if errorlevel 1 (
    echo The primary DNS (%customDNS1%) could not be reached.
    echo Please try again.
    pause
    goto retry_dns
)

set /p customDNS2=Enter secondary DNS (optional): 
if not "%customDNS2%"=="" (
    ping -n 1 %customDNS2% >nul
    if errorlevel 1 (
        echo The secondary DNS (%customDNS2%) could not be reached.
        echo It will not be set.
        set customDNS2=
        pause
    )
)

echo Setting DNS for Wi-Fi...
netsh interface ip set dns name="Wi-Fi" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Wi-Fi" %customDNS2% index=2

echo Setting DNS for Ethernet...
netsh interface ip set dns name="Ethernet" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Ethernet" %customDNS2% index=2

echo DNS has been updated to:
echo Primary: %customDNS1%
if not "%customDNS2%"=="" echo Secondary: %customDNS2%
pause
goto choice5:retry_dns
set /p customDNS1=Enter primary DNS: 
ping -n 1 %customDNS1% >nul
if errorlevel 1 (
    echo The primary DNS (%customDNS1%) could not be reached.
    echo Please try again.
    goto retry_dns
)

set /p customDNS2=Enter secondary DNS (optional): 
if not "%customDNS2%"=="" (
    ping -n 1 %customDNS2% >nul
    if errorlevel 1 (
        echo The secondary DNS (%customDNS2%) could not be reached.
        echo It will not be set.
        set customDNS2=
    )
)

netsh interface ip set dns name="Wi-Fi" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Wi-Fi" %customDNS2% index=2

netsh interface ip set dns name="Ethernet" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Ethernet" %customDNS2% index=2

echo DNS has been updated to %customDNS1% %customDNS2%
pause
goto choice5:retry_dns
set /p customDNS1=Indtast primær DNS: 
ping -n 1 %customDNS1% >nul
if errorlevel 1 (
    echo Den primære DNS (%customDNS1%) kunne ikke kontaktes.
    echo Proev igen.
    goto retry_dns
)

set /p customDNS2=Indtast sekundær DNS (valgfri): 
if not "%customDNS2%"=="" (
    ping -n 1 %customDNS2% >nul
    if errorlevel 1 (
        echo Den sekundære DNS (%customDNS2%) kunne ikke kontaktes.
        echo Den vil ikke blive sat.
        set customDNS2=
    )
)

netsh interface ip set dns name="Wi-Fi" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Wi-Fi" %customDNS2% index=2

netsh interface ip set dns name="Ethernet" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Ethernet" %customDNS2% index=2

echo DNS blev opdateret til %customDNS1% %customDNS2%
pause
goto choice5

:choice20
cls
echo ===============================================
echo     Saving Installed Driver Report to Desktop
echo ===============================================
driverquery /v > "%USERPROFILE%\Desktop\Installed_Drivers.txt"
echo.
echo Driver report has been saved to:
echo %USERPROFILE%\Desktop\Installed_Drivers.txt
pause
goto menu

:choice21
cls
echo ===============================================
echo      Windows Update Repair Tool [Admin]
echo ===============================================

echo Stopping services...
net stop wuauserv >nul 2>&1
net stop bits >nul 2>&1
net stop cryptsvc >nul 2>&1
net stop msiserver >nul 2>&1

echo Deleting cache folders...
rd /s /q %windir%\SoftwareDistribution
rd /s /q %windir%\System32\catroot2

echo Starting services...
net start wuauserv >nul 2>&1
net start bits >nul 2>&1
net start cryptsvc >nul 2>&1
net start msiserver >nul 2>&1

echo.
echo Windows Update components reset.
pause
goto menu


:choice22
cls
echo ===============================================
echo      Generating Separated System Reports...
echo ===============================================

set REPORT1=%USERPROFILE%\Desktop\System_Info_2025-06-08.txt
set REPORT2=%USERPROFILE%\Desktop\Network_Info_2025-06-08.txt
set REPORT3=%USERPROFILE%\Desktop\Driver_List_2025-06-08.txt

echo Writing system info to %REPORT1% ...
systeminfo > "%REPORT1%"

echo Writing network info to %REPORT2% ...
ipconfig /all > "%REPORT2%"

echo Writing driver list to %REPORT3% ...
driverquery > "%REPORT3%"

echo.
echo Reports have been saved to Desktop:
echo - System_Info_2025-06-08.txt
echo - Network_Info_2025-06-08.txt
echo - Driver_List_2025-06-08.txt
pause

:choice23
cls
echo ===============================================
echo      Printing Network Routes...
echo ===============================================
route print
pause

goto menu
