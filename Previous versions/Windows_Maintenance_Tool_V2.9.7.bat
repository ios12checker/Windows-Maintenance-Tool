@echo off
chcp 65001 >nul  REM Use UTF-8 encoding for better text display

REM Ensure the script runs with admin privileges
if /i not "%~1"=="am_admin" (
    echo(This script requires administrator privileges.
    echo(Requesting elevation now ... 
    powershell start -verb runas '%0' am_admin 
    exit /b
)

:menu
cls
color 07

echo ======================================================
echo           WINDOWS MAINTENANCE TOOL V2.9.7 - By Lil_Batti
echo ======================================================
echo.

echo      === WINDOWS UPDATES ===
echo   [1] Update Windows Apps / Programs (Winget upgrade)

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
echo  [23] Windows Update Utility ^& Service Reset
echo  [24] View Network Routing Table [Advanced]

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
setlocal EnableDelayedExpansion

REM Check winget
where winget >nul 2>nul || (
    echo Winget is not installed. Please install it from Microsoft Store.
    pause
    goto menu
)

echo ===============================================
echo     Windows Update (via Winget)
echo ===============================================
echo Listing available upgrades...
echo.

REM Show upgradeable apps
cmd /c "winget upgrade --include-unknown"
echo.
pause

echo ===============================================
echo Options:
echo [1] Upgrade all packages
echo [2] Upgrade selected packages
echo [0] Cancel
echo.
set /p upopt=Choose an option:

if "%upopt%"=="1" (
    echo Running full upgrade...
    cmd /c "winget upgrade --all --include-unknown"
    pause
    goto menu
)

if "%upopt%"=="2" (
    cls
    echo ===============================================
    echo   Available Packages [Copy ID to upgrade]
    echo ===============================================
    cmd /c "winget upgrade --include-unknown"
    echo.

    echo Enter one or more package IDs to upgrade
    echo (Example: Microsoft.Edge,Spotify.Spotify  use exact IDs from the list above)

    echo.
    set /p packlist=IDs: 

    REM Remove spaces
    set "packlist=!packlist: =!"

    if not defined packlist (
        echo No package IDs entered.
        pause
        goto menu
    )

    echo.
    for %%G in (!packlist!) do (
        echo Upgrading %%G...
        cmd /c "winget upgrade --id %%G --include-unknown"
        echo.
    )

    pause
    goto menu
)

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
echo [1] Set DNS to Google (8.8.8.8 / 8.8.4.4)
echo [2] Set DNS to Cloudflare (1.1.1.1 / 1.0.0.1)
echo [3] Restore original DNS settings
echo [4] Use your own DNS
echo [5] Return to menu
echo ======================================================
set /p dns_choice=Enter your choice: 

if "%dns_choice%"=="1" goto set_google_dns
if "%dns_choice%"=="2" goto set_cloudflare_dns
if "%dns_choice%"=="3" goto restore_dns
if "%dns_choice%"=="4" goto custom_dns
if "%dns_choice%"=="5" goto menu

echo Invalid choice, please try again.
pause
goto choice5

REM --- SET GOOGLE DNS ---
:set_google_dns
echo Saving current DNS settings...

netsh interface ip show config name="Wi-Fi" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\wifi_dns_backup.txt
netsh interface ip show config name="Ethernet" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\ethernet_dns_backup.txt

echo Applying Google DNS...

netsh interface ip set dns name="Wi-Fi" static 8.8.8.8 primary
netsh interface ip add dns name="Wi-Fi" 8.8.4.4 index=2
netsh interface ip set dns name="Ethernet" static 8.8.8.8 primary
netsh interface ip add dns name="Ethernet" 8.8.4.4 index=2

echo Google DNS applied successfully.
pause
goto menu

REM --- SET CLOUDFLARE DNS ---
:set_cloudflare_dns
echo Saving current DNS settings...

netsh interface ip show config name="Wi-Fi" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\wifi_dns_backup.txt
netsh interface ip show config name="Ethernet" | findstr "Statically Configured DNS Servers" > %SystemRoot%\Temp\ethernet_dns_backup.txt

echo Applying Cloudflare DNS...

netsh interface ip set dns name="Wi-Fi" static 1.1.1.1 primary
netsh interface ip add dns name="Wi-Fi" 1.0.0.1 index=2
netsh interface ip set dns name="Ethernet" static 1.1.1.1 primary
netsh interface ip add dns name="Ethernet" 1.0.0.1 index=2

echo Cloudflare DNS applied successfully.
pause
goto menu

REM --- RESTORE ORIGINAL DNS SETTINGS ---
:restore_dns
cls
echo ======================================================
echo        RESTORE ORIGINAL DNS SETTINGS
echo ======================================================
echo.

echo [Step 1] Setting Wi-Fi DNS to automatic (DHCP)...
netsh interface ip set dns name="Wi-Fi" source=dhcp >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Could not restore Wi-Fi DNS. Please check manually.
) else (
    echo [OK] Wi-Fi DNS successfully restored.
)

echo.
echo [Step 2] Setting Ethernet DNS to automatic (DHCP)...
netsh interface ip set dns name="Ethernet" source=dhcp >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Could not restore Ethernet DNS. Please check manually.
) else (
    echo [OK] Ethernet DNS successfully restored.
)

echo.
echo ------------------------------------------------------
echo Done restoring DNS settings.
echo ------------------------------------------------------
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
echo ===============================================
echo Running advanced error scan on all drives...
echo ===============================================

REM Loop through all mounted drives with free space using PowerShell
for /f "delims=" %%d in ('powershell -NoProfile -Command ^
  "Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | ForEach-Object { $_.Name + ':' }"') do (
    echo.
    echo Scanning drive %%d ...
    chkdsk %%d /f /r /x
)

echo.
echo All drives scanned.
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

REM Create backup folder
set backupFolder=%SystemRoot%\Temp\RegistryBackups
if not exist "%backupFolder%" mkdir "%backupFolder%"

REM Create log file
set logFile=%SystemRoot%\Temp\RegistryCleanupLog.txt
echo Registry Cleanup Log - %date% %time% > "%logFile%"

REM Initialize counter
set count=0
set safe_count=0

REM Advanced registry scan
echo Analyzing Windows Registry for errors and performance issues...
for /f "tokens=*" %%A in ('reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall 2^>nul') do (
    set /a count+=1
    set entries[!count!]=%%A
    
    REM Check if the key is safe to delete
    echo %%A | findstr /I "IE40 IE4Data DirectDrawEx DXM_Runtime SchedulingAgent" >nul && (
        set /a safe_count+=1
        set safe_entries[!safe_count!]=%%A
    )
)

REM If no entries are found, exit
if %count%==0 (
    echo No unnecessary registry entries found.
    pause
    goto menu
)

REM Show found registry entries to the user
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
echo [0] Cancel
echo.
echo Enter your choice:
set /p user_choice=

REM Convert input to uppercase for consistency
for %%A in (%user_choice%) do set user_choice=%%A
if /I "%user_choice%"=="0" goto menu
if /I "%user_choice%"=="A" goto delete_safe_entries
if /I "%user_choice%"=="B" goto review_safe_entries
if /I "%user_choice%"=="C" goto create_backup
if /I "%user_choice%"=="D" goto restore_backup
if /I "%user_choice%"=="E" goto scan_registry
if "%user_choice%"=="" goto menu

echo Invalid input, returning to menu.
pause
goto menu

REM Only delete safe registry errors
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

REM Review secure entries before deletion
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

REM Create a manual backup of the registry
:create_backup
set backupName=RegistryBackup_%date:~-4,4%-%date:~-7,2%-%date:~-10,2%_%time:~0,2%-%time:~3,2%.reg
echo Creating registry backup: %backupFolder%\%backupName%...
reg export HKLM "%backupFolder%\%backupName%" /y
echo Backup successfully created.
pause
goto menu

REM Restore registry backup
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

REM Scan for corrupt registry entries
:scan_registry
cls
echo Scanning for corrupt registry entries...
sfc /scannow
dism /online /cleanup-image /checkhealth
echo Registry scan complete. If errors were found, restart your PC.
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
    echo [!] ERROR: The primary DNS "%customDNS1%" is not reachable.
    echo Please enter a valid DNS address.
    pause
    cls
    goto get_dns
)

if not "%customDNS2%"=="" (
    ping -n 1 %customDNS2% >nul
    if errorlevel 1 (
        echo [!] ERROR: The secondary DNS "%customDNS2%" is not reachable.
        echo It will be skipped.
        set "customDNS2="
        pause
    )
)

cls
echo ===============================================
echo     Setting DNS for Wi-Fi and Ethernet...
echo ===============================================

REM Wi-Fi
netsh interface ip set dns name="Wi-Fi" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Wi-Fi" %customDNS2% index=2

REM Ethernet
netsh interface ip set dns name="Ethernet" static %customDNS1%
if not "%customDNS2%"=="" netsh interface ip add dns name="Ethernet" %customDNS2% index=2

echo.
echo ===============================================
echo      DNS has been successfully updated:
echo        Primary: %customDNS1%
if not "%customDNS2%"=="" echo        Secondary: %customDNS2%
echo ===============================================
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
echo.
echo [1/4] Stopping update-related services...

call :stopIfExists wuauserv
call :stopIfExists bits
call :stopIfExists cryptsvc
call :stopIfExists msiserver
call :stopIfExists usosvc
call :stopIfExists trustedinstaller
timeout /t 2 >nul

echo [2/4] Renaming update cache folders...
set "SUFFIX=.bak_%RANDOM%"
set "SD=%windir%\SoftwareDistribution"
set "CR=%windir%\System32\catroot2"

if exist "%SD%" (
    ren "%SD%" "SoftwareDistribution%SUFFIX%" 2>nul
    if exist "%windir%\SoftwareDistribution%SUFFIX%" (
        echo Renamed: %windir%\SoftwareDistribution%SUFFIX%
    ) else (
        echo Warning: Could not rename SoftwareDistribution.
    )
) else (
    echo Info: SoftwareDistribution not found.
)

if exist "%CR%" (
    ren "%CR%" "catroot2%SUFFIX%" 2>nul
    if exist "%windir%\System32\catroot2%SUFFIX%" (
        echo Renamed: %windir%\System32\catroot2%SUFFIX%
    ) else (
        echo Warning: Could not rename catroot2.
    )
) else (
    echo Info: catroot2 not found.
)

echo.
echo [3/4] Restarting services...
call :startIfExists wuauserv
call :startIfExists bits
call :startIfExists cryptsvc
call :startIfExists msiserver
call :startIfExists usosvc
call :startIfExists trustedinstaller

echo.
echo [4/4] Windows Update components have been reset.
echo.
echo Renamed folders:
echo   - %windir%\SoftwareDistribution%SUFFIX%
echo   - %windir%\System32\catroot2%SUFFIX%
echo You may delete them manually after reboot if all is working.
echo.
pause
goto menu

REM === THESE MUST BE PLACED AT THE VERY BOTTOM OF YOUR SCRIPT ===

:stopIfExists
sc query "%~1" | findstr /i "STATE" >nul
if not errorlevel 1 (
    echo Stopping %~1
    net stop "%~1" >nul 2>&1
)
goto :eof

:startIfExists
sc query "%~1" | findstr /i "STATE" >nul
if not errorlevel 1 (
    echo Starting %~1
    net start "%~1" >nul 2>&1
)
goto :eof

:choice22
cls
echo ===============================================
echo     Generating Separated System Reports...
echo ===============================================
echo.

REM === Get Desktop path securely ===
for /f "usebackq delims=" %%d in (`powershell -NoProfile -Command "$env:USERPROFILE + '\Desktop'"`) do (
    set "DESKTOP=%%d"
)

REM === Generate timestamp ===
for /f "usebackq delims=" %%t in (`powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"`) do (
    set "DATESTR=%%t"
)

set "SYS=%DESKTOP%\System_Info_%DATESTR%.txt"
set "NET=%DESKTOP%\Network_Info_%DATESTR%.txt"
set "DRV=%DESKTOP%\Driver_List_%DATESTR%.txt"

echo Writing system info to %SYS% ...
systeminfo > "%SYS%" 2>nul

echo Writing network info to %NET% ...
ipconfig /all > "%NET%" 2>nul

echo Writing driver list to %DRV% ...
driverquery > "%DRV%" 2>nul

echo.
echo Reports have been saved to Desktop:
echo  - %~nx1
echo  - %~nx2
echo  - %~nx3
echo.
pause
goto menu

:choice23
cls
echo ======================================================
echo            Windows Update Utility ^& Service Reset
echo ======================================================
echo This tool will restart core Windows Update services.
echo Make sure no Windows Updates are installing right now.
pause

echo.
echo [1] Reset Update Services (wuauserv, cryptsvc, appidsvc, bits)
echo [2] Return to Main Menu
echo.
set /p fixchoice=Select an option: 

if "%fixchoice%"=="1" goto reset_windows_update
if "%fixchoice%"=="2" goto menu

echo Invalid input. Try again.
pause
goto choice23

:reset_windows_update
cls
echo ======================================================
echo     Resetting Windows Update ^& Related Services
echo ======================================================

echo Stopping Windows Update service...
net stop wuauserv >nul

echo Stopping Cryptographic service...
net stop cryptsvc >nul

echo Starting Application Identity service...
net start appidsvc >nul

echo Starting Windows Update service...
net start wuauserv >nul

echo Starting Background Intelligent Transfer Service...
net start bits >nul

echo.
echo [OK] Update-related services have been restarted.
pause
goto menu

:choice24
setlocal EnableDelayedExpansion
cls
echo ===============================================
echo      View Network Routing Table  [Advanced]
echo ===============================================
echo This shows how your system handles network traffic.
echo.
echo [1] Display routing table in this window
echo [2] Save routing table as a text file on Desktop
echo [3] Return to Main Menu
echo.
set /p routeopt=Choose an option: 

if "%routeopt%"=="1" (
    cls
    route print
    echo.
    pause
    goto menu
)

if "%routeopt%"=="2" (
    REM === Get Desktop path and verify it exists ===
    set "DESKTOP=%USERPROFILE%\Desktop"
    if not exist "!DESKTOP!" (
        echo Desktop folder not found.
        pause
        goto menu
    )

    REM === Generate timestamp using PowerShell ===
    for /f "usebackq delims=" %%i in (`powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HH-mm-ss"`) do (
        set "dt=%%i"
    )

    REM === Fallback if timestamp fails ===
    if not defined dt (
        echo Failed to generate timestamp. Using fallback...
        set "dt=manual_timestamp"
    )

    REM === Save routing table to file ===
    set "FILE=!DESKTOP!\routing_table_!dt!.txt"
    cls
    echo Saving routing table to: "!FILE!"
    echo.
    route print > "!FILE!"

    if exist "!FILE!" (
        echo [OK] Routing table saved successfully.
    ) else (
        echo [ERROR] Failed to save routing table to file.
    )
    echo.
    pause
    goto menu
)

if "%routeopt%"=="3" (
    goto menu
)

echo Invalid input. Please enter 1, 2 or 3.
pause
goto choice24
