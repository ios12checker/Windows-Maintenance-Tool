@echo off

REM Ensure the script runs with admin privileges
if /i not "%~1"=="am_admin" (
    echo(This script requires administrator privileges.
    echo(Requesting elevation now ... 
    powershell start -verb runas '%0' am_admin 
    exit /b
)

REM NOW set UTF-8 code page you are in the admin session!
chcp 65001 >nul  REM Use UTF-8 encoding for better text display

:menu
cls
color 07


echo ======================================================
echo           WINDOWS MAINTENANCE TOOL V3.1.1 - By Lil_Batti
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
echo  [12] Advanced Registry Cleanup-Optimization (Only use if Necessary)
echo  [13] Optimize SSDs (ReTrim)

echo      === SUPPORT ===
echo  [14] Contact and Support information (Discord)

echo.
echo      === UTILITIES ^& EXTRAS ===
echo  [20] Show installed drivers
echo  [21] Windows Update Repair Tool
echo  [22] Generate Full System Report
echo  [23] Windows Update Utility ^& Service Reset
echo  [24] View Network Routing Table [Advanced]

echo  [15] === EXIT ===
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

REM Check if winget is available
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

REM List upgradeable apps
cmd /c "winget upgrade --include-unknown"
echo.
pause

:option_prompt
echo ===============================================
echo Options:
echo [1] Upgrade all packages
echo [2] Upgrade selected packages
echo [0] Cancel
echo.
set /p upopt=Choose an option: 

REM Remove leading/trailing spaces from input
for /f "tokens=* delims= " %%A in ("!upopt!") do set upopt=%%A

if "%upopt%"=="0" (
    echo Cancelled. Returning to menu...
    pause
    goto menu
)

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

    REM Remove spaces from input
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

REM Handle invalid input
echo Invalid option. Please choose 1, 2, or 0.
goto option_prompt


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
@echo off
setlocal EnableDelayedExpansion
cls
echo ======================================================
echo DNS / Network Tool ^& Language Independent
echo ======================================================
echo [1] Set DNS to Google (8.8.8.8 / 8.8.4.4)
echo [2] Set DNS to Cloudflare (1.1.1.1 / 1.0.0.1)
echo [3] Restore automatic DNS (DHCP)
echo [4] Use your own DNS
echo [5] Return to menu
echo ======================================================
set /p dns_choice=Enter your choice: 

if "%dns_choice%"=="1" goto google_dns_all
if "%dns_choice%"=="2" goto cloudflare_dns_all
if "%dns_choice%"=="3" goto dns_auto_all
if "%dns_choice%"=="4" goto custom_dns_all
if "%dns_choice%"=="5" goto menu

echo Invalid choice, please try again.
pause
goto choice5

REM -------- Find all active adapters - language neutral -------------
:find_adapters
setlocal EnableDelayedExpansion
set "ADAPTERLIST="

for /f "usebackq delims=" %%a in (`powershell -Command "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name"`) do (
    set "ADAPTERLIST=!ADAPTERLIST!;%%a"
)

endlocal & set "ADAPTERLIST=%ADAPTERLIST:~1%"
goto :eof

REM ----------------- Google DNS --------------------
:google_dns_all
call :find_adapters
if not defined ADAPTERLIST (
    echo No active network adapters found!
    pause
    goto menu
)
echo Applying Google DNS (8.8.8.8/8.8.4.4) to:
for %%I in (%ADAPTERLIST:;= % ) do (
    echo   - %%I
    netsh interface ip set dns name="%%I" static 8.8.8.8 primary >nul 2>&1
    netsh interface ip add dns name="%%I" 8.8.4.4 index=2 >nul 2>&1
)
echo Done. Google DNS set.
pause
goto menu

REM ----------------- Cloudflare DNS -----------------
:cloudflare_dns_all
call :find_adapters
if not defined ADAPTERLIST (
    echo No active network adapters found!
    pause
    goto menu
)
echo Applying Cloudflare DNS (1.1.1.1/1.0.0.1) to:
for %%I in (%ADAPTERLIST:;= % ) do (
    echo   - %%I
    netsh interface ip set dns name="%%I" static 1.1.1.1 primary >nul 2>&1
    netsh interface ip add dns name="%%I" 1.0.0.1 index=2 >nul 2>&1
)
echo Done. Cloudflare DNS set.
pause
goto menu

REM ------------- Restore DNS to DHCP (automatic) -------------
:dns_auto_all
call :find_adapters
if not defined ADAPTERLIST (
    echo No active network adapters found!
    pause
    goto menu
)
echo Restoring automatic DNS (DHCP) on:
for %%I in (%ADAPTERLIST:;= % ) do (
    echo   - %%I
    netsh interface ip set dns name="%%I" source=dhcp >nul 2>&1
)
echo Done. DNS set to automatic.
pause
goto menu

REM ------------- Custom DNS -------------
:custom_dns_all
call :find_adapters
if not defined ADAPTERLIST (
    echo No active network adapters found!
    pause
    goto menu
)
set /p customDNS1=Enter primary DNS: 
set /p customDNS2=Enter secondary DNS (optional): 
echo Applying custom DNS to:
for %%I in (%ADAPTERLIST:;= % ) do (
    echo   - %%I
    netsh interface ip set dns name="%%I" static %customDNS1% >nul 2>&1
    if not "%customDNS2%"=="" netsh interface ip add dns name="%%I" %customDNS2% index=2 >nul 2>&1
)
echo Done. Custom DNS applied.
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
echo ===============================================
echo Restarting all Wi-Fi adapters...
echo ===============================================
set "FOUND_ADAPTER="

REM Loop through all detected Wi-Fi adapter names
for /f "tokens=2 delims=:" %%a in ('netsh wlan show interfaces ^| find /i "name"') do (
    for /f "tokens=*" %%b in ("%%~a") do (
        if /i not "%%~b"=="" (
            set "FOUND_ADAPTER=1"
            echo Restarting "%%~b" ...
            >nul 2>&1 netsh interface set interface name="%%~b" admin=disable
            >nul 2>&1 timeout /t 1 /nobreak
            >nul 2>&1 netsh interface set interface name="%%~b" admin=enable
            REM Check if restart was successful (adapter must be enabled after)
            netsh interface show interface name="%%~b" | findstr /i /c:"Enabled" >nul
            if not errorlevel 1 (
                echo "%%~b" was successfully restarted.
            ) else (
                echo WARNING: "%%~b" might NOT have restarted successfully!
            )
        )
    )
)
if not defined FOUND_ADAPTER (
    echo No Wi-Fi adapters found.
)
echo.
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
@echo off
setlocal enabledelayedexpansion
cls

:confirm_loop
echo ===============================================
echo    Delete Temporary Files and System Cache
echo ===============================================
echo.
echo This will permanently remove temp files for your user and Windows.
echo.
set /p confirm=Do you want to continue? (Y/N): 

if /I "!confirm!"=="Y"  goto verify_temp
if /I "!confirm!"=="YES" goto verify_temp
if /I "!confirm!"=="N"  goto cancelled
if /I "!confirm!"=="NO" goto cancelled

echo Invalid input. Please type Y or N.
goto confirm_loop

:cancelled
echo Operation cancelled.
pause
goto menu

:verify_temp
REM -- Find actual temp folder via PowerShell (safe even if env is messed up)
for /f "delims=" %%T in ('powershell -NoProfile -Command "[System.IO.Path]::GetTempPath()"') do set "REAL_TEMP=%%T"

REM -- Validate temp path is under userprofile
echo !REAL_TEMP! | findstr /I "%USERNAME%" >nul
if errorlevel 1 (
    echo [ERROR] TEMP path unsafe or invalid: !REAL_TEMP!
    echo Aborting to prevent system damage.
    pause
    goto menu
)

cls
echo Deleting temporary files using PowerShell...
powershell -NoProfile -Command ^
    "Remove-Item -Path '$env:TEMP\*','C:\Windows\Temp\*','$env:USERPROFILE\AppData\Local\Temp\*' -Recurse -Force -ErrorAction SilentlyContinue"

echo.
echo Temporary files deleted.
pause
goto menu

:choice12
cls
echo ======================================================
echo Advanced Registry Cleanup ^& Optimization
echo ======================================================
echo.
echo [1] List "safe to delete" registry keys under Uninstall
echo [2] Delete all "safe" registry keys
echo [3] Create Registry Backup
echo [4] Restore Registry Backup
echo [5] Scan for corrupt registry entries
echo [0] Return to main menu
echo.
set /p rchoice=Enter your choice: 

if "%rchoice%"=="1" goto list_reg_keys
if "%rchoice%"=="2" goto delete_safe_keys
if "%rchoice%"=="3" goto reg_backup
if "%rchoice%"=="4" goto reg_restore
if "%rchoice%"=="5" goto reg_scan
if "%rchoice%"=="0" goto menu
goto choice12

:list_reg_keys
echo.
echo Listing registry keys matching: IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent
powershell -NoLogo -NoProfile -Command ^
    "Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.Name -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } | ForEach-Object { Write-Host $_.Name }"
pause
goto choice12

:delete_safe_keys
echo.
echo Deleting registry keys matching: IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent
powershell -NoLogo -NoProfile -Command ^
    "Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.Name -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } | ForEach-Object { Remove-Item $_.PsPath -Recurse -Force -ErrorAction SilentlyContinue; Write-Host 'Deleted:' $_.Name }"
pause
goto choice12

:reg_backup
set "backupFolder=%SystemRoot%\Temp\RegistryBackups"
if not exist "%backupFolder%" mkdir "%backupFolder%"
set "backupName=RegistryBackup_%date:~-4,4%-%date:~-7,2%-%date:~-10,2%_%time:~0,2%-%time:~3,2%.reg"
set "backupFile=%backupFolder%\%backupName%"
reg export HKLM "%backupFile%" /y
echo Backup created: %backupFile%
pause
goto choice12

:reg_restore
set "backupFolder=%SystemRoot%\Temp\RegistryBackups"
echo Available backups:
dir /b "%backupFolder%\*.reg"
set /p backupFile=Enter the filename to restore: 
if exist "%backupFolder%\%backupFile%" (
    reg import "%backupFolder%\%backupFile%"
    echo Backup successfully restored.
) else (
    echo File not found.
)
pause
goto choice12

:reg_scan
cls
echo Scanning for corrupt registry entries...
sfc /scannow
dism /online /cleanup-image /checkhealth
echo Registry scan complete. If errors were found, restart your PC.
pause
goto choice12

:choice13
setlocal enabledelayedexpansion
cls
echo ==========================================
echo      Optimize SSDs (ReTrim/TRIM)
echo ==========================================
echo This will automatically optimize (TRIM) all detected SSDs.
echo.
echo Listing all detected SSD drives...
echo.

set "DRIVES_FOUND=0"
set "LOGFILE=%USERPROFILE%\Desktop\SSD_OPTIMIZE_%DATE:~0,4%-%DATE:~5,2%-%DATE:~8,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.log"
echo SSD Optimize Log - %DATE% %TIME% > "%LOGFILE%"

for /f "delims=" %%D in ('powershell -NoLogo -NoProfile -Command "Get-PhysicalDisk | Where-Object MediaType -eq 'SSD' | Get-Disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null | Select-Object -ExpandProperty DriveLetter"') do (
    set /a DRIVES_FOUND+=1
    echo Found SSD: DriveLetter %%D
    echo Running: Optimize-Volume -DriveLetter %%D -ReTrim -Verbose >> "%LOGFILE%"
    powershell -NoLogo -NoProfile -Command "Optimize-Volume -DriveLetter %%D -ReTrim -Verbose" >> "%LOGFILE%" 2>&1
    echo Done with drive %%D >> "%LOGFILE%"
    echo -------------------------------------- >> "%LOGFILE%"
)

if !DRIVES_FOUND! EQU 0 (
    echo No SSDs detected.
    pause
    endlocal
    goto menu
)

echo.
echo SSD optimization completed. Log file saved on Desktop: 
echo %LOGFILE%
pause
endlocal
goto menu


:choice14
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

:choice15
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
@echo off
setlocal enabledelayedexpansion
cls
echo ===============================================
echo     Generating Separated System Reports...
echo ===============================================
echo.
echo Choose output location:
echo  [1] Desktop (recommended)
echo  [2] Enter custom path
echo  [3] Show guide for custom path setup
set /p "opt=> "

REM === OPTION 1: Automatic folder on Desktop ===
if "!opt!"=="1" (
    for /f "usebackq delims=" %%d in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('Desktop')"`) do (
        set "DESKTOP=%%d"
    )
    for /f "usebackq delims=" %%t in (`powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HHmm"`) do (
        set "REPORTDIR=SystemReports_%%t"
    )
    set "OUTPATH=!DESKTOP!\!REPORTDIR!"
    if not exist "!OUTPATH!" mkdir "!OUTPATH!"
    goto genReports
) else if "!opt!"=="2" (
    set /p "OUTPATH=Enter full path (e.g. D:\Reports): "
    goto checkPath
) else if "!opt!"=="3" (
    goto pathGuide
) else (
    echo.
    echo Invalid selection.
    timeout /t 2 >nul
    goto choice22
)

:pathGuide
cls
echo ===============================================
echo     How to Use a Custom Report Path
echo ===============================================
echo.
echo 1. Open File Explorer and create a new folder, e.g.:
echo    C:\Users\YourName\Desktop\SystemReports
echo    or
echo    C:\Users\YourName\OneDrive\Documents\SystemReports
echo.
echo 2. Copy the folder's full path from the address bar.
echo 3. Re-run this and choose option [2], then paste it.
echo.
pause
goto menu

:checkPath
if not exist "!OUTPATH!" (
    echo.
    echo [ERROR] Folder not found: "!OUTPATH!"
    pause
    goto choice22
)
goto genReports

:genReports
REM === Generate date ===
for /f "usebackq delims=" %%t in (`powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"`) do (
    set "DATESTR=%%t"
)

set "SYS=!OUTPATH!\System_Info_!DATESTR!.txt"
set "NET=!OUTPATH!\Network_Info_!DATESTR!.txt"
set "DRV=!OUTPATH!\Driver_List_!DATESTR!.txt"

echo.
echo Writing system info to: !SYS!
systeminfo > "!SYS!" 2>nul

echo Writing network info to: !NET!
ipconfig /all > "!NET!" 2>nul

echo Writing driver list to: !DRV!
driverquery > "!DRV!" 2>nul

echo.
echo Reports saved in:
echo !OUTPATH!
echo.
pause
endlocal
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