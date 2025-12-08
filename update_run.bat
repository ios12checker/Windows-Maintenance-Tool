@echo off
REM Ensure the working directory is the same as the batch file location
cd /d "%~dp0"

REM --- 1. UPDATE THE SCRIPT ---
REM We use a simple inline PowerShell command to download the file.
echo Updating Windows_Maintenance_Tool.ps1...
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; try { Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Chaython/Windows-Maintenance-Tool/main/Windows_Maintenance_Tool.ps1' -OutFile 'Windows_Maintenance_Tool.ps1' -ErrorAction Stop } catch { Write-Warning 'Update failed. Using local copy.' }"

REM --- 2. RUN AS ADMIN IN TERMINAL ---
REM Check if the file exists (either downloaded or local backup)
IF EXIST "Windows_Maintenance_Tool.ps1" (
    REM Launch wt.exe as Admin (-Verb RunAs)
    REM We use '-d .' to ensure it starts in this folder, avoiding path errors
    PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process wt.exe -ArgumentList '--size 100,50 -d . powershell -NoExit -ExecutionPolicy Bypass -File \"Windows_Maintenance_Tool.ps1\"' -Verb RunAs"
) ELSE (
    echo [ERROR] Script not found. Check your internet connection.
    pause
)

EXIT