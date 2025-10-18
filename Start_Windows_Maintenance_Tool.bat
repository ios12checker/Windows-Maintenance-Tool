@echo off
:: Batch file to run PowerShell script as administrator in Windows Terminal, falling back to PowerShell

:: Find script location
set SCRIPT=%~dp0Windows_Maintenance_Tool.ps1

:: Check if Windows Terminal is available
where wt.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    :: Windows Terminal found, run script in wt.exe as admin with -NoExit and specific size
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "Start-Process wt.exe -ArgumentList '--size 100,50 powershell -NoExit -ExecutionPolicy Bypass -File ""%SCRIPT%""' -Verb RunAs"
) else (
    :: Windows Terminal not found, fall back to PowerShell as admin with -NoExit
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
      "Start-Process PowerShell -ArgumentList '-NoExit -ExecutionPolicy Bypass -File ""%SCRIPT%""' -Verb RunAs"
)