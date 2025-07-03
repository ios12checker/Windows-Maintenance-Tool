@echo off
:: Batchfile to always run PowerShell script as administrator, keep window open

:: Find script location
set SCRIPT=%~dp0Windows_Maintenance_Tool.ps1

:: Start PowerShell as administrator with -NoExit, regardless of user's execution policy
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process PowerShell -ArgumentList '-NoExit -ExecutionPolicy Bypass -File ""%SCRIPT%""' -Verb RunAs"
