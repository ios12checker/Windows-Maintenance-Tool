@echo off
:: Start_WMT_GUI.bat version 1.1 (matches WMT-GUI.ps1 $AppVersion)
set "GUI_LAUNCHER_VERSION=1.1"
:: Launch WMT-GUI.ps1 silently (no extra console) with elevation.

set "SCRIPT=%~dp0WMT-GUI.ps1"

:: Start elevated PowerShell hidden and run the GUI script
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
  "Start-Process -Verb RunAs -WindowStyle Hidden -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%SCRIPT%\"' -WorkingDirectory '%~dp0'"
