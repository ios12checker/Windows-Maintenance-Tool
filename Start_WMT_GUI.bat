@echo off
setlocal EnableExtensions DisableDelayedExpansion
:: Start_WMT_GUI.bat
set "GUI_LAUNCHER_VERSION=1.3"
set "BAT_URL=https://raw.githubusercontent.com/ios12checker/Windows-Maintenance-Tool/refs/heads/main/Start_WMT_GUI.bat"
set "SCRIPT_URL=https://raw.githubusercontent.com/ios12checker/Windows-Maintenance-Tool/refs/heads/main/WMT-GUI.ps1"
set "SCRIPT=%~dp0WMT-GUI.ps1"
set "WMT_SCRIPT_PATH=%SCRIPT%"
set "WMT_SCRIPT_DIR=%~dp0"

:: 1. Check for updates to this Launcher (.bat)
echo Checking for launcher updates...
set "TEMP_BAT=%TEMP%\Start_WMT_GUI_update.bat"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "function Convert-WmtVersion([string]$v) { $m=[regex]::Match(([string]$v).Trim(),'^\s*v?(\d+(?:\.\d+){0,3})\s*$'); if (-not $m.Success) { throw ('Invalid version: ' + $v) }; $p=@($m.Groups[1].Value.Split('.')); while ($p.Count -lt 4) { $p += '0' }; [version]::new([int]$p[0],[int]$p[1],[int]$p[2],[int]$p[3]) }; " ^
  "$remote = try { (Invoke-WebRequest -Uri '%BAT_URL%' -UseBasicParsing).Content } catch { $null }; " ^
  "if ($remote -match 'GUI_LAUNCHER_VERSION=([0-9]+(?:\.[0-9]+){0,3})') { " ^
  "  if ((Convert-WmtVersion $matches[1]) -gt (Convert-WmtVersion '%GUI_LAUNCHER_VERSION%')) { " ^
  "    [IO.File]::WriteAllText('%TEMP_BAT%', $remote); exit 43 " ^
  "  } " ^
  "}"

if "%ERRORLEVEL%"=="43" (
  echo New launcher version found! Updating...
  timeout /t 1 /nobreak >nul
  copy /y "%TEMP_BAT%" "%~f0" >nul
  del "%TEMP_BAT%" >nul
  start "" "%~f0"
  exit /b
)

:: 2. Check for updates to the GUI Script (.ps1) by comparing $AppVersion
echo Checking for WMT-GUI.ps1 updates...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "function Convert-WmtVersion([string]$v) { $m=[regex]::Match(([string]$v).Trim(),'^\s*v?(\d+(?:\.\d+){0,3})\s*$'); if (-not $m.Success) { throw ('Invalid version: ' + $v) }; $p=@($m.Groups[1].Value.Split('.')); while ($p.Count -lt 4) { $p += '0' }; [version]::new([int]$p[0],[int]$p[1],[int]$p[2],[int]$p[3]) }; " ^
  "$rx='\$AppVersion\s*=\s*.?([0-9]+(?:\.[0-9]+){0,3})'; $f=$env:WMT_SCRIPT_PATH; $u='%SCRIPT_URL%'; $lv=Convert-WmtVersion '0'; " ^
  "if (Test-Path -LiteralPath $f) { $lt=Get-Content -LiteralPath $f -Raw -ErrorAction Ignore; if ($lt -match $rx) { $lv=Convert-WmtVersion $matches[1] } }; " ^
  "$rt=try { (Invoke-WebRequest -Uri $u -UseBasicParsing).Content } catch { $null }; " ^
  "if ($rt -match $rx) { $rv=Convert-WmtVersion $matches[1]; if ($rv -gt $lv -and $rt.Length -ge 100000) { " ^
  "$tokens=$null; $parseErrors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput($rt,[ref]$tokens,[ref]$parseErrors); if (-not $parseErrors.Count) { " ^
  "$tmp=$f + '.update-' + [guid]::NewGuid().ToString('N'); $bak=$f + '.launcher-backup'; [IO.File]::WriteAllText($tmp,$rt,[Text.UTF8Encoding]::new($true)); " ^
  "try { if (Test-Path -LiteralPath $f) { Move-Item -LiteralPath $f -Destination $bak -Force }; Move-Item -LiteralPath $tmp -Destination $f -Force; exit 45 } catch { if (Test-Path -LiteralPath $bak) { Move-Item -LiteralPath $bak -Destination $f -Force }; Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue; if (Test-Path -LiteralPath $f) { exit 0 } else { exit 1 } } " ^
  "} } } " ^
  "if (Test-Path -LiteralPath $f) { exit 0 } else { exit 1 }"

set "PS_EXIT=%ERRORLEVEL%"
if "%PS_EXIT%"=="45" (
  echo [INFO] WMT-GUI.ps1 was updated to the latest version.
) else if "%PS_EXIT%"=="1" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Add-Type -AssemblyName PresentationFramework; $msg='WMT-GUI.ps1 was not found and the download failed.' + [Environment]::NewLine + 'Please check your internet connection.'; [System.Windows.MessageBox]::Show($msg,'WMT Launcher Error',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null"
  exit /b 1
)

:: 3. Guard against accidentally downloaded HTML page
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$p=$env:WMT_SCRIPT_PATH; $head=((Get-Content -LiteralPath $p -TotalCount 120 -ErrorAction SilentlyContinue) -join \"`n\"); if($head -match '(?is)<!doctype\s+html|<html\b|<head\b|<body\b|<meta\b[^>]*charset'){ exit 42 } else { exit 0 }"

if "%ERRORLEVEL%"=="42" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Add-Type -AssemblyName PresentationFramework; $msg='Invalid WMT-GUI.ps1 detected.' + [Environment]::NewLine + 'It looks like an HTML page was downloaded instead of the raw PowerShell script.' + [Environment]::NewLine + [Environment]::NewLine + 'Please download from Releases or use the raw file link.'; [System.Windows.MessageBox]::Show($msg,'WMT Launcher Error',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null"
  start "" "https://github.com/ios12checker/Windows-Maintenance-Tool/releases"
  exit /b 1
)

:: 4. Force Admin Escalation from the batch file
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
  "try { Start-Process -Verb RunAs -WindowStyle Hidden -FilePath 'powershell.exe' -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('\"{0}\"' -f $env:WMT_SCRIPT_PATH)) -WorkingDirectory $env:WMT_SCRIPT_DIR; exit 0 } catch { exit 1 }"

:: 5. Catch if the user declines the UAC prompt or the launch fails
set "LAUNCH_EXIT=%ERRORLEVEL%"
if not "%LAUNCH_EXIT%"=="0" (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Add-Type -AssemblyName PresentationFramework; $msg='Failed to start WMT-GUI.ps1.' + [Environment]::NewLine + 'Admin rights were declined or the script was blocked.' + [Environment]::NewLine + 'Launcher exit code: %LAUNCH_EXIT%' + [Environment]::NewLine + [Environment]::NewLine + 'Path:' + [Environment]::NewLine + $env:WMT_SCRIPT_PATH; [System.Windows.MessageBox]::Show($msg,'WMT Launcher Error',[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null"
  exit /b %LAUNCH_EXIT%
)
