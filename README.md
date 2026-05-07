# Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v5.5-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Windows Maintenance Tool is an all-in-one GUI toolkit for repairing, cleaning, updating, and tuning Windows systems. It is designed for power users, technicians, and end users who want common maintenance actions in one place instead of scattered across Control Panel, Settings, PowerShell, and third-party tools.

## Highlights

- Clean modern GUI with grouped maintenance pages
- Package update scanning and one-by-one package updates
- Windows repair tools: SFC, DISM, CHKDSK, WinRE, Windows Update repair
- Startup Manager for startup apps, scheduled tasks, context menu entries, and services
- Restore Manager with create, delete, restore, enable, and disable controls
- My Device dashboard with system specs, driver tools, RAM cleanup, TRIM, and more
- DNS, firewall, driver, cleanup, and system tweak tools
- Safety prompts, backups, and revert options for risky operations

## Screenshots

<img width="1920" height="1033" alt="image" src="https://github.com/user-attachments/assets/f3a8c0e2-53f9-4bbe-9470-f81d85fa6d4b" />


## What's New in v5.5

### Package Updater Improvements

- Adds `pnpm` as a package update provider.
- Restores and expands provider support for Winget, Microsoft Store, pip, npm, pnpm, Chocolatey, Scoop, Ruby Gems, and Cargo.
- Adds better scan timeout handling so one slow provider does not leave the UI waiting forever.
- Improves Winget scan behavior with non-interactive source agreement handling.
- Uses `python -m pip` for more reliable pip actions across Python environments.

### Driver Exporter Overhaul

- Replaces the one-click background driver export with a dedicated Driver Export Tool GUI.
- Runs driver scanning and export work outside the main WMT window so the main app stays responsive.
- Groups drivers by category, including Display, Network, Audio, Storage, USB, Printer, System, and Other.
- Adds driver search, selective export, progress feedback, and Export All.

### Cleanup Analyze Preview

- Adds an Analyze button to Advanced Cleanup / Temp File cleanup.
- Shows a preview window with files that would be deleted before cleanup runs.
- Supports Clean Selected, Clean All, opening a file's folder, and deleting individual files from the preview.
- Displays human-readable file sizes.

## Features

### Updates and Software

- Scan for package updates from providers such as Winget, Microsoft Store, Chocolatey, pip, npm, pnpm, Scoop, Ruby Gems, Cargo, and more.
- Update packages one at a time with visible progress windows.
- Search packages before updating.
- Ignore selected Winget packages.
- Browse and install curated software.

### System Health

- Run `sfc /scannow`.
- Run DISM CheckHealth and RestoreHealth.
- Run Quick Fix for common Windows repair steps.
- Check Windows Recovery Environment (WinRE) status with a simplified summary.
- Run CHKDSK tools.
- Repair Windows Update components.

### My Device

- View system and device information.
- Check driver versions and vendor pages.
- Clean RAM.
- Run SSD TRIM and disk optimization tools.
- Open Windows Update quickly.

### Tweaks

- Performance service optimization and revert.
- Hibernation, SysMain, memory compression, and power plan controls.
- Windows Update policy presets.
- Optional Windows feature toggles.
- Taskbar, clock, search, widgets, Task View, Chat, and HAGS tweaks.
- Bloatware and AppX cleanup tools.

### Network and DNS

- Flush DNS and reset network settings.
- Set DNS to Cloudflare, Google, Quad9, DHCP, or custom servers.
- Enable or disable DNS over HTTPS rules.
- View routing tables.
- Edit hosts file and apply ad-block hosts lists.

### Firewall Manager

- View and search firewall rules.
- Add, edit, enable, disable, and delete rules.
- Export and import firewall rules.
- Reset firewall defaults or purge rules with confirmation.

### Drivers

- Export installed drivers.
- Export selected drivers from the Driver Export Tool GUI.
- Restore drivers from backup.
- Generate driver reports.
- Remove ghost devices.
- Enable or disable Windows driver updates.
- Toggle device metadata downloads.
- Clean old duplicate drivers.

### Cleanup

- Delete temp files and recycle bin data.
- Analyze temp/cleanup files before deletion and delete selected results from the preview.
- Run advanced cleanup selection.
- Clean browser and Explorer traces.
- Find and fix broken shortcuts.
- Clean selected registry issues with backups and safelists.
- Clear Xbox credentials for login-loop fixes.
- Free local OneDrive disk space.

### Utilities

- Startup Manager.
- Restore Manager.
- Context menu builder.
- System reports.
- Release download stats.
- .NET roll-forward configuration.
- Group Policy Editor installer for supported Windows Home systems.
- Optional MAS activation helper with explicit user confirmation.

## Getting Started

### Recommended Launch

Double-click:

```bat
Start_WMT_GUI.bat
```

The launcher validates `WMT-GUI.ps1`, handles update checks, and starts the GUI with the required permissions.

### Manual Launch

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "WMT-GUI.ps1"
```

Keep `Start_WMT_GUI.bat` and `WMT-GUI.ps1` in the same folder.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges
- Internet connection for update checks, package scans, downloads, and online sources

## Output and Data Folder

WMT stores generated files in the local `data` folder next to the script.

| Output | Purpose |
| --- | --- |
| `settings.json` | Saved WMT settings |
| `Installed_Drivers.txt` | Driver report |
| `Drivers_Backup_*` | Exported driver backups |
| `SystemReports_*` | System, network, and driver reports |
| `RegistryBackups` | Registry cleanup backups |
| `hosts_backups` | Hosts file backups |
| `winapp2.ini` / cache files | Advanced cleanup community rules |

## Safety Notes

- Destructive actions use confirmation prompts.
- Registry and hosts changes create backups where applicable.
- Many tweak groups include revert actions.
- Startup and service changes are visible in the Startup Manager.
- No telemetry is sent by WMT itself.
- Some features use online sources, package managers, or Microsoft/Windows components.

## Troubleshooting

| Problem | What to Try |
| --- | --- |
| The app does not start | Run `Start_WMT_GUI.bat` from the same folder as `WMT-GUI.ps1`. |
| SmartScreen blocks launch | Choose **More info** and **Run anyway** if you trust your local copy. |
| Admin prompt appears | Accept it. Most maintenance actions require elevation. |
| Winget scan fails | Make sure App Installer / Winget is installed and internet is available. |
| Package update hangs | Retry the individual provider or update the package manually. |
| A tweak causes issues | Use the matching revert button where available. |
| Registry cleanup finds protected entries | Use the latest version; known protected entries are safelisted. |

## Project Links

- Issues: [GitHub Issues](https://github.com/ios12checker/Windows-Maintenance-Tool/issues)
- Pull Requests: [GitHub Pull Requests](https://github.com/ios12checker/Windows-Maintenance-Tool/pulls)
- Changelog: [CHANGELOG.md](CHANGELOG.md)

## Credits

- Author: [Lil_Batti / ios12checker](https://github.com/ios12checker)
- Contributor: [Chaython](https://github.com/Chaython)

## Community

[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289DA?logo=discord)](https://discord.gg/bCQqKHGxja)

## Contributing

Issues and pull requests are welcome. Please include:

- Windows version
- WMT version
- Steps to reproduce
- Screenshot or error output when possible

If this tool helps you, consider starring the repository.
