# Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v5.6-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Windows Maintenance Tool is an all-in-one GUI toolkit for repairing, cleaning, updating, and tuning Windows 10 and Windows 11 systems. It brings common maintenance tasks into one interface instead of spreading them across Settings, Control Panel, PowerShell, Task Scheduler, Registry Editor, and separate utilities.

It is built for technicians, power users, and end users who want practical Windows maintenance tools with clear buttons, visible output, confirmation prompts, and local backups where risky changes are involved.

## Highlights

- Modern grouped GUI for Windows repair, cleanup, updates, drivers, tweaks, firewall, DNS, and utilities.
- Package updater with Winget, Microsoft Store, pip, npm, pnpm, Chocolatey, Scoop, Ruby Gems, and Cargo support.
- One-by-one package update flow with visible progress windows.
- My Device dashboard with system specs, storage, network, battery/power, driver tools, RAM cleanup, TRIM, and Windows Update access.
- Startup Manager for startup apps, scheduled tasks, context menu entries, and services.
- Restore Manager with create, delete, restore, enable, and disable actions.
- Advanced Cleanup with analyze/preview mode before deletion.
- Safety prompts, backups, revert actions, and clearer error messages for risky operations.

## Screenshot

<img width="1920" height="1034" alt="image" src="https://github.com/user-attachments/assets/9da0ae6e-b5ad-4f43-bbd3-f8a54e35bdfd" />

## What's New in v5.6

### Faster Startup and Better Responsiveness

- My Device system statistics now load in a background runspace, so the main GUI stays responsive while hardware, storage, network, and battery details are collected.
- Startup initialization now waits for content rendering, reducing the white PowerShell/window flash during launch.
- Stuck `winget` and `msiexec` processes are cleared before package scans/actions to reduce updater lockups.

### Expanded My Device Dashboard

- Added Network Info for the active physical adapter, including IP address, gateway, DNS, and link speed.
- Added Battery / Power info, including charge level, status, estimated runtime, battery health, and active power plan.

### Cleanup Improvements

- Added **Clear Event Logs** to Advanced Cleanup.
- Event log clearing uses elevated `wevtutil` in a background runspace so the cleanup window does not freeze.

## Core Features

### Updates and Software

- Scan for updates from Winget, Microsoft Store, Chocolatey, pip, npm, pnpm, Scoop, Ruby Gems, Cargo, and more.
- Update packages one at a time with a visible update window.
- Search package results before updating.
- Ignore selected Winget packages.
- Browse and install curated software.
- Handles slow providers with timeout protection.

### System Health

- Run `sfc /scannow`.
- Run DISM CheckHealth and RestoreHealth.
- Run Quick Fix for common Windows repair steps.
- Check Windows Recovery Environment (WinRE) status with a simple summary and optional technical details.
- Run CHKDSK tools.
- Repair Windows Update components.
- Reset update services.

### My Device

- View Windows, CPU, RAM, GPU, motherboard, storage, network, battery, and power details.
- Check driver versions and open vendor driver pages.
- Clean RAM.
- Run SSD TRIM and disk optimization tools.
- Open Windows Update quickly.

### Tweaks

- Performance service optimization and revert actions.
- Hibernation, SysMain, memory compression, and power plan controls.
- Windows Update policy presets.
- Optional Windows feature toggles.
- Taskbar alignment, search, widgets, Task View, Chat, and button combine behavior.
- Clock options for 12-hour/24-hour format and seconds display.
- Hardware-Accelerated GPU Scheduling (HAGS) toggle.
- Bloatware and AppX cleanup tools.

### Cleanup

- Delete temporary files and recycle bin data.
- Analyze cleanup targets before deleting files.
- Clean selected files from the preview window.
- Run advanced cleanup selections.
- Clear Windows Event Logs.
- Clean browser and Explorer traces.
- Find and fix broken shortcuts.
- Clean selected registry issues with backups and safelists.
- Clear Xbox credentials for login-loop fixes.
- Free local OneDrive disk space while keeping cloud copies.

### Drivers

- Export installed drivers with the Driver Export Tool GUI.
- Export selected drivers by category.
- Restore drivers from backup.
- Generate driver reports.
- Remove ghost devices.
- Enable or disable Windows driver updates.
- Toggle device metadata downloads.
- Clean old duplicate drivers.

### Network and DNS

- Flush DNS and reset network settings.
- Set DNS to Cloudflare, Google, Quad9, DHCP, or custom DNS servers.
- Enable or disable DNS over HTTPS rules.
- View routing tables.
- Edit the hosts file.
- Apply ad-block hosts lists.

### Firewall Manager

- View and search firewall rules.
- Add, edit, enable, disable, and delete firewall rules.
- Export and import firewall policies.
- Restore firewall defaults or purge rules with confirmation.

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

Keep `Start_WMT_GUI.bat` and `WMT-GUI.ps1` in the same folder. The launcher validates the script and starts the GUI with the required permissions.

### Manual Launch

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "WMT-GUI.ps1"
```

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges
- Internet connection for update checks, package scans, downloads, and online sources

## Output and Data Folder

WMT stores generated files in a local `data` folder next to the script.

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
- Startup and service changes are visible in Startup Manager.
- WMT itself does not send telemetry.
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

If this tool helps you, consider starring the repository or Donating.
