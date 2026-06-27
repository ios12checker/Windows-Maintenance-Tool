# Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v6.1-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Windows Maintenance Tool is an all-in-one GUI toolkit for repairing, cleaning, updating, and tuning Windows 10 and Windows 11 systems. It brings common maintenance tasks into one interface instead of spreading them across Settings, Control Panel, PowerShell, Task Scheduler, Registry Editor, and separate utilities.

It is built for technicians, power users, and end users who want practical Windows maintenance tools with clear buttons, visible output, confirmation prompts, and local backups where risky changes are involved.

<details>
<summary><b>Click here for links to report a False Positive to your Antivirus provider</b></summary>

If you're recieving a notification of a PUP or false positive regarding our open sourse tool; please submit a report to your AV's developer and whitelist the file locally so you can use it. Do not create an issue in our repository.

## Submission Directory

| Antivirus Vendor | Submission Link or Email | Notes |
| :--- | :--- | :--- |
| **Avast** | [Avast False Positive Form](https://www.avast.com/en-us/false-positive-file-form.php) | Web form for file or URL submission. |
| **AVG** | [AVG False Positive Form](https://www.avg.com/en-us/false-positive-file-form) | AVG and Avast share engines, but use their respective forms. |
| **Avira** | [Avira Analysis Submit](https://analysis.avira.com/en/submit) | Requires creating an account or logging in. |
| **Bitdefender** | [Bitdefender Submission Portal](https://www.bitdefender.com/submit/) | Alternatively, email `virus_submission@bitdefender.com`. |
| **ClamAV** | [ClamAV False Positives](http://www.clamav.net/reports/fp) | Open-source engine used by many secondary providers. |
| **ESET** | `samples@eset.com` | Compress file in a `.zip` with the password **infected**. Use the subject "False positive". |
| **F-Secure** | [F-Secure Sample Submit](https://www.f-secure.com/en/web/labs_global/submit-a-sample) | Check the box for "I want to give more details..." to clarify it is a false positive. |
| **Kaspersky** | [Kaspersky OpenTip](https://opentip.kaspersky.com/) | Upload the file, analyze it, and then click "Submit to Review". Or email `newvirus@kaspersky.com`. |
| **Malwarebytes** | [Malwarebytes Forums](https://forums.malwarebytes.com/forum/122-false-positives/) | Submissions are handled directly through their community forums. |
| **McAfee** | `virus_research@mcafee.com` | Compress file in a `.zip` with password **infected**. Mention it is a false positive in the subject line. |
| **Microsoft Defender** | [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/filesubmission) | Select "Software Developer" to submit your own application. Requires Microsoft login. |
| **Norton / Symantec** | [Symantec Submit Form](https://symsubmit.symantec.com/) | Choose "Incorrectly Detected by Symantec" at the top of the portal. |
| **Sophos** | [Sophos Sample Submission](https://secure2.sophos.com/en-us/support/submit-a-sample.aspx) | Clarify in the "Why do you want to send this sample?" section that it is a false positive. |
| **Trend Micro** | [Detection Re-evaluation](https://www.trendmicro.com/en_us/about/legal/detection-reevaluation.html) | Fill out the web form and provide the SHA-256 hash or file. |

A revolving list of all Antivirus contacts can be found here: https://docs.virustotal.com/docs/false-positive-contacts
</details>

## Highlights

- Modern grouped GUI for Windows repair, cleanup, updates, drivers, tweaks, firewall, DNS, and utilities.
- Full dark/light theme support with a persistent theme toggle.
- Package updater with Winget, Microsoft Store / Store CLI, pip, npm, pnpm, Chocolatey, Scoop, Ruby Gems, Cargo, .NET global tools, PowerShell modules, Composer, Steam game manifests, Legendary Epic Games updates, and GOGDL GOG game updates.
- One-by-one package update flow with visible progress windows, plus experimental headless/background automation.
- Optional EXE build support through PS2EXE for release builds.
- Optional system tray mode with background update scans, notifications, and reduced RAM mode while hidden.
- Unified Game Library for installed Steam, Epic/Legendary, and GOG titles.
- Individual provider controls for update scans, package search, library search, and metadata.
- My Device dashboard with system specs, storage health, improved drive benchmark, network, battery/power, driver tools, RAM cleanup, TRIM, export, and quick shortcuts to related tools.
- Startup Manager for startup apps, scheduled tasks, context menu entries, and services.
- Restore Manager with create, delete, restore, enable, and disable actions.
- Advanced Cleanup with analyze/preview mode, Winapp2 community rules, and BleachBit CleanerML support.
- Safety prompts, backups, revert actions, and clearer error messages for risky operations.

## Screenshot
<img width="1920" height="1033" alt="image" src="https://github.com/user-attachments/assets/e3e7ca22-4e27-4382-a812-7a66d2cc3789" />



## What's New in v6.1

### Game Library

- Added a unified Game Library for locally installed Steam, Epic/Legendary, and GOG games.
- Added library search, provider filtering, sorting, cache refresh, and supported launch/install/uninstall actions.
- Added Steam library discovery through configured library folders, app manifests, and cached app metadata.
- Added Epic library discovery through Legendary and GOG library discovery through GOGDL/local metadata.
- Added Game Library entries to global search.
- Integrated owned Legendary and GOG games into the main package search when library searching is enabled.

### Providers and Search

- Added individual controls for each provider's update scans, package search, library search, and metadata use.
- Added provider capability detection so only supported options are displayed.
- Added package searching for Steam, Scoop, RubyGems, and Cargo.
- Added a 24-hour cached PyPI index for much faster Python package searches with less network traffic.
- Added automatic update-scan intervals for 8 hours, 12 hours, and 1 day.
- Added individual Windows Update category controls.

### Interface and Startup

- Added **Start with Windows** in Support & Credits, with automatic startup-entry validation and repair if WMT is moved.
- Consolidated 31 paired on/off or enable/disable controls into single state-aware Tweaks buttons.
- Applied matching unified toggle behavior to relevant My Device and Drivers actions.
- Added clearer state-aware tooltips and hover descriptions.
- Added Enter/Space checkbox control and improved click-drag selection in the Updates list.

### Fixes and Performance

- Fixed Advanced Cleanup deletion after the WPF conversion.
- Fixed Windows Update category handling and provider-toggle persistence.
- Fixed several consolidated controls showing or applying the wrong action.
- Fixed Steam library detection across additional configured library folders.
- Improved Steam metadata caching, provider search performance, and startup registration for script and EXE launches.
- Reduced repeated C# compilation work and corrected transparency in the EXE/tray icon.

## Core Features

### Updates and Software

- Scan for updates from Winget, Microsoft Store / Store CLI, Chocolatey, pip, npm, pnpm, Scoop, Ruby Gems, Cargo, .NET global tools, PowerShell modules, Composer, Steam manifests, Legendary, GOGDL, and more.
- Update packages one at a time with a visible update window.
- Run optional background scans and experimental headless/auto-install flows from tray mode.
- Search package results before updating.
- Control update scanning, package search, library search, and metadata separately for supported providers.
- Ignore selected Winget packages.
- Browse and install curated software.
- Handles slow providers with timeout protection.
- Optionally include Winget unknown-version packages with `--include-unknown`.
- Delegates Microsoft Store app updates through Store CLI / Microsoft Store update handling where supported.
- Delegates Steam game updates through the Steam client after detecting pending local manifests.
- Updates Epic games through the standalone Legendary executable when authenticated; updates installed GOG games through Heroic's GOGDL when GOG auth is available.
- Right-click supported Winget package rows to view manifest details.
- Use **Update All** for batch update flows where available.

### Game Library

- View installed Steam, Epic/Legendary, and GOG games in one combined library.
- Search and filter the library by title and provider.
- Sort library columns and refresh locally cached game metadata.
- Launch installed games and use supported install/uninstall actions.
- Include owned Legendary/GOG games in package searches when library searching is enabled.

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
- View drive health details and run a drive benchmark.
- Export the current My Device summary.
- Use related quick-action buttons from My Device cards, including driver, cleanup, storage, DNS, and health tools.
- Check driver versions and open vendor driver pages.
- Clean RAM.
- Run SSD TRIM and disk optimization tools.
- Open Disk Management.
- Open Windows Update quickly.

### Tweaks

- Use state-aware toggle buttons instead of separate on/off buttons for supported settings.
- Performance service optimization and revert actions.
- Hibernation, SysMain, memory compression, and power plan controls.
- Windows Update policy presets.
- Optional Windows feature toggles.
- Taskbar alignment, search, widgets, Task View, Chat, and button combine behavior.
- Clock options for 12-hour/24-hour format and seconds display.
- Hardware-Accelerated GPU Scheduling (HAGS) toggle.
- Explorer options for file extensions, hidden files, full path title bars, launch location, and recent/frequent items.
- Mouse pointer speed, acceleration, and single-click/double-click behavior.
- Context menu tweaks for classic Windows 11 menu, Take Ownership, and PowerShell Here.
- Privacy, search, gaming, visual effect, notification, and lock screen tweaks.
- Bloatware and AppX cleanup tools.

### Cleanup

- Delete temporary files and recycle bin data.
- Analyze cleanup targets before deleting files, including file status for protected or in-use items.
- Clean selected files from the preview window.
- Run advanced cleanup selections with internal rules, Winapp2 community rules, and BleachBit CleanerML rules.
- Clear Windows Event Logs.
- Clean browser and Explorer traces.
- Find, inspect, fix, or delete broken shortcuts using the rebuilt Broken Shortcut Manager.
- Clean selected registry issues with backups, review-only protected findings, richer scan coverage, Regedit context tools, and clearer result details.
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
- Set custom IPv4/IPv6 DNS servers from a dedicated dialog.
- Register or remove DNS over HTTPS templates for custom DNS entries.
- Enable or disable DNS over HTTPS rules.
- View routing tables.
- Edit the hosts file.
- Apply ad-block hosts lists.

### Firewall Manager

- View and search firewall rules.
- Lazy-load firewall rules and selected-rule details for better responsiveness, with background preload and detail caching.
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
- PS2EXE build script for creating release EXE builds.
- Start or stop WMT launching automatically with Windows.
- Group Policy Editor installer for supported Windows Home systems.
- Optional MAS activation helper with explicit user confirmation.

## Getting Started

### Recommended Launch

Double-click:

```bat
Start_WMT_GUI.bat
```

Keep `Start_WMT_GUI.bat` and `WMT-GUI.ps1` in the same folder. The launcher validates the script and starts the GUI with the required permissions.

### EXE Build

To build a local EXE release:

```powershell
.\PS2EXE\Build-Exe.ps1 -InstallPS2EXE
```

The default output is:

```text
dist\WindowsMaintenanceTool.exe
```

The EXE build uses the version from `$AppVersion` in `WMT-GUI.ps1` and requires administrator privileges at runtime.

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
| `legendary` / `gogdl` | Local game-provider helper tools and auth files |
| Provider/library cache files | Cached PyPI and game-library metadata |
| `last-crash.txt` | Last captured WMT crash/monitor diagnostic |

## Safety Notes

- Destructive actions use confirmation prompts.
- Registry and hosts changes create backups where applicable.
- Many tweak groups include revert actions.
- Startup and service changes are visible in Startup Manager.
- Start with Windows repairs its saved launch path when WMT has been moved.
- Registry cleaner review-only rows are shown for inspection and are not fixed automatically.
- Tray/headless package automation is experimental and may still require manual provider interaction.
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
| Background/headless update does not finish | Disable headless mode and run the provider visibly from the Updates tab. |
| A game is missing from Game Library | Refresh the library and verify its launcher, local manifest, authentication, and provider toggles. |
| Start with Windows no longer works after moving WMT | Open Support & Credits; WMT can validate and repair its startup entry. |
| A tweak causes issues | Use the matching revert button where available. |
| Registry cleanup finds protected entries | Review-only entries are intentionally not fixed automatically. Inspect them before taking action. |

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
