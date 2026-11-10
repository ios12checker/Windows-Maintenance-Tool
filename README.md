# Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v6.9-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)
[![Community](https://img.shields.io/badge/Community-Join%20Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/bCQqKHGxja)
[![Sponsor Chaython](https://img.shields.io/badge/Sponsor-Chaython-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/Chaython)
[![Sponsor ios12checker](https://img.shields.io/badge/Sponsor-ios12checker-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/ios12checker)

Now available on winget! `winget install Chaython.WindowsMaintenanceTool`

Windows Maintenance Tool (WMT) is an all-in-one Windows 10/11 maintenance GUI for updates, repairs, cleanup, drivers, networking, firewall management, system tuning, compression, software/game libraries, and diagnostics. It brings tasks that normally live across Settings, Control Panel, PowerShell, Task Scheduler, Registry Editor, Device Manager, and separate utilities into one interface.

WMT is designed for technicians, power users, and everyday users who want visible status, searchable tools, confirmation prompts, backups where appropriate, and background work that avoids freezing the WPF interface.

## Core Features

<details>
<summary><strong>Updates and Software</strong></summary>

- Scan for updates from Winget, Microsoft Store / Store CLI, Chocolatey, pip, npm, pnpm, Scoop, Ruby Gems, Cargo, .NET global tools, PowerShell modules, Composer, Steam manifests, Legendary, GOGDL, and other supported providers.
- Update packages one at a time with visible status/progress, or use supported batch/update-all flows.
- Search packages by name and inspect provider results as individual providers finish instead of waiting for every provider.
- Control update scans, package search, game/library search, and metadata behavior independently for supported providers.
- Ignore selected Winget packages and optionally include unknown-version Winget entries for manual review.
- Attach a custom PowerShell update command to a package when you want WMT to run your command instead of the provider's normal update command.
- Use placeholders in custom commands: `{id}`, `{name}`, `{source}`, `{version}`, and `{available}`.
- View Winget manifest details from package rows; Chocolatey package/community information is also integrated where available.
- Delegates Steam game updates through Steam after local manifest comparison.
- Updates Epic games through Legendary when authenticated and installed GOG games through GOGDL/Heroic authentication.
- Checks WMT-managed portable Legendary/GOGDL binaries for newer releases and can surface provider updates as normal update rows.
- Background update scanning can run from tray mode; **BG Jobs** and **Update Scans** are independently toggleable.
- Shared provider process/runspace infrastructure includes timeout/error handling so a slow provider is less likely to block the entire Updates page.

</details>

<details>
<summary><strong>Game & Software Library</strong></summary>

- View installed Steam games plus owned/installed Epic/Legendary and GOG titles in one combined library.
- Search/filter the library by title/provider and sort list columns.
- Install owned Epic games through a themed Legendary options dialog with library-root/folder selection, platform, workers, shared-memory limit, owned DLC selection, and optional file reordering.
- Install owned GOG games through the GOGDL options dialog with install root, language, build/version, owned DLC selection, and download-worker controls.
- **Locate / Import** (Your Library action bar or a game's context menu): select an existing installation folder for any Steam, Epic/Legendary, or GOG/GOGDL game. Legendary runs verified `import` and updates its installed-game database; GOGDL validates `goggame-*.info` via `import` and WMT atomically stores the detected install path in `data/gogdl_installs.json`. Imports run in a background worker so the WPF window stays responsive. Only a successful matching provider registration changes the installed state; game files are not downloaded or moved by WMT.
- For **Steam**, a matching `appmanifest_<appid>.acf` in a registered Steam library is recognized on refresh. When the library is not registered or the manifest is missing, WMT explains how to add the library using Steam > Settings > Storage or offers to open Steam's native install/verification flow. WMT intentionally does not forge Steam manifest files or claim that unregistered folders are installed.
- Optionally create a desktop shortcut and/or a **Start menu > Programs > WMT Games** entry after a successful Legendary or GOGDL install.
- Legendary install preflight validates saved Epic credentials and metadata when possible and can offer re-authentication when the saved login is missing or invalid.
- Launch installed titles and use supported install/uninstall/folder actions. Legendary folder actions can recover missing or stale paths from Legendary's local installed-game registry.
- Explicit library refreshes rebuild provider caches; Legendary installed state is merged from the local installed-game database so installed games remain visible even when live metadata is incomplete or unavailable.
- Open supported Steam/Epic/GOG store pages directly from library/provider rows.
- Include owned Legendary/GOG titles in package search when library searching is enabled; installing those search results opens the same full Legendary/GOGDL installer used by **Your Library** instead of a separate headless/provider-specific path.
- Package search now tracks installed state across supported providers: uninstalled results expose **Install**, installed results expose **Uninstall/Repair** where supported, and **Update** appears only when WMT can identify a newer provider version.
- Search-result context actions include provider-aware **Manifest / Metadata** and **Package / Store Page** access for Winget/Microsoft Store, Chocolatey, npm, NuGet/.NET tools, PowerShell Gallery, Packagist, PyPI, Scoop, crates.io, RubyGems, Steam, Epic, and GOG where applicable.
- Optionally hide Unreal Engine / Fab marketplace assets from the visible library without hiding installed games.
- Uses cached provider/library metadata, atomic cache writes, and background refreshes to improve repeat-load performance and preserve known-good state across provider failures.

</details>

<details>
<summary><strong>System Health</strong></summary>

- Run `sfc /scannow`.
- Run DISM CheckHealth and RestoreHealth operations.
- Run Quick Fix/common repair routines.
- Check Windows Recovery Environment (WinRE) state with concise and technical views.
- Run CHKDSK tools.
- Repair Windows Update components and reset update services.
- Long-running repair operations use background workers where practical to reduce WPF-thread stalls.

</details>

<details>
<summary><strong>Disk Analyzer</strong></summary>

- Analyze selected folders or drives with a recursive background scan while keeping the WPF interface responsive.
- Explore disk usage through an interactive, squarified treemap and a hierarchical folder tree containing the scanned folders and subfolders.
- Select a treemap area to navigate to or expand its corresponding folder; double-click entries to open their location in File Explorer.
- Use the Details view to browse the full scanned hierarchy, filter results, sort columns, and resize columns using the native, continuous ListView-style headers.
- Navigate with Back and Up using the in-memory scan results; only starting a new scan reads the selected location from disk.
- Browse to a folder to select it and automatically start scanning. The drive indicator follows the selected folder's drive, defaulting to C: when no other drive is selected.
- Use the themed context menu for supported file and folder actions, including opening locations, copying paths, opening terminals, viewing Properties, refreshing, expanding/collapsing, and deleting with confirmation.
- Review file-type usage, inspect immediate-folder file/folder counts, and export scan reports.
- Open the analyzer from **Utilities** or **My Device > Storage Drives**.

</details>

<details>
<summary><strong>My Device</strong></summary>

- View Windows, CPU, RAM, GPU, motherboard, storage, network, battery, and power details.
- View drive health details and run drive benchmarks.
- Export the current My Device summary.
- Use quick actions for driver, cleanup, storage, DNS, update, and health functions.
- Clean RAM and manage memory-compression related settings.
- Run SSD TRIM/disk optimization logic while avoiding TRIM actions on HDDs.
- Open Disk Management, Windows Update, and related Windows tools.

</details>

<details>
<summary><strong>Tweaks</strong></summary>

- State-aware toggle buttons for supported settings, with consistent active/inactive visual states.
- Export the current tweak configuration to JSON and import a previous export, applying only settings that differ.
- Performance service optimization/revert controls.
- Hibernation, SysMain, memory compression, power plan, Windows Update policy, and optional Windows feature controls.
- Ghost-device cleanup uses a fast direct PnP enumeration to list potential disconnected/Unknown-status devices in an edge-to-edge review dialog, with separate Refresh, Remove Selected and Remove All controls. Device presence is rechecked immediately before removal; connected devices are skipped. An Unknown status by itself does not mean the device is disconnected.
- Driver cleanup, driver export, and driver backup selection use edge-to-edge list/grid layouts with full-width themed footer controls; confirmation prompts retain compact padding.
- Pagefile management detects automatic and custom configurations in the background, confirms before disabling, saves the previous settings to `data/pagefile-restore.json`, restores the previous configuration when re-enabled, and verifies writes with rollback on errors. If no saved configuration exists, enabling uses Windows automatic management. Restart Windows for changes to take effect. Disabling pagefiles is **not recommended**: it reduces available committed memory and can prevent crash dumps.
- Taskbar alignment, search, widgets, Task View, Chat, combine behavior, and related shell controls.
- Clock options including 12/24-hour format and seconds display.
- Hardware-Accelerated GPU Scheduling (HAGS).
- Explorer controls for file extensions, hidden files, full-path title bars, launch location, recent/frequent items, and related behavior.
- Mouse pointer speed/acceleration and single-click/double-click behavior.
- Context-menu tweaks including classic Windows 11 menu, Take Ownership, and PowerShell Here.
- Privacy, search, gaming, visual-effect, notification, lock-screen, AppX/bloatware, and advanced/power-user controls.
- Tweak state loading runs in the background and is scoped to the Tweaks page so loading overlays do not leak onto other tabs.

</details>

<details>
<summary><strong>Cleanup</strong></summary>

- Delete temporary files, recycle-bin contents, Windows Error Reporting data, thumbnail caches, browser traces, Explorer traces, and other selected targets.
- Analyze/preview cleanup targets before deleting files, including status for protected or in-use items.
- Run advanced cleanup rules from WMT's internal cleaners, Winapp2, Winapp3, and BleachBit CleanerML.
- CleanerML support includes broader action parsing such as truncate, registry actions, SQLite vacuum, and process guarding where the source rules define them.
- Cache parsed cleaner rules for faster repeat startup and optionally skip downloads/use cached definitions.
- Configure how often WMT refreshes local parsed cleaner caches and how often it checks upstream cleaner definitions for changes.
- Configure automatic cleanup intervals using your saved cleaner selections; the cleaner work itself runs in an isolated hidden process.
- Filter the cleaner selection list, including a **Show Enabled** view for quickly reviewing active selections.
- Clear Windows Event Logs.
- Find, inspect, repair, or delete broken shortcuts.
- Registry cleaner with backups, confidence/risk metadata, richer scan coverage, Regedit context actions, and review-only handling for findings that should not be changed automatically.
- Registry cleanup includes safer BAM/DAM stale activity cleanup and pair-preserving handling of `PendingFileRenameOperations`.
- Clear Xbox credentials for login-loop fixes.
- Free local OneDrive disk space while keeping cloud copies.

</details>

<details>
<summary><strong>Compact Compression</strong></summary>

- Compress a folder or a whole local NTFS drive from a dedicated GUI.
- Use standard NTFS compression and supported Compact/WOF executable compression modes.
- Persistently track previously compressed targets in `data\compact-tracker.json`.
- Enable/disable automatic recompression per tracked target.
- Schedule background recompression through Windows Task Scheduler so tracked targets can be handled even when WMT itself is not open.
- Choose preset schedules or a custom interval.
- Detect whether tracked content has changed before recompressing rather than blindly recompressing unchanged data.
- Optionally skip extensions that are commonly already-compressed/poor compression candidates, with support for custom extension skip lists.
- Keep last-run/result/status information for tracked targets and surface it in the compression UI.

</details>

<details>
<summary><strong>Drivers</strong></summary>

- Inventory third-party packages staged in the Windows Driver Store.
- Show package status including **In Use**, **Old**, **Unattached**, and **Inactive** with device-usage context.
- Search/filter drivers by status, class, provider, file name, and related metadata.
- Preload the driver list at startup when Background Jobs are enabled, reuse cached rows on tab visits, and retry the device-usage phase without re-enumerating packages. Use **Reload** for an explicit full refresh.
- Export installed drivers and selected categories.
- Restore drivers from backup.
- Generate detailed driver reports.
- Remove ghost devices.
- Clean old/superseded driver packages from the shared inventory, protecting packages used by PnP devices or installed driver services. Backups, confirmation prompts and live pre-deletion usage checks remain in place.
- Enable/disable Windows automatic driver updates and device metadata downloads.
- Open external research/update checks for selected drivers, including Microsoft Update Catalog and VirusTotal where supported by the UI.
- Driver backup/cleanup and `pnputil` operations are moved off the WPF thread where possible.

</details>

<details>
<summary><strong>Network and DNS</strong></summary>

- Flush DNS and reset network settings.
- Set DNS to Cloudflare, Google, Quad9, DHCP, or custom IPv4/IPv6 servers.
- Register/remove DNS-over-HTTPS templates for custom DNS entries.
- Enable/disable DNS-over-HTTPS rules.
- View routing tables.
- Edit the hosts file and apply supported ad-block hosts lists with backup handling.

</details>

<details>
<summary><strong>Firewall Manager</strong></summary>

- View, search, add, edit, enable, disable, and delete firewall rules.
- Background-load the base firewall rule list to keep navigation responsive.
- Preload protocol/port metadata using the Windows Firewall COM interface (`HNetCfg.FwPolicy2`) from background work when enabled.
- Fall back to lazy NetSecurity detail lookup when the fast path is unavailable.
- Cache selected-rule details to reduce repeated expensive queries.
- Export/import firewall policies.
- Restore firewall defaults or purge rules with confirmation.
- Background firewall preload respects the global Background Jobs setting.

</details>

<details>
<summary><strong>Startup & Restore Management</strong></summary>

- Startup Manager for startup apps, scheduled tasks, context-menu entries, and services.
- Open relevant file locations, Registry paths, and Task Scheduler locations/actions where possible.
- Restore Manager for creating, deleting, restoring, enabling, and disabling restore points/system protection workflows.

</details>

<details>
<summary><strong>System Tray, Background Jobs, and Automation</strong></summary>

- Optional system-tray mode keeps selected background scans/notifications active while the main window is hidden.
- Start WMT with Windows and optionally launch minimized.
- Independent **BG Jobs** and **Update Scans** toggles are exposed on Support & Credits.
- Tray menu follows the active theme and provides shortcuts to major pages plus a theme toggle and Exit.
- Update scans can run periodically while WMT remains active in the tray.
- Cleaner definition maintenance and auto-clean use separate hidden worker processes to avoid blocking the GUI.
- Compact auto-recompression uses a scheduled worker/task and does not require the main WMT window to stay open.
- Shared polling/runspace infrastructure centralizes background completion handling and reduces duplicated UI timers.

</details>

<details>
<summary><strong>Utilities</strong></summary>

- Startup Manager.
- Restore Manager.
- Compact Compression manager.
- Disk Usage Analyzer with a squarified treemap space map, a Details folder tree covering every scanned folder, cache-backed Back/Up navigation, right-click file actions, and file-type breakdown.
- Context menu builder.
- System reports.
- Release download statistics.
- .NET roll-forward configuration.
- Group Policy Editor installer for supported Windows Home systems.
- Optional MAS activation helper with explicit user confirmation.
- Quick access to common Windows administrative tools.

</details>

<details>
<summary><strong>Getting Started</strong></summary>

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

Default output:

```text
dist\WindowsMaintenanceTool.exe
```

The EXE build uses the version from `$AppVersion` in `WMT-GUI.ps1` and requires administrator privileges at runtime.

For theme diagnostics, PS2EXE reserves `-Debug` for its own debugger switch. Pass script arguments after `-end` so WMT receives its debug switch:

```powershell
.\dist\WindowsMaintenanceTool.exe -end -Debug
```

### Manual Launch

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "WMT-GUI.ps1"
```

</details>

<details>
<summary><strong>Requirements</strong></summary>

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges for most maintenance actions
- Internet connection for online update checks, provider scans, downloads, metadata, and community cleaner definitions

</details>

<details>
<summary><strong>Output and Data Folder</strong></summary>

WMT stores generated data next to the script in its local `data` folder.

| Output | Purpose |
| --- | --- |
| `settings.json` | Saved WMT settings and feature toggles |
| `Installed_Drivers.txt` | Driver report output |
| `Drivers_Backup_*` | Exported driver backups |
| `SystemReports_*` | System, network, and driver reports |
| `RegistryBackups` | Registry-cleaner backups |
| `hosts_backups` | Hosts-file backups |
| `winapp2.ini` / `winapp3.ini` / cleaner cache files | Advanced cleanup community rules and parsed caches |
| `bleachbit_cleanerml` / CleanerML cache files | BleachBit CleanerML definitions/cache |
| `compact-tracker.json` | Tracked Compact Compression targets, schedules, state, and results |
| Compact worker/log files | Scheduled/background recompression support |
| `legendary` / `gogdl` | WMT-managed portable game-provider tools/auth data |
| Provider/library cache files | Cached package and game-library metadata |
| Cleaner refresh/auto-clean result files | Last background cleaner maintenance/automatic-clean summaries |
| `last-crash.txt` | Last captured WMT crash/monitor diagnostic |

</details>

<details>
<summary><strong>Safety Notes</strong></summary>

- Destructive actions use confirmation prompts where practical.
- Registry and hosts changes create backups where applicable.
- Many tweak groups include revert actions.
- Registry cleaner review-only rows are shown for inspection and are not fixed automatically.
- Automatic cleanup uses **saved explicit cleaner selections** rather than silently opting into first-run defaults.
- Compact auto-recompression tracks only targets you explicitly add/enable.
- Background jobs can be disabled globally; update scans also have a separate toggle.
- Start with Windows can validate/repair its saved launch path after WMT is moved.
- WMT itself does not send telemetry.
- Some functions call Windows components, package managers, GitHub/community rule sources, or third-party provider CLIs and therefore depend on those components/services being available.

</details>

<details>
<summary><strong>Troubleshooting</strong></summary>

| Problem | What to try |
| --- | --- |
| App does not start | Run `Start_WMT_GUI.bat` from the same folder as `WMT-GUI.ps1`. |
| SmartScreen blocks launch | Choose **More info** and **Run anyway** only if you trust the copy you downloaded/built. |
| Admin prompt appears | Accept it if you intend to use maintenance actions that require elevation. |
| Winget scan fails | Verify App Installer/Winget is installed and internet access is working. |
| Package provider hangs/fails | Retry that provider; WMT includes timeouts but some provider CLIs still require manual intervention. |
| A Steam game appears as a Winget update | Refresh scans/library data; v6.7 includes additional Steam ownership filtering for duplicate/unknown-version rows. |
| Epic/GOG game is missing | Refresh the library and verify Legendary/GOGDL authentication, local manifests, and provider toggles. |
| Cleaner definitions look stale | Review the cleaner local-refresh/upstream-check intervals and ensure Background Jobs/downloads are enabled. |
| Automatic cleanup does not run | Confirm an auto-clean interval is set, Background Jobs are enabled, and at least one cleaner selection has been saved/enabled. |
| Compact scheduled recompression does not run | Re-save the Compact schedule and verify the generated Windows scheduled task/worker files still exist. |
| Firewall ports initially look blank | Allow the background preload to finish, or select a rule so the lazy fallback can load its details. |
| Start with Windows stops working after moving WMT | Open Support & Credits and use the startup controls so WMT can validate/repair the saved path. |
| A tweak causes issues | Use the matching revert/toggle action or import a known-good tweaks JSON export. |
| Registry cleanup finds protected/review-only entries | Inspect them; those rows are intentionally not changed automatically. |

</details>

<details>
<summary><strong>Development and Releases</strong></summary>

- `.github/workflows/validate-powershell.yml` validates PowerShell syntax and can also be run manually.
- `.github/workflows/release-ps2exe.yml` automatically publishes a rolling prerelease from `Main`, and separately supports manual versioned releases, both with Sigstore attestations.
- Release tooling includes optional WinGet submission and Chocolatey package publication paths when the required secrets/package entries are available.
- Long-running GUI operations are increasingly routed through shared runspace/process/polling infrastructure to keep the main WPF dispatcher responsive.

</details>

<details>
<summary><strong>Keyboard Shortcuts & Quick Find</strong></summary>

The main WMT window supports a few familiar, context-sensitive shortcuts:

| Shortcut | Action |
| --- | --- |
| **F5** | Refresh the visible Updates, Drivers, Firewall, or Your Library view, if its refresh action is enabled. |
| **Ctrl+F** | Focus the search field for the visible Updates, Drivers, Firewall, or Your Library view (or Quick Find elsewhere). When the activity log has focus, search the log instead. |
| **Ctrl+Shift+F** | Focus global Quick Find. |

F5 on Updates is an explicit package scan: merely visiting the Updates tab does **not** trigger a scan. Refresh shortcuts reuse the corresponding on-screen actions and respect disabled controls. Other pages do not run a refresh action on F5.

### Quick Find

Quick Find is in the left sidebar above the navigation buttons (without an extra Navigation heading). Typing a tool name or related description opens the **Find Tools** page in the main workspace. Related tools are dynamically grouped by section and presented using the **actual WPF buttons** from their existing pages, including current labels, icons, enabled states, and original click handlers. Clicking these buttons performs their normal action **immediately**, just as on the original page; review sensitive operations before clicking. The original control is restored to its exact place when the search changes, the user switches tabs, the window closes, or Quick Find is hidden. Controls that depend on their original page context (such as catalogue navigation or non-button search fields), along with disabled controls and tools inside hidden subsections, instead offer **Open section**. The Software Catalog and Your Game Library results navigate into the correct sub-view. Broad searches display up to 40 matching controls to limit WPF layout work, with a short debounce during typing. Clearing the query removes the result cards; navigation stays available while searching. Automated Windows smoke tests exercise button relocation, original click handlers, inherited state, and restoration.

</details>

<details>
<summary><strong>Project Links</strong></summary>

- [Releases](https://github.com/ios12checker/Windows-Maintenance-Tool/releases)
- [Issues](https://github.com/ios12checker/Windows-Maintenance-Tool/issues)
- [Pull Requests](https://github.com/ios12checker/Windows-Maintenance-Tool/pulls)
- [Actions](https://github.com/ios12checker/Windows-Maintenance-Tool/actions)
- [Commit history](https://github.com/ios12checker/Windows-Maintenance-Tool/commits/main)

</details>

## Credits

- Original author: [Lil_Batti / ios12checker](https://github.com/ios12checker)
- GUI, features, and current fork maintenance: [Chaython](https://github.com/Chaython)
- Upstream project: [ios12checker/Windows-Maintenance-Tool](https://github.com/ios12checker/Windows-Maintenance-Tool)

<details>
<summary><strong>Contributing</strong></summary>

Issues and pull requests are welcome. When reporting a problem, include when possible:

- Windows version
- WMT version
- Reproduction steps
- Relevant provider/tool involved
- Screenshot, copied row data, activity-log output, or error text

If WMT helps you, consider starring the repository.

</details>