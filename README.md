# Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v6.7-green)
![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)
[![Community](https://img.shields.io/badge/Community-Join%20Discord-5865F2?logo=discord&logoColor=white)](https://discord.gg/bCQqKHGxja)
[![Sponsor Chaython](https://img.shields.io/badge/Sponsor-Chaython-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/Chaython)
[![Sponsor ios12checker](https://img.shields.io/badge/Sponsor-ios12checker-EA4AAA?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/ios12checker)

Windows Maintenance Tool (WMT) is an all-in-one Windows 10/11 maintenance GUI for updates, repairs, cleanup, drivers, networking, firewall management, system tuning, compression, software/game libraries, and diagnostics. It brings tasks that normally live across Settings, Control Panel, PowerShell, Task Scheduler, Registry Editor, Device Manager, and separate utilities into one interface.

WMT is designed for technicians, power users, and everyday users who want visible status, searchable tools, confirmation prompts, backups where appropriate, and background work that avoids freezing the WPF interface.

<details>
<summary><b>False positive / antivirus reporting links</b></summary>

If your antivirus reports WMT as a PUP or false positive, submit the file to the antivirus vendor for review and whitelist your trusted local copy if appropriate. WMT is open source, and antivirus false positives should be reported to the antivirus vendor rather than opened as WMT bug reports.

| Antivirus vendor | Submission link or email | Notes |
| :--- | :--- | :--- |
| **Avast** | [Avast False Positive Form](https://www.avast.com/en-us/false-positive-file-form.php) | Web form for file or URL submission. |
| **AVG** | [AVG False Positive Form](https://www.avg.com/en-us/false-positive-file-form) | AVG and Avast share engines, but use their respective forms. |
| **Avira** | [Avira Analysis Submit](https://analysis.avira.com/en/submit) | Requires an account/login. |
| **Bitdefender** | [Bitdefender Submission Portal](https://www.bitdefender.com/submit/) | You can also contact Bitdefender sample submission support. |
| **ClamAV** | [ClamAV False Positives](http://www.clamav.net/reports/fp) | Open-source engine used by many secondary providers. |
| **ESET** | `samples@eset.com` | Follow ESET's sample-submission instructions. |
| **F-Secure** | [F-Secure Sample Submit](https://www.f-secure.com/en/web/labs_global/submit-a-sample) | Include details that the detection is believed to be a false positive. |
| **Kaspersky** | [Kaspersky OpenTip](https://opentip.kaspersky.com/) | Analyze the file and submit it for review. |
| **Malwarebytes** | [Malwarebytes Forums](https://forums.malwarebytes.com/forum/122-false-positives/) | False-positive reports are handled through their forums. |
| **McAfee** | `virus_research@mcafee.com` | Follow McAfee's sample-submission instructions. |
| **Microsoft Defender** | [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/filesubmission) | Select the appropriate developer/software submission option. |
| **Norton / Symantec** | [Symantec Submit Form](https://symsubmit.symantec.com/) | Choose the incorrect-detection workflow. |
| **Sophos** | [Sophos Sample Submission](https://secure2.sophos.com/en-us/support/submit-a-sample.aspx) | Explain that you believe the file is a false positive. |
| **Trend Micro** | [Detection Re-evaluation](https://www.trendmicro.com/en_us/about/legal/detection-reevaluation.html) | Provide the requested file/hash details. |

VirusTotal maintains a broader vendor contact directory here: https://docs.virustotal.com/docs/false-positive-contacts
</details>

## Highlights

- Modern searchable GUI with persistent dark/light themes, tray support, start-with-Windows, and start-minimized controls.
- Updates panel covering Windows/package managers, language ecosystems, PowerShell tooling, Steam, Epic/Legendary, and GOG/GOGDL.
- Per-provider update, package-search, library-search, and metadata controls where supported.
- Custom per-package PowerShell updater commands with placeholders for package metadata.
- Unified game/software library with Steam, Epic/Legendary, GOG, and package-provider integration, including owned-title install flows and installed-state recovery.
- Rebuilt Drivers page that inventories third-party Driver Store packages and classifies in-use, old/superseded, unattached, and inactive packages.
- Advanced cleanup with internal rules, Winapp2, Winapp3, BleachBit CleanerML, preview/analyze mode, configurable cache/update refresh intervals, and optional automatic cleanup.
- Compact Compression utility for folders and drives with persistent tracking, skip lists, change-aware recompression, and scheduled auto-recompression that can run without the WMT window being open.
- Firewall Manager with background rule loading, cached details, and fast protocol/port preloading through the Windows Firewall COM/.NET path with fallback behavior.
- Background runspace/process infrastructure for long-running scans, DISM, networking, service, driver, package, and other operations so the GUI remains responsive.
- Safety-focused registry cleanup, backups/revert paths, review-only findings, confirmation prompts, and detailed activity logging.
- PS2EXE release builds plus validation/release workflows, with optional release submission paths for WinGet and Chocolatey.

## Screenshot

<img width="1902" height="1024" alt="image" src="https://github.com/user-attachments/assets/4fbd8b16-b03f-45c5-a53e-48b9caf45376" />



<details>
<summary><strong>What's new in v6.7</strong></summary>

v6.7 is a broad maintenance and reliability update focused on background execution, automation, package/game providers, cleanup, compression, memory usage, and UI responsiveness.

- Added a full **Epic / Legendary install flow** to Your Library. Owned Epic titles can now be installed with a selectable library root, optional game-folder override, platform, download-worker count, shared-memory limit, owned DLC selection, and Legendary's optional file-reordering mode.
- Added Legendary credential and metadata preflight. WMT checks the local saved-login state, validates Epic access before install when possible, offers to open Legendary authentication when credentials are missing/invalid, and can fall back to cached metadata when live metadata is unavailable.
- Hardened Legendary install tracking and destination handling with duplicate/pending-install guards, longer-running install support, improved final-path resolution, clearer destination reporting, and post-install **desktop / Start menu shortcut** creation.
- Reworked Legendary library refresh and recovery around Legendary's local installed-game JSON. WMT merges installed state and install paths with owned/cached metadata, preserves known-good library data when live Epic metadata is unavailable, recovers stale/missing installed folders for library actions, and rebuilds provider caches during an explicit library refresh.
- Added a full **GOG / GOGDL install flow** to Your Library. Owned GOG games can now be installed with a selectable install root, language, build/version, individual owned DLCs, and configurable download-worker count.
- Added persistent GOGDL install tracking so WMT can distinguish **Owned**, **Downloading**, and **Installed** titles, prevent duplicate downloads, resolve completed install paths from GOGDL manifests, and better handle repair/relaunch scenarios.
- Improved GOGDL authentication/path discovery, including compatible Heroic GOG authentication fallback, language validation, install-path resolution, themed install UI, and lower-memory defaults.
- Added optional post-install **desktop shortcuts and Start menu entries** for both Legendary and GOGDL installs.
- Added portable **Legendary** and **GOGDL** provider-binary update checks to the normal Updates flow.
- Added the **Compact Compression** tracker with persistent folder/drive history, automatic recompression, custom schedules, change detection, per-target state/results, and optional skip lists for already-compressed or poor-compression file formats.
- Added Windows Task Scheduler integration for Compact recompression so scheduled compression can run even when WMT itself is closed.
- Hardened Compact tracker persistence, including automatic recovery/repair when stale ACLs on the ProgramData tracker block WMT from reading or updating it.
- Added configurable cleaner **local cache refresh**, **upstream definition checks**, and **automatic cleaning** intervals.
- Automatic cleaning uses only explicitly saved cleaner selections and runs in a separate hidden worker process while WMT is open or hidden in the tray; overlapping runs are prevented and the global **BG Jobs** toggle disables new cleaner background work.
- Added **Show Enabled** filtering and substantial cleaner worker/poller race, closure, startup, cancellation, and completion-state hardening.
- Restored aggressive **Reduce RAM while hidden in tray** behavior and now releases large reloadable CleanerML, Winapp2, Winapp3, game-library, and related caches while hidden.
- Reworked settings persistence with safer value copying, atomic writes, backup recovery, corrupt-file preservation, external-edit cache invalidation, cleaner interval persistence, and persistent debug/verbose logging state.
- Reworked shared background execution, runspace pools, process running, polling, cancellation, Steam parsing, provider startup, BitLocker/Winget preflight handling, and driver operations to move more blocking work off the WPF thread.
- Added atomic provider/library cache writes and preserves known-good caches when a refresh unexpectedly returns no useful data.
- Hardened Steam ownership detection so Steam-installed games are less likely to appear as duplicate or unknown-version Winget updates.
- Added UTF-8 Steam manifest handling so registered, trademarked, and accented titles render correctly.
- Added per-package **custom updater commands** for pending update rows, including `{id}`, `{name}`, `{source}`, `{version}`, and `{available}` placeholders.
- Improved Firewall Manager background loading and bulk protocol/port preloading using persistent-store `Get-NetFirewallPortFilter` data, while retaining lazy/fallback detail loading.
- Expanded and themed the system-tray context menu with direct shortcuts to Updates, System Health, Cleanup, Drivers, Utilities, and theme switching.
- Added tweak configuration **Export JSON / Import JSON** support and fixed Tweaks loading-overlay state leaking onto other tabs.
- Fixed AppX selection theming, Updates status-text overlap, Firewall Manager action alignment, tray theme-state text, and several other UI consistency issues. ComboBox/dropdown hover and selection colors now follow the same theme inversion as list views, including the GOGDL/Legendary installer dialogs, and folder-selection flows use the Explorer-style picker.
- Expanded registry-cleaner handling for BAM/DAM and `PendingFileRenameOperations`, including safer pair-preserving rewrites and review-only handling where automatic changes are unsafe.
- Invalid Microsoft Defender exclusions now use the supported Defender API (`Remove-MpPreference`) with result verification instead of attempting direct deletion of protected Defender registry values.
- Fixed self-update script-path resolution when WMT is launched directly through PowerShell, resolving **#161**.
- Expanded PowerShell CI from syntax parsing into regression/smoke testing for settings persistence/recovery, cleaner worker state, closure hazards, and shared runspace helper loading.
- Improved the PS2EXE release workflow with SHA-256 generation, safer release existence checks, GitHub release asset replacement, and optional WinGet/Chocolatey publishing when the required package entries/secrets are available.
- Refreshed and reorganized the README for v6.7, including updated screenshots, troubleshooting, safety notes, community/sponsor links, and release/development documentation.

</details>

## Keyboard Shortcuts

The main WMT window supports a few familiar, context-sensitive shortcuts:

| Shortcut | Action |
| --- | --- |
| **F5** | Refresh the visible Updates, Drivers, Firewall, or Your Library view, if its refresh action is enabled. |
| **Ctrl+F** | Focus the search field for the visible Updates, Drivers, Firewall, or Your Library view (or Quick Find elsewhere). When the activity log has focus, search the log instead. |
| **Ctrl+Shift+F** | Focus global Quick Find. |

F5 on Updates is an explicit package scan: merely visiting the Updates tab does **not** trigger a scan. Refresh shortcuts reuse the corresponding on-screen actions and respect disabled controls. Other pages do not run a refresh action on F5.

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
- Reload/rescan the driver list with caching to avoid unnecessary repeated work.
- Export installed drivers and selected categories.
- Restore drivers from backup.
- Generate detailed driver reports.
- Remove ghost devices.
- Clean old/superseded duplicate driver packages with safety checks for unknown/in-use devices.
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
- `.github/workflows/release-ps2exe.yml` builds PS2EXE releases and supports manual release controls.
- Release tooling includes optional WinGet submission and Chocolatey package publication paths when the required secrets/package entries are available.
- Long-running GUI operations are increasingly routed through shared runspace/process/polling infrastructure to keep the main WPF dispatcher responsive.

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
