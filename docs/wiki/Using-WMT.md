# Using Windows Maintenance Tool

## First launch

1. Launch WMT from the Start menu, or run `wmt` in PowerShell/Windows Terminal after installing with WinGet.
2. Review the interface and open the page for the task you want to perform.
3. Use the sidebar's Quick Find field to search for a tool by name or related description.
4. Read confirmation prompts before applying changes, especially for cleanup, registry, driver, service, and tweak operations.

Many functions require administrator privileges. WMT requests elevation where the operation needs it; do not assume every page or read-only action requires an elevated session.

## Navigation and Quick Find

- Use the left navigation to open the main WMT sections.
- Use Quick Find to locate tools across pages without manually browsing each section.
- `Ctrl+Shift+F` focuses global Quick Find.
- `Ctrl+F` focuses the active page's search field where supported, or Quick Find elsewhere.
- `F5` refreshes supported visible views, such as Updates, Drivers, Firewall, and Your Library.

Quick Find can expose actions directly. Review the action label and any confirmation dialog before running an operation.

## Updates and package providers

The Updates page can query supported package managers and software/game providers. Availability depends on which providers are installed, configured, authenticated, and reachable.

If a provider is unavailable, install or configure that provider separately and retry its scan. A failed provider does not necessarily mean the other providers or WMT itself are broken.

## Disk Usage Analyzer

Open Disk Usage Analyzer from Utilities or My Device > Storage Drives. Select a folder or drive and start a scan. The analyzer displays a treemap and a hierarchical Details view. Browsing to a folder selects it and starts a scan automatically.

A scan reads the selected location. Back and Up navigation reuse the in-memory scan results rather than rescanning the disk.

## Tweaks and cleanup

- Review the current state before changing a setting.
- Use the matching revert/toggle action when you want to undo a tweak.
- Export a known-good tweak configuration before making a large batch of changes.
- Use cleanup preview/analyze features before deleting files.
- Treat registry-cleaner review-only findings as informational; they are intentionally not changed automatically.

## Background jobs and tray mode

WMT includes optional background jobs and update scans. These can be controlled independently in Support & Credits. Tray mode can keep selected background work active while the main window is hidden.

Some scheduled tasks, such as configured compression jobs, can run independently of the main WMT window. Review the schedule and target list before enabling automation.
