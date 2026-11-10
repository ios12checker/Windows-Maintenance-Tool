# Windows Maintenance Tool Documentation

Windows Maintenance Tool (WMT) is a portable Windows maintenance application. It can be launched directly from its executable or installed through WinGet, which registers the portable application and exposes the `wmt` terminal command.

> **Important:** Installing WMT with WinGet does not turn it into a traditional MSI-style application. WinGet manages the portable package and its command alias; you can launch it from the Start menu or run `wmt` in a terminal.

## Start here

- [Install and launch WMT](Installation.md)
- [Using WMT](Using-WMT.md)
- [Troubleshooting](Troubleshooting.md)
- [Updates and release channels](Updates-and-Releases.md)
- [Security and release verification](Security.md)

## Quick start

Install from an elevated or normal PowerShell/Windows Terminal session:

```powershell
winget install --id Chaython.WindowsMaintenanceTool --exact
```

After installation, open a new terminal and run:

```powershell
wmt
```

You can also launch WMT from the Start menu. Most maintenance operations request administrator privileges when required.

## What WMT does

WMT brings Windows updates, package management, system repair, cleanup, driver inventory, networking, firewall management, system tweaks, disk analysis, compression, startup management, restore-point tools, and diagnostics into one searchable GUI.

See the [project README](../../README.md) for the full feature list, screenshots, requirements, and project links.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later for the script-based launch
- Administrator privileges for many system-maintenance operations
- Internet access for online package providers, metadata, downloads, and community cleaner definitions

## Support

For bugs or feature requests, use the [GitHub Issues](https://github.com/Chaython/Windows-Maintenance-Tool/issues) page. Include your WMT version, Windows version, reproduction steps, and relevant error or activity-log output.
