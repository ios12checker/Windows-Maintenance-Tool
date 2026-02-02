# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v5.0-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

All-in-one Windows maintenance and optimization toolkit. Features system repair, performance tweaks, bloatware removal, software management, and more. Runs locally with a modern dark GUI.

---

## 📸 Screenshots
<img width="1920" height="1035" alt="image" src="https://github.com/user-attachments/assets/31401819-9f01-45a6-849c-1863445c40f4" />

---

## ✅ Features

### ⚡ System Tweaks (NEW in v5.0!)
- **Performance Optimization:**
  - Services to Manual - Optimize 100+ services for better performance
  - Services Revert - Restore all services to default settings
  - Disable/Enable Hibernation - Free up disk space
  - Disable/Enable Superfetch (SysMain)
  - Disable/Enable Memory Compression
  - Ultimate Performance Power Plan
- **AppX Bloatware Removal:** Remove pre-installed UWP apps (Xbox, Solitaire, Office Hub, Mail, etc.)
- **Windows Optional Features:** Toggle Hyper-V, WSL, Sandbox, .NET 3.5, NFS, Telnet, IIS, Legacy Media
- **Scheduled Tasks:** Disable/Restore telemetry tasks (CEIP, Error Reporting, Compatibility Appraiser)
- **Windows Update Presets:** Default / Security Only / Disable All

### 🔄 Updates & Software
- **Winget Package Manager:** Scan for updates across multiple providers (winget, chocolatey, pip, npm, scoop, gem, cargo)
- **Software Catalog (NEW!):** Browse and install 26 curated popular apps (browsers, dev tools, utilities, games, security)
- **Bulk Install/Uninstall:** Multi-select operations with progress tracking

### 💓 System Health & Repair
- **System File Checker:** SFC scan for corrupted files
- **DISM:** Check and Restore Windows image health
- **CHKDSK:** Scan all drives for filesystem errors
- **Windows Update Repair:** Reset components, clear cache, restart services

### 🌐 Network & DNS
- **Network Tools:** Flush DNS, reset Wi-Fi, full network repair
- **DNS Management:** Google, Cloudflare, Quad9, Auto (DHCP), Custom DNS
- **DNS over HTTPS:** Enable/Disable DoH for all major providers
- **Hosts File Editor:** Built-in editor with ad-blocking hosts download
- **Routing:** View and save routing tables

### 🔥 Firewall Manager
- **Rule Management:** View, search, add, edit, enable/disable, delete rules
- **Bulk Operations:** Export, import, reset to defaults, purge all
- **Visual Indicators:** Color-coded allow/block and enabled/disabled states

### 🔧 Drivers & Devices
- **Driver Reports:** Export installed drivers to Desktop
- **Ghost Device Removal:** Clean up disconnected devices
- **Driver Update Control:** Enable/disable Windows Update driver installation
- **Device Metadata:** Control metadata retrieval
- **Backup/Restore:** Safely backup and restore drivers

### 🧹 Cleanup & Privacy
- **Temp File Cleanup:** Clear user and system temp folders
- **Registry Cleanup:** Safe removal of obsolete keys with auto-backup
- **Broken Shortcuts:** Find and fix broken .lnk files
- **Xbox Cleanup:** Clear Xbox credentials to fix login loops
- **Privacy Traces:** Clean recent files, thumbcache, etc.

### 🛠️ Utilities
- **System Reports:** Save System/Network/Driver info
- **SSD TRIM:** Optimize SSD performance
- **Registry Backup/Restore:** Daily backup task management
- **.NET Roll-Forward:** Configure runtime roll-forward
- **Task Scheduler:** Manage scheduled tasks
- **MAS Activation:** Optional Windows activation helper (requires explicit consent)
- **Gpedit Installer:** Enable Group Policy Editor on Home editions

---

## 🚀 Getting Started

### Quick Start (Recommended)
Double-click `Start_WMT_GUI.bat` to launch with admin rights and hidden console.

### Manual Launch
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "WMT-GUI.ps1"
```

> ⚠️ **Note:** Keep both `Start_WMT_GUI.bat` and `WMT-GUI.ps1` in the same folder.

---

## 📋 Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Administrator privileges (auto-elevated)
- Internet connection (for updates, downloads, and winget)

---

## 📁 Output Files

| File | Location |
|------|----------|
| Installed_Drivers.txt | Desktop |
| System_Info_YYYY-MM-DD.txt | Desktop |
| Network_Info_YYYY-MM-DD.txt | Desktop |
| Driver_List_YYYY-MM-DD.txt | Desktop |
| routing_table_YYYY-MM-DD.txt | Desktop |
| RegistryBackup_YYYY-MM-DD_HH-MM.reg | Data folder |
| hosts_backup_* | Data folder |
| settings.json | Data folder |

---

## 🆕 What's New in v5.0

### Major New Features
- **⚡ Tweaks Tab:** Complete system optimization suite
- **📦 Software Catalog:** Curated app installer with 26 popular apps
- **🎨 Modern UI:** GitHub Dark theme, crisp text, card-based layout

### Improvements
- **Performance:** Fixed hanging updates scan with proper timeouts
- **Visibility:** Real-time progress output during operations
- **Navigation:** Emoji icons, active tab indicator, comprehensive ToolTips

See [CHANGELOG.md](CHANGELOG.md) for full details.

---

## 🧪 Troubleshooting

| Issue | Solution |
|-------|----------|
| "Needs admin" | Right-click BAT → Run as administrator |
| Update fetch fails | Check network connection |
| Winget not found | Tool will auto-install winget if missing |
| Registry cleanup | Keys are backed up before deletion |
| Services optimization issues | Use "Revert Services" button to restore defaults |

---

## 🛡️ Safety Features

- **Backups:** Registry keys and hosts file backed up before changes
- **Revert Options:** Services, scheduled tasks, and tweaks can be reverted
- **Confirmations:** Destructive actions require confirmation
- **Local Only:** No data sent to external servers

---

## 📜 Credits

- **Author:** [Lil_Batti](https://github.com/ios12checker)
- **Contributor:** [Chaython](https://github.com/Chaython)

MIT Licensed — see [LICENSE](LICENSE).

---

## 🖥️ Other Projects

- [MSS Mac Service Script](https://github.com/ios12checker/MSS-Mac-Service-Script)
- [Winrar Patcher](https://github.com/ios12checker/Winrar-Patcher)

---

## 🤝 Contributing

Issues and PRs welcome! Please include:
- Steps to reproduce
- Windows version
- Screenshot if applicable

---

**⭐ Star this repo if you find it useful!**
