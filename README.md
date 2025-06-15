# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v3-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch.  
Designed for power users, sysadmins, and curious tinkerers – now smarter, safer, and fully offline-compatible.

---

## 📸 Screenshot

![89e266338bc2cabf1fefe44dd7068698](https://github.com/user-attachments/assets/beca6ba4-94b3-4c20-80d0-a66585366aa7)


---

## ✅ Features

- Run essential repair tools: `SFC`, `DISM`, `CHKDSK`
- Optimize SSD drives (TRIM/defrag compatible)
- Windows Update via `winget` (interactive selection)
- View and upgrade individual packages (choose by ID)
- Network diagnostics: `ipconfig`, routing table, DNS config, adapter reset
- Clean temp files, logs, and browser cache
- Save detailed reports to Desktop or custom folder:
  - System Info, Network Info, Driver List
- **Registry tools** *(new and improved!)*:
  - Safe cleanup, backup, and corruption scan
  - Fully menu-driven registry cleanup:  
    - List "safe to delete" entries (matches: `IE40`, `IE4Data`, `DirectDrawEx`, `DXM_Runtime`, `SchedulingAgent`)
    - Bulk delete all safe entries (now 100% stable)
    - Easy backup & restore with versioned .reg files
    - PowerShell-based logic for precision and compatibility
- All language/region support – no hardcoded adapter names
- No third-party dependencies required

---

## ⚙️ Installation

1. Download the `.bat` file.
2. **Right-click → Run as Administrator** (auto-elevation supported).
3. Follow the interactive menu.

> ⚠️ Script output may appear in your system language (e.g. English, Danish, etc). This is normal.

---

## 📁 Output Files

Saved directly to your chosen folder (by default: Desktop\SystemReports):

- `System_Info_YYYY-MM-DD.txt`
- `Network_Info_YYYY-MM-DD.txt`
- `Driver_List_YYYY-MM-DD.txt`
- `routing_table_YYYY-MM-DD.txt`
- `RegistryBackup_YYYY-MM-DD_HH-MM.reg` (registry backup files)

---

## 🧪 Troubleshooting & FAQ

**Q: The script didn’t restart as Admin?**  
A: Make sure UAC is enabled. Right-click and select **Run as Administrator**.

**Q: Why does it crash when selecting registry cleanup?**  
A: This has been fixed in v3.1.0. The script now safely lists and deletes registry keys using PowerShell, and errors are properly handled.

**Q: Why was Registry Defrag removed?**  
A: The feature depended on a third-party tool (NTREGOPT) which is no longer accessible.  
The script is now fully offline and native to Windows.

---

## ✍️ Changelog (v3)

See `CHANGELOG.md` for full history.

- **New registry cleanup menu:**  
  - Now uses PowerShell for all registry queries and deletions
  - No more script crashes on delete
  - Option to list, bulk delete, backup, and restore registry entries  
- **Backup/restore improvements:**  
  - Backups are auto-versioned and easily restorable from the menu  
- **Bugfixes and stability:**  
  - Registry functions are now safer and more robust
  - Improved error messages and input validation
- **General enhancements:**  
  - Menu structure and output improved
  - All features verified on multiple Windows editions

---

## 🤝 Contributing

Pull requests, issues, and feedback are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

Licensed under the **MIT License**.  
See [`LICENSE`](LICENSE) for full details.

## 🔗 Related Projects

- [🍎 MSS – Mac Service Script](https://github.com/ios12checker/MSS-Mac-Service-Script)
