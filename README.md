# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v2.9.9-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch.  
Designed for power users, sysadmins, and curious tinkerers – now smarter, safer, and fully offline-compatible.

---

## 📸 Screenshot

![f562edf726d2e0880f1089c29136693d](https://github.com/user-attachments/assets/edb29f79-6e6b-43bf-bd12-6e5abd8da74a)


---

## ✅ Features

- Run essential repair tools: `SFC`, `DISM`, `CHKDSK`
- Windows Update via `winget` (interactive selection)
- View and upgrade individual packages (choose by ID)
- Network diagnostics: `ipconfig`, routing table, DNS config, adapter reset
- Clean temp files, logs, and browser cache
- Save detailed reports to Desktop or custom folder:
  - System Info, Network Info, Driver List
- Registry tools:
  - Safe cleanup, backup, corruption scan
- Fully menu-driven interface with clean output
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

---

## 🧪 Troubleshooting & FAQ

**Q: The script didn’t restart as Admin?**  
A: Make sure UAC is enabled. Right-click and select **Run as Administrator**.

**Q: Why does it crash when selecting winget upgrades?**  
A: Ensure you are running the latest version. All input is validated and error-handled.

**Q: Why was Registry Defrag removed?**  
A: The feature depended on a third-party tool (NTREGOPT) which is no longer accessible.  
The script is now fully offline and native to Windows.

---

## ✍️ Changelog (v2.9.9)

See `CHANGELOG.md` for full history.

- Major DNS tools rewrite: works on all language editions (adapter auto-detection)
- Reports now save to a dedicated folder (`SystemReports`) on Desktop (auto-created)
- Improved error logging: any script errors are saved to `Desktop\WMT_errorlog.txt`
- User can choose report save location or get a guided walkthrough
- Safer temp deletion, confirmation required
- Registry cleanup improved, more backup and restore options
- Bug fixes and performance tweaks throughout

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
