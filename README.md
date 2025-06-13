# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v2.9.7-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch.  
Designed for power users, sysadmins, and curious tinkerers – now safer, smarter, and fully offline-compatible.

---

## 📸 Screenshot
![8d964ca61b63b8c0234132d84f21f043](https://github.com/user-attachments/assets/4082067c-5f3f-491f-bea2-4257617e1c58)

---

## ✅ Features

- Run essential repair tools: `SFC`, `DISM`, `CHKDSK`
- Windows Update repair and cache reset (`choice21`)
- **New:** Interactive `winget` upgrade selection (manual or full)
- **New:** Routing Table Viewer (live or save to Desktop)
- Generate detailed reports:
  - System Info
  - Network Info
  - Driver List
- Full compatibility with OneDrive-synced Desktops
- Clean browser cache, temp files, logs
- Safe Registry cleanup (no third-party EXEs)
- Network troubleshooting tools (flush DNS, IP config, adapter reset)
- Fully menu-driven interface with clean output
- No external tools or dependencies

---

## ⚙️ Installation

1. Download the `.bat` file.
2. **Right-click → Run as Administrator** (auto-elevation included).
3. Use the interactive menu to choose an action.

> ⚠️ Output may appear in your system language (e.g. English, Danish, etc). This is expected behavior.

---

## 📁 Output Files

Saved directly to your Desktop:

- `System_Info_YYYY-MM-DD.txt`
- `Network_Info_YYYY-MM-DD.txt`
- `Driver_List_YYYY-MM-DD.txt`
- `routing_table_YYYY-MM-DD_HH-mm-ss.txt` *(added in v2.9.6)*

All paths are auto-detected to support OneDrive redirection.

---

## 🧪 Troubleshooting & FAQ

**Q: Script won't restart as admin?**  
A: Ensure UAC is enabled. Right-click → **Run as Administrator**.

**Q: Crashing after CHKDSK or routing tool?**  
A: Fixed in v2.9.7. Services are now conditionally checked and fail-safe.

**Q: My Desktop path is redirected?**  
A: Fully supported. The script uses PowerShell to locate your actual Desktop, even with OneDrive sync.

**Q: Why was NTREGOPT removed?**  
A: The tool is no longer available and was replaced by native-safe registry cleanup logic.

---

## ✍️ Changelog (v2.9.7)

- ✅ Winget upgrade menu now supports individual package selection
- 🛰️ Routing table can now be viewed or saved with timestamp to Desktop
- 🧰 CHKDSK engine completely rewritten (choice10)
- 🧠 Desktop path detection rewritten using PowerShell (OneDrive supported)
- 🔁 Removed all third-party registry dependencies
- 🧽 Cleaned logic, rewrote flow control and subroutines
- 🛑 Eliminated batch crashes related to `goto` and `exit /b`
- ✏️ All comments and prompts rewritten for clarity

---

## 🤝 Contributing

Issues, suggestions, and PRs are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## 📜 License

Licensed under the MIT License. See [`LICENSE`](LICENSE) for full terms.

---

## 🔗 Related Projects

- [🍎 MSS – Mac Service Script](https://github.com/ios12checker/MSS-Mac-Service-Script)
