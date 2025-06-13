# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v2.9.8-brightgreen)
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

## ✍️ Changelog (v2.9.8)
📂 Improved Output Path Options (choice22)

Users can now select where reports are saved:

[1] Desktop (recommended)

[2] Enter a custom path

[3] Step-by-step help for entering a path manually

Designed to work even if Desktop is synced with OneDrive or replaced

🧭 Path validation with clear error handling

Checks if the selected folder exists before proceeding

Displays a clear error if the path is invalid, and returns to the menu

📘 New user guidance option

Option [3] explains how to:

Create a new folder (e.g., on OneDrive or another drive)

Copy the full path using File Explorer

Paste it safely into the script

🗃️ Report filenames remain date-tagged and readable

System_Info_YYYY-MM-DD.txt

Network_Info_YYYY-MM-DD.txt

Driver_List_YYYY-MM-DD.txt

💡 General improvements

More informative output

Better layout and prompt consistency

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
