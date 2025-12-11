# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v4.0-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

All-in-one Windows maintenance toolkit in PowerShell + Batch. Runs locally, no install required.

---

## 📸 Screenshots
<img width="1180" height="837" alt="Windows Maintenance Tool UI" src="https://github.com/user-attachments/assets/fd029aed-69cb-4e35-9ba5-bd5212bdf13a" />

---

## ✅ Features

- **System Health & Repair:** One-click SFC, DISM (Check/Restore), CHKDSK on all drives; Windows Update component repair/reset.
- **Winget Updates:** Refresh, search, update/uninstall apps; auto-installs winget if missing.
- **Network & DNS:** Flush/reset, adapter reset, routing table view/save, DoH on/off (Cloudflare/Google/Quad9/AdGuard), custom DNS, hosts editor/adblock with backups.
- **Firewall Manager:** Search/view rules, add/edit/enable/disable/delete, export/import, reset, or purge.
- **Drivers & Devices:** Driver report to Desktop, ghost device removal, enable/disable driver updates and device metadata, clean old drivers with backup/restore safeguards.
- **Cleanup & Privacy:** Temp/cache cleanup, Recycle Bin empty, privacy traces (recent/thumbcache), broken shortcut fixer, Xbox credential cleanup.
- **Storage:** SSD TRIM/ReTrim.
- **Registry Tools:** Safe list/delete of obsolete keys with auto-backup, HKLM backup/restore, SFC/DISM scan option.
- **Reports:** Save System/Network/Driver lists to Desktop or a chosen folder.
- **.NET Roll-Forward:** Set or unset runtime/SDK roll-forward.
- **Windows Update Utilities:** Full repair/reset, service restart, BITS queue cleanup.
- **Activation (Optional):** MAS (massgrave.dev) downloader/runner with explicit warning/consent.
- **Gpedit Installer:** Enables Local Group Policy Editor on supported Home editions.
- **GUI & CLI:** GUI feature parity with the CLI; runs elevated with a hidden console.


---

## 🔄 Updater Guide

The included `update_run.bat` checks your local version, downloads the latest PS1/BAT from the repo, and only overwrites when newer (or when remote version is unknown but the payload is valid).

1) Open your Windows Maintenance Tool folder (e.g., `C:\Users\<you>\Desktop\Windows Maintenance Tool`).
2) Run `update_run.bat`.
   - Reads local version from `Windows_Maintenance_Tool.ps1`.
   - Downloads `Windows_Maintenance_Tool.ps1` and `Start_Windows_Maintenance_Tool.bat`.
   - Updates only if newer; warns and skips on download failure.
   - Leaves the window open with status messages.
3) Press any key to exit after reviewing the messages.

Tips:
- Keep `update_run.bat` in the same folder as `Windows_Maintenance_Tool.ps1`.
- Batch launcher is validated before overwrite.
- GUI launcher carries `GUI_LAUNCHER_VERSION` inside `Start_WMT_GUI.bat` for “already up to date” detection.

---

## ⚙️ Manual Launch

- CLI: Run `Start_Windows_Maintenance_Tool.bat` (or `powershell -NoProfile -ExecutionPolicy Bypass -File "Windows_Maintenance_Tool.ps1"`).
- GUI: Run `Start_WMT_GUI.bat` (launches `WMT-GUI.ps1` elevated, hidden console).
- Keep both the BAT and PS1 in the same folder.

---

## 📁 Output Files (defaults)

- `Installed_Drivers.txt` (Desktop)
- `System_Info_YYYY-MM-DD.txt`
- `Network_Info_YYYY-MM-DD.txt`
- `Driver_List_YYYY-MM-DD.txt`
- `routing_table_YYYY-MM-DD.txt`
- `RegistryBackup_YYYY-MM-DD_HH-MM.reg`

---

## 🧪 Troubleshooting

- **Needs admin:** Right-click BAT → Run as administrator; ensure UAC prompts appear.
- **Update fetch fails:** Check network; updater will warn and keep your local copy.
- **Registry cleanup safety:** Keys are backed up before deletion; HKLM backup/restore available.
- **MAS is optional:** MAS is fetched from massgrave.dev only after your confirmation; not bundled.

---

## 📜 Credits

- Author: [Lil_Batti](https://github.com/ios12checker)
- Contributor: [Chaython](https://github.com/Chaython)

MIT Licensed — see `LICENSE`.

---

## 🤝 Contributing

Issues/PRs welcome. Please include repro steps and environment details for bugs.
