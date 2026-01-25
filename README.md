# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v4.12-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

All-in-one Windows maintenance toolkit in PowerShell + Batch. Runs locally.

---

## 📸 Screenshots
<img width="963" height="1030" alt="image" src="https://github.com/user-attachments/assets/25b8d463-17c0-45ae-bae9-3cec3da8283e" />










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

## ⚙️ Manual Launch

- Click: Run `Start_WMT_GUI.bat` (or `powershell -NoProfile -ExecutionPolicy Bypass -File "WMT-GUI.ps1"`).
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

## 🖥️ Other programs ive made
[MSS Mac Service Script](https://github.com/ios12checker/MSS-Mac-Service-Script)

[Winrar Patcher](https://github.com/ios12checker/Winrar-Patcher)

---

## 🤝 Contributing

Issues/PRs welcome. Please include repro steps and environment details for bugs.
