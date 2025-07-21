# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v3.5.0-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch & Powershell.  
Designed for power users, sysadmins, and curious tinkerers – now smarter, safer, and fully offline-compatible.

---

## 📸 Screenshot

<img width="699" height="660" alt="b3e6728b438512df8ab1c841ea5ed955" src="https://github.com/user-attachments/assets/573f1efa-a44c-4d02-9150-ac3287d5243c" />


---

## ✅ Features

**Run essential repair tools:**
- Quick access to SFC, DISM, and CHKDSK for core Windows repairs

**Optimize SSD drives:**
- TRIM and compatible defrag for faster, healthier drives

**Windows Update management:**
- Use winget to install, upgrade, and repair system packages
- NEW: Automatically installs winget if missing!
- Flexible package handling: View, search, and upgrade individual apps/packages by entering their ID directly

**Network diagnostics & repair:**
- Includes ipconfig, routing table viewer, DNS config, adapter reset, and more

**Privacy & temp cleanup:**
- Clean temp files, logs, and browser cache
- NEW: Privacy cleanup for extra traces (history, cookies, etc.)

**Save detailed reports:**
- Export System Info, Network Info, and Driver List to your Desktop or a custom folder

**Registry tools:**
- Safe cleanup, backup, and corruption scan
- Menu-driven, stable registry cleaning:
- List “safe to delete” entries (IE40, IE4Data, DirectDrawEx, etc.)
- Bulk delete all safe entries
- Easy backup & restore with versioned .reg files

**DNS-Adblock management:**
- Block ad/tracker domains with hosts file (adblock/mirrors included)
- Improved: Handles locked files, better messaging, multiple backup/restore

**Firewall Manager (NEW!):**
- Built-in menu-driven PowerShell Firewall Manager
- Manage firewall rules, enable/disable Windows Firewall, direct from the tool—no external software needed

**Task & driver management:**
- View and repair scheduled tasks
- List and export all installed drivers

**Menu-driven and user-friendly:**
- All functions accessible from a clear main menu—no PowerShell experience needed
- Support/help, Discord/GitHub contact, openable with a single key press

**Portable & safe:**
- Runs from USB, no install or admin deployment required
- No third-party dependencies or internet downloads required (except optional winget)
---

## ⚙️ Installation

1. Start `Start_Windows_Maintenance_Tool.bat` file.
2. Follow the interactive menu.
3. Make sure that `Start_Windows_Maintenance_Tool.bat` and `Windows_Maintenance_Tool.ps1` are in the same folder, otherwise the Maintenance Tool wont start properly.

> ⚠️ Script output may appear in your system language (e.g. English, Danish, etc). This is normal.

---

## 📁 Output Files

Saved directly to your chosen folder (by default: Desktop\SystemReports):

- `System_Info_YYYY-MM-DD.txt`
  (Full system information report)
  
- `Network_Info_YYYY-MM-DD.txt`
  (Detailed network configuration)
  
- `Driver_List_YYYY-MM-DD.txt`
  (List of all installed drivers)

- `routing_table_YYYY-MM-DD.txt`
  (Network routing table)

- `RegistryBackup_YYYY-MM-DD_HH-MM.reg`
  (Registry backup files, with date and time)
---

## 🧪 Troubleshooting & FAQ

Q: The script didn’t run with administrator rights?
A: For the tool to work properly, administrator rights are required.
Right-click the .bat file and choose "Run as administrator". This will ensure that both the Batch and PowerShell scripts run with the necessary privileges.
If nothing happens, check that User Account Control (UAC) is enabled and try again.

If you want to run the PowerShell script manually, use this command from an elevated PowerShell window:
```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File 'Path\To\Windows_Maintenance_Tool.ps1'"
```
Q: Why does it crash when selecting registry cleanup?
A: This has been fully resolved in v3.1.3. The tool now safely lists and deletes registry keys using PowerShell.
Before any deletion, a backup is automatically created, and errors are properly handled to avoid script crashes or accidental data loss.

**Q: Why was Registry Defrag removed?**  
A: The feature depended on a third-party tool (NTREGOPT) which is no longer accessible.  
The script is now fully offline and native to Windows.

---

## 🤝 Contributing

Pull requests, issues, and feedback are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🌐 Media & Community Thanks

A huge thank you to everyone who has shared, reviewed, or written about the Windows Maintenance Tool!
Your articles, mentions, and feedback help more users discover and benefit from this project.

**Special thanks to:**

- [Korben.info – Script de réparation Windows automatique](https://korben.info/script-reparation-windows-automatique.html)
- [Phonandroid.com – Gagnez un temps fou sur Windows 11 avec ce nouvel outil gratuit…](https://www.phonandroid.com/gagnez-un-temps-fou-sur-windows-11-avec-ce-nouvel-outil-gratuit-qui-repare-et-optimise-votre-pc.html)
- [Ghacks – Windows Maintenance Tool: one-click access to Windows repairs and optimizations](https://www.ghacks.net/2025/06/11/windows-maintenance-tool-one-click-access-to-windows-repairs-and-optimizations/)
- [PCWorld – This free all-in-one tool fixes common Windows problems](https://www.pcworld.com/article/2809221/this-free-all-in-one-tool-fixes-common-windows-problems.html)
- [Unofficial script does the most useful official Windows 11/10 repairs you want automatically](https://www.neowin.net/news/unofficial-script-does-the-most-useful-official-windows-1110-repairs-you-want-automatically/)


Also thank you to Neowin and all other tech sites and community members for your support and coverage!

If you wrote an article or made a video about this project, feel free to open an issue or pull request to get listed here!

## 🎬 Video Guides

- [Windows Maintenance Tool – Guide by Info4Geek](https://www.youtube.com/watch?v=TpZY1nXHTsw)
- [Walkthrough, by ThomyPC](https://www.youtube.com/watch?v=0aUu2agaIto)
- [Showcase of Windows Maintenance Tool by Tech Enthusiast](https://www.youtube.com/watch?v=zfIQvk8BEcM)


---

## Donations to buy me a coffee
If you find this project helpful and would like to support its continued development, you’re welcome to make a donation.
Your support helps keep the Windows Maintenance Tool free and up-to-date for everyone.

[Donate via PayPal](https://www.paypal.me/Lilbatti69)

Or simply star ⭐ the repository and share it!
---

## 📜 License

Licensed under the **MIT License**.  
See [`LICENSE`](LICENSE) for full details.

## 🔗 Related Projects

- [🍎 MSS – Mac Service Script](https://github.com/ios12checker/MSS-Mac-Service-Script)
