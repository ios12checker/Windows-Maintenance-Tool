# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v3.1.2-green)
![Platform](https://img.shields.io/badge/platform-Windows-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch & Powershell.  
Designed for power users, sysadmins, and curious tinkerers – now smarter, safer, and fully offline-compatible.

---

## 📸 Screenshot

![d9b47971d689d8aec75e6a7615edbfcf](https://github.com/user-attachments/assets/3d399b99-9223-4d22-81d2-1889a977ec0d)





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

1. Start `Start_Windows_Maintenance_Tool.bat` file.
2. Follow the interactive menu.

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

**Q: The script didn’t run with administrator rights?**  
A: PowerShell requires elevation for system-level tasks. Right-click the `.ps1` file and choose **"Run with PowerShell"**, then confirm the UAC prompt.  
If nothing happens, run this from PowerShell manually:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File 'Path\To\Windows_Maintenance_Tool.ps1'"
```
**Q: Why does it crash when selecting registry cleanup?**  
A: This has been fixed in v3.1.0. The script now safely lists and deletes registry keys using PowerShell, and errors are properly handled.

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
