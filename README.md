# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v3.6.1-green)  
![Platform](https://img.shields.io/badge/platform-Windows-blue)  
![License: MIT](https://img.shields.io/badge/license-MIT-blue)  

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch & PowerShell.  
Designed for power users, sysadmins, and curious tinkerers – now smarter, safer, and fully offline-compatible.  

---

## 📸 Screenshot  
<img width="944" height="697" alt="c2996cf0da297aac0a50deec9880f2c4" src="https://github.com/user-attachments/assets/33dba0a2-c1ef-46ca-a2bb-9f34a5dd1fd2" />



---

## ✅ Features  

**Run essential repair tools:**  
- Quick access to SFC, DISM, and CHKDSK for core Windows repairs  

**Optimize SSD drives:**  
- TRIM and compatible defrag for faster, healthier drives  

**Windows Update management:**  
- Use winget to install, upgrade, and repair system packages  
- Automatically installs winget if missing  
- Flexible package handling: View, search, and upgrade individual apps/packages by entering their ID directly  
- **Improved in v3.6.0:** Windows Update Repair Tool now supports **full nuke & rebuild** with more repair options  

**Network diagnostics & repair:**  
- Includes ipconfig, routing table viewer, DNS config, adapter reset, and more  

**Privacy & temp cleanup:**  
- Clean temp files, logs, and browser cache  
- Privacy cleanup for extra traces (history, cookies, etc.)  

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
- Improved handling of locked files, better messaging, multiple backup/restore  

**Firewall Manager:**  
- Built-in menu-driven PowerShell Firewall Manager  
- Manage firewall rules, enable/disable Windows Firewall directly from the tool  

**.NET RollForward Settings (New in v3.6.0):**  
- Lets the system use a specific .NET version (SDK/runtime)  
- Reduces the need to install multiple .NET runtimes  

**Shortcut Fixer (New in v3.6.0):**  
- Automatic shortcut repair  
- Menu reorganized (options 30 and 0 moved to the end for better structure)  

**Menu-driven and user-friendly:**  
- More return-to-menu options added (v3.6.0)  
- All functions accessible from a clear main menu—no PowerShell experience needed  
- Support/help, Discord/GitHub contact, openable with a single key press  

**Portable & safe:**  
- Runs from USB, no install or admin deployment required  
- No third-party dependencies or internet downloads required (except optional winget)  

---

## ⚙️ Installation  

1. Start `Start_Windows_Maintenance_Tool.bat`.  
2. Follow the interactive menu.  
3. Ensure that both `Start_Windows_Maintenance_Tool.bat` and `Windows_Maintenance_Tool.ps1` are in the same folder.  

> ⚠️ Script output may appear in your system language (e.g. English, Danish, etc). This is normal.  

---

## 📁 Output Files  

Saved directly to your chosen folder (default: Desktop\SystemReports):  

- `System_Info_YYYY-MM-DD.txt` – full system information  
- `Network_Info_YYYY-MM-DD.txt` – detailed network configuration  
- `Driver_List_YYYY-MM-DD.txt` – list of all installed drivers  
- `routing_table_YYYY-MM-DD.txt` – network routing table  
- `RegistryBackup_YYYY-MM-DD_HH-MM.reg` – registry backup files with date/time  

---

## 🧪 Troubleshooting & FAQ  

**Q: The script didn’t run with administrator rights?**  
A: For the tool to work properly, administrator rights are required.  
Right-click the `.bat` file and choose "Run as administrator".  

If nothing happens, check that UAC is enabled and try again.  

Run manually with PowerShell if needed:  
```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File 'Path\To\Windows_Maintenance_Tool.ps1'"
```  

**Q: Why does it crash when selecting registry cleanup?**  
A: This was fixed in v3.1.3. The tool now safely lists and deletes registry keys with auto-backup.  

**Q: Why was Registry Defrag removed?**  
A: It depended on NTREGOPT, which is no longer accessible. The script is now fully offline and native to Windows.  

---

## 📜 Credits  

This release (**v3.6.0**) was fully contributed by **[@Chaython](https://github.com/Chaython)**.  
All new features, fixes, and improvements are thanks to his work.  

---

## 🤝 Contributing  

Pull requests, issues, and feedback are welcome!  
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.  

---

## 🌐 Media & Community Thanks  

A huge thank you to everyone who has shared, reviewed, or written about the Windows Maintenance Tool!  

**Special mentions:**  
- [Korben.info](https://korben.info/script-reparation-windows-automatique.html)  
- [Phonandroid.com](https://www.phonandroid.com/gagnez-un-temps-fou-sur-windows-11-avec-ce-nouvel-outil-gratuit-qui-repare-et-optimise-votre-pc.html)  
- [Ghacks](https://www.ghacks.net/2025/06/11/windows-maintenance-tool-one-click-access-to-windows-repairs-and-optimizations/)  
- [PCWorld](https://www.pcworld.com/article/2809221/this-free-all-in-one-tool-fixes-common-windows-problems.html)  
- [Neowin](https://www.neowin.net/news/unofficial-script-does-the-most-useful-official-windows-1110-repairs-you-want-automatically/)  

If you wrote an article or made a video, open an issue or PR to get listed here.  

---

## 🎬 Video Guides  

- [Guide by Info4Geek](https://www.youtube.com/watch?v=TpZY1nXHTsw)  
- [Walkthrough by ThomyPC](https://www.youtube.com/watch?v=0aUu2agaIto)  
- [Showcase by Tech Enthusiast](https://www.youtube.com/watch?v=zfIQvk8BEcM)  

---

## ☕ Donations  

If you find this project helpful, you can support its continued development:  

[Donate via PayPal](https://www.paypal.me/Lilbatti69)  

Or simply star ⭐ the repository and share it!  

---

## 📜 License  

Licensed under the **MIT License**.  
See [`LICENSE`](LICENSE) for details.  
