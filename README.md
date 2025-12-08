# 🖥️ Windows Maintenance Tool

![Version](https://img.shields.io/badge/version-v3.10-green)  
![Platform](https://img.shields.io/badge/platform-Windows-blue)  
![License: MIT](https://img.shields.io/badge/license-MIT-blue)  

A powerful, all-in-one Windows maintenance toolkit built entirely in Batch & PowerShell.  
Designed for power users, sysadmins, and curious tinkerers – now smarter, safer, and fully offline-compatible.  

---

## 📸 Screenshot  
<img width="863" height="841" alt="image" src="https://github.com/user-attachments/assets/18d4d868-7cfe-4a2b-a947-892e94cd3a55" />




---

## ✅ Features  

**Run essential repair tools:**  
- Quick access to SFC, DISM, and CHKDSK for core Windows repairs  
- Component store repair and basic health scans for stuck or broken systems  

**Optimize SSD drives:**  
- TRIM and compatible defrag for faster, healthier SSDs and HDDs  

**Windows Update management & repair:**  
- Use winget to install, upgrade, and repair system packages  
- Automatically installs/configures winget if missing  
- Flexible package handling: view, search, and upgrade individual apps/packages by entering their ID directly  
- Windows Update Repair Tool supports a **full nuke & rebuild** of update components, including automatic restart of key services like `cryptsvc`  

**Network diagnostics, DNS & DoH:**  
- Includes ipconfig, routing table viewer, DNS configuration, adapter reset, and more  
- **DNS over HTTPS (DoH) management:**  
  - Enable DoH using `netsh dns add encryption` for known providers (Cloudflare, Google, Quad9, AdGuard)  
  - One-click **Disable DoH** option to remove the same encryption entries and revert cleanly  
- Export detailed network information to file for troubleshooting or support  

**Privacy & temp cleanup:**  
- Clean temp files, logs, and browser cache  
- Privacy cleanup for extra traces (history, cookies, etc.)  

**Save detailed reports:**  
- Export System Info, Network Info, and Driver List to your Desktop or a custom folder  

**Driver & device maintenance:**  
- Enumerate all drivers in the Driver Store using fast pnputil parsing  
- **Old Driver Cleanup:**  
  - Groups drivers by package (OriginalFileName + Provider)  
  - Keeps the newest version in each group and marks older duplicates as removal candidates  
- **Mandatory driver backup before cleanup:**  
  - Automatically exports all drivers with `pnputil /export-driver *` to a timestamped `DriverBackup_…` folder on the Desktop  
  - Reuses an existing backup if it already contains at least as many driver INF files as the current system  
  - No deletions are performed if backup or verification fails  
- **Driver restore:**  
  - Built-in “Restore Drivers from Backup” option  
  - Re-imports all drivers from a selected `DriverBackup_…` folder using `pnputil /add-driver ... /subdirs /install`  

**Registry tools:**  
- Safe cleanup, backup, and corruption scan  
- Menu-driven, stable registry cleaning:  
  - List “safe to delete” entries (IE40, IE4Data, DirectDrawEx, etc.)  
  - Bulk delete all safe entries  
  - Easy backup & restore with versioned `.reg` files  

**DNS / hosts-based Adblock management:**  
- Block ad/tracker domains with a curated hosts file (multiple mirrors supported)  
- Automatic backup of the existing hosts file before changes  
- Improved handling of locked files and clearer status/error messages  

**Firewall Manager:**  
- Built-in menu-driven PowerShell Firewall Manager  
- Manage firewall rules, enable/disable Windows Firewall directly from the tool  

**.NET RollForward Settings:**  
- Lets the system use a specific .NET version (SDK/runtime)  
- Reduces the need to install multiple .NET runtimes  

**Shortcut Fixer:**  
- Automatic shortcut repair for broken Start Menu / desktop shortcuts  
- Menu reorganized so “exit” and global options sit at the end for better structure  

**Menu-driven and user-friendly:**  
- All functions accessible from a clear main menu—no PowerShell experience needed  
- More consistent “return to menu” behavior across tools  
- Built-in support/help, Discord/GitHub contact links  
- **Developer Options submenu:**  
  - **Dry Run mode:** simulate menu actions without touching the system, with a visible “DRY RUN ENABLED” banner in the main menu  
  - **Dev Mode:** extra diagnostics and a “DEV MODE ENABLED” banner so you always see when you are in test mode  

**Windows Activation:**  
- Thanks to the [MAS (Microsoft Activation Script)](https://massgrave.dev) project, Windows and Office activation support is integrated as an **optional** tool  
- Full credit goes to the Massgrave team for maintaining and developing MAS  
- This project does not modify or redistribute MAS — it only provides a convenient way to download and run it  
- Clear warning and confirmation step ensures users read the documentation and accept responsibility before running the script  

**Portable & safe (for personal use):**  
- Runs from any folder or USB drive, no installation required  
- Automatically relaunches itself with a **temporary process-scoped ExecutionPolicy bypass** when needed, so no code-signing certificate is required  
- Core maintenance features can run offline; some modules (winget, MAS, DoH profiles, hosts adblock) use the internet when invoked  


---
## 🔄 Windows Maintenance Tool – Updater Guide

The updater makes it easy to install or update Windows Maintenance Tool to the latest release. No manual downloads, no hassle.

### 📌 How to Use the Updater

1. Open the **Updater** folder inside your Windows Maintenance Tool directory.  
   (Example: `C:\Users\<username>\Desktop\Windows Maintenance Tool\Updater`)

2. Launch **Updater.exe**.  
   The updater will automatically scan for an existing Windows Maintenance Tool installation in the selected folder.

3. Make sure the selected path contains the following files:  
   - `Start_Windows_Maintenance_Tool.bat`  
   - `Windows_Maintenance_Tool.ps1`

4. Click **“Update Windows Maintenance Tool”**.  
   The updater downloads the latest release and updates the tool automatically.

5. After the update completes:  
   - Use **Open tool** to launch Windows Maintenance Tool immediately.  
   - Use **Open folder** to open the installation directory.

### 💡 Tips

- If you move the tool to a new location, simply select the new folder using **Choose…**.
- The updater always shows the newest available version and its release date.
- “Ready” means a valid installation has been detected and the updater is good to go.

## ⚙️ Manual Installation  

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

This release (**v3.9**) was contributed by **[@Chaython](https://github.com/Chaython)**, **[@ios12checker](https://github.com/ios12checker)**  
All new features, fixes, and improvements  

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

## 📜 License  

Licensed under the **MIT License**.  
See [`LICENSE`](LICENSE) for details.  
