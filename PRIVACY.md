# Privacy Policy for WMT (Windows Maintenance Tool / WMT-GUI)

**Effective Date:** October 26, 2026  
**Privacy Policy URL (`PrivacyUrl`):** `https://raw.githubusercontent.com/Chaython/Windows-Maintenance-Tool/refs/heads/Main/PRIVACY.md`

---

## 1. Overview
WMT is committed to respecting user privacy. WMT is built with a **privacy-first approach**: we do not operate telemetry servers, collect usage analytics, run background tracking, or automatically transmit personal data to servers owned or controlled by the WMT maintainers.

---

## 2. Information Handled Locally on Your Device

To support system tweaks, package management workflows, and game/app library integrations, WMT stores operational state locally on your device:

* **Authentication Data:** If you choose to authenticate through optional helper tools (e.g., Legendary or GOGDL), session tokens, account credentials, or API metadata are saved strictly on your local file system.
* **Provider & Library Caches:** WMT maintains local cache files (such as package indexes, provider manifests, and game/app library metadata) to optimize interface performance and prevent unnecessary network requests.

> **Note:** All cached data and authentication tokens remain stored locally in your Windows user profile directories (`%LOCALAPPDATA%` or `%APPDATA%`). WMT never uploads or transmits these tokens or cache files to any third-party or developer-controlled servers.

---

## 3. GitHub Hosting & Distribution Metrics

WMT is hosted and distributed via GitHub. When you download WMT releases, run update checks, or visit the project repository:
* **Aggregated Traffic Metrics:** GitHub records standard, non-personally identifiable traffic metrics (such as total download counts, release view counts, and HTTP referrers like search engines or web links).
* **Anonymized Data:** These metrics are aggregated by GitHub and do **not** expose raw IP addresses, individual user identifiers, or personal browsing histories to the WMT maintainers.
* For more information on how GitHub processes data, review the [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement).

---

## 4. Optional Third-Party Integrations & External Utilities

WMT acts as a graphical user interface and wrapper for external package managers, store clients, developer toolchains, and system servicing engines. **All third-party tools are strictly optional and are not bundled or included inside WMT.** 

If you choose to install and trigger any of these optional utilities through WMT, they communicate directly with their respective network endpoints under their own privacy policies:

* **Windows Package Manager (`winget`) & Microsoft Store (`msstore`):** [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement)
* **Windows Update:** [Microsoft Privacy Statement](https://privacy.microsoft.com/privacystatement)
* **Legendary (Epic Games alternative):** [Epic Games Privacy Policy](https://www.epicgames.com/site/en-US/privacypolicy)
* **GOGDL (GOG Downloader):** [GOG User Agreement & Privacy Policy](https://support.gog.com/hc/en-us/articles/212632109-GOG-User-Agreement-and-Privacy-Policy)
* **Steam:** [Valve / Steam Privacy Agreement](https://store.steampowered.com/privacy_agreement/)
* **Chocolatey:** [Chocolatey Privacy Policy](https://chocolatey.org/privacy)
* **Scoop:** [Scoop Project Policies](https://scoop.sh)
* **Node.js / pnpm:** [OpenJS Foundation Privacy Policy](https://privacy.openjsf.org/) & [npm/pnpm Privacy Notice](https://docs.npmjs.com/policies/privacy)
* **Python / pip:** [Python Software Foundation Privacy Policy](https://www.python.org/privacy/) & [PyPI Privacy Policy](https://pypi.org/policy/privacy/)
* **.NET SDK (`dotnet`):** [Microsoft .NET Telemetry and Privacy Notice](https://learn.microsoft.com/dotnet/core/tools/telemetry)
* **Rust / Cargo:** [Rust Foundation Privacy Notice](https://www.rust-lang.org/policies/privacy) & [crates.io Privacy Policy](https://crates.io/policies/privacy)
* **Ruby / RubyGems (`gem`):** [RubyGems Privacy Policy](https://rubygems.org/privacy)
* **PHP / Composer:** [Packagist Privacy Policy](https://packagist.org/privacy)

---

## 5. Data Control and Complete Removal

Because all application data is stored locally on your machine:
* You can revoke session state or clear provider caches at any time by clearing or deleting the local WMT configuration folders in your user profile.
* Uninstalling WMT and removing its application data directory permanently deletes all local tokens, cached manifests, and session files from your system.

---

## 6. Updates to This Policy
This Privacy Policy may be updated periodically to maintain compliance with repository standards (such as Microsoft Windows Package Manager policies) or to reflect functional updates. Revisions are effective immediately upon updating the **Effective Date** at the top of this document.

---

## 7. Contact & Issues
If you have questions regarding this Privacy Policy or data security within WMT, please open an issue on the official project repository:
* **Repository Issues:** `https://github.com/ios12checker/Windows-Maintenance-Tool/issues`
