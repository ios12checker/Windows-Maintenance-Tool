---
name: Bug Report
about: Report an issue or bug with the maintenance tool
title: '[BUG] '
labels: 'bug'
assignees: ''
---

> [!WARNING]
> ### 🛑 STOP: Is your Antivirus flagging this tool?
> **DO NOT open a GitHub issue.** Because this tool performs system maintenance and interacts with Windows internals, some Antivirus software will incorrectly flag it as suspicious (a "False Positive"). We cannot fix your Antivirus for you. You must report the false positive directly to your Antivirus vendor so they can update their definitions. 

<details>
<summary><b>Click here for links to report a False Positive to your Antivirus provider</b></summary>

If you are submitting via email, most vendors require you to place the file inside a `.zip` or `.rar` archive encrypted with the password **infected** (or sometimes **virus**) to prevent the email from being blocked in transit.

## Submission Directory

| Antivirus Vendor | Submission Link or Email | Notes |
| :--- | :--- | :--- |
| **Avast** | [Avast False Positive Form](https://www.avast.com/en-us/false-positive-file-form.php) | Web form for file or URL submission. |
| **AVG** | [AVG False Positive Form](https://www.avg.com/en-us/false-positive-file-form) | AVG and Avast share engines, but use their respective forms. |
| **Avira** | [Avira Analysis Submit](https://analysis.avira.com/en/submit) | Requires creating an account or logging in. |
| **Bitdefender** | [Bitdefender Submission Portal](https://www.bitdefender.com/submit/) | Alternatively, email `virus_submission@bitdefender.com`. |
| **ClamAV** | [ClamAV False Positives](http://www.clamav.net/reports/fp) | Open-source engine used by many secondary providers. |
| **ESET** | `samples@eset.com` | Compress file in a `.zip` with the password **infected**. Use the subject "False positive". |
| **F-Secure** | [F-Secure Sample Submit](https://www.f-secure.com/en/web/labs_global/submit-a-sample) | Check the box for "I want to give more details..." to clarify it is a false positive. |
| **Kaspersky** | [Kaspersky OpenTip](https://opentip.kaspersky.com/) | Upload the file, analyze it, and then click "Submit to Review". Or email `newvirus@kaspersky.com`. |
| **Malwarebytes** | [Malwarebytes Forums](https://forums.malwarebytes.com/forum/122-false-positives/) | Submissions are handled directly through their community forums. |
| **McAfee** | `virus_research@mcafee.com` | Compress file in a `.zip` with password **infected**. Mention it is a false positive in the subject line. |
| **Microsoft Defender** | [Microsoft Security Intelligence](https://www.microsoft.com/en-us/wdsi/filesubmission) | Select "Software Developer" to submit your own application. Requires Microsoft login. |
| **Norton / Symantec** | [Symantec Submit Form](https://symsubmit.symantec.com/) | Choose "Incorrectly Detected by Symantec" at the top of the portal. |
| **Sophos** | [Sophos Sample Submission](https://secure2.sophos.com/en-us/support/submit-a-sample.aspx) | Clarify in the "Why do you want to send this sample?" section that it is a false positive. |
| **Trend Micro** | [Detection Re-evaluation](https://www.trendmicro.com/en_us/about/legal/detection-reevaluation.html) | Fill out the web form and provide the SHA-256 hash or file. |

</details>

---

<!-- If your issue is NOT about an Antivirus flag, please fill out the template below: -->

**Describe the bug**
A clear and concise description of what the bug is.

**Windows Version**
- OS: [e.g. Windows 10 22H2, Windows 11 23H2]
- Architecture: [e.g. 64-bit]

**To Reproduce**
Steps to reproduce the behavior:
1. Open the tool
2. Click on '....'
3. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots or Error Logs**
If applicable, add screenshots or paste error logs here to help explain your problem.