# Security and release verification

## Portable application and permissions

WMT is an open-source Windows maintenance utility. It does not require an MSI installer. Many features interact with protected Windows configuration and may require administrator privileges. Review each operation and its confirmation prompt before proceeding.

WMT itself does not send telemetry. Some features communicate with Windows components, package managers, GitHub/community rule sources, and third-party provider services to perform the functions requested.

## Verify a release

Newly published stable and rolling releases include:

- `WindowsMaintenanceTool.exe`
- `WindowsMaintenanceTool.exe.sha256`
- `WindowsMaintenanceTool.exe.sigstore.json`

Download the executable and attestation bundle from the **same** release. Install the [GitHub CLI](https://cli.github.com/) and run this from the download directory:

```powershell
gh attestation verify .\WindowsMaintenanceTool.exe `
  --repo Chaython/Windows-Maintenance-Tool `
  --bundle .\WindowsMaintenanceTool.exe.sigstore.json `
  --signer-workflow Chaython/Windows-Maintenance-Tool/.github/workflows/release-ps2exe.yml
```

You can also verify the SHA-256 checksum against the value published with that exact release.

## What verification means

GitHub attestations provide evidence about the artifact's build provenance and integrity. They are **not** Windows Authenticode signatures. They do not make SmartScreen treat the EXE as signed by a trusted publisher, and they do not guarantee that antivirus products will never flag it.

Do not bypass a security warning solely because a file is open source. Verify that you downloaded the expected release and inspect the source if you have concerns.

## Antivirus false positives

If an antivirus product flags WMT, submit the file to that vendor for review. The project README lists vendor submission links. Avoid downloading replacement executables from unofficial mirrors.
