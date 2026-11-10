# Updates and release channels

WMT has two GitHub release channels. WinGet and Chocolatey publication is associated with stable releases, not the rolling preview.

## Stable releases

[Download the latest stable release](https://github.com/Chaython/Windows-Maintenance-Tool/releases/latest).

Stable releases are versioned and intended for regular use. When a stable version is published to WinGet, install or update it with:

```powershell
winget install --id Chaython.WindowsMaintenanceTool --exact
winget upgrade --id Chaython.WindowsMaintenanceTool --exact
```

## Rolling preview

[Open the rolling prerelease](https://github.com/Chaython/Windows-Maintenance-Tool/releases/tag/rolling).

The rolling preview is built automatically from Main. Its URL remains the same while its contents are replaced by the newest successful build. It is intended for testing and is not submitted to WinGet or Chocolatey.

## WinGet package behavior

WMT is packaged as a portable application. WinGet installs and tracks the portable executable and registers the `wmt` command alias. After installation, open a new terminal and run:

```powershell
wmt
```

Use WinGet to upgrade or uninstall the package; avoid manually modifying the package-managed directory.

## Release assets

New stable and rolling releases include the executable, a SHA-256 checksum, and a Sigstore/GitHub attestation bundle. Older releases created before provenance attestations were introduced may not include the bundle.

See [Security and release verification](Security.md) before trusting a downloaded executable.
