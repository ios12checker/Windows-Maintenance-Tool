# Troubleshooting

## The `wmt` command is not recognized

1. Confirm the WinGet installation completed successfully.
2. Close and reopen Windows Terminal or PowerShell so it reloads the updated command-alias environment.
3. Check the package is installed:

   ```powershell
   winget list --id Chaython.WindowsMaintenanceTool --exact
   ```

4. If it is missing, install it again:

   ```powershell
   winget install --id Chaython.WindowsMaintenanceTool --exact
   ```

If WinGet reports the package is installed but `wmt` is still unavailable, try launching WMT from the Start menu and check the WinGet package's command-alias registration.

## WMT does not start

- For a source checkout, keep `Start_WMT_GUI.bat` and `WMT-GUI.ps1` together and run the batch launcher.
- For a downloaded portable release, confirm the EXE completed downloading and was not quarantined.
- For a WinGet installation, launch with `wmt` or from the Start menu rather than moving the managed executable.
- Review Windows Security/antivirus history if the file was blocked. Only restore or allow a file after verifying its source and release integrity.

## A feature says administrator access is required

Some maintenance actions modify protected Windows resources. Approve the elevation prompt only when you intended to run that action. If elevation is unavailable, reopen WMT in an elevated session and retry.

## WinGet cannot install or upgrade WMT

Run:

```powershell
winget source update
winget upgrade --id Chaython.WindowsMaintenanceTool --exact
```

If WMT is not installed yet, use `winget install --id Chaython.WindowsMaintenanceTool --exact`. Check the exact error printed by WinGet; source, network, package-manager, and installer errors have different causes.

## Package scans fail

- Confirm the relevant provider is installed and available in PATH.
- Check network connectivity for online providers.
- Confirm that authentication is still valid for providers that require an account.
- Retry the individual provider; one unavailable provider should not be treated as proof that all WMT functions have failed.

## A tweak causes unexpected behavior

Use the corresponding revert/toggle action. If you exported a known-good tweak configuration, restore it through the Tweaks page. Some Windows changes require a sign-out or restart before they take effect.

## Cleanup or registry results are unclear

Use preview/analyze mode where available. Review the target and risk information before applying cleanup. Registry entries marked for review are not automatically modified.

## Collect useful information for a bug report

When reporting a reproducible problem, include:

- WMT version and installation method (WinGet, downloaded portable EXE, or source)
- Windows edition and version
- Exact steps to reproduce the issue
- The affected page/provider/tool
- Full error text and relevant activity-log output
- Whether the issue occurs after restarting WMT or Windows

Report bugs at [GitHub Issues](https://github.com/Chaython/Windows-Maintenance-Tool/issues).
