# Install and launch WMT

WMT is distributed as a **portable executable**, not a conventional MSI installer. WinGet can install and manage that portable executable for you.

## Install with WinGet (recommended)

Open PowerShell or Windows Terminal and run:

```powershell
winget install --id Chaython.WindowsMaintenanceTool --exact
```

If WinGet asks you to accept package/source agreements, review and accept them to continue. Once installation finishes, open a **new** terminal window and run:

```powershell
wmt
```

The `wmt` command is the package's registered command alias. It launches the portable WMT executable managed by WinGet.

You can also find and launch Windows Maintenance Tool from the Windows Start menu.

### Update WMT

```powershell
winget upgrade --id Chaython.WindowsMaintenanceTool --exact
```

### Uninstall WMT

```powershell
winget uninstall --id Chaython.WindowsMaintenanceTool --exact
```

WinGet handles the package lifecycle. Do not manually delete or move files from WinGet's package directory while the package is installed.

## Run a downloaded portable release

1. Download `WindowsMaintenanceTool.exe` from the [latest stable release](https://github.com/Chaython/Windows-Maintenance-Tool/releases/latest).
2. Save it in a folder you control, such as a dedicated WMT folder under your user profile.
3. Run the executable.

The downloaded EXE is portable; it does not require an MSI setup wizard. Keep it in a stable folder if you configure Start with Windows, scheduled tasks, or other features that refer to its location.

## Run from source

1. Download or clone the repository.
2. Keep `Start_WMT_GUI.bat` and `WMT-GUI.ps1` together.
3. Run `Start_WMT_GUI.bat`.

You can also launch the PowerShell script directly:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\WMT-GUI.ps1"
```

## Administrator permissions

WMT can start without elevating every action. Operations that modify protected Windows settings, services, drivers, firewall rules, or system files may request administrator privileges or require an elevated session. Only approve elevation when you intend to perform the requested operation.

## Portable data and moving the app

WMT keeps application data in its local `data` folder relative to the script/application location where supported by the build. For a manually downloaded copy, keep the executable and its associated data together when moving the app.

For a WinGet-managed copy, let WinGet manage the installation directory. Use the `wmt` command rather than relying on a hard-coded path to the package's internal executable.
