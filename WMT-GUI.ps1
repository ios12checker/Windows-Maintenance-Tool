<#
    Windows Maintenance Tool - GUi Edition
    CLI: Lil_Batti (author) with contributions from Chaython
    Feature Integration & Updates: Lil_Batti & Chaython
    GUI thanks to https://github.com/Chaython
    Imported and integrated from Lil_Batti (author) with contributions from Chaython
#>

# ==========================================
# 1. SETUP
# ==========================================
$AppVersion = "4.7"
$ErrorActionPreference = "SilentlyContinue"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

# HIDE CONSOLE
$t = '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr handle, int state);'
$w = Add-Type -MemberDefinition $t -Name "Win32ShowWindow" -Namespace Win32Functions -PassThru
$null = $w::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

# ADMIN CHECK
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName PresentationFramework, System.Windows.Forms, System.Drawing, Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()
# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

function Get-Ctrl { param($Name) return $window.FindName($Name) }

function Write-GuiLog {
    param($Msg)
    $lb = Get-Ctrl "LogBox"
    if ($lb) {
        $lb.AppendText("[$((Get-Date).ToString('HH:mm'))] $Msg`n")
        $lb.ScrollToEnd()
    }
}

function Invoke-UiCommand {
    param([scriptblock]$Sb, $Msg="Processing...")
    [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
    Write-GuiLog $Msg
    try { 
        $res = & $Sb | Out-String
        if ($res){ Write-GuiLog $res.Trim() } 
        else { Write-GuiLog "Done." }
    } catch { 
        Write-GuiLog "ERROR: $($_.Exception.Message)" 
    }
    [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
}

function Start-GuiJob {
    param(
        [scriptblock]$ScriptBlock, 
        [string]$JobName, 
        [scriptblock]$CompletedAction,
        [object[]]$Arguments = @()   # <--- ADDED THIS
    )
    
    # Pass arguments into the background job
    $job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $Arguments
    
    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $timer.Add_Tick({
        if ($job.State -ne 'Running') {
            $timer.Stop()
            $result = Receive-Job -Job $job
            Remove-Job -Job $job
            
            # Execute completion logic (Back on the UI thread)
            & $CompletedAction $result
        }
    })
    $timer.Start()
}

# Centralized data path for exports (in repo folder)
function Get-DataPath {
    $root = Split-Path -Parent $PSCommandPath
    $dataPath = Join-Path $root "data"
    if (-not (Test-Path $dataPath)) {
        New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
    }
    return $dataPath
}
$script:DataDir = Get-DataPath

# Simple modal text viewer (read-only)
function Show-TextDialog {
    param(
        [string]$Title = "Output",
        [string]$Text = ""
    )
    $f = New-Object System.Windows.Forms.Form
    $f.Text = $Title
    $f.Size = "800,600"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $f.ForeColor = [System.Drawing.Color]::White

    $tb = New-Object System.Windows.Forms.RichTextBox
    $tb.Dock = "Fill"
    $tb.ReadOnly = $true
    $tb.BackColor = [System.Drawing.Color]::FromArgb(20,20,20)
    $tb.ForeColor = [System.Drawing.Color]::White
    $tb.Font = New-Object System.Drawing.Font("Consolas", 10)
    $tb.Text = $Text
    $tb.WordWrap = $false
    $f.Controls.Add($tb)

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "Close"
    $btn.Dock = "Bottom"
    $btn.Height = 35
    $btn.BackColor = "DimGray"
    $btn.ForeColor = "White"
    $btn.Add_Click({ $f.Close() })
    $f.Controls.Add($btn)

    $f.ShowDialog() | Out-Null
}

function Show-DownloadStats {
    Invoke-UiCommand {
        try {
            $repo = "ios12checker/Windows-Maintenance-Tool"
            $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing
            if (-not $rel -or -not $rel.assets) { throw "No release data returned." }
            $total = ($rel.assets | Measure-Object download_count -Sum).Sum
            $lines = @()
            $lines += "Release: $($rel.name)"
            $lines += "Total downloads: $total"
            $lines += ""
            foreach ($a in $rel.assets) {
                $lines += ("{0} : {1}" -f $a.name, $a.download_count)
            }
            $msg = $lines -join "`r`n"
            Write-Output $msg
            [System.Windows.MessageBox]::Show($msg, "Latest Release Downloads", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        } catch {
            $err = "Failed to fetch download stats: $($_.Exception.Message)"
            Write-Output $err
            [System.Windows.MessageBox]::Show($err, "Latest Release Downloads", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error) | Out-Null
        }
    } "Fetching latest release download counts..."
}

# --- UPDATE CHECKER ---
function Invoke-UpdateCheck {
    $lb = Get-Ctrl "LogBox"
    
    # 1. CONFIG & CACHE BUSTING
    $time = Get-Date -Format "yyyyMMddHHmmss"
    $updateUrl = "https://raw.githubusercontent.com/ios12checker/Windows-Maintenance-Tool/refs/heads/main/WMT-GUI.ps1?t=$time"
    
    $localVer = [Version]$script:AppVersion
    $remoteVer = [Version]"0.0"
    $remoteContent = $null

    # 2. GET REMOTE VERSION
    if ($lb) { 
        $lb.AppendText("`n[UPDATE] Checking for updates...`n") 
        $lb.ScrollToEnd()
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webReq = Invoke-WebRequest -Uri $updateUrl -UseBasicParsing -TimeoutSec 5
        $remoteContent = $webReq.Content

        # Robust Regex Matching
        if ($remoteContent -match '\$AppVersion\s*=\s*"(\d+(\.\d+)+)"') {
            $remoteVer = [Version]$matches[1]
        }
        elseif ($remoteContent -match "Windows Maintenance Tool.*v(\d+(\.\d+)+)") {
            $remoteVer = [Version]$matches[1]
        }
    } catch {
        if ($lb) { 
            $lb.AppendText("[UPDATE] Check failed: $($_.Exception.Message)`n")
            $lb.ScrollToEnd() 
        }
        return
    }

    if ($lb) { 
        $lb.AppendText("[UPDATE] Local: v$localVer | Remote: v$remoteVer`n") 
        $lb.ScrollToEnd()
    }

    # 3. COMPARE & INSTALL
    if ($remoteVer -gt $localVer) {
        if ($lb) { $lb.AppendText(" -> Update Available!`n"); $lb.ScrollToEnd() }
        
        $msg = "A new version is available!`n`nLocal Version:  v$localVer`nRemote Version: v$remoteVer`n`nDo you want to update now?"
        $result = [System.Windows.MessageBox]::Show($msg, "Update Available", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)

        if ($result -eq "Yes") {
            try {
                $backupName = "$(Split-Path $PSCommandPath -Leaf).bak"
                $backupPath = Join-Path (Get-DataPath) $backupName
                Copy-Item -Path $PSCommandPath -Destination $backupPath -Force
                Set-Content -Path $PSCommandPath -Value $remoteContent -Encoding UTF8
                
                [System.Windows.MessageBox]::Show("Update complete! Backup saved to data folder.`nRestarting...", "Updated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                Start-Process powershell.exe -ArgumentList "-File `"$PSCommandPath`""
                exit
            } catch {
                [System.Windows.MessageBox]::Show("Update failed: $_", "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
            }
        }
    } else {
        if ($lb) { $lb.AppendText(" -> You are up to date.`n"); $lb.ScrollToEnd() }
    }
}

# --- RESTORED LOGIC ---

function Start-UpdateRepair {
    Invoke-UiCommand {
        Stop-Service -Name wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
        $rnd = Get-Random
        if(Test-Path "$env:windir\SoftwareDistribution"){ Rename-Item "$env:windir\SoftwareDistribution" "$env:windir\SoftwareDistribution.bak_$rnd" -ErrorAction SilentlyContinue }
        if(Test-Path "$env:windir\System32\catroot2"){ Rename-Item "$env:windir\System32\catroot2" "$env:windir\System32\catroot2.bak_$rnd" -ErrorAction SilentlyContinue }
        netsh winsock reset | Out-Null
        Start-Service -Name wuauserv, bits, cryptsvc, msiserver -ErrorAction SilentlyContinue
    } "Repairing Windows Update..."
}

function Start-NetRepair {
    Invoke-UiCommand {
        ipconfig /release | Out-Null
        ipconfig /renew | Out-Null
        ipconfig /flushdns | Out-Null
        netsh winsock reset | Out-Null
        netsh int ip reset | Out-Null
    } "Running Full Network Repair..."
}

function Start-RegClean {
    Invoke-UiCommand {
        $bkDir = Join-Path (Get-DataPath) "RegistryBackups"
        if(!(Test-Path $bkDir)){ New-Item -Path $bkDir -ItemType Directory | Out-Null }
        $bkFile = "$bkDir\Backup_$(Get-Date -F 'yyyyMMdd_HHmm').reg"
        reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $bkFile /y | Out-Null
        $keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' }
        if ($keys) { foreach ($k in $keys) { Remove-Item $k.PSPath -Recurse -Force; Write-Output "Removed: $($k.PSChildName)" } } else { Write-Output "No obsolete keys found." }
        Write-Output "Backup saved to: $bkFile"
    } "Cleaning Registry..."
}

function Start-XboxClean {
    Invoke-UiCommand {
        Write-Output "Stopping Xbox Auth Manager..."
        Stop-Service -Name "XblAuthManager" -Force -ErrorAction SilentlyContinue

        $allCreds = (cmdkey /list) -split "`r?`n"
        $targets = @()
        foreach ($line in $allCreds) {
            if ($line -match "(?i)^\\s*Target:.*(Xbl.*)$") { $targets += $matches[1] }
        }

        if ($targets.Count -eq 0) {
            Write-Output "No Xbox Live credentials found."
        } else {
            foreach ($t in $targets) {
                Write-Output "Deleting credential: $t"
                cmdkey /delete:$t 2>$null
            }
            Write-Output "Deleted $($targets.Count) credential(s)."
        }

        Start-Service -Name "XblAuthManager" -ErrorAction SilentlyContinue
    } "Cleaning Xbox Credentials..."
}

function Start-GpeditInstall {
    # Check for User Confirmation
    $msg = "Install Local Group Policy Editor?`n`nThis enables the Group Policy Editor (gpedit.msc) on Windows Home editions by installing the built-in system packages.`n`nContinue?"
    $res = [System.Windows.Forms.MessageBox]::Show($msg, "Confirm Install", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxImage]::Question)
    if ($res -eq "No") { return }

    Invoke-UiCommand {
        $packageRoot = Join-Path $env:SystemRoot "servicing\\Packages"
        
        if (-not (Test-Path $packageRoot)) {
            throw "Package directory not found: $packageRoot"
        }

        Write-Output "Searching packages in $packageRoot..."
        
        $clientTools = Get-ChildItem -Path $packageRoot -Filter "Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum" -ErrorAction SilentlyContinue
        $clientExtensions = Get-ChildItem -Path $packageRoot -Filter "Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum" -ErrorAction SilentlyContinue
        
        if (-not $clientTools -or -not $clientExtensions) {
            Write-Output "WARNING: Required GroupPolicy packages were not found."
            Write-Output "Ensure you are on a compatible Windows 10/11 version."
            return
        }

        $packages = @($clientTools + $clientExtensions) | Sort-Object Name -Unique
        
        foreach ($pkg in $packages) {
            Write-Output "Installing: $($pkg.Name)..."
            # Using DISM to add package
            $proc = Start-Process dism.exe -ArgumentList "/online","/norestart","/add-package:`"$($pkg.FullName)`"" -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                 Write-Output " -> Failed (Exit Code: $($proc.ExitCode))"
            }
        }
        Write-Output "`nInstallation Complete. Try running 'gpedit.msc'. (A reboot may be required)."
    } "Installing Group Policy Editor..."
}

# --- NETWORK / DNS HELPERS (from CLI) ---
function Get-ActiveAdapters {
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*' -and $_.Name -notlike '*vEthernet*' }
}

function Set-DnsAddresses {
    param(
        [string[]]$Addresses,
        [string]$Label = "Custom DNS"
    )
    if (-not $Addresses -or $Addresses.Count -eq 0) { return }
    $addrList = $Addresses
    $labelText = $Label
    Invoke-UiCommand {
        $adapters = Get-ActiveAdapters | Select-Object -ExpandProperty Name
        if (-not $adapters) { Write-Output "No active adapters found."; return }
        foreach ($adapter in $adapters) {
            try {
                Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $addrList -ErrorAction Stop
                Write-Output "[$labelText] Applied to $adapter : $($addrList -join ', ')"
            } catch {
                Write-Output "[$labelText] Failed on $adapter : $($_.Exception.Message)"
            }
        }
    } "Applying $labelText..."
}

function Enable-AllDoh {
    $dnsServers = @(
        @{ Server = "1.1.1.1"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ Server = "1.0.0.1"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ Server = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ Server = "2606:4700:4700::1001"; Template = "https://cloudflare-dns.com/dns-query" },
        @{ Server = "8.8.8.8"; Template = "https://dns.google/dns-query" },
        @{ Server = "8.8.4.4"; Template = "https://dns.google/dns-query" },
        @{ Server = "2001:4860:4860::8888"; Template = "https://dns.google/dns-query" },
        @{ Server = "2001:4860:4860::8844"; Template = "https://dns.google/dns-query" },
        @{ Server = "9.9.9.9"; Template = "https://dns.quad9.net/dns-query" },
        @{ Server = "149.112.112.112"; Template = "https://dns.quad9.net/dns-query" },
        @{ Server = "2620:fe::fe"; Template = "https://dns.quad9.net/dns-query" },
        @{ Server = "2620:fe::fe:9"; Template = "https://dns.quad9.net/dns-query" },
        @{ Server = "94.140.14.14"; Template = "https://dns.adguard.com/dns-query" },
        @{ Server = "94.140.15.15"; Template = "https://dns.adguard.com/dns-query" },
        @{ Server = "2a10:50c0::ad1:ff"; Template = "https://dns.adguard.com/dns-query" },
        @{ Server = "2a10:50c0::ad2:ff"; Template = "https://dns.adguard.com/dns-query" }
    )
    Invoke-UiCommand {
        param($dnsServers)
        $applied = 0
        foreach ($dns in $dnsServers) {
            try {
                $cmd = "netsh dns add encryption server=$($dns.Server) dohtemplate=$($dns.Template) autoupgrade=yes udpfallback=no"
                Invoke-Expression $cmd | Out-Null
                if ($LASTEXITCODE -eq 0) { $applied++; Write-Output "Enabled DoH for $($dns.Server)" }
            } catch { Write-Output "Failed DoH for $($dns.Server): $($_.Exception.Message)" }
        }
        try { ipconfig /flushdns | Out-Null } catch {}
        try {
            $svc = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
            if ($svc.Status -eq "Running" -and $svc.StartType -ne "Disabled") { Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue }
        } catch {}
        Write-Output "Applied DoH templates to $applied server(s)."

        if ($applied -gt 0) {
            [System.Windows.MessageBox]::Show("Enabled DoH for $applied server(s).", "Enable DoH", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        } else {
            [System.Windows.MessageBox]::Show("Failed to enable DoH. Check the log for details.", "Enable DoH", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
        }
    } "Enabling DoH for known DNS providers..."
}

function Disable-AllDoh {
    $dnsServers = @(
        "1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001",
        "8.8.8.8","8.8.4.4","2001:4860:4860::8888","2001:4860:4860::8844",
        "9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::fe:9",
        "94.140.14.14","94.140.15.15","2a10:50c0::ad1:ff","2a10:50c0::ad2:ff"
    )
    Invoke-UiCommand {
        param($dnsServers)
        $removed = 0
        foreach ($dns in $dnsServers) {
            try {
                Invoke-Expression "netsh dns delete encryption server=$dns" | Out-Null
                if ($LASTEXITCODE -eq 0) { $removed++; Write-Output "Removed DoH entry for $dns" }
            } catch { Write-Output ("Failed removing DoH for {0}: {1}" -f $dns, $_.Exception.Message) }
        }
        try { ipconfig /flushdns | Out-Null } catch {}
        Write-Output "Removed $removed DoH entries."
        if ($removed -gt 0) {
            [System.Windows.MessageBox]::Show("Removed $removed DoH entries.", "Disable DoH", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        } else {
            [System.Windows.MessageBox]::Show("No DoH entries were removed. Check the log for details.", "Disable DoH", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
        }
    } "Disabling DoH entries..."
}
# --- Hosts Adblock ---
function Invoke-HostsUpdate {
    Invoke-UiCommand {
        # 1. Find PATHS
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        $backupDir = Join-Path (Get-DataPath) "hosts_backups"
        if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }

        # Capture original ACL to preserve permissions (e.g., Users read access)
        $origAcl = $null
        if (Test-Path $hostsPath) {
            try { $origAcl = Get-Acl -Path $hostsPath } catch {}
        }

        # 2. DOWNLOAD HOSTS FILE
        $mirrors = @(
            "https://o0.pages.dev/Lite/hosts.win",
            "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.win"
        )
        $adBlockContent = $null
        foreach ($mirror in $mirrors) {
            try {
                $wc = New-Object System.Net.WebClient
                # CRITICAL SPEED FIX: Bypasses auto-proxy detection delay (saves 1-5s)
                $wc.Proxy = $null 
                $wc.Encoding = [System.Text.Encoding]::UTF8
                
                Write-GuiLog "Downloading from $mirror..."
                $tempContent = $wc.DownloadString($mirror)
                
                # SAFETY CHECK: Ensure file is valid (> 1KB)
                if ($tempContent.Length -gt 1024) { 
                    $adBlockContent = $tempContent
                    Write-Output "Download complete ($([math]::Round($adBlockContent.Length / 1KB, 2)) KB)"
                    break 
                }
            } catch { 
                Write-Output "Mirror failed: $mirror" 
            } finally { 
                if ($wc) {$wc.Dispose()} 
            }
        }

        if (-not $adBlockContent) { 
            Write-GuiLog "ERROR: Download failed or file was empty. Aborting."
            return 
        }

        # 3. BACKUP EXISTING
        if (Test-Path $hostsPath) {
            $bkName = "hosts_$(Get-Date -F yyyyMMdd_HHmmss).bak"
            Copy-Item $hostsPath (Join-Path $backupDir $bkName) -Force
            Write-Output "Backup created: $bkName"
        }

        # 4. PRESERVE CUSTOM ENTRIES
        $customStart = "# === BEGIN USER CUSTOM ENTRIES ==="
        $customEnd = "# === END USER CUSTOM ENTRIES ==="
        $userEntries = "$customStart`r`n# Add custom entries here`r`n127.0.0.1 localhost`r`n::1 localhost`r`n$customEnd"

        if (Test-Path $hostsPath) {
            try {
                $raw = Get-Content $hostsPath -Raw
                if ($raw -match "(?s)$([regex]::Escape($customStart))(.*?)$([regex]::Escape($customEnd))") {
                    $userEntries = $matches[0]
                }
            } catch {}
        }

        # 5. CONSTRUCT & WRITE
        $finalContent = "$userEntries`r`n`r`n# UPDATED: $(Get-Date)`r`n$adBlockContent"
        
        try {
            Set-Content -Path $hostsPath -Value $finalContent -Encoding UTF8 -Force

            # Re-apply original ACL or ensure Users has read access
            try {
                if ($origAcl) {
                    Set-Acl -Path $hostsPath -AclObject $origAcl
                    Write-Output "Restored original permissions on hosts file."
                } else {
                    $fs = Get-Acl -Path $hostsPath
                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute","Allow")
                    $fs.SetAccessRule($rule)
                    Set-Acl -Path $hostsPath -AclObject $fs
                    Write-Output "Applied Users read permission to hosts file."
                }
            } catch {
                Write-Output "Warning: Could not reapply permissions: $($_.Exception.Message)"
            }
            
            # Validation
            if ((Get-Item $hostsPath).Length -lt 100) { throw "Write verification failed (File empty)." }
            
            ipconfig /flushdns | Out-Null
            Write-Output "Hosts file updated successfully."
        } catch {
            Write-GuiLog "CRITICAL ERROR: $($_.Exception.Message)"
            # Restore backup if write failed
            $latestBackup = Get-ChildItem $backupDir | Sort-Object CreationTime -Descending | Select-Object -First 1
            if ($latestBackup) {
                Copy-Item $latestBackup.FullName $hostsPath -Force
                Write-GuiLog "Restored backup due to failure."
            }
        }
    } "Updating hosts file..."
}
# --- HOSTS EDITOR ---
function Show-HostsEditor {
    # 1. SETUP FORM
    $hForm = New-Object System.Windows.Forms.Form
    $hForm.Text = "Hosts File Editor"
    $hForm.Size = "900, 700"
    $hForm.StartPosition = "CenterScreen"
    $hForm.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $hForm.KeyPreview = $true
    
    # Initialize Dirty Flag (False)
    $hForm.Tag = $false
    
    # 2. CONTROLS
    $txtHosts = New-Object System.Windows.Forms.RichTextBox
    $txtHosts.Dock = "Fill"
    $txtHosts.BackColor = [System.Drawing.Color]::FromArgb(45,45,48)
    $txtHosts.ForeColor = "White"
    $txtHosts.Font = "Consolas, 11"
    $txtHosts.AcceptsTab = $true
    $txtHosts.DetectUrls = $false
    $hForm.Controls.Add($txtHosts)
    
    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"
    $pnl.Height = 50
    $hForm.Controls.Add($pnl)
    
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "Save"
    $btn.BackColor = "SeaGreen"
    $btn.ForeColor = "White"
    $btn.FlatStyle = "Flat"
    $btn.Top = 10
    $btn.Left = 20
    $btn.Width = 100
    $pnl.Controls.Add($btn)
    
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Ctrl+S to Save"
    $lblInfo.ForeColor = "Gray"
    $lblInfo.AutoSize = $true
    $lblInfo.Top = 15
    $lblInfo.Left = 140
    $pnl.Controls.Add($lblInfo)
    
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    
    # 3. LOAD FILE
    if (Test-Path $hostsPath) {
        $diskSize = (Get-Item $hostsPath).Length
        $content = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
        
        # Safety Check
        if ($diskSize -gt 0 -and [string]::IsNullOrWhiteSpace($content)) {
            [System.Windows.Forms.MessageBox]::Show("Could not read Hosts file. Aborting.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return
        }
        $txtHosts.Text = $content
    }
    
    # 4. HIGHLIGHTING HELPER
    $Highlight = {
        $sel = $txtHosts.SelectionStart
        $len = $txtHosts.SelectionLength
        $txtHosts.SelectAll()
        $txtHosts.SelectionColor = "White"
        $s = $txtHosts.Text.IndexOf("# === BEGIN USER CUSTOM ENTRIES ===")
        $e = $txtHosts.Text.IndexOf("# === END USER CUSTOM ENTRIES ===")
        if ($s -ge 0 -and $e -gt $s) {
            $txtHosts.Select($s, ($e + 33) - $s)
            $txtHosts.SelectionColor = "Cyan"
        }
        $txtHosts.Select($sel, $len)
    }
    & $Highlight
    
    # 5. CHANGE TRACKING
    $txtHosts.Add_TextChanged({
        $hForm.Tag = $true
        if ($hForm.Text -notmatch "\*$") {
            $hForm.Text = "Hosts File Editor *"
        }
    })
    
    # 6. SAVE LOGIC (Modified to use local variables)
    $SaveAction = {
        param($FormObj, $TextBox, $FilePath, $HighlightScript)
        
        try {
            if ([string]::IsNullOrWhiteSpace($TextBox.Text)) {
                $check = [System.Windows.Forms.MessageBox]::Show(
                    "Save EMPTY file?", 
                    "Warning", 
                    [System.Windows.Forms.MessageBoxButtons]::YesNo, 
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                if ($check -eq "No") { return $false }
            }
            
            Set-Content -Path $FilePath -Value $TextBox.Text -Encoding UTF8 -Force
            Start-Process icacls.exe -ArgumentList "`"$FilePath`" /reset" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            
            if ((Get-Item $FilePath).Length -eq 0 -and $TextBox.Text.Length -gt 0) {
                throw "Write failed (0 bytes)."
            }
            
            # Reset State
            if ($FormObj) {
                $FormObj.Tag = $false
                $FormObj.Text = "Hosts File Editor"
            }
            
            [System.Windows.Forms.MessageBox]::Show("Saved successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            
            # Re-apply highlighting
            & $HighlightScript
            
            return $true
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error saving: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            return $false
        }
    }
    
    # 7. EVENTS
    $btn.Add_Click({
        $null = & $SaveAction -FormObj $hForm -TextBox $txtHosts -FilePath $hostsPath -HighlightScript $Highlight
    })
    
    $hForm.Add_KeyDown({
        param($src, $e)
        if ($e.Control -and $e.KeyCode -eq 'S') {
            $e.SuppressKeyPress = $true
            $null = & $SaveAction -FormObj $src -TextBox $txtHosts -FilePath $hostsPath -HighlightScript $Highlight
        }
    })
    
    # 8. CLOSE PROMPT (FIXED - Pass all required parameters)
    $hForm.Add_FormClosing({
        param($src, $e)
        
        if ($src.Tag -eq $true) {
            $res = [System.Windows.Forms.MessageBox]::Show(
                "You have unsaved changes. Save now?", 
                "Confirm", 
                [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, 
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            
            if ($res -eq "Yes") {
                # Pass all required parameters to SaveAction
                $success = & $SaveAction -FormObj $src -TextBox $txtHosts -FilePath $hostsPath -HighlightScript $Highlight
                if (-not $success) {
                    $e.Cancel = $true
                }
            } elseif ($res -eq "Cancel") {
                $e.Cancel = $true
            }
            # If "No", just close without saving
        }
    })
    
    $hForm.ShowDialog()
}
# --- STORAGE / SYSTEM ---
function Invoke-ChkdskAll {
    $confirm = [System.Windows.MessageBox]::Show("Run CHKDSK /f /r on all drives? This may require a reboot and can take a while.", "Confirm CHKDSK", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    if ($confirm -ne "Yes") { return }
    Invoke-UiCommand {
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Free } | Select-Object -ExpandProperty Name
        foreach ($drive in $drives) {
            Write-Output "Scanning drive $drive`:"
            chkdsk "${drive}:" /f /r /x
        }
    } "Running CHKDSK on all drives..."
}

function Show-AdvancedCleanupSelection {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # 1. SETUP FORM
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Advanced Cleanup Selection"
    $form.Size = New-Object System.Drawing.Size(450, 550)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $form.ForeColor = "White"

    # 2. MAIN SCROLLABLE PANEL
    $mainPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $mainPanel.FlowDirection = "TopDown"
    $mainPanel.WrapContents = $false
    $mainPanel.AutoScroll = $true
    $mainPanel.Dock = "Top"
    $mainPanel.Height = 440
    $mainPanel.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $form.Controls.Add($mainPanel)

    # 3. BUTTON PANEL
    $btnPanel = New-Object System.Windows.Forms.Panel
    $btnPanel.Dock = "Bottom"
    $btnPanel.Height = 60
    $btnPanel.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)
    $form.Controls.Add($btnPanel)

    $btnClean = New-Object System.Windows.Forms.Button
    $btnClean.Text = "Clean Selected"
    $btnClean.Size = New-Object System.Drawing.Size(140, 35)
    $btnClean.Location = New-Object System.Drawing.Point(280, 12)
    $btnClean.BackColor = "SeaGreen"
    $btnClean.ForeColor = "White"
    $btnClean.FlatStyle = "Flat"
    $btnClean.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $btnPanel.Controls.Add($btnClean)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Size = New-Object System.Drawing.Size(100, 35)
    $btnCancel.Location = New-Object System.Drawing.Point(170, 12)
    $btnCancel.BackColor = "DimGray"
    $btnCancel.ForeColor = "White"
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $btnPanel.Controls.Add($btnCancel)

    # 4. DATA DEFINITION (Categories and Items)
    $cleanupData = [ordered]@{
        "System" = @(
            @{ Name="Temporary Files";      Key="TempFiles";    Desc="User and System Temp folders" },
            @{ Name="Recycle Bin";          Key="RecycleBin";   Desc="Empties the Recycle Bin" },
            @{ Name="Windows Error Logs";   Key="WER";          Desc="Crash dumps and error reports" },
            @{ Name="DNS Cache";            Key="DNS";          Desc="Flushes network DNS resolver cache" },
            @{ Name="Thumbnail Cache";      Key="Thumbnails";   Desc="Windows Explorer thumbnail database" }
        )
        "Explorer & Privacy" = @(
            @{ Name="Recent Items (Safe)";  Key="Recent";       Desc="Clears Recent list but keeps Quick Access pins" },
            @{ Name="Run History";          Key="RunMRU";       Desc="Run dialog command history" },
            @{ Name="Address Bar History";  Key="TypedPaths";   Desc="Explorer address bar history" },
            @{ Name="User Assist";          Key="UserAssist";   Desc="Logs of programs executed (ROT13 encoded)" }
        )
        "Browsers" = @(
            @{ Name="Edge Cache";           Key="Edge";         Desc="Microsoft Edge temporary internet files" },
            @{ Name="Chrome Cache";         Key="Chrome";       Desc="Google Chrome temporary internet files" },
            @{ Name="Firefox Cache";        Key="Firefox";      Desc="Mozilla Firefox temporary internet files" }
        )
    }

    # 5. UI GENERATOR HELPER
    $global:checkboxes = @{} # Store references to retrieve values later

    foreach ($category in $cleanupData.Keys) {
        # A. Category Header (Select All)
        $catPanel = New-Object System.Windows.Forms.Panel
        $catPanel.Size = New-Object System.Drawing.Size(400, 30)
        $catPanel.Margin = New-Object System.Windows.Forms.Padding(10, 10, 0, 0)
        
        $catChk = New-Object System.Windows.Forms.CheckBox
        $catChk.Text = $category
        $catChk.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $catChk.ForeColor = [System.Drawing.Color]::DeepSkyBlue
        $catChk.AutoSize = $true
        $catChk.Location = New-Object System.Drawing.Point(5, 5)
        $catPanel.Controls.Add($catChk)
        $mainPanel.Controls.Add($catPanel)

        # B. Items Container
        $itemFlow = New-Object System.Windows.Forms.FlowLayoutPanel
        $itemFlow.FlowDirection = "TopDown"
        $itemFlow.AutoSize = $true
        $itemFlow.Margin = New-Object System.Windows.Forms.Padding(25, 0, 0, 0) # Indent

        $childChecks = @()

        foreach ($item in $cleanupData[$category]) {
            $chk = New-Object System.Windows.Forms.CheckBox
            $chk.Text = $item.Name
            $chk.Tag  = $item.Key
            $chk.AutoSize = $true
            $chk.ForeColor = "White"
            $chk.Checked = $true # Default Checked
            
            # Tooltip for description
            $tt = New-Object System.Windows.Forms.ToolTip
            $tt.SetToolTip($chk, $item.Desc)

            $itemFlow.Controls.Add($chk)
            $global:checkboxes[$item.Key] = $chk
            $childChecks += $chk
        }
        
        $mainPanel.Controls.Add($itemFlow)

        # C. Event Wiring (Select All Logic)
        $catChk.Add_Click({ 
            param($src, $e) # Changed $sender to $src
            foreach ($c in $childChecks) { $c.Checked = $src.Checked }
        })
    }

    $form.AcceptButton = $btnClean
    $form.CancelButton = $btnCancel

    # 6. SHOW AND RETURN
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedKeys = @()
        foreach ($key in $global:checkboxes.Keys) {
            if ($global:checkboxes[$key].Checked) { $selectedKeys += $key }
        }
        return $selectedKeys
    }
    return $null
}
function Invoke-TempCleanup {
    # 1. Open the BleachBit-style UI
    $selections = Show-AdvancedCleanupSelection
    
    # If user cancelled or selected nothing, exit
    if (-not $selections -or $selections.Count -eq 0) { return }

    Invoke-UiCommand {
        param($selections)
        $deleted = 0

        # --- SYSTEM CATEGORY ---
        if ($selections -contains "TempFiles") {
            Write-Output "Cleaning Temp Files..."
            $paths = @($env:TEMP, "C:\Windows\Temp") | Select-Object -Unique
            foreach ($path in $paths) {
                if (Test-Path $path) {
                    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                        try { Remove-Item $_.FullName -Force -Recurse -ErrorAction Stop; $deleted++ } catch {}
                    }
                }
            }
        }

        if ($selections -contains "RecycleBin") {
            try { 
                [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory("C:\`$Recycle.Bin", 'OnlyErrorDialogs', 'DeletePermanently')
                Write-Output "Recycle Bin emptied."
            } catch { Write-Output "Recycle Bin cleanup skipped (empty or locked)." }
        }

        if ($selections -contains "WER") {
            try { Remove-Item "C:\ProgramData\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Output "Cleared Windows Error Reporting logs." } catch {}
        }

        if ($selections -contains "DNS") {
            try { Clear-DnsClientCache -ErrorAction SilentlyContinue; Write-Output "DNS Cache flushed." } catch {}
        }

        if ($selections -contains "Thumbnails") {
            try { Remove-Item "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue; Write-Output "Thumbnail cache cleared." } catch {}
        }

        # --- EXPLORER & PRIVACY ---
        if ($selections -contains "Recent") {
            try { 
                # Protect CustomDestinations (Quick Access pins)
                Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -Force -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -ne "CustomDestinations" -and $_.Name -ne "AutomaticDestinations" } | 
                Remove-Item -Force -Recurse -ErrorAction SilentlyContinue 
                Write-Output "Recent Items cleared (Quick Access preserved)."
            } catch {}
        }

        if ($selections -contains "RunMRU") {
            try { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue; Write-Output "Run dialog history cleared." } catch {}
        }

        if ($selections -contains "TypedPaths") {
            try { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name * -ErrorAction SilentlyContinue; Write-Output "Address bar history cleared." } catch {}
        }

        if ($selections -contains "UserAssist") {
             try { reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f | Out-Null; Write-Output "UserAssist history cleared." } catch {}
        }

        # --- BROWSERS ---
        if ($selections -contains "Edge") {
             try { Remove-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Output "Edge cache cleared." } catch {}
        }
        if ($selections -contains "Chrome") {
             try { Remove-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Output "Chrome cache cleared." } catch {}
        }
        if ($selections -contains "Firefox") {
             try { Get-ChildItem "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*" -Directory | ForEach-Object { 
                Remove-Item "$($_.FullName)\cache2\entries\*" -Recurse -Force -ErrorAction SilentlyContinue 
            }; Write-Output "Firefox cache cleared." } catch {}
        }

        Write-Output "Cleanup complete. Deleted $deleted files."

    } "Running advanced cleanup..." -ArgumentList $selections
}

function Show-RegistryCleaner {
    param($ScanResults)

    # 1. SETUP FORM
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Deep Registry Cleaner"
    $f.Size = "1100, 600"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = [System.Drawing.Color]::White
    
    # 2. HEADER PANEL
    $pnlHead = New-Object System.Windows.Forms.Panel
    $pnlHead.Dock = "Top"; $pnlHead.Height = 60
    $pnlHead.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $f.Controls.Add($pnlHead)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = "Scan Complete. Issues found: $($ScanResults.Count)"
    $lblStatus.AutoSize = $true; $lblStatus.Top = 18; $lblStatus.Left = 15
    $lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $pnlHead.Controls.Add($lblStatus)

    # 3. DATAGRIDVIEW
    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Fill"
    $dg.BackgroundColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.ForeColor = [System.Drawing.Color]::White
    $dg.GridColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")
    $dg.BorderStyle = "None"
    $dg.RowHeadersVisible = $false
    $dg.AllowUserToAddRows = $false
    $dg.AllowUserToResizeRows = $false
    $dg.SelectionMode = "FullRowSelect"
    $dg.MultiSelect = $true
    
    # Headers Style
    $dg.EnableHeadersVisualStyles = $false
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 4)
    $dg.ColumnHeadersHeight = 35
    $dg.ColumnHeadersBorderStyle = "Single"

    # Row Style
    $dg.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC")
    $dg.DefaultCellStyle.SelectionForeColor = "White"
    
    $f.Controls.Add($dg)
    $dg.BringToFront()

    # 4. COLUMNS
    # Checkbox - Fixed Tiny
    $colChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colChk.HeaderText = " "
    $colChk.Width = 30
    $colChk.Name = "Check"
    $colChk.TrueValue = $true; $colChk.FalseValue = $false
    $colChk.Resizable = [System.Windows.Forms.DataGridViewTriState]::False
    $dg.Columns.Add($colChk) | Out-Null

    # Problem - Fixed Width
    $dg.Columns.Add("Problem", "Problem") | Out-Null
    $dg.Columns["Problem"].Width = 200

    # Data - FILL (Shares space)
    $dg.Columns.Add("Data", "Data (Path/Value)") | Out-Null
    $dg.Columns["Data"].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $dg.Columns["Data"].FillWeight = 50 # 50% of remaining space

    # Key - FILL (Shares space)
    $dg.Columns.Add("Key", "Registry Key") | Out-Null
    $dg.Columns["Key"].AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    $dg.Columns["Key"].FillWeight = 50 # 50% of remaining space
    
    # Hidden columns
    $dg.Columns.Add("FullPath", "FullPath"); $dg.Columns["FullPath"].Visible = $false
    $dg.Columns.Add("ValueName", "ValueName"); $dg.Columns["ValueName"].Visible = $false
    $dg.Columns.Add("Type", "Type"); $dg.Columns["Type"].Visible = $false

    # 5. POPULATE GRID
    foreach ($item in $ScanResults) {
        $row = $dg.Rows.Add()
        $dg.Rows[$row].Cells["Check"].Value = $true
        $dg.Rows[$row].Cells["Problem"].Value = $item.Problem
        $dg.Rows[$row].Cells["Data"].Value = $item.Data
        $dg.Rows[$row].Cells["Key"].Value = $item.DisplayKey
        $dg.Rows[$row].Cells["FullPath"].Value = $item.RegPath
        $dg.Rows[$row].Cells["ValueName"].Value = $item.ValueName
        $dg.Rows[$row].Cells["Type"].Value = $item.Type
    }

    # 6. BOTTOM PANEL
    $pnlBot = New-Object System.Windows.Forms.Panel
    $pnlBot.Dock = "Bottom"; $pnlBot.Height = 60
    $pnlBot.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.Controls.Add($pnlBot)

    $btnFix = New-Object System.Windows.Forms.Button
    $btnFix.Text = "Fix Selected Issues..."
    $btnFix.Width = 200; $btnFix.Height = 35
    $btnFix.Top = 12; $btnFix.Left = 860
    $btnFix.Anchor = [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $btnFix.FlatStyle = "Flat"
    $btnFix.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC")
    $btnFix.ForeColor = "White"
    $btnFix.FlatAppearance.BorderSize = 0
    $pnlBot.Controls.Add($btnFix)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Close"
    $btnCancel.Width = 100; $btnCancel.Height = 35
    $btnCancel.Top = 12; $btnCancel.Left = 20
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")
    $btnCancel.ForeColor = "White"
    $btnCancel.FlatAppearance.BorderSize = 0
    $btnCancel.Add_Click({ $f.Close() })
    $pnlBot.Controls.Add($btnCancel)

    # 7. LOGIC
    $btnFix.Add_Click({
        $toFix = @()
        foreach ($row in $dg.Rows) {
            if ($row.Cells["Check"].Value -eq $true) {
                $toFix += [PSCustomObject]@{
                    RegPath   = $row.Cells["FullPath"].Value
                    ValueName = $row.Cells["ValueName"].Value
                    Type      = $row.Cells["Type"].Value
                    DisplayKey= $row.Cells["Key"].Value
                }
            }
        }

        if ($toFix.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No issues selected.", "Registry Cleaner", "OK", "Information")
            return
        }

        $res = [System.Windows.Forms.MessageBox]::Show("Do you want to fix $($toFix.Count) selected registry issues?`n`nA backup will be created automatically.", "Registry Cleaner", "YesNo", "Question")
        if ($res -eq "Yes") {
            $f.Tag = $toFix
            $f.DialogResult = "OK"
            $f.Close()
        }
    })

    if ($ScanResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No issues found!", "Registry Cleaner", "OK", "Information")
        return $null
    }

    $f.ShowDialog() | Out-Null
    return $f.Tag
}

function Invoke-RegistryTask {
    param([string]$Action)

    $bkDir = Join-Path (Get-DataPath) "RegistryBackups"
    if (-not (Test-Path $bkDir)) { New-Item -Path $bkDir -ItemType Directory | Out-Null }

    # --- HELPER: Appends a specific key to a master .reg file ---
    function Backup-RegKey {
        param($KeyPath, $FilePath)
        $temp = [System.IO.Path]::GetTempFileName()
        # Export specific key to temp
        reg export $KeyPath $temp /y 2>$null
        
        if ((Get-Item $temp).Length -gt 0) {
            if (-not (Test-Path $FilePath)) {
                # New file: Write content with correct Unicode encoding (required for .reg)
                Get-Content $temp -Raw | Set-Content $FilePath -Encoding Unicode
            } else {
                # Existing file: Skip header line and append
                Get-Content $temp -ReadCount 0 | Select-Object -Skip 1 | Add-Content $FilePath -Encoding Unicode
            }
        }
        Remove-Item $temp -ErrorAction SilentlyContinue
    }

    switch ($Action) {
        "List" {
            Invoke-UiCommand { 
                $keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } 
                if ($keys) { $keys | Select-Object -ExpandProperty PSChildName | Out-String } else { "No obsolete Uninstall keys found." }
            } "Listing removable keys..."
        }
        
        "Delete" {
            Invoke-UiCommand {
                $bkFile = Join-Path $bkDir ("SmartClean_Backup_{0}.reg" -f (Get-Date -Format "yyyyMMdd_HHmm"))
                $count = 0

                # A. Clean Obsolete Uninstall Keys
                $keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' }
                
                if ($keys) {
                    foreach ($k in $keys) {
                        Backup-RegKey -KeyPath $k.Name -FilePath $bkFile
                        try { Remove-Item $k.PSPath -Recurse -Force -ErrorAction Stop; Write-Output "Removed: $($k.PSChildName)"; $count++ } catch { Write-Output "Failed: $($k.PSChildName)" }
                    }
                }

                # B. Clean MuiCache
                $muiPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
                if (Test-Path $muiPath) {
                    Backup-RegKey -KeyPath "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" -FilePath $bkFile
                    $items = Get-ItemProperty $muiPath
                    foreach ($name in $items.PSObject.Properties.Name) {
                        if ($name -match '^[a-zA-Z]:\\' -and -not (Test-Path $name -ErrorAction SilentlyContinue)) {
                            Remove-ItemProperty -Path $muiPath -Name $name -ErrorAction SilentlyContinue
                            $count++
                        }
                    }
                }
                
                if ($count -gt 0) { Write-Output "Cleaned $count items. Backup saved: $bkFile" } else { Write-Output "Nothing found to clean." }

            } "Smart cleaning keys..."
        }

        "DeepClean" {
            # 1. SCANNING PHASE
            $findings = New-Object System.Collections.Generic.List[PSObject]

            Invoke-UiCommand {
                Write-Output "Scanning registry (Ultra Deep Mode)..."
                
                # HELPER: Checks if we have permission to delete this key
                function Test-IsDeletable($Path) {
                    try {
                        if (-not (Test-Path $Path)) { return $false }
                        $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
                        if (-not $acl) { return $true }
                        if ($acl.Owner -match "TrustedInstaller" -or $acl.Owner -match "SYSTEM") { return $false }
                        return $true
                    } catch { return $false }
                }

                # --- A. App Paths (Missing EXEs) ---
                $appPaths = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
                $subKeys = Get-ChildItem $appPaths -ErrorAction SilentlyContinue
                foreach ($key in $subKeys) {
                    $exePath = (Get-ItemProperty $key.PSPath)."(default)"
                    if ($exePath -and ($exePath -match '^[a-zA-Z]:\\') -and -not (Test-Path $exePath -ErrorAction SilentlyContinue)) {
                        if (Test-IsDeletable $key.PSPath) {
                            $findings.Add([PSCustomObject]@{ Problem="Missing App Path"; Data=$exePath; DisplayKey=$key.PSChildName; RegPath=$key.PSPath; ValueName=$null; Type="Key" })
                        }
                    }
                }

                # --- B. SharedDLLs ---
                $dllLocs = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs")
                foreach ($dllPath in $dllLocs) {
                    if (Test-Path $dllPath) {
                        $props = Get-ItemProperty $dllPath
                        foreach ($dll in $props.PSObject.Properties.Name) {
                            if ($dll -match '^[a-zA-Z]:\\' -and -not (Test-Path $dll -ErrorAction SilentlyContinue)) {
                                if (Test-IsDeletable $dllPath) {
                                    $findings.Add([PSCustomObject]@{ Problem="Missing Shared DLL"; Data=$dll; DisplayKey=$(Split-Path $dllPath -Leaf); RegPath=$dllPath; ValueName=$dll; Type="Value" })
                                }
                            }
                        }
                    }
                }

                # --- C. ActiveX / COM Issues ---
                $comLocations = @("HKLM:\SOFTWARE\Classes\CLSID", "HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID")
                foreach ($root in $comLocations) {
                    if (Test-Path $root) {
                        $clsids = Get-ChildItem $root -ErrorAction SilentlyContinue
                        foreach ($clsid in $clsids) {
                            $srv = Join-Path $clsid.PSPath "InProcServer32"
                            if (Test-Path $srv) {
                                $dll = (Get-ItemProperty $srv)."(default)"
                                if ($dll -and $dll -match '^[a-zA-Z]:\\' -and -not (Test-Path $dll -ErrorAction SilentlyContinue)) {
                                    if (Test-IsDeletable $clsid.PSPath) {
                                        $findings.Add([PSCustomObject]@{ Problem="ActiveX/COM Issue"; Data=$dll; DisplayKey=$clsid.PSChildName; RegPath=$srv; ValueName=$null; Type="Key" })
                                    }
                                }
                            }
                        }
                    }
                }

                # --- D. Application Classes (Expanded to HKCU) ---
                $appRoots = @("HKLM:\SOFTWARE\Classes\Applications", "HKLM:\SOFTWARE\WOW6432Node\Classes\Applications", "HKCU:\Software\Classes\Applications")
                foreach ($root in $appRoots) {
                     if (Test-Path $root) {
                         $apps = Get-ChildItem $root -ErrorAction SilentlyContinue
                         foreach ($app in $apps) {
                            $openCmd = Join-Path $app.PSPath "shell\open\command"
                            if (Test-Path $openCmd) {
                                $cmd = (Get-ItemProperty $openCmd)."(default)"
                                if ($cmd -match '"([^"]+)"') { $cmdPath = $matches[1] } else { $cmdPath = $cmd.Split(" ")[0] }
                                
                                if ($cmdPath -match '^[a-zA-Z]:\\' -and -not (Test-Path $cmdPath -ErrorAction SilentlyContinue)) {
                                    if (Test-IsDeletable $app.PSPath) {
                                        $findings.Add([PSCustomObject]@{ Problem="Invalid App Association"; Data=$cmdPath; DisplayKey=$app.PSChildName; RegPath=$app.PSPath; ValueName=$null; Type="Key" })
                                    }
                                }
                            }
                         }
                     }
                }

                # --- E. Installer Folders ---
                $instPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders"
                if (Test-Path $instPath) {
                    $folders = Get-ItemProperty $instPath
                    foreach ($f in $folders.PSObject.Properties.Name) {
                        if ($f -match '^[a-zA-Z]:\\' -and -not (Test-Path $f -ErrorAction SilentlyContinue)) {
                             if (Test-IsDeletable $instPath) {
                                $findings.Add([PSCustomObject]@{ Problem="Missing Installer Folder"; Data=$f; DisplayKey="Installer\Folders"; RegPath=$instPath; ValueName=$f; Type="Value" })
                             }
                        }
                    }
                }

                # --- F. MuiCache & Compatibility ---
                $userKeys = @("HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store")
                foreach ($path in $userKeys) {
                    if (Test-Path $path) {
                        $items = Get-ItemProperty $path
                        foreach ($name in $items.PSObject.Properties.Name) {
                            $cleanPath = $name -replace '\.(FriendlyAppName|ApplicationCompany)$', ''
                            if ($cleanPath -match '^[a-zA-Z]:\\' -and -not (Test-Path $cleanPath -ErrorAction SilentlyContinue)) {
                                $findings.Add([PSCustomObject]@{ Problem="Obsolete User Ref"; Data=$cleanPath; DisplayKey=$(Split-Path $path -Leaf); RegPath=$path; ValueName=$name; Type="Value" })
                            }
                        }
                    }
                }

                # --- G. Invalid Firewall Rules ---
                $fwPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
                if (Test-Path $fwPath) {
                    $rules = Get-ItemProperty $fwPath
                    foreach ($ruleName in $rules.PSObject.Properties.Name) {
                        $ruleData = $rules.$ruleName
                        if ($ruleData -is [string] -and $ruleData -match "App=([^|]+)") {
                            $rawApp = $matches[1]
                            try {
                                $expanded = [Environment]::ExpandEnvironmentVariables($rawApp)
                                if ($expanded -match '^[a-zA-Z]:\\' -and -not (Test-Path $expanded -ErrorAction SilentlyContinue)) {
                                    if (Test-IsDeletable $fwPath) {
                                        $findings.Add([PSCustomObject]@{ Problem="Invalid Firewall Rule"; Data=$expanded; DisplayKey=$ruleName; RegPath=$fwPath; ValueName=$ruleName; Type="Value" })
                                    }
                                }
                            } catch {}
                        }
                    }
                }

                # --- H. Startup Items (NEW) ---
                $runKeys = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
                foreach ($runKey in $runKeys) {
                    if (Test-Path $runKey) {
                        $items = Get-ItemProperty $runKey
                        foreach ($name in $items.PSObject.Properties.Name) {
                            $val = $items.$name
                            if ($val -is [string] -and $val -match '^[a-zA-Z]:\\') {
                                # Clean args (e.g. "C:\Program Files\App.exe" /min)
                                if ($val -match '"([^"]+)"') { $exe = $matches[1] } else { $exe = $val.Split(" ")[0] }
                                if (-not (Test-Path $exe -ErrorAction SilentlyContinue)) {
                                    $findings.Add([PSCustomObject]@{ Problem="Broken Startup Item"; Data=$exe; DisplayKey=$runKey; RegPath=$runKey; ValueName=$name; Type="Value" })
                                }
                            }
                        }
                    }
                }

                # --- I. Unused File Extensions (NEW) ---
                # Scans HKLM and HKCU Classes for extensions that are empty/useless
                $classRoots = @("HKLM:\SOFTWARE\Classes", "HKCU:\Software\Classes")
                foreach ($root in $classRoots) {
                    if (Test-Path $root) {
                        # Get only keys starting with "."
                        $exts = Get-ChildItem $root -Name | Where-Object { $_.StartsWith(".") }
                        foreach ($ext in $exts) {
                            $path = Join-Path $root $ext
                            # Check if key is effectively empty (No subkeys, No default value)
                            $subkeys = Get-ChildItem $path -ErrorAction SilentlyContinue
                            $props = Get-ItemProperty $path -ErrorAction SilentlyContinue
                            $def = $props."(default)"
                            
                            if ($subkeys.Count -eq 0 -and ([string]::IsNullOrEmpty($def))) {
                                if (Test-IsDeletable $path) {
                                    $findings.Add([PSCustomObject]@{ Problem="Unused File Ext"; Data=$ext; DisplayKey=$path; RegPath=$path; ValueName=$null; Type="Key" })
                                }
                            }
                        }
                    }
                }
                
                Write-Output "Scan complete. Found $($findings.Count) actionable issues."
            } "Scanning Registry (Ultra Mode)..."

            # 2. GUI PHASE
            $toDelete = Show-RegistryCleaner -ScanResults ($findings | Select-Object *)
            if (-not $toDelete) { return }

            # 3. FIXING PHASE
            Invoke-UiCommand {
                $bkFile = Join-Path $bkDir ("DeepClean_Backup_{0}.reg" -f (Get-Date -Format "yyyyMMdd_HHmm"))
                $fixedCount = 0
                $skippedCount = 0

                foreach ($item in $toDelete) {
                    if ($item.Type -eq "Key") {
                        Backup-RegKey -KeyPath ($item.RegPath -replace "Microsoft.PowerShell.Core\\Registry::", "") -FilePath $bkFile
                        Remove-Item $item.RegPath -Recurse -Force -ErrorAction SilentlyContinue
                        if (Test-Path $item.RegPath) { $skippedCount++ } else { $fixedCount++ }
                    }
                    elseif ($item.Type -eq "Value") {
                        Backup-RegKey -KeyPath ($item.RegPath -replace "Microsoft.PowerShell.Core\\Registry::", "") -FilePath $bkFile
                        Remove-ItemProperty -Path $item.RegPath -Name $item.ValueName -ErrorAction SilentlyContinue
                        if (Get-ItemProperty -Path $item.RegPath -Name $item.ValueName -ErrorAction SilentlyContinue) { $skippedCount++ } else { $fixedCount++ }
                    }
                }
                
                $msg = "Cleanup Complete.`n`nFixed: $fixedCount`nSkipped (Protected): $skippedCount`nBackup: $bkFile"
                Write-Output "Fixed: $fixedCount. Skipped: $skippedCount."
                [System.Windows.Forms.MessageBox]::Show($msg, "Registry Cleaner", "OK", "Information") | Out-Null

            } "Fixing selected issues..."
        }

        "BackupHKLM" {
            Invoke-UiCommand {
                $bkFile = Join-Path $bkDir ("Full_HKLM_Backup_{0}.reg" -f (Get-Date -Format "yyyyMMdd_HHmm"))
                reg export HKLM $bkFile /y | Out-Null
                Write-Output "Full HKLM backup created: $bkFile"
            } "Backing up HKLM..."
        }

        "Restore" {
            $dlg = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.InitialDirectory = $bkDir
            $dlg.Filter = "Registry Backup (*.reg)|*.reg"
            if ($dlg.ShowDialog() -eq "OK") {
                $restoreFile = $dlg.FileName
                Invoke-UiCommand { 
                    Start-Process reg -ArgumentList "import `"$restoreFile`"" -Wait -NoNewWindow
                    Write-Output "Restored: $restoreFile"
                } "Restoring registry..."
            }
        }

        "Scan" {
            Invoke-UiCommand { 
                Write-Output "Starting System File Checker..."
                sfc /scannow
                Write-Output "`nStarting DISM Health Check..."
                dism /online /cleanup-image /checkhealth 
            } "Scanning system files..."
        }
    }
}

function Invoke-SSDTrim {
    Invoke-UiCommand {
        $ssds = Get-PhysicalDisk | Where-Object MediaType -eq 'SSD'
        if (-not $ssds) { Write-Output "No SSDs detected."; return }
        $log = Join-Path (Get-DataPath) ("SSD_OPTIMIZE_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"))
        $out = @("SSD Optimize Log - $(Get-Date)")
        foreach ($ssd in $ssds) {
            $disk = Get-Disk | Where-Object { $_.FriendlyName -eq $ssd.FriendlyName }
            if ($disk) {
                $vols = $disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null
                foreach ($v in $vols) {
                    $out += "Optimizing $($v.DriveLetter):"
                    $out += Optimize-Volume -DriveLetter $v.DriveLetter -ReTrim -Verbose 4>&1
                }
            }
        }
        $out | Out-File -FilePath $log -Encoding UTF8
        Write-Output "SSD optimization complete. Log: $log"
    } "Running SSD Trim/ReTrim..."
}
function Show-BrokenShortcuts {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Broken Shortcut Manager"
    $f.Size = "1100, 650"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $f.ForeColor = "White"

    # 1. SETUP GRID
    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Top"; $dg.Height = 480
    $dg.BackgroundColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $dg.ForeColor = "Black"
    $dg.AutoSizeColumnsMode = "Fill"
    $dg.SelectionMode = "FullRowSelect"
    $dg.MultiSelect = $true
    $dg.ReadOnly = $true
    $dg.RowHeadersVisible = $false
    $dg.AllowUserToAddRows = $false
    $dg.BorderStyle = "None"
    
    $dg.EnableHeadersVisualStyles = $false
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 50)
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 4)
    $dg.ColumnHeadersHeight = 35
    $dg.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
    $dg.DefaultCellStyle.SelectionForeColor = "White"

    $f.Controls.Add($dg)

    # 2. STATUS
    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = "Initializing..."
    $lblStatus.AutoSize = $true
    $lblStatus.ForeColor = "Yellow"
    $lblStatus.Location = "20, 490"
    $f.Controls.Add($lblStatus)

    # 3. BUTTONS
    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"; $pnl.Height = 80
    $pnl.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $f.Controls.Add($pnl)

    # --- CHANGED: Delete Button ---
    $btnDelete = New-Object System.Windows.Forms.Button
    $btnDelete.Text = "Delete Selected"
    $btnDelete.Location = "20, 20"; $btnDelete.Width = 150; $btnDelete.Height = 35
    $btnDelete.BackColor = "IndianRed"; $btnDelete.ForeColor = "White"; $btnDelete.FlatStyle = "Flat"
    $pnl.Controls.Add($btnDelete)

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "Apply Fixes" # Renamed slightly to be clearer
    $btnApply.Location = "780, 20"; $btnApply.Width = 150; $btnApply.Height = 35
    $btnApply.BackColor = "SeaGreen"; $btnApply.ForeColor = "White"; $btnApply.FlatStyle = "Flat"
    $btnApply.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $pnl.Controls.Add($btnApply)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Close"
    $btnCancel.Location = "950, 20"; $btnCancel.Width = 100; $btnCancel.Height = 35
    $btnCancel.BackColor = "DimGray"; $btnCancel.ForeColor = "White"; $btnCancel.FlatStyle = "Flat"
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $pnl.Controls.Add($btnCancel)
    
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Right-click for Deep Search or Manual Browse."
    $lblInfo.AutoSize = $true; $lblInfo.ForeColor = "Gray"
    $lblInfo.Location = "200, 30"
    $pnl.Controls.Add($lblInfo)

    # 4. CONTEXT MENU
    $ctx = New-Object System.Windows.Forms.ContextMenuStrip
    
    # --- Manual Browse ---
    $itemBrowse = $ctx.Items.Add("Browse for target...")
    $itemBrowse.Add_Click({
        if ($dg.SelectedRows.Count -eq 1) {
            $row = $dg.SelectedRows[0]
            $obj = $row.DataBoundItem
            $dlg = New-Object System.Windows.Forms.OpenFileDialog
            $dlg.Filter = "Executables (*.exe)|*.exe|All Files (*.*)|*.*"
            if ($dlg.ShowDialog() -eq "OK") {
                $obj.Action = "Fix"
                $obj.NewTarget = $dlg.FileName
                $obj.Details = "Manual fix: $($dlg.FileName)"
                $dg.Refresh()
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightGreen
            }
        }
    })

    # --- Deep Search ---
    $itemDeep = $ctx.Items.Add("Deep Search (Slow - Scan All Drives)")
    $itemDeep.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $itemDeep.ForeColor = [System.Drawing.Color]::DarkBlue
    
    $itemDeep.Add_Click({
        if ($dg.SelectedRows.Count -ne 1) { return }
        $row = $dg.SelectedRows[0]
        $obj = $row.DataBoundItem
        
        $searchName = $null
        $shell = New-Object -ComObject WScript.Shell
        try {
            $sc = $shell.CreateShortcut($obj.FullPath)
            if ($sc.TargetPath) {
                $searchName = Split-Path $sc.TargetPath -Leaf
            }
        } catch {}

        if (-not $searchName) {
            $base = [System.IO.Path]::GetFileNameWithoutExtension($obj.Shortcut)
            $searchName = "$base.exe"
        }

        $warnMsg = "This will scan ALL local hard drives for:`n`n'$searchName'`n`nDepending on your drive size, this can take 5-10+ minutes.`nDuring this time, the application may appear frozen.`n`nDo you want to continue?"
        $res = [System.Windows.Forms.MessageBox]::Show($warnMsg, "Deep Search Warning", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        
        if ($res -eq "Yes") {
            [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
            $lblStatus.Text = "Deep Searching for '$searchName'..."
            $f.Update()

            $foundPath = $null
            $drives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' }
            
            foreach ($d in $drives) {
                if ($foundPath) { break }
                $root = $d.RootDirectory.FullName
                $lblStatus.Text = "Scanning drive $root for '$searchName'..."
                $f.Update()
                try {
                    $match = Get-ChildItem -Path $root -Filter $searchName -Recurse -ErrorAction SilentlyContinue -Force | Select-Object -First 1
                    if ($match) { $foundPath = $match.FullName }
                } catch {}
            }

            if ($foundPath) {
                $obj.Action = "Fix"
                $obj.NewTarget = $foundPath
                $obj.Details = "Deep Search: $foundPath"
                $dg.Refresh()
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightGreen
                $lblStatus.Text = "Found: $foundPath"
                [System.Windows.Forms.MessageBox]::Show("File found!`n`n$foundPath", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            } else {
                $lblStatus.Text = "Deep Search failed."
                [System.Windows.Forms.MessageBox]::Show("Could not find '$searchName' on any local drive.", "Not Found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
            [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
        }
    })

    $ctx.Items.Add( (New-Object System.Windows.Forms.ToolStripSeparator) )

    # --- Unmark ---
    $itemUnmark = $ctx.Items.Add("Unmark / Cancel Action")
    $itemUnmark.Add_Click({
        foreach ($row in $dg.SelectedRows) {
            $obj = $row.DataBoundItem
            $obj.Action = "None"
            $obj.Details = "Review Needed"
            $dg.Refresh()
            $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange
        }
    })
    $dg.ContextMenuStrip = $ctx

    # --- CHANGED: DELETE BUTTON LOGIC ---
    $btnDelete.Add_Click({
        $count = $dg.SelectedRows.Count
        if ($count -eq 0) { return }

        $res = [System.Windows.Forms.MessageBox]::Show("Permanently delete $count selected shortcut(s)?`n`nThis action is immediate.", "Confirm Delete", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        
        if ($res -eq "Yes") {
            $rows = @($dg.SelectedRows) # Copy collection to avoid modification errors
            $deletedCount = 0
            
            foreach ($row in $rows) {
                try {
                    # Get FullPath from the hidden column we added
                    $path = $row.Cells["FullPath"].Value
                    
                    if ($path -and (Test-Path $path)) {
                        Remove-Item -Path $path -Force -ErrorAction Stop
                    }
                    
                    # Remove from UI
                    $dg.Rows.Remove($row)
                    $deletedCount++
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Could not delete: $path`n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            }
            $lblStatus.Text = "Deleted $deletedCount shortcuts."
        }
    })

    $script:ScanResults = @()

    # 5. SCAN LOGIC
    $f.Add_Shown({
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
        $lblStatus.Text = "Scanning shortcuts... Please wait."
        $f.Text = "Broken Shortcut Manager - Scanning..."
        [System.Windows.Forms.Application]::DoEvents()

        $paths = @(
            "C:\ProgramData\Microsoft\Windows\Start Menu", 
            "$env:APPDATA\Microsoft\Windows\Start Menu",
            "$env:USERPROFILE\Desktop",
            "C:\Users\Public\Desktop",
            "$env:USERPROFILE\OneDrive\Desktop"
        ) | Select-Object -Unique | Where-Object { $_ -and (Test-Path $_) }

        $knownFixes = @{
            "My Computer"   = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
            "This PC"       = "::{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
            "Recycle Bin"   = "::{645FF040-5081-101B-9F08-00AA002F954E}"
            "Control Panel" = "::{21EC2020-3AEA-1069-A2DD-08002B30309D}"
            "Documents"     = "::{450D8FBA-AD25-11D0-98A8-0800361B1103}"
        }

        $shell = New-Object -ComObject WScript.Shell
        
        $tempList = @()
        
        foreach ($path in $paths) {
            Get-ChildItem -Path $path -Filter *.lnk -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $lnkPath = $_.FullName
                try {
                    $sc = $shell.CreateShortcut($lnkPath)
                    $target = $sc.TargetPath
                } catch { return }

                if ($target -match '^shell:' -or $target -match '^\s*::{') { return }
                if ($target -match '^\s*$' -or $target.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) { return }

                if (-not (Test-Path $target)) {
                    $action = "None"; $details = "Review Needed"; $newT = $null
                    $baseName = $_.BaseName

                    if ($knownFixes.ContainsKey($baseName)) {
                        $action = "Fix"; $details = "Restore System Path"; $newT = $knownFixes[$baseName]
                    } else {
                        $guessName = if ($target) { Split-Path $target -Leaf } else { ($baseName + ".exe") }
                        $peers = Get-ChildItem $_.DirectoryName -Filter *.lnk -ErrorAction SilentlyContinue | Where-Object { $_.FullName -ne $lnkPath }
                        foreach ($p in $peers) {
                            try {
                                $pt = $shell.CreateShortcut($p.FullName).TargetPath
                                if ($pt -and (Test-Path $pt)) {
                                    $parent = Split-Path $pt -Parent; $candidate = Join-Path $parent $guessName
                                    if (Test-Path $candidate) { $action = "Fix"; $details = "Auto-Found: $parent"; $newT = $candidate; break }
                                }
                            } catch {}
                        }
                    }

                    $tempList += [PSCustomObject]@{
                        Shortcut  = $_.Name
                        Folder    = (Split-Path $_.DirectoryName -Leaf)
                        Action    = $action
                        Details   = $details
                        NewTarget = $newT
                        FullPath  = $lnkPath
                    }
                }
            }
        }

        # 6. BIND
        $dt = New-Object System.Data.DataTable
        # Added 'FullPath' column to the DataTable so we can access it for deletion
        $dt.Columns.Add("Shortcut"); $dt.Columns.Add("Folder"); $dt.Columns.Add("Action"); $dt.Columns.Add("Details"); $dt.Columns.Add("NewTarget"); $dt.Columns.Add("FullPath")
        
        foreach ($item in $tempList) {
            $row = $dt.NewRow()
            $row["Shortcut"]  = $item.Shortcut
            $row["Folder"]    = $item.Folder
            $row["Action"]    = $item.Action
            $row["Details"]   = $item.Details
            $row["NewTarget"] = $item.NewTarget
            $row["FullPath"]  = $item.FullPath
            $dt.Rows.Add($row)
        }
        $dg.DataSource = $dt
        $dg.ClearSelection()
        
        # Hide FullPath from view
        if ($dg.Columns["FullPath"]) { $dg.Columns["FullPath"].Visible = $false }

        # 7. COLORS
        for ($i = 0; $i -lt $dg.Rows.Count; $i++) {
            $row = $dg.Rows[$i]
            $act = $row.Cells["Action"].Value
            if ($act -eq "Fix") { $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightGreen; $row.Selected = $true }
            elseif ($act -eq "None") { $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange }
            else { $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Gray }
        }
        
        $lblStatus.Text = "Scan Complete. Found $($tempList.Count) broken shortcuts."
        $f.Text = "Broken Shortcut Manager"
        [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default

        if ($tempList.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("Scan complete. No broken shortcuts found.", "All Clean", [System.Windows.Forms.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        }
    })

    # Return Logic: Rebuild list from whatever is left in the grid to avoid processing deleted items
    if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { 
        $finalList = @()
        foreach ($row in $dg.Rows) {
            # Map DataRowView back to object
            $finalList += [PSCustomObject]@{
                Shortcut  = $row.Cells["Shortcut"].Value
                Folder    = $row.Cells["Folder"].Value
                Action    = $row.Cells["Action"].Value
                Details   = $row.Cells["Details"].Value
                NewTarget = $row.Cells["NewTarget"].Value
                FullPath  = $row.Cells["FullPath"].Value
            }
        }
        return $finalList
    }
    return $null
}
function Invoke-ShortcutFix {
    $items = Show-BrokenShortcuts
    if (-not $items -or $items.Count -eq 0) { return }

    # 1. ANALYZE PLANNED ACTIONS
    $toFix = $items | Where-Object { $_.Action -eq "Fix" }
    $toDel = $items | Where-Object { $_.Action -eq "Delete" }

    if ($toFix.Count -eq 0 -and $toDel.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No actions were selected.`n`n(Tip: Select rows and click 'Mark for Delete' or Browse to fix them.)", "No Action", [System.Windows.Forms.MessageBoxButton]::OK, [System.Windows.Forms.MessageBoxImage]::Information)
        return
    }

    # 2. CONFIRMATION PROMPT
    $msg = "You are about to apply the following actions:`n`n"
    if ($toFix.Count -gt 0) { $msg += "• Fix: $($toFix.Count) shortcut(s)`n" }
    if ($toDel.Count -gt 0) { $msg += "• DELETE: $($toDel.Count) shortcut(s)`n" }
    $msg += "`nAre you sure you want to continue?"

    $confirm = [System.Windows.Forms.MessageBox]::Show($msg, "Confirm Actions", [System.Windows.Forms.MessageBoxButton]::YesNo, [System.Windows.Forms.MessageBoxImage]::Warning)
    
    if ($confirm -ne "Yes") { return }

    # 3. EXECUTE
    Invoke-UiCommand {
        param($toFix, $toDel)
        $shell = New-Object -ComObject WScript.Shell
        
        # Apply Fixes
        foreach ($item in $toFix) {
            try {
                $sc = $shell.CreateShortcut($item.FullPath)
                $sc.TargetPath = $item.NewTarget
                $sc.Save()
                Write-Output "Fixed: $($item.Shortcut)"
            } catch { Write-Output "Failed to fix $($item.Shortcut): $($_.Exception.Message)" }
        }

        # Apply Deletes
        foreach ($item in $toDel) {
            try {
                Remove-Item $item.FullPath -Force -ErrorAction Stop
                Write-Output "Deleted: $($item.Shortcut)"
            } catch { Write-Output "Failed to delete $($item.Shortcut): $($_.Exception.Message)" }
        }

        Write-Output "Operation complete."

    } "Applying shortcut fixes..." -ArgumentList $toFix, $toDel
}

# --- FIREWALL TOOLS ---
function Invoke-FirewallExport {
    $target = Join-Path (Get-DataPath) ("firewall_rules_{0}.wfw" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    Invoke-UiCommand { netsh advfirewall export "$target" } "Exporting firewall rules..."
}

function Invoke-FirewallImport {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Windows Firewall Policy (*.wfw)|*.wfw"
    if ($dlg.ShowDialog() -ne "OK") { return }
    $file = $dlg.FileName
    Invoke-UiCommand { netsh advfirewall import "$file" } "Importing firewall rules..."
}

function Invoke-FirewallDefaults {
    $confirm = [System.Windows.MessageBox]::Show("Restore default Windows Firewall rules? Custom rules will be removed.", "Restore Defaults", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    if ($confirm -ne "Yes") { return }
    Invoke-UiCommand { netsh advfirewall reset } "Restoring default firewall rules..."
}

function Invoke-FirewallPurge {
    $confirm = [System.Windows.MessageBox]::Show("Delete ALL firewall rules? This is destructive.", "Delete All Rules", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    if ($confirm -ne "Yes") { return }
    Invoke-UiCommand { Remove-NetFirewallRule -All } "Deleting all firewall rules..."
}

# --- DRIVER TOOLS ---
function Invoke-DriverReport {
    Invoke-UiCommand {
        $outfile = Join-Path (Get-DataPath) "Installed_Drivers.txt"
        driverquery /v > $outfile
        Write-Output "Driver report saved to $outfile"
    } "Creating driver report..."
}

function Invoke-ExportDrivers {
    Invoke-UiCommand {
        $path = Join-Path (Get-DataPath) ("Drivers_Backup_{0}" -f (Get-Date -Format "yyyyMMdd_HHmm"))
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $proc = Start-Process pnputil.exe -ArgumentList "/export-driver","*","""$path""" -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -eq 0) {
            Write-Output "Drivers exported to $path"
            [System.Windows.MessageBox]::Show("Drivers exported to:`n$path","Export Drivers",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
        } else {
            Write-Output "Export failed (pnputil exit $($proc.ExitCode))."
            [System.Windows.MessageBox]::Show("Export failed (pnputil exit $($proc.ExitCode)).","Export Drivers",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
        }
    } "Exporting drivers to data folder..."
}

function Show-GhostDevicesDialog {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Ghost Devices"
    $f.Size = "800, 500"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = [System.Drawing.Color]::White

    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Top"
    $dg.Height = 380
    $dg.BackgroundColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.ForeColor = [System.Drawing.Color]::White
    $dg.AutoSizeColumnsMode = "Fill"
    $dg.SelectionMode = "FullRowSelect"
    $dg.MultiSelect = $true
    $dg.ReadOnly = $true
    $dg.RowHeadersVisible = $false
    $dg.AllowUserToAddRows = $false
    $dg.BorderStyle = "None"
    $dg.EnableHeadersVisualStyles = $false
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 4)
    $dg.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
    $dg.ColumnHeadersHeight = 28
    $dg.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC")
    $dg.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $dg.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#252526")
    $dg.GridColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")
    $f.Controls.Add($dg)

    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"
    $pnl.Height = 80
    $pnl.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.Controls.Add($pnl)

    function New-GDButton($text,$x,$color=$null){
        $b=New-Object System.Windows.Forms.Button
        $b.Text=$text
        $b.Left=$x; $b.Top=20; $b.Width=120; $b.Height=35
        $b.FlatStyle="Flat"
        $b.FlatAppearance.BorderSize=1
        $b.FlatAppearance.BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#444444")
        $b.ForeColor=[System.Drawing.Color]::White
        if($color){
            $b.BackColor=[System.Drawing.ColorTranslator]::FromHtml($color)
            $b.FlatAppearance.MouseOverBackColor=[System.Windows.Forms.ControlPaint]::Light($b.BackColor)
        } else {
            $b.BackColor=[System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
            $b.FlatAppearance.MouseOverBackColor=[System.Drawing.ColorTranslator]::FromHtml("#3E3E42")
        }
        $pnl.Controls.Add($b); return $b
    }

    $btnRefresh = New-GDButton "Refresh" 20
    $btnRemoveSel = New-GDButton "Remove Selected" 160 "#802020"
    $btnRemoveAll = New-GDButton "Remove All" 320 "#A04040"
    $btnClose = New-GDButton "Close" 480

    $Load = {
        $items = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Unknown' }
        $dt = New-Object System.Data.DataTable
        $dt.Columns.Add("InstanceId")
        $dt.Columns.Add("Class")
        $dt.Columns.Add("FriendlyName")
        foreach($d in $items){
            $r=$dt.NewRow()
            $r["InstanceId"]=$d.InstanceId
            $r["Class"]=$d.Class
            $r["FriendlyName"]=$d.FriendlyName
            $dt.Rows.Add($r)
        }
        $dg.DataSource=$dt
        $dg.ClearSelection()
        if(-not $items -or $items.Count -eq 0){
            [System.Windows.MessageBox]::Show("No hidden/ghost devices found.","Ghost Devices",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
        }
    }

    $btnRefresh.Add_Click({ & $Load })
    $btnRemoveSel.Add_Click({
        if($dg.SelectedRows.Count -eq 0){ return }
        foreach($row in $dg.SelectedRows){
            $id = $row.Cells["InstanceId"].Value
            if($id){ pnputil /remove-device $id | Out-Null }
        }
        & $Load
    })
    $btnRemoveAll.Add_Click({
        if($dg.Rows.Count -eq 0){ return }
        foreach($row in $dg.Rows){
            $id = $row.Cells["InstanceId"].Value
            if($id){ pnputil /remove-device $id | Out-Null }
        }
        & $Load
    })
    $btnClose.Add_Click({ $f.Close() })

    & $Load
    $f.ShowDialog() | Out-Null
}

function Invoke-DriverUpdates {
    param([bool]$Enable)
    $value = if ($Enable) { 0 } else { 1 }
    $msg = if ($Enable) { "Enabled automatic driver updates." } else { "Disabled automatic driver updates." }
    Invoke-UiCommand {
        param($value,$msg)
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "SearchOrderConfig" -Value $value -Type DWord
        Write-Output $msg
    } "Updating driver update policy..."
}

function Invoke-DeviceMetadata {
    param([bool]$Enable)
    $value = if ($Enable) { 0 } else { 1 }
    $msg = if ($Enable) { "Device metadata downloads enabled." } else { "Device metadata downloads disabled." }
    Invoke-UiCommand {
        param($value,$msg)
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "PreventDeviceMetadataFromNetwork" -Value $value -Type DWord
        Write-Output $msg
    } "Updating device metadata policy..."
}

function Show-DriverCleanupDialog {
    # 1. SCANNING PHASE
    $rawOutput = pnputil.exe /enum-drivers 2>&1
    $drivers = @()
    $current = $null

    foreach ($line in $rawOutput) {
        $line = $line.ToString().Trim()
        
        if ($line.Contains(":")) {
            $parts = $line -split ":", 2
            $key   = $parts[0].Trim()
            $val   = $parts[1].Trim()
            
            # 1. Check for Published Name (Start of new driver block)
            if ($val -match '^(oem\d+\.inf)$') {
                if ($current) { $drivers += [PSCustomObject]$current }
                $current = [ordered]@{ 
                    PublishedName = $val
                    OriginalName  = $null
                    Provider      = "Unknown"
                    Version       = [Version]"0.0.0.0"
                    DisplayVer    = "Unknown"
                    SortDate      = [DateTime]::MinValue
                    DisplayDate   = "Unknown"
                }
            }
            elseif ($current) {
                # 2. Parse by Label with Regex Extraction
                if ($key -match "Original Name") {
                    if ($val -notmatch '^oem\d+\.inf$') { $current.OriginalName = $val }
                }
                elseif ($key -match "Provider") {
                    $current.Provider = $val
                }
                elseif ($key -match "Version") {
                    # EXTRACT Version Number (e.g. 2.2.0.134)
                    if ($val -match '(\d+(\.\d+){1,3})') {
                        $vStr = $matches[1]
                        $current.DisplayVer = $vStr
                        try { $current.Version = [Version]$vStr } catch {}
                    } else {
                        $current.DisplayVer = $val 
                    }

                    # Check if line ALSO contains a Date
                    if ($current.DisplayDate -eq "Unknown" -and $val -match '(\d{2}[/\-]\d{2}[/\-]\d{4})') {
                        $dStr = $matches[1]
                        if ($dStr -as [DateTime]) {
                             $current.DisplayDate = $dStr
                             $current.SortDate = [DateTime]$dStr
                        }
                    }
                }
                elseif ($key -match "Date") {
                    if ($val -as [DateTime]) {
                        $current.DisplayDate = $val
                        $current.SortDate = [DateTime]$val
                    } elseif ($val -match '(\d{2}[/\-]\d{2}[/\-]\d{4})') {
                        $dStr = $matches[1]
                        $current.DisplayDate = $dStr
                        if ($dStr -as [DateTime]) { $current.SortDate = [DateTime]$dStr }
                    }
                }

                # 3. Fallback
                elseif ($null -eq $current.OriginalName -and $val -match '\.inf$') {
                    $current.OriginalName = $val
                }
            }   
        }
    }
    if ($current) { $drivers += [PSCustomObject]$current }

    # 2. FILTERING DUPLICATES
    $grouped = $drivers | Where-Object { $_.OriginalName } | Group-Object OriginalName
    $toDelete = @()

    foreach ($group in $grouped) {
        if ($group.Count -gt 1) {
            $sorted = $group.Group | Sort-Object SortDate, Version -Descending
            $toDelete += $sorted | Select-Object -Skip 1
        }
    }

    if (-not $toDelete -or $toDelete.Count -eq 0) {
        [System.Windows.MessageBox]::Show("Driver store is already clean. No duplicates found.", "Clean Old Drivers", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        return
    }

    # 3. GUI SETUP (THEMED)
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Clean Old Drivers"
    $f.Size = "950, 600"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = [System.Drawing.Color]::White

    # Initialize ToolTip provider
    $tip = New-Object System.Windows.Forms.ToolTip
    $tip.AutoPopDelay = 5000
    $tip.InitialDelay = 500
    $tip.ReshowDelay = 500
    $tip.ShowAlways = $true

    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Top"
    $dg.Height = 470
    $dg.BackgroundColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.ForeColor = [System.Drawing.Color]::White
    $dg.AutoSizeColumnsMode = "Fill"
    $dg.SelectionMode = "FullRowSelect"
    $dg.MultiSelect = $true
    $dg.ReadOnly = $true
    $dg.RowHeadersVisible = $false
    $dg.AllowUserToAddRows = $false
    $dg.BorderStyle = "None"
    $dg.CellBorderStyle = "SingleHorizontal"
    
    # Header Styling
    $dg.EnableHeadersVisualStyles = $false
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 6)
    $dg.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
    $dg.ColumnHeadersHeight = 35
    
    # Row Styling
    $dg.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC")
    $dg.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $dg.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#252526")
    $dg.GridColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")
    
    $f.Controls.Add($dg)

    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"
    $pnl.Height = 80
    $pnl.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.Controls.Add($pnl)

    # Helper for Themed Buttons with Tooltips
    function New-DrvBtn($text, $x, $color=$null, $tooltipText=""){
        $b=New-Object System.Windows.Forms.Button
        $b.Text=$text; $b.Left=$x; $b.Top=20; $b.Width=160; $b.Height=35
        $b.FlatStyle="Flat"; $b.FlatAppearance.BorderSize=1
        $b.FlatAppearance.BorderColor=[System.Drawing.ColorTranslator]::FromHtml("#444444")
        $b.ForeColor=[System.Drawing.Color]::White
        if($color){
            $b.BackColor=[System.Drawing.ColorTranslator]::FromHtml($color)
            $b.FlatAppearance.MouseOverBackColor=[System.Windows.Forms.ControlPaint]::Light($b.BackColor)
        } else {
            $b.BackColor=[System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
            $b.FlatAppearance.MouseOverBackColor=[System.Drawing.ColorTranslator]::FromHtml("#3E3E42")
        }
        
        if ($tooltipText) {
            $tip.SetToolTip($b, $tooltipText)
        }

        $pnl.Controls.Add($b); return $b
    }

    $btnBackupClean = New-DrvBtn "Backup && Remove All" 20 "#006600" "Safely backs up all listed drivers to the data folder, then attempts to delete them."
    $btnRemoveSel   = New-DrvBtn "Remove Selected" 200 "#802020" "Removes only the currently highlighted driver(s) from the list."
    $btnClose       = New-DrvBtn "Close" 380 $null "Close this window."

    # 4. DATA BINDING
    $script:CurrentList = $toDelete

    $LoadGrid = {
        $dt = New-Object System.Data.DataTable
        $dt.Columns.Add("PublishedName")
        $dt.Columns.Add("OriginalName")
        $dt.Columns.Add("Provider")
        $dt.Columns.Add("Version")
        $dt.Columns.Add("Date")

        foreach($d in $script:CurrentList){
            $r=$dt.NewRow()
            $r["PublishedName"] = $d.PublishedName
            $r["OriginalName"]  = $d.OriginalName
            $r["Provider"]      = $d.Provider
            $r["Version"]       = $d.DisplayVer
            $r["Date"]          = $d.DisplayDate
            $dt.Rows.Add($r)
        }
        $dg.DataSource = $dt
        $dg.ClearSelection()
    }

    # 5. ACTION LOGIC
    $DoRemove = {
        param($items, $CloseWindow)
        
        if(-not $items -or $items.Count -eq 0){ return }
        $count = $items.Count
        
        $msg = "Processing $count driver(s).`n`n" +
               "1. Selected drivers will be backed up.`n" +
               "2. Attempts safe deletion.`n" +
               "3. Offers FORCE delete on failure."
               
        $confirm = [System.Windows.MessageBox]::Show($msg, "Driver Cleanup", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
        if ($confirm -ne "Yes") { return }

        # A. BACKUP
        $timestamp = Get-Date -f 'yyyyMMdd_HHmm'
        $mainBkPath = Join-Path (Get-DataPath) "Drivers_Backup_$timestamp"
        if (-not (Test-Path $mainBkPath)) { New-Item -Path $mainBkPath -ItemType Directory -Force | Out-Null }
        
        $backupCount = 0
        $prog = 1
        foreach($item in $items) {
            $f.Text = "Backing up ($prog/$count): $($item.OriginalName)..."
            $f.Update()
            
            $folderName = if ($item.OriginalName) { $item.OriginalName } else { $item.PublishedName }
            $drvPath = Join-Path $mainBkPath $folderName
            New-Item -Path $drvPath -ItemType Directory -Force | Out-Null

            $proc = Start-Process pnputil.exe -ArgumentList "/export-driver", $item.PublishedName, """$drvPath""" -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -eq 0) { $backupCount++ }
            $prog++
        }
        $f.Text = "Processing Deletions..."
        $f.Update()

        # B. DELETION
        $deleted = 0
        $failed = 0
        
        foreach($item in $items){
            $name = $item.PublishedName
            
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo.FileName = "pnputil.exe"
            $p.StartInfo.Arguments = "/delete-driver $name /uninstall"
            $p.StartInfo.RedirectStandardOutput = $true
            $p.StartInfo.RedirectStandardError = $true
            $p.StartInfo.UseShellExecute = $false
            $p.StartInfo.CreateNoWindow = $true
            $p.Start() | Out-Null
            $stdOut = $p.StandardOutput.ReadToEnd()
            $stdErr = $p.StandardError.ReadToEnd()
            $p.WaitForExit()
            
            if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 3010) {
                $deleted++
            } else {
                # Force Prompt
                $fullLog = "$stdOut`n$stdErr".Trim()
                $warnMsg = "Driver: $($item.OriginalName) ($name)`n`nError:`n$fullLog`n`nForce Delete?"
                $forceDec = [System.Windows.MessageBox]::Show($warnMsg, "Deletion Failed", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Error)
                
                if ($forceDec -eq "Yes") {
                    $procForce = Start-Process pnputil.exe -ArgumentList "/delete-driver $name /uninstall /force" -NoNewWindow -Wait -PassThru
                    if ($procForce.ExitCode -eq 0 -or $procForce.ExitCode -eq 3010) { $deleted++ } else { $failed++ }
                } else {
                    $failed++
                }
            }
        }

        # C. REPORT & REFRESH
        [System.Windows.MessageBox]::Show("Done.`nDeleted: $deleted`nBackups: $backupCount`nPath: $mainBkPath", "Result", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null

        if ($deleted -gt 0) {
            # Remove deleted items from the current list
            $script:CurrentList = $script:CurrentList | Where-Object { 
                $obj = $_; -not ($items | Where-Object { $_.PublishedName -eq $obj.PublishedName })
            }
            $dg.DataSource = $null
            $LoadGrid.Invoke()
        }
        
        $f.Text = "Clean Old Drivers"
        if ($CloseWindow) { $f.Close() }
    }

    $btnBackupClean.Add_Click({ $DoRemove.Invoke($script:CurrentList, $true) })
    $btnRemoveSel.Add_Click({
        if($dg.SelectedRows.Count -eq 0){ return }
        $selected = @()
        foreach($row in $dg.SelectedRows){
            $pub = $row.Cells["PublishedName"].Value
            $match = $script:CurrentList | Where-Object { $_.PublishedName -eq $pub } | Select-Object -First 1
            if($match){ $selected += $match }
        }
        $DoRemove.Invoke($selected, $false)
    })
    $btnClose.Add_Click({ $f.Close() })

    $LoadGrid.Invoke()
    $f.ShowDialog() | Out-Null
}
function Invoke-RestoreDrivers {
    $dataPath = Get-DataPath
    $backups = @()
    try {
        $backups = Get-ChildItem -Path $dataPath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^DriverBackup_' -or $_.Name -match '^Drivers_Backup_' }
    } catch {}

    $selectedPath = $null
    if ($backups -and $backups.Count -gt 0) {
        $backups = $backups | Sort-Object LastWriteTime -Descending
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "Select Driver Backup"
        $form.Size = "600,400"
        $form.StartPosition = "CenterScreen"
        $form.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
        $form.ForeColor = "White"

        $lst = New-Object System.Windows.Forms.ListBox
        $lst.Dock = "Top"
        $lst.Height = 280
        $lst.BackColor = [System.Drawing.Color]::FromArgb(20,20,20)
        $lst.ForeColor = "White"
        $lst.BorderStyle = "FixedSingle"
        $items = @()
        foreach ($b in $backups) {
            $items += [PSCustomObject]@{
                Name = $b.Name
                Path = $b.FullName
                Display = "{0}  (modified {1})" -f $b.Name, $b.LastWriteTime
            }
        }
        $lst.DisplayMember = "Display"
        $lst.ValueMember = "Path"
        $lst.DataSource = $items
        $form.Controls.Add($lst)

        $pnl = New-Object System.Windows.Forms.Panel
        $pnl.Dock = "Bottom"
        $pnl.Height = 60
        $pnl.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
        $form.Controls.Add($pnl)

        $btnUse = New-Object System.Windows.Forms.Button
        $btnUse.Text = "Use Selected"
        $btnUse.Left = 20; $btnUse.Top = 15; $btnUse.Width = 140
        $btnUse.BackColor = "SeaGreen"; $btnUse.ForeColor = "White"
        $btnUse.FlatStyle = "Flat"
        $btnUse.Add_Click({
            if ($lst.SelectedItem) {
                $form.Tag = $lst.SelectedItem.Path
                $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $form.Close()
            }
        })
        $pnl.Controls.Add($btnUse)

        $btnBrowse = New-Object System.Windows.Forms.Button
        $btnBrowse.Text = "Browse..."
        $btnBrowse.Left = 180; $btnBrowse.Top = 15; $btnBrowse.Width = 120
        $btnBrowse.BackColor = "DimGray"; $btnBrowse.ForeColor = "White"
        $btnBrowse.FlatStyle = "Flat"
        $btnBrowse.Add_Click({
            $form.Tag = "BROWSE"
            $form.DialogResult = [System.Windows.Forms.DialogResult]::Retry
            $form.Close()
        })
        $pnl.Controls.Add($btnBrowse)

        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Text = "Cancel"
        $btnCancel.Left = 320; $btnCancel.Top = 15; $btnCancel.Width = 120
        $btnCancel.BackColor = "Gray"; $btnCancel.ForeColor = "White"
        $btnCancel.FlatStyle = "Flat"
        $btnCancel.Add_Click({
            $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
            $form.Close()
        })
        $pnl.Controls.Add($btnCancel)

        $res = $form.ShowDialog()
        if ($res -eq [System.Windows.Forms.DialogResult]::OK -and $form.Tag) {
            $selectedPath = $form.Tag
        } elseif ($res -eq [System.Windows.Forms.DialogResult]::Retry) {
            # fall through to browse
            $selectedPath = $null
        } else {
            return
        }
    }

    if (-not $selectedPath) {
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = "Select DriverBackup folder"
        if (Test-Path $dataPath) { $dlg.SelectedPath = $dataPath }
        if ($dlg.ShowDialog() -ne "OK") { return }
        $selectedPath = $dlg.SelectedPath
    }

    Invoke-UiCommand {
        param($Path)
        if (-not (Test-Path $Path)) {
            Write-Output "Restore failed: path not found $Path"
            [System.Windows.MessageBox]::Show("Restore failed: path not found.`n$Path","Restore Drivers",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
            return
        }

        $infFiles = Get-ChildItem -Path $Path -Filter *.inf -Recurse -ErrorAction SilentlyContinue
        if (-not $infFiles -or $infFiles.Count -eq 0) {
            Write-Output "Restore aborted: no INF files found in $Path"
            [System.Windows.MessageBox]::Show("No INF files found in:`n$Path","Restore Drivers",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning) | Out-Null
            return
        }

        $output = pnputil.exe /add-driver "$Path\*.inf" /subdirs 2>&1
        $code = $LASTEXITCODE
        Write-Output $output
        if ($code -eq 0 -or $code -eq 3010) {
            Write-Output "Drivers restored from $Path"
            [System.Windows.MessageBox]::Show("Drivers restored from:`n$Path","Restore Drivers",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
        } else {
            Write-Output "Restore failed (exit $code)."
            $msg = "Restore failed (exit $code)." + "`n`nOutput:`n" + ($output | Out-String)
            [System.Windows.MessageBox]::Show($msg,"Restore Drivers",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
        }
    } "Restoring drivers..."
}

# --- UPDATE / REPORT TOOLS ---
function Invoke-WindowsUpdateRepairFull {
    Invoke-UiCommand {
        $services = @('wuauserv','bits','cryptsvc','msiserver','usosvc','trustedinstaller')
        foreach ($svc in $services) { try { Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue } catch {} }
        try { Get-BitsTransfer -AllUsers | Remove-BitsTransfer -Confirm:$false } catch {}
        $suffix = ".bak_{0}" -f (Get-Random -Maximum 99999)
        if (Test-Path "$env:windir\\SoftwareDistribution") { try { Rename-Item "$env:windir\\SoftwareDistribution" ("SoftwareDistribution" + $suffix) -ErrorAction SilentlyContinue; Write-Output "Renamed SoftwareDistribution$suffix" } catch {} }
        if (Test-Path "$env:windir\\System32\\catroot2") { try { Rename-Item "$env:windir\\System32\\catroot2" ("catroot2" + $suffix) -ErrorAction SilentlyContinue; Write-Output "Renamed catroot2$suffix" } catch {} }
        $dlls = @("atl.dll","urlmon.dll","mshtml.dll","shdocvw.dll","browseui.dll","jscript.dll","vbscript.dll","scrrun.dll","msxml.dll","msxml3.dll","msxml6.dll","actxprxy.dll","softpub.dll","wintrust.dll","dssenh.dll","rsaenh.dll","gpkcsp.dll","sccbase.dll","slbcsp.dll","cryptdlg.dll","oleaut32.dll","ole32.dll","shell32.dll","initpki.dll","wuapi.dll","wuaueng.dll","wuaueng1.dll","wucltui.dll","wups.dll","wups2.dll","wuweb.dll","qmgr.dll","qmgrprxy.dll","wucltux.dll","muweb.dll","wuwebv.dll")
        foreach ($dll in $dlls) { try { regsvr32.exe /s $dll } catch {} }
        try { netsh winsock reset | Out-Null } catch {}
        try { netsh winhttp reset proxy | Out-Null } catch {}
        foreach ($svc in $services) { try { Start-Service -Name $svc -ErrorAction SilentlyContinue } catch {} }
        Write-Output "Windows Update repair completed."
    } "Running full Windows Update repair..."
}

function Invoke-SystemReports {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Select output folder for system reports"
    if ($dlg.ShowDialog() -ne "OK") { return }
    $outdir = Join-Path $dlg.SelectedPath ("SystemReports_{0}" -f (Get-Date -Format "yyyy-MM-dd_HHmm"))
    if (-not (Test-Path $outdir)) { New-Item -ItemType Directory -Path $outdir | Out-Null }
    Invoke-UiCommand {
        param($outdir)
        $date = Get-Date -Format "yyyy-MM-dd"
        $sys = Join-Path $outdir "System_Info_$date.txt"
        $net = Join-Path $outdir "Network_Info_$date.txt"
        $drv = Join-Path $outdir "Driver_List_$date.txt"
        systeminfo | Out-File -FilePath $sys -Encoding UTF8
        ipconfig /all | Out-File -FilePath $net -Encoding UTF8
        driverquery | Out-File -FilePath $drv -Encoding UTF8
        Write-Output "Reports saved to $outdir"
    } "Generating system reports..."
}

function Invoke-UpdateServiceReset {
    Invoke-UiCommand {
        try {
            $script:UpdateSvcResult = "OK"
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Stop-Service -Name cryptsvc -Force -ErrorAction SilentlyContinue
            Start-Service -Name appidsvc -ErrorAction SilentlyContinue
            Start-Service -Name wuauserv -ErrorAction SilentlyContinue
            Start-Service -Name cryptsvc -ErrorAction SilentlyContinue
            Start-Service -Name bits -ErrorAction SilentlyContinue
            Write-Output "Restarted Windows Update related services."
        } catch {
            $script:UpdateSvcResult = "ERR: $($_.Exception.Message)"
            throw
        }
    } "Restarting Windows Update services..."
}

function Set-DotNetRollForward {
    param([string]$Mode)
    switch ($Mode) {
        "Runtime" { [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", "LatestMajor", "Machine"); Write-Output "Runtime roll-forward enabled (LatestMajor)." }
        "SDK" {
            $latestSdk = & dotnet --list-sdks | Sort-Object -Descending | Select-Object -First 1
            if ($latestSdk) {
                $version = $latestSdk.Split()[0]
                $globalJsonPath = "$env:USERPROFILE\global.json"
                @{
                    sdk = @{
                        version = $version
                        rollForward = "latestMajor"
                    }
                } | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 $globalJsonPath
                Write-Output "SDK roll-forward set to $version (global.json at $globalJsonPath)."
            } else { Write-Output "No SDK detected." }
        }
        "Both" {
            [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", "LatestMajor", "Machine")
            $latestSdk = & dotnet --list-sdks | Sort-Object -Descending | Select-Object -First 1
            if ($latestSdk) {
                $version = $latestSdk.Split()[0]
                $globalJsonPath = "$env:USERPROFILE\global.json"
                @{
                    sdk = @{
                        version = $version
                        rollForward = "latestMajor"
                    }
                } | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 $globalJsonPath
            }
            Write-Output "Runtime + SDK roll-forward configured."
        }
        "Disable" {
            [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", $null, "Machine")
            $globalJsonPath = "$env:USERPROFILE\global.json"
            if (Test-Path $globalJsonPath) {
                try {
                    $json = Get-Content $globalJsonPath -Raw | ConvertFrom-Json
                    if ($json.sdk.rollForward) { $json.sdk.PSObject.Properties.Remove("rollForward"); $json | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 $globalJsonPath }
                } catch {}
            }
            Write-Output ".NET roll-forward disabled."
        }
    }
}

function Invoke-MASActivation {
    $masInput = [Microsoft.VisualBasic.Interaction]::InputBox("Type YES, I UNDERSTAND to download and run MAS from massgrave.dev", "MAS Activation Confirmation", "")
    if ($masInput -ne "YES, I UNDERSTAND") { return }
    Invoke-UiCommand {
        $scriptContent = Invoke-RestMethod -Uri "https://get.activated.win"
        Invoke-Expression -Command $scriptContent
        Write-Output "MAS script executed."
    } "Running MAS activation..."
}

# --- FIREWALL RULE DIALOG ---
function Show-RuleDialog {
    param($Title, $RuleObj=$null) 
    $f = New-Object System.Windows.Forms.Form
    $f.Text = $Title; $f.Size = "450, 450"; $f.StartPosition = "CenterScreen"; $f.BackColor = [System.Drawing.Color]::FromArgb(40,40,40); $f.ForeColor = "White"
    function New-Input { param($L, $Y, $V="", $Opts=$null)
        $lbl=New-Object System.Windows.Forms.Label; $lbl.Text=$L; $lbl.Top=$Y; $lbl.Left=20; $lbl.AutoSize=$true; $f.Controls.Add($lbl)
        if ($Opts) { $c=New-Object System.Windows.Forms.ComboBox; $c.DropDownStyle="DropDownList"; foreach($opt in $Opts){ [void]$c.Items.Add($opt) }; if($V){$c.SelectedItem=$V}else{$c.SelectedIndex=0} } 
        else { $c=New-Object System.Windows.Forms.TextBox; $c.Text=$V }
        $c.Top=$Y+20; $c.Left=20; $c.Width=380; $c.BackColor=[System.Drawing.Color]::FromArgb(60,60,60); $c.ForeColor="White"; $f.Controls.Add($c); return $c
    }
    $vName=""; $vDir="Inbound"; $vAct="Block"; $vProt="TCP"; $vPort=""
    if ($RuleObj) { $vName=$RuleObj.DisplayName; $vDir=$RuleObj.Direction; $vAct=$RuleObj.Action; $vProt=$RuleObj.Protocol; $vPort=$RuleObj.LocalPort }
    $iName = New-Input "Rule Name" 10 $vName
    if ($RuleObj) { $iName.ReadOnly=$true; $iName.BackColor=[System.Drawing.Color]::FromArgb(30,30,30) }
    $iDir = New-Input "Direction" 60 $vDir @("Inbound", "Outbound")
    $iAct = New-Input "Action" 110 $vAct @("Allow", "Block")
    $iProt = New-Input "Protocol" 160 $vProt @("TCP", "UDP", "Any")
    $iPort = New-Input "Local Port (e.g. 80)" 210 $vPort
    $btn = New-Object System.Windows.Forms.Button; $btn.Text="Save"; $btn.Top=300; $btn.Left=20; $btn.Width=380; $btn.Height=40; $btn.BackColor="SeaGreen"; $btn.ForeColor="White"; $btn.DialogResult="OK"; $f.Controls.Add($btn)
    $tip = New-Object System.Windows.Forms.ToolTip; $tip.SetToolTip($btn, "Confirm and save this firewall rule")
    if ($f.ShowDialog() -eq "OK") { return @{ Name=$iName.Text; Direction=$iDir.SelectedItem; Action=$iAct.SelectedItem; Protocol=$iProt.SelectedItem; Port=$iPort.Text } }
    return $null
}

# --- TASK SCHEDULER MANAGER (styled to match Firewall UI) ---
function Show-TaskManager {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Task Scheduler Manager"
    $f.Size = "900, 600"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = [System.Drawing.Color]::White

    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Top"
    $dg.Height = 450
    $dg.BackgroundColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.ForeColor = [System.Drawing.Color]::White
    $dg.AutoSizeColumnsMode = "Fill"
    $dg.SelectionMode = "FullRowSelect"
    $dg.MultiSelect = $false
    $dg.ReadOnly = $true
    $dg.RowHeadersVisible = $false
    $dg.AllowUserToAddRows = $false
    $dg.BorderStyle = "None"
    $dg.EnableHeadersVisualStyles = $false
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 4)
    $dg.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
    $dg.ColumnHeadersHeight = 30
    $dg.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC")
    $dg.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $dg.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#252526")
    $dg.GridColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")
    $f.Controls.Add($dg)

    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"
    $pnl.Height = 80
    $pnl.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.Controls.Add($pnl)

    function New-StyledBtn ($Text, $X, $Color=$null) {
        $b = New-Object System.Windows.Forms.Button
        $b.Text = $Text
        $b.Top = 20; $b.Left = $X; $b.Width = 100; $b.Height = 35
        $b.FlatStyle = "Flat"
        $b.FlatAppearance.BorderSize = 1
        $b.FlatAppearance.BorderColor = [System.Drawing.ColorTranslator]::FromHtml("#444444")
        $b.ForeColor = [System.Drawing.Color]::White
        if ($Color) {
            $b.BackColor = [System.Drawing.ColorTranslator]::FromHtml($Color)
            $b.FlatAppearance.MouseOverBackColor = [System.Windows.Forms.ControlPaint]::Light($b.BackColor)
        } else {
            $b.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
            $b.FlatAppearance.MouseOverBackColor = [System.Drawing.ColorTranslator]::FromHtml("#3E3E42")
        }
        $pnl.Controls.Add($b)
        return $b
    }

    $btnRef = New-StyledBtn "Refresh" 20
    $btnEn  = New-StyledBtn "Enable" 130 "#006600"
    $btnDis = New-StyledBtn "Disable" 240 "#CCAA00"
    $btnDel = New-StyledBtn "Delete" 350 "#802020"

    $dg.Add_RowPrePaint({
        param($src, $e)
        $row = $src.Rows[$e.RowIndex]
        if ($row.Cells["State"].Value) {
            $state = $row.Cells["State"].Value.ToString()
            if ($state -eq "Running") {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#00FF00")
            } elseif ($state -eq "Ready") {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFFF00")
            } elseif ($state -eq "Disabled") {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FF3333")
            } else {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightGray
            }
        }
    })

    $LoadTasks = {
        $tasks = Get-ScheduledTask | Select-Object TaskName, State, Author, TaskPath
        $dt = New-Object System.Data.DataTable
        $dt.Columns.Add("TaskName"); $dt.Columns.Add("State"); $dt.Columns.Add("Author"); $dt.Columns.Add("Path")
        foreach ($t in $tasks) {
            $r=$dt.NewRow()
            $r["TaskName"]=$t.TaskName; $r["State"]=$t.State; $r["Author"]=$t.Author; $r["Path"]=$t.TaskPath
            $dt.Rows.Add($r)
        }
        $dg.DataSource = $dt
        $dg.ClearSelection()
    }

    $btnRef.Add_Click({ & $LoadTasks })
    $btnEn.Add_Click({ if($dg.SelectedRows.Count -gt 0){ $n=$dg.SelectedRows[0].Cells["TaskName"].Value; Enable-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; & $LoadTasks } })
    $btnDis.Add_Click({ if($dg.SelectedRows.Count -gt 0){ $n=$dg.SelectedRows[0].Cells["TaskName"].Value; Disable-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue; & $LoadTasks } })
    $btnDel.Add_Click({ if($dg.SelectedRows.Count -gt 0){ $n=$dg.SelectedRows[0].Cells["TaskName"].Value; if([System.Windows.Forms.MessageBox]::Show("Delete $n?","Confirm",[System.Windows.Forms.MessageBoxButtons]::YesNo) -eq "Yes"){ Unregister-ScheduledTask -TaskName $n -Confirm:$false; & $LoadTasks } } })
    & $LoadTasks; $f.ShowDialog()
}

# ==========================================
# 3. XAML GUI
# ==========================================
[xml]$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows Maintenance Tool v$AppVersion" Height="850" Width="1200"
        WindowStartupLocation="CenterScreen" Background="#121212" Foreground="#E0E0E0">

    <Window.Resources>
        <Style TargetType="Button" x:Key="BaseBtn">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Foreground" Value="#CCCCCC"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                         <Border Name="Bd" Background="{TemplateBinding Background}" CornerRadius="4" Padding="10">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                         </Border>
                         <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#333333"/>
                                <Setter Property="Foreground" Value="White"/>
                            </Trigger>
                         </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="Button" x:Key="ActionBtn">
            <Setter Property="Background" Value="#2D2D30"/>
            <Setter Property="Foreground" Value="White"/>
            <Setter Property="Height" Value="35"/>
            <Setter Property="Margin" Value="4"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Name="Bd" Background="{TemplateBinding Background}" CornerRadius="3" BorderBrush="#444" BorderThickness="1">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="#007ACC"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="Bd" Property="Background" Value="#222"/>
                                <Setter Property="Foreground" Value="#555"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        
        <Style x:Key="FwItem" TargetType="ListViewItem">
            <Setter Property="BorderThickness" Value="0"/>
            <Style.Triggers>
                <Trigger Property="ItemsControl.AlternationIndex" Value="0"><Setter Property="Background" Value="#1E1E1E"/></Trigger>
                <Trigger Property="ItemsControl.AlternationIndex" Value="1"><Setter Property="Background" Value="#252526"/></Trigger>
                <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#007ACC"/><Setter Property="Foreground" Value="White"/></Trigger>
                <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#3E3E42"/></Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="240"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <Border Grid.Column="0" Background="#1E1E1E" BorderBrush="#333" BorderThickness="0,0,1,0">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/> 
                    <RowDefinition Height="Auto"/> 
                    <RowDefinition Height="*"/>    
                    <RowDefinition Height="Auto"/> 
                </Grid.RowDefinitions>

                <StackPanel Grid.Row="0" Margin="10,20,10,10">
                    <TextBlock Text="GLOBAL SEARCH" FontSize="10" Foreground="#666" FontWeight="Bold" Margin="2,0,0,5"/>
                    <TextBox Name="txtGlobalSearch" Height="30" Padding="5" Background="#1E1E1E" Foreground="White" BorderBrush="#444" ToolTip="Type to search for any function within the app"/>
                </StackPanel>

                <StackPanel Name="pnlNavButtons" Grid.Row="1" Margin="0,10,0,0">
                    <Button Name="btnTabUpdates" Content="Updates (Winget)" Style="{StaticResource BaseBtn}" Tag="pnlUpdates"/>
                    <Button Name="btnTabHealth" Content="System Health" Style="{StaticResource BaseBtn}" Tag="pnlHealth"/>
                    <Button Name="btnTabNetwork" Content="Network &amp; DNS" Style="{StaticResource BaseBtn}" Tag="pnlNetwork"/>
                    <Button Name="btnTabFirewall" Content="Firewall Manager" Style="{StaticResource BaseBtn}" Tag="pnlFirewall"/>
                    <Button Name="btnTabDrivers" Content="Drivers" Style="{StaticResource BaseBtn}" Tag="pnlDrivers"/>
                    <Button Name="btnTabCleanup" Content="Cleanup" Style="{StaticResource BaseBtn}" Tag="pnlCleanup"/>
                    <Button Name="btnTabUtils" Content="Utilities" Style="{StaticResource BaseBtn}" Tag="pnlUtils"/>
                    <Button Name="btnTabSupport" Content="Support &amp; Credits" Style="{StaticResource BaseBtn}" Tag="pnlSupport"/>
                    <Button Name="btnNavDownloads" Content="Release Downloads" Style="{StaticResource BaseBtn}" ToolTip="Show latest release download counts"/>
                </StackPanel>
                
                <ListBox Name="lstSearchResults" Grid.Row="2" Background="#111" BorderThickness="0" Foreground="Cyan" Visibility="Collapsed" Margin="5"/>

                <StackPanel Grid.Row="3" Margin="10">
                     <TextBlock Text="LOG OUTPUT" FontSize="10" Foreground="#666" FontWeight="Bold"/>
                    <TextBox Name="LogBox" Height="290" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11" Background="#111" Foreground="#0F0" BorderThickness="0"/>
                </StackPanel>
            </Grid>
        </Border>

        <Border Grid.Column="1" Background="#121212">
            <Grid Margin="20">
                
                <Grid Name="pnlUpdates" Visibility="Visible">
                    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                    
                    <Grid Grid.Row="0" Margin="0,0,0,15">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="300"/></Grid.ColumnDefinitions>
                        <StackPanel>
                             <TextBlock Name="lblWingetTitle" Text="Available Updates" FontSize="24" Foreground="White" FontWeight="Light"/>
                             <TextBlock Name="lblWingetStatus" Text="Scanning..." Foreground="Yellow" Visibility="Hidden"/>
                        </StackPanel>
                        <Grid Grid.Column="1">
                             <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                             <TextBox Name="txtWingetSearch" Grid.Column="0" Height="30" VerticalContentAlignment="Center" Text="Search new packages..." Padding="5" Background="#1E1E1E" Foreground="White"/>
                             <Button Name="btnWingetFind" Grid.Column="1" Content="Find" Width="50" Height="30" Background="#007ACC" Foreground="White" ToolTip="Search the Winget repository for new apps"/>
                        </Grid>
                    </Grid>

                    <ListView Name="lstWinget" Grid.Row="1" Background="#1E1E1E" Foreground="#DDD" BorderThickness="1" BorderBrush="#333" SelectionMode="Extended" AlternationCount="2" ItemContainerStyle="{StaticResource FwItem}">
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="Name" Width="300" DisplayMemberBinding="{Binding Name}"/>
                                <GridViewColumn Header="Id" Width="200" DisplayMemberBinding="{Binding Id}"/>
                                <GridViewColumn Header="Version" Width="120" DisplayMemberBinding="{Binding Version}"/>
                                <GridViewColumn Header="Available" Width="120" DisplayMemberBinding="{Binding Available}"/>
                            </GridView>
                        </ListView.View>
                    </ListView>

                    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
                        <Button Name="btnWingetScan" Content="Refresh Updates" Width="150" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnWingetUpdateSel" Content="Update Selected" Width="150" Style="{StaticResource ActionBtn}" Background="#006600"/>
                        <Button Name="btnWingetInstall" Content="Install Selected" Width="150" Style="{StaticResource ActionBtn}" Background="#006600" Visibility="Collapsed"/>
                        <Button Name="btnWingetUninstall" Content="Uninstall Selected" Width="150" Style="{StaticResource ActionBtn}" Background="#802020"/>
                    </StackPanel>
                </Grid>

                <StackPanel Name="pnlHealth" Visibility="Collapsed">
                    <TextBlock Text="System Health" FontSize="24" Margin="0,0,0,20"/>
                    <WrapPanel>
                        <Button Name="btnSFC" Content="SFC Scan" Width="220" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDISMCheck" Content="DISM Check" Width="220" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDISMRestore" Content="DISM Restore" Width="220" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnCHKDSK" Content="CHKDSK" Width="220" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>
                </StackPanel>

                <StackPanel Name="pnlNetwork" Visibility="Collapsed">
                    <TextBlock Text="Network &amp; DNS" FontSize="24" Margin="0,0,0,20"/>
                    
                    <TextBlock Text="General Tools" Foreground="#888" Margin="5"/>
                    <WrapPanel Margin="0,0,0,15">
                        <Button Name="btnNetInfo" Content="Show IP Config" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFlushDNS" Content="Flush DNS" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnResetWifi" Content="Restart Wi-Fi" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnNetRepair" Content="Full Network Repair" Width="180" Style="{StaticResource ActionBtn}" Background="#8B8000"/>
                        <Button Name="btnRouteTable" Content="Save Routing Table" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnRouteView" Content="View Routing Table" Width="180" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>
                    
                    <TextBlock Text="DNS Presets" Foreground="#888" Margin="5"/>
                    <WrapPanel Margin="0,0,0,15">
                        <Button Name="btnDnsGoogle" Content="Google (8.8.8.8)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsCloudflare" Content="Cloudflare (1.1.1.1)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsQuad9" Content="Quad9 (9.9.9.9)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsAuto" Content="Auto (DHCP)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsCustom" Content="Custom DNS..." Width="180" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>

                    <TextBlock Text="DNS Encryption (DoH)" Foreground="#888" Margin="5"/>
                    <WrapPanel Margin="0,0,0,15">
                        <Button Name="btnDohAuto" Content="Enable DoH (All)" Width="250" Style="{StaticResource ActionBtn}" Background="#006666"/>
                        <Button Name="btnDohDisable" Content="Disable DoH" Width="180" Style="{StaticResource ActionBtn}" Background="#660000"/>
                    </WrapPanel>

                    <TextBlock Text="Hosts File" Foreground="#888" Margin="5"/>
                    <WrapPanel>
                        <Button Name="btnHostsUpdate" Content="Download AdBlock" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnHostsEdit" Content="Edit Hosts" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnHostsBackup" Content="Backup Hosts" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnHostsRestore" Content="Restore Hosts" Width="180" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>
                </StackPanel>

                <Grid Name="pnlFirewall" Visibility="Collapsed">
                    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                    <Grid Grid.Row="0" Margin="0,0,0,10">
                        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="200"/></Grid.ColumnDefinitions>
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="Firewall Manager" FontSize="24" Margin="0,0,20,0"/>
                            <TextBlock Name="lblFwStatus" Text="Loading..." Foreground="Yellow" Visibility="Collapsed"/>
                        </StackPanel>
                        <TextBox Name="txtFwSearch" Grid.Column="1" Text="Search Rules..." Padding="5" Background="#1E1E1E" Foreground="White" BorderBrush="#444" ToolTip="Type rule name or port to search"/>
                    </Grid>
                    
                    <ListView Name="lstFirewall" Grid.Row="1" Background="#1E1E1E" Foreground="#DDD" BorderThickness="1" BorderBrush="#333" AlternationCount="2" ItemContainerStyle="{StaticResource FwItem}">
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="Name" Width="350" DisplayMemberBinding="{Binding Name}"/>
                                <GridViewColumn Header="Dir" Width="60" DisplayMemberBinding="{Binding Direction}"/>
                                <GridViewColumn Header="Action" Width="60">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding Action}" FontWeight="Bold">
                                                <TextBlock.Style>
                                                    <Style TargetType="TextBlock">
                                                        <Setter Property="Foreground" Value="White"/>
                                                        <Style.Triggers>
                                                            <DataTrigger Binding="{Binding Action}" Value="Allow"><Setter Property="Foreground" Value="#00FF00"/></DataTrigger>
                                                            <DataTrigger Binding="{Binding Action}" Value="Block"><Setter Property="Foreground" Value="#FF3333"/></DataTrigger>
                                                        </Style.Triggers>
                                                    </Style>
                                                </TextBlock.Style>
                                            </TextBlock>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                                <GridViewColumn Header="Enabled" Width="60">
                                    <GridViewColumn.CellTemplate>
                                        <DataTemplate>
                                            <TextBlock Text="{Binding Enabled}" FontWeight="Bold">
                                                <TextBlock.Style>
                                                    <Style TargetType="TextBlock">
                                                        <Setter Property="Foreground" Value="White"/>
                                                        <Style.Triggers>
                                                            <DataTrigger Binding="{Binding Enabled}" Value="True"><Setter Property="Foreground" Value="#00FF00"/></DataTrigger>
                                                            <DataTrigger Binding="{Binding Enabled}" Value="False"><Setter Property="Foreground" Value="#FF3333"/></DataTrigger>
                                                        </Style.Triggers>
                                                    </Style>
                                                </TextBlock.Style>
                                            </TextBlock>
                                        </DataTemplate>
                                    </GridViewColumn.CellTemplate>
                                </GridViewColumn>
                                <GridViewColumn Header="Proto" Width="60" DisplayMemberBinding="{Binding Protocol}"/>
                                <GridViewColumn Header="Port" Width="80" DisplayMemberBinding="{Binding LocalPort}"/>
                            </GridView>
                        </ListView.View>
                    </ListView>

                    <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,10,0,0">
                        <Button Name="btnFwRefresh" Content="Reload" Width="100" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwAdd" Content="Add Rule" Width="100" Style="{StaticResource ActionBtn}" Background="#006600"/>
                        <Button Name="btnFwEdit" Content="Modify" Width="100" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwEnable" Content="Enable" Width="80" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwDisable" Content="Disable" Width="80" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwDelete" Content="Delete" Width="80" Style="{StaticResource ActionBtn}" Background="#802020"/>
                        <Button Name="btnFwExport" Content="Export" Width="90" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwImport" Content="Import" Width="90" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwDefaults" Content="Restore Defaults" Width="140" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnFwPurge" Content="Delete All" Width="100" Style="{StaticResource ActionBtn}" Background="#7A1F1F"/>
                    </StackPanel>
                </Grid>

                <StackPanel Name="pnlDrivers" Visibility="Collapsed">
                    <TextBlock Text="Drivers" FontSize="24" Margin="0,0,0,20"/>
                    <WrapPanel>
                        <Button Name="btnDrvReport" Content="Generate Driver Report" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvBackup" Content="Export Drivers" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvGhost" Content="Remove Ghost Devices" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvClean" Content="Clean Old Drivers" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvRestore" Content="Restore Drivers" Width="200" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>
                    <WrapPanel Margin="0,10,0,0">
                        <Button Name="btnDrvDisableWU" Content="Disable Driver Updates" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvEnableWU" Content="Enable Driver Updates" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvDisableMeta" Content="Disable Device Metadata" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvEnableMeta" Content="Enable Device Metadata" Width="200" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>
                </StackPanel>

                <StackPanel Name="pnlCleanup" Visibility="Collapsed">
                    <TextBlock Text="System Cleanup" FontSize="24" Margin="0,0,0,20"/>
                    <WrapPanel>
                        <Button Name="btnCleanDisk" Content="Disk Cleanup" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnCleanTemp" Content="Delete Temp Files" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnCleanShortcuts" Content="Fix Shortcuts" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnCleanReg" Content="Clean Registry Keys" Width="200" Style="{StaticResource ActionBtn}" Background="#B8860B"/>
                        <Button Name="btnCleanXbox" Content="Clean Xbox Data" Width="200" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>
                </StackPanel>

                <StackPanel Name="pnlUtils" Visibility="Collapsed">
                    <TextBlock Text="Utilities" FontSize="24" Margin="0,0,0,20"/>
                    
                    <TextBlock Text="System &amp; Activation" Foreground="#888" Margin="5"/>
                    <WrapPanel Margin="0,0,0,15">
                        <Button Name="btnUtilSysInfo" Content="System Info Report" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnUtilTrim" Content="Trim SSD" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnUtilMas" Content="MAS Activation" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnTaskManager" Content="Task Scheduler Manager" Width="200" Style="{StaticResource ActionBtn}" Background="#004444"/>
                    </WrapPanel>

                    <TextBlock Text="Repairs &amp; Settings" Foreground="#888" Margin="5"/>
                    <WrapPanel>
                        <Button Name="btnUpdateRepair" Content="Reset Windows Update" Width="200" Style="{StaticResource ActionBtn}" Background="#8B8000"/>
                        <Button Name="btnUpdateServices" Content="Restart Update Services" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDotNetEnable" Content="Set .NET RollForward" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDotNetDisable" Content="Unset .NET RollForward" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnInstallGpedit" Content="Install Gpedit (Home)" Width="200" Style="{StaticResource ActionBtn}" Background="#004444"/>
                    </WrapPanel>
                </StackPanel>

                <StackPanel Name="pnlSupport" Visibility="Collapsed">
                    <TextBlock Text="Support &amp; Credits" FontSize="24" Margin="0,0,0,20"/>
                    <TextBlock Text="Windows Maintenance Tool v$AppVersion" FontSize="16" FontWeight="Bold"/>
                    
                    <TextBlock Text="Credits:" FontWeight="Bold" Margin="0,10,0,5"/>
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                        <TextBlock Text="- Author: " Foreground="#AAA" VerticalAlignment="Center"/>
                        <Button Name="btnCreditLilBattiCLI" Content="Lil_Batti" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                        <TextBlock Text=" | Contributor: " Foreground="#AAA" VerticalAlignment="Center"/>
                        <Button Name="btnCreditChaythonCLI" Content="Chaython" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                        <TextBlock Text="- GUI Design &amp; Implementation: " Foreground="#AAA" VerticalAlignment="Center"/>
                        <Button Name="btnCreditChaythonGUI" Content="Chaython" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                        <TextBlock Text="- Feature Integration &amp; Updates: " Foreground="#AAA" VerticalAlignment="Center"/>
                         <Button Name="btnCreditIos12checker" Content="Lil_Batti" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                        <TextBlock Text=" &amp; " Foreground="#AAA" VerticalAlignment="Center"/>
                       <Button Name="btnCreditChaythonFeatures" Content="Chaython" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                    </StackPanel>

                    <TextBlock Text="License: MIT License" Foreground="#666" Margin="0,10,0,0" FontSize="10"/>
                    <TextBlock Text="Copyright (c) 2025" Foreground="#666" FontSize="10"/>
                    
                    <StackPanel Orientation="Horizontal" Margin="0,20,0,0">
                         <Button Name="btnSupportDiscord" Content="Join Discord" Width="180" Style="{StaticResource ActionBtn}" Background="#5865F2"/>
                         <Button Name="btnSupportIssue" Content="Report Issue" Width="180" Style="{StaticResource ActionBtn}"/>
                         <Button Name="btnDonateIos12" Content="Sponsor Lil_Batti" Width="160" Style="{StaticResource ActionBtn}" Background="#2EA043"/>
                         <Button Name="btnDonate" Content="Sponsor Chaython" Width="160" Style="{StaticResource ActionBtn}" Background="#2EA043"/>
                    </StackPanel>
                </StackPanel>

            </Grid>
        </Border>
    </Grid>
</Window>
"@

# ==========================================
# 4. INIT & HELPERS
# ==========================================
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

function Get-Ctrl { param($Name) return $window.FindName($Name) }

# --- ICON INJECTION SYSTEM (SILENT + TOOLTIPS) ---
function Set-ButtonIcon {
    param($BtnName, $PathData, $Text, $Tooltip="", $Scale=16, $Color="White")
    $btn = Get-Ctrl $BtnName
    if (-not $btn) { return }
    
    # Visuals
    $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation="Horizontal"
    $path = New-Object System.Windows.Shapes.Path
    $path.Data = [System.Windows.Media.Geometry]::Parse($PathData)
    $path.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString($Color)
    $path.Stretch = "Uniform"; $path.Height=$Scale; $path.Width=$Scale; $path.Margin="0,0,10,0"
    $txt = New-Object System.Windows.Controls.TextBlock; $txt.Text=$Text; $txt.VerticalAlignment="Center"
    [void]$sp.Children.Add($path); [void]$sp.Children.Add($txt)
    $btn.Content = $sp
    
    # Tooltip
    if ($Tooltip) { $btn.ToolTip = $Tooltip }
}

# --- ICONS & TOOLTIPS ---
Set-ButtonIcon "btnTabUpdates" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "Updates (Winget)" "Manage Windows software updates via Winget" 18 "#00FF00"
# Set-ButtonIcon "btnTabHealth" - CUSTOM LOGIC BELOW
Set-ButtonIcon "btnTabNetwork" "M5,3A2,2 0 0,0 3,5V15A2,2 0 0,0 5,17H8V15H5V5H19V15H16V17H19A2,2 0 0,0 21,15V5A2,2 0 0,0 19,3H5M11,15H13V17H11V15M11,11H13V13H11V11M11,7H13V9H11V7Z" "Network & DNS" "DNS, IP Config, Network Repair tools" 18
Set-ButtonIcon "btnTabFirewall" "M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M12,11.95L7,12.2V11.2L12,10.95L17,11.2V12.2L12,11.95Z" "Firewall Manager" "View and manage Windows Firewall rules" 18 "#FF5555"
Set-ButtonIcon "btnTabDrivers" "M7,17L10.5,12.5L5,9.6V17H7M12,21L14.6,16.3L9.5,13.6L12,21M17,17V9.6L11.5,12.5L15,17H17M20.2,4.8L12,1L3.8,4.8C2.7,5.4 2,6.5 2,7.7V17C2,19.8 4.2,22 7,22H17C19.8,22 22,19.8 22,17V7.7C22,6.5 21.3,5.4 20.2,4.8Z" "Drivers" "Backup, Restore, and Clean drivers" 18
Set-ButtonIcon "btnTabCleanup" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Cleanup" "Disk cleanup, Temp files, Shortcuts, Registry" 18
Set-ButtonIcon "btnTabUtils" "M22.7,19L13.6,9.9C14.5,7.6 14,4.9 12.1,3C10.1,1 7.1,0.6 4.7,1.7L9,6L6,9L1.6,4.7C0.4,7.1 0.9,10.1 2.9,12.1C4.8,14 7.5,14.5 9.8,13.6L18.9,22.7C19.3,23.1 19.9,23.1 20.3,22.7L22.7,20.3C23.1,19.9 23.1,19.3 22.7,19Z" "Utilities" "System Info, SSD Trim, Activation, Task Scheduler" 18
Set-ButtonIcon "btnTabSupport" "M10,19H13V22H10V19M12,2C17.35,2.22 19.68,7.62 16.5,11.67C15.67,12.67 14.33,13.33 13.67,14.17C13,15 13,16 13,17H10C10,15.33 10,13.92 10.67,12.92C11.33,11.92 12.67,11.33 13.5,10.67C15.92,8.43 15.32,5.26 12,5A3,3 0 0,0 9,8H6A6,6 0 0,1 12,2Z" "Support & Credits" "Links to Discord and GitHub" 18

# --- CUSTOM HEALTH ICON (Red Squircle with White Cross) ---
$btnHealth = Get-Ctrl "btnTabHealth"
if ($btnHealth) {
    $grid = New-Object System.Windows.Controls.Grid
    $grid.Width = 18; $grid.Height = 18; $grid.Margin = "0,0,10,0"
    
    # Red Squircle
    $rect = New-Object System.Windows.Shapes.Rectangle
    $rect.RadiusX=4; $rect.RadiusY=4
    $rect.Fill = [System.Windows.Media.BrushConverter]::new().ConvertFromString("#FF3333")
    [void]$grid.Children.Add($rect)
    
    # White Cross (Plus shape)
    $path = New-Object System.Windows.Shapes.Path
    $path.Data = [System.Windows.Media.Geometry]::Parse("M8,4H10V8H14V10H10V14H8V10H4V8H8V4Z")
    $path.Fill = [System.Windows.Media.Brushes]::White
    $path.Stretch = "Uniform"; $path.Margin = "3"
    [void]$grid.Children.Add($path)
    
    $sp = New-Object System.Windows.Controls.StackPanel; $sp.Orientation="Horizontal"
    [void]$sp.Children.Add($grid)
    $txt = New-Object System.Windows.Controls.TextBlock; $txt.Text="System Health"; $txt.VerticalAlignment="Center"
    [void]$sp.Children.Add($txt)
    
    $btnHealth.Content = $sp
    $btnHealth.ToolTip = "System integrity checks (SFC, DISM, CHKDSK)"
}

Set-ButtonIcon "btnNetRepair" "M20,12H19.5C19.5,14.5 17.5,16.5 15,16.5H9V18.5H15C18.6,18.5 21.5,15.6 21.5,12H21C21,15 19,17.5 16,18V16L13,19L16,22V20C19.9,19.4 23,16 23,12M3,12H3.5C3.5,9.5 5.5,7.5 8,7.5H14V5.5H8C4.4,5.5 1.5,8.4 1.5,12H2C2,9 4,6.5 7,6V8L10,5L7,2V4C3.1,4.6 0,8 0,12H3Z" "Full Net Repair" "Full network stack reset (Winsock, IP, Flush DNS)"
Set-ButtonIcon "btnRouteTable" "M19,15L13,21L11.58,19.58L15.17,16H4V4H6V14H15.17L11.58,10.42L13,9L19,15Z" "Save Route Table" "Exports the current IP routing table to the data folder"
Set-ButtonIcon "btnRouteView" "M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M12,17C14.76,17 17,14.76 17,12C17,9.24 14.76,7 12,7C9.24,7 7,9.24 7,12C7,14.76 9.24,17 12,17M12,9A3,3 0 0,1 15,12A3,3 0 0,1 12,15A3,3 0 0,1 9,12A3,3 0 0,1 12,9Z" "View Route Table" "Displays the routing table in the log"
Set-ButtonIcon "btnCleanReg" "M5,3H19A2,2 0 0,1 21,5V19A2,2 0 0,1 19,21H5A2,2 0 0,1 3,19V5A2,2 0 0,1 5,3M7,7V9H9V7H7M11,7V9H13V7H11M15,7V9H17V7H15M7,11V13H9V11H7M11,11V13H13V11H11M15,11V13H17V11H15M7,15V17H9V15H7M11,15V17H13V15H11M15,15V17H17V15H15Z" "Clean Reg Keys" "Backs up & deletes obsolete Uninstall registry keys"
Set-ButtonIcon "btnCleanXbox" "M6.4,4.8L12,10.4L17.6,4.8L19.2,6.4L13.6,12L19.2,17.6L17.6,19.2L12,13.6L6.4,19.2L4.8,17.6L10.4,12L4.8,6.4L6.4,4.8Z" "Clean Xbox Data" "Removes Xbox Live credentials to fix login loops" 18 "#107C10"
Set-ButtonIcon "btnUpdateRepair" "M21,10.12H14.22L16.96,7.3C14.55,4.61 10.54,4.42 7.85,6.87C5.16,9.32 5.35,13.33 7.8,16.03C10.25,18.72 14.26,18.91 16.95,16.46C17.65,15.82 18.2,15.05 18.56,14.21L20.62,15.05C19.79,16.89 18.3,18.42 16.39,19.34C13.4,20.78 9.77,20.21 7.37,17.96C4.96,15.71 4.54,12.06 6.37,9.32C8.2,6.59 11.83,5.65 14.65,7.09L17.38,4.35H10.63V2.35H21V10.12Z" "Reset Update Svc" "Stops services, clears cache, and resets Windows Update components"
Set-ButtonIcon "btnUpdateServices" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12H20A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4C14.23,4 16.24,4.82 17.76,6.24L14,10H22V2L19.36,4.64C17.5,2.89 14.89,2 12,2Z" "Restart Update Svcs" "Restarts update-related services"
Set-ButtonIcon "btnDotNetEnable" "M14.6,16.6L19.2,12L14.6,7.4L16,6L22,12L16,18L14.6,16.6M9.4,16.6L4.8,12L9.4,7.4L8,6L2,12L8,18L9.4,16.6Z" "Set .NET RollFwd" "Sets DOTNET_ROLL_FORWARD=LatestMajor (Force apps to use newest .NET)"
Set-ButtonIcon "btnDotNetDisable" "M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z" "Reset .NET RollFwd" "Removes the DOTNET_ROLL_FORWARD environment variable"
Set-ButtonIcon "btnTaskManager" "M14,10H2V12H14V10M14,6H2V8H14V6M2,16H10V14H2V16M21.5,11.5L23,13L16,20L11.5,15.5L13,14L16,17L21.5,11.5Z" "Task Scheduler" "View, Enable, Disable, or Delete Windows Scheduled Tasks"
Set-ButtonIcon "btnInstallGpedit" "M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6M6,4H13V9H18V20H6V4M8,12V14H16V12H8M8,16V18H13V16H8Z" "Install Gpedit" "Installs the Group Policy Editor on Windows Home editions"

Set-ButtonIcon "btnSFC" "M15.5,14L20.5,19L19,20.5L14,15.5V14.71L13.73,14.43C12.59,15.41 11.11,16 9.5,16A6.5,6.5 0 0,1 3,9.5A6.5,6.5 0 0,1 9.5,3A6.5,6.5 0 0,1 16,9.5C16,11.11 15.41,12.59 14.43,13.73L14.71,14H15.5M9.5,14C12,14 14,12 14,9.5C14,7 12,5 9.5,5C7,5 5,7 5,9.5C5,12 7,14 9.5,14Z" "SFC Scan" "Scans system files for corruption and repairs them"
Set-ButtonIcon "btnDISMCheck" "M22,10V9C22,5.1 18.9,2 15,2C11.1,2 8,5.1 8,9V10H22M19.5,12.5C19.5,11.1 20.6,10 22,10H8V15H19.5V12.5Z" "DISM Check" "Checks the health of the Windows Image (dism /checkhealth)"
Set-ButtonIcon "btnDISMRestore" "M19.5,12.5C19.5,11.1 20.6,10 22,10V9C22,5.1 18.9,2 15,2C11.1,2 8,5.1 8,9V10C9.4,10 10.5,11.1 10.5,12.5C10.5,13.9 9.4,15 8,15V19H12V22H8C6.3,22 5,20.7 5,19V15C3.6,15 2.5,13.9 2.5,12.5C2.5,11.1 3.6,10 5,10V9C5,3.5 9.5,-1 15,-1C20.5,-1 25,3.5 25,9V10C26.4,10 27.5,11.1 27.5,12.5C27.5,13.9 26.4,15 25,15V19C25,20.7 23.7,22 22,22H17V19H22V15C20.6,15 19.5,13.9 19.5,12.5Z" "DISM Restore" "Attempts to repair the Windows Image (dism /restorehealth)"
Set-ButtonIcon "btnCHKDSK" "M6,2H18C19.1,2 20,2.9 20,4V20C20,21.1 19.1,22 18,22H6C4.9,22 4,21.1 4,20V4C4,2.9 4.9,2 6,2M6,4V20H18V4H6M11,17C11,17.55 11.45,18 12,18C12.55,18 13,17.55 13,17C13,16.45 12.55,16 12,16C11.45,16 11,16.45 11,17M7,17C7,17.55 7.45,18 8,18C8.55,18 9,17.55 9,17C9,16.45 8.55,16 8,16C7.45,16 7,16.45 7,17M15,17C15,17.55 15.45,18 16,18C16.55,18 17,17.55 17,17C17,16.45 16.55,16 16,16C15.45,16 15,16.45 15,17Z" "Check Disk" "Scans all drives for filesystem errors (requires reboot)"
Set-ButtonIcon "btnFlushDNS" "M2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2A10,10 0 0,0 2,12M4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12M10,17L15,12L10,7V17Z" "Flush DNS" "Clears the client DNS resolver cache"
Set-ButtonIcon "btnNetInfo" "M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" "Show IP Config" "Displays full IP configuration for all adapters"
Set-ButtonIcon "btnResetWifi" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z" "Restart Wi-Fi" "Disables and Re-Enables Wi-Fi adapters"
Set-ButtonIcon "btnCleanDisk" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Disk Cleanup" "Opens the built-in Windows Disk Cleanup utility"
Set-ButtonIcon "btnCleanTemp" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Delete Temp Files" "Deletes temporary files from User and System Temp folders"
Set-ButtonIcon "btnCleanShortcuts" "M19,3H5C3.89,3 3,3.89 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V5C21,3.89 20.1,3 19,3M19,19H5V5H19V19M10,17L5,12L6.41,10.59L10,14.17L17.59,6.58L19,8L10,17Z" "Fix Shortcuts" "Scans for and fixes broken .lnk shortcuts"
(Get-Ctrl "btnWingetFind").Width = 80
Set-ButtonIcon "btnWingetFind" "M9.5,3A6.5,6.5 0 0,1 16,9.5C16,11.11 15.41,12.59 14.44,13.73L14.71,14H15.5L20.5,19L19,20.5L14,15.5V14.71L13.73,14.44C12.59,15.41 11.11,16 9.5,16A6.5,6.5 0 0,1 3,9.5A6.5,6.5 0 0,1 9.5,3M9.5,5C7,5 5,7 5,9.5C5,12 7,14 9.5,14C12,14 14,12 14,9.5C14,7 12,5 9.5,5Z" "Find" "Search Winget"
Set-ButtonIcon "btnWingetScan" "M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15V18M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z" "Refresh Updates" "Checks the Winget repository for available application updates"
Set-ButtonIcon "btnWingetUpdateSel" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "Update Selected" "Updates the selected applications"
Set-ButtonIcon "btnWingetInstall" "M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z" "Install Selected" "Installs the selected applications"
Set-ButtonIcon "btnWingetUninstall" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Uninstall Selected" "Uninstalls the selected applications"
Set-ButtonIcon "btnSupportDiscord" "M19.27 5.33C17.94 4.71 16.5 4.26 15 4a.09.09 0 0 0-.07.03c-.18.33-.39.76-.53 1.09a16.09 16.09 0 0 0-4.8 0c-.14-.34-.35-.76-.54-1.09c-.01-.02-.04-.03-.07-.03c-1.5.26-2.93.71-4.27 1.33c-.01 0-.02.01-.03.02c-2.72 4.07-3.47 8.03-3.1 11.95c0 .02.01.04.03.05c1.8 1.32 3.53 2.12 5.2 2.65c.03.01.06 0 .07-.02c.4-.55.76-1.13 1.07-1.74c.02-.04 0-.08-.04-.09c-.57-.22-1.11-.48-1.64-.78c-.04-.02-.04-.08.01-.11c.11-.08.22-.17.33-.25c.02-.02.05-.02.07-.01c3.44 1.57 7.15 1.57 10.55 0c.02-.01.05-.01.07.01c.11.09.22.17.33.26c.04.03.04.09-.01.11c-.52.31-1.07.56-1.64.78c-.04.01-.05.06-.04.09c.32.61.68 1.19 1.07 1.74c.03.01.06.02.09.01c1.67-.53 3.4-1.33 5.2-2.65c.02-.01.03-.03.03-.05c.44-4.53-.73-8.46-3.1-11.95c-.01-.01-.02-.02-.04-.02z" "Join Discord" "Opens the community support Discord server"
Set-ButtonIcon "btnSupportIssue" "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" "Report Issue" "Opens the GitHub Issues page to report bugs"
Set-ButtonIcon "btnNavDownloads" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M11,6H13V12H11V6M11,14H13V16H11V14Z" "Release Downloads" "Show latest release download counts"
Set-ButtonIcon "btnDonateIos12" "M7,15H9C9,16.08 10.37,17 12,17C13.63,17 15,16.08 15,15C15,13.9 13.9,13.5 12,13.5C8.36,13.5 6,12.28 6,10C6,7.24 8.7,5 12,5V3H14V5C15.68,5.37 16.86,6.31 17.38,7.5H15.32C14.93,6.85 13.95,6.2 12,6.2C10.37,6.2 9,7.11 9,8.2C9,9.3 10.1,9.7 12,9.7C15.64,9.7 18,10.92 18,13.2C18,15.96 15.3,18.2 12,18.2V20H10V18.2C8.32,17.83 7.14,16.89 6.62,15.7L8.68,15Z" "Sponsor Lil_Batti" "Support Lil_Batti via GitHub Sponsors" "#00FF00"
Set-ButtonIcon "btnDonate" "M7,15H9C9,16.08 10.37,17 12,17C13.63,17 15,16.08 15,15C15,13.9 13.9,13.5 12,13.5C8.36,13.5 6,12.28 6,10C6,7.24 8.7,5 12,5V3H14V5C15.68,5.37 16.86,6.31 17.38,7.5H15.32C14.93,6.85 13.95,6.2 12,6.2C10.37,6.2 9,7.11 9,8.2C9,9.3 10.1,9.7 12,9.7C15.64,9.7 18,10.92 18,13.2C18,15.96 15.3,18.2 12,18.2V20H10V18.2C8.32,17.83 7.14,16.89 6.62,15.7L8.68,15Z" "Sponsor Chaython" "Support Chaython via GitHub Sponsors" "#00FF00"
Set-ButtonIcon "btnDnsGoogle" "M21.35,11.1H12.18V13.83H18.69C18.36,17.64 15.19,19.27 12.19,19.27C8.36,19.27 5,16.25 5,12C5,7.9 8.2,4.73 12.2,4.73C15.29,4.73 17.1,6.7 17.1,6.7L19,4.72C19,4.72 16.56,2 12.1,2C6.42,2 2.03,6.8 2.03,12C2.03,17.05 6.16,22 12.25,22C17.6,22 21.5,18.33 21.5,12.91C21.5,11.76 21.35,11.1 21.35,11.1V11.1Z" "Google" "Sets DNS to 8.8.8.8 & 8.8.4.4"
Set-ButtonIcon "btnDnsCloudflare" "M19.35,10.04C18.67,6.59 15.64,4 12,4C9.11,4 6.6,5.64 5.35,8.04C2.34,8.36 0,10.91 0,14A6,6 0 0,0 6,20H19A5,5 0 0,0 24,15C24,12.36 21.95,10.22 19.35,10.04Z" "Cloudflare" "Sets DNS to 1.1.1.1 & 1.0.0.1"
Set-ButtonIcon "btnDnsQuad9" "M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" "Quad9" "Sets DNS to 9.9.9.9 (Malware Blocking)"
Set-ButtonIcon "btnDnsAuto" "M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15V18M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z" "Auto (DHCP)" "Resets DNS settings to DHCP (Automatic)"
Set-ButtonIcon "btnDnsCustom" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M17,7L12,12L7,7H17Z" "Custom DNS" "Set custom DNS addresses across active adapters"
Set-ButtonIcon "btnHostsUpdate" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "Download AdBlock" "Updates Hosts file with AdBlocking list"
Set-ButtonIcon "btnHostsEdit" "M14.06,9L15,9.94L5.92,19H5V18.08L14.06,9M17.66,3C17.41,3 17.15,3.1 16.96,3.29L15.13,5.12L18.88,8.87L20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18.17,3.09 17.92,3 17.66,3M14.06,6.19L3,17.25V21H6.75L17.81,9.94L14.06,6.19Z" "Edit Hosts" "Opens the Hosts File Editor"
Set-ButtonIcon "btnHostsBackup" "M19,9H15V3H9V9H5L12,16L19,9Z" "Backup Hosts" "Backs up the current hosts file to the data folder"
Set-ButtonIcon "btnHostsRestore" "M13,3A9,9 0 0,0 4,12H1L4.89,15.89L4.96,16.03L9,12H6A7,7 0 0,1 13,5A7,7 0 0,1 20,12A7,7 0 0,1 13,19C11.07,19 9.32,18.21 8.06,16.94L6.64,18.36C8.27,20 10.5,21 13,21A9,9 0 0,0 22,12A9,9 0 0,0 13,3Z" "Restore Hosts" "Restores a previous hosts file backup"
Set-ButtonIcon "btnDohAuto" "M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" "Enable DoH (All)" "Enables DNS over HTTPS for all supported providers" "#00FFFF"
Set-ButtonIcon "btnDohDisable" "M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z" "Disable DoH" "Disables DNS over HTTPS" "#FF5555"
Set-ButtonIcon "btnFwRefresh" "M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z" "Reload" "Refreshes the firewall rule list"
Set-ButtonIcon "btnFwAdd" "M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z" "Add Rule" "Create a new firewall rule"
Set-ButtonIcon "btnFwEdit" "M14.06,9L15,9.94L5.92,19H5V18.08L14.06,9M17.66,3C17.41,3 17.15,3.1 16.96,3.29L15.13,5.12L18.88,8.87L20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18.17,3.09 17.92,3 17.66,3M14.06,6.19L3,17.25V21H6.75L17.81,9.94L14.06,6.19Z" "Modify" "Edit the selected firewall rule"
Set-ButtonIcon "btnFwEnable" "M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" "Enable" "Enable selected rule"
Set-ButtonIcon "btnFwDisable" "M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z" "Disable" "Disable selected rule"
Set-ButtonIcon "btnFwDelete" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Delete" "Delete selected rule"
Set-ButtonIcon "btnFwExport" "M15,14H14V10H10V14H9L12,17L15,14M12,3L4.5,8V14C4.5,17.93 7.36,21.43 12,23C16.64,21.43 19.5,17.93 19.5,14V8L12,3Z" "Export" "Export firewall policy to the data folder"
Set-ButtonIcon "btnFwImport" "M12,3L4.5,8V14C4.5,17.93 7.36,21.43 12,23C16.64,21.43 19.5,17.93 19.5,14V8L12,3M12,6.15L17.5,10.2V14C17.5,16.96 15.56,19.5 12,20.82C8.44,19.5 6.5,16.96 6.5,14V10.2L12,6.15M12,9L8,13H11V17H13V13H16L12,9Z" "Import" "Import firewall policy (.wfw)"
Set-ButtonIcon "btnFwDefaults" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12C22,6.47 17.5,2 12,2M7,9H9V13H11V9H13V13H15V9H17V15H7V9Z" "Restore Defaults" "Reset firewall to default rules"
Set-ButtonIcon "btnFwPurge" "M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z" "Delete All" "Delete all firewall rules"
Set-ButtonIcon "btnDrvReport" "M13,9H18.5L13,3.5V9M6,2H14L20,8V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V4C4,2.89 4.89,2 6,2M15,18V16H6V18H15M18,14V12H6V14H18Z" "Generate Driver Report" "Saves a list of all installed drivers to the data folder"
Set-ButtonIcon "btnDrvGhost" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z" "Remove Ghost Devices" "Removes disconnected (ghost) PnP devices"
Set-ButtonIcon "btnDrvBackup" "M13,9H18.5L13,3.5V9M6,2H14L20,8V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V4C4,2.89 4.89,2 6,2M15,18V16H6V18H15M18,14V12H6V14H18Z" "Export Drivers" "Exports all drivers to the data folder"
Set-ButtonIcon "btnDrvClean" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Clean Old Drivers" "Removes obsolete drivers from the Windows Driver Store"
Set-ButtonIcon "btnDrvRestore" "M12,2L3,7V17L12,22L21,17V7L12,2M12,4.3L18.5,8L12,11.7L5.5,8L12,4.3M5,9.85L12,14L19,9.85V16.15L12,20.3L5,16.15V9.85M7,11H9V14H7V11M15,11H17V14H15V11Z" "Restore Drivers" "Imports drivers from a DriverBackup folder"
Set-ButtonIcon "btnDrvDisableWU" "M19,4H5V6H19M5,20H19V18H5M9,9H15V11H9V9M9,13H15V15H9V13Z" "Disable Driver Updates" "Turn off automatic driver updates"
Set-ButtonIcon "btnDrvEnableWU" "M19,4H5V6H19M5,20H19V18H5M9,9H15V11H9V9M9,13H13V15H9V13Z" "Enable Driver Updates" "Turn on automatic driver updates"
Set-ButtonIcon "btnDrvDisableMeta" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M15,17H9V15H15V17M16.59,11.17L15.17,12.59L12,9.41L8.83,12.59L7.41,11.17L12,6.58L16.59,11.17Z" "Disable Device Metadata" "Block device metadata downloads"
Set-ButtonIcon "btnDrvEnableMeta" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M15,17H9V15H15V17M11,14V9H9L12,6L15,9H13V14H11Z" "Enable Device Metadata" "Allow device metadata downloads"
Set-ButtonIcon "btnUtilSysInfo" "M13,9H18.5L13,3.5V9M6,2H14L20,8V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V4C4,2.89 4.89,2 6,2M15,18V16H6V18H15M18,14V12H6V14H18Z" "System Info Report" "Generates a full system information report"
Set-ButtonIcon "btnUtilTrim" "M6,2H18A2,2 0 0,1 20,4V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V4A2,2 0 0,1 6,2M12,4A6,6 0 0,0 6,10C6,13.31 8.69,16 12,16A6,6 0 0,0 18,10C18,6.69 15.31,4 12,4M12,14A4,4 0 0,1 8,10A4,4 0 0,1 12,6A4,4 0 0,1 16,10A4,4 0 0,1 12,14Z" "Trim SSD" "Optimizes SSD performance via Trim command"
Set-ButtonIcon "btnUtilMas" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "MAS Activation" "Downloads and runs Microsoft Activation Scripts"

# ==========================================
# 5. LOGIC & EVENTS
# ==========================================
$TabButtons = @("btnTabUpdates","btnTabHealth","btnTabNetwork","btnTabFirewall","btnTabDrivers","btnTabCleanup","btnTabUtils","btnTabSupport")
$Panels     = @("pnlUpdates","pnlHealth","pnlNetwork","pnlFirewall","pnlDrivers","pnlCleanup","pnlUtils","pnlSupport")

# --- INITIALIZE ALL CONTROLS ---
$btnWingetScan = Get-Ctrl "btnWingetScan"
$btnWingetUpdateSel = Get-Ctrl "btnWingetUpdateSel"
$btnWingetInstall = Get-Ctrl "btnWingetInstall"
$btnWingetUninstall = Get-Ctrl "btnWingetUninstall"
$btnWingetFind = Get-Ctrl "btnWingetFind"
$lstWinget = Get-Ctrl "lstWinget"
$txtWingetSearch = Get-Ctrl "txtWingetSearch"
$lblWingetStatus = Get-Ctrl "lblWingetStatus"
$lblWingetTitle = Get-Ctrl "lblWingetTitle"

$btnSFC = Get-Ctrl "btnSFC"
$btnDISMCheck = Get-Ctrl "btnDISMCheck"
$btnDISMRestore = Get-Ctrl "btnDISMRestore"
$btnCHKDSK = Get-Ctrl "btnCHKDSK"

$btnNetInfo = Get-Ctrl "btnNetInfo"
$btnFlushDNS = Get-Ctrl "btnFlushDNS"
$btnResetWifi = Get-Ctrl "btnResetWifi"
$btnNetRepair = Get-Ctrl "btnNetRepair"
$btnRouteTable = Get-Ctrl "btnRouteTable"
$btnRouteView = Get-Ctrl "btnRouteView"
$btnDnsGoogle = Get-Ctrl "btnDnsGoogle"
$btnDnsCloudflare = Get-Ctrl "btnDnsCloudflare"
$btnDnsQuad9 = Get-Ctrl "btnDnsQuad9"
$btnDnsAuto = Get-Ctrl "btnDnsAuto"
$btnDnsCustom = Get-Ctrl "btnDnsCustom"
$btnDohAuto = Get-Ctrl "btnDohAuto"
$btnDohDisable = Get-Ctrl "btnDohDisable"
$btnHostsUpdate = Get-Ctrl "btnHostsUpdate"
$btnHostsEdit = Get-Ctrl "btnHostsEdit"
$btnHostsBackup = Get-Ctrl "btnHostsBackup"
$btnHostsRestore = Get-Ctrl "btnHostsRestore"

$btnFwRefresh = Get-Ctrl "btnFwRefresh"
$btnFwAdd = Get-Ctrl "btnFwAdd"
$btnFwEdit = Get-Ctrl "btnFwEdit"
$btnFwEnable = Get-Ctrl "btnFwEnable"
$btnFwDisable = Get-Ctrl "btnFwDisable"
$btnFwDelete = Get-Ctrl "btnFwDelete"
$btnFwExport = Get-Ctrl "btnFwExport"
$btnFwImport = Get-Ctrl "btnFwImport"
$btnFwDefaults = Get-Ctrl "btnFwDefaults"
$btnFwPurge = Get-Ctrl "btnFwPurge"
$lstFw = Get-Ctrl "lstFirewall"
$txtFwSearch = Get-Ctrl "txtFwSearch"
$lblFwStatus = Get-Ctrl "lblFwStatus"

$btnDrvReport = Get-Ctrl "btnDrvReport"
$btnDrvBackup = Get-Ctrl "btnDrvBackup"
$btnDrvGhost = Get-Ctrl "btnDrvGhost"
$btnDrvClean = Get-Ctrl "btnDrvClean"
$btnDrvRestore = Get-Ctrl "btnDrvRestore"
$btnDrvDisableWU = Get-Ctrl "btnDrvDisableWU"
$btnDrvEnableWU = Get-Ctrl "btnDrvEnableWU"
$btnDrvDisableMeta = Get-Ctrl "btnDrvDisableMeta"
$btnDrvEnableMeta = Get-Ctrl "btnDrvEnableMeta"

$btnCleanDisk = Get-Ctrl "btnCleanDisk"
$btnCleanTemp = Get-Ctrl "btnCleanTemp"
$btnCleanShortcuts = Get-Ctrl "btnCleanShortcuts"
$btnCleanReg = Get-Ctrl "btnCleanReg"
$btnCleanXbox = Get-Ctrl "btnCleanXbox"

$btnUtilSysInfo = Get-Ctrl "btnUtilSysInfo"
$btnUtilTrim = Get-Ctrl "btnUtilTrim"
$btnUtilMas = Get-Ctrl "btnUtilMas"
$btnUpdateRepair = Get-Ctrl "btnUpdateRepair"
$btnUpdateServices = Get-Ctrl "btnUpdateServices"
$btnDotNetEnable = Get-Ctrl "btnDotNetEnable"
$btnDotNetDisable = Get-Ctrl "btnDotNetDisable"
$btnTaskManager = Get-Ctrl "btnTaskManager"
$btnInstallGpedit = Get-Ctrl "btnInstallGpedit"

$btnSupportDiscord = Get-Ctrl "btnSupportDiscord"
$btnSupportIssue = Get-Ctrl "btnSupportIssue"
$btnNavDownloads = Get-Ctrl "btnNavDownloads"
$btnDonateIos12 = Get-Ctrl "btnDonateIos12"
$btnDonate = Get-Ctrl "btnDonate"
$btnCreditLilBattiCLI = Get-Ctrl "btnCreditLilBattiCLI"
$btnCreditChaythonCLI = Get-Ctrl "btnCreditChaythonCLI"
$btnCreditChaythonGUI = Get-Ctrl "btnCreditChaythonGUI"
$btnCreditChaythonFeatures = Get-Ctrl "btnCreditChaythonFeatures"
$btnCreditIos12checker = Get-Ctrl "btnCreditIos12checker"

$txtGlobalSearch = Get-Ctrl "txtGlobalSearch"
$lstSearchResults = Get-Ctrl "lstSearchResults"
$pnlNavButtons = Get-Ctrl "pnlNavButtons"

# --- TABS LOGIC ---
foreach ($btnName in $TabButtons) {
    (Get-Ctrl $btnName).Add_Click({
        param($s,$e)
        foreach ($p in $Panels) { (Get-Ctrl $p).Visibility = "Collapsed" }
        foreach ($b in $TabButtons) { (Get-Ctrl $b).Background = "Transparent"; (Get-Ctrl $b).Foreground = "#CCCCCC" }
        $target = (Get-Ctrl $s.Tag)
        $target.Visibility = "Visible"
        $s.Background = "#333"; $s.Foreground = "White"
        if ($s.Name -eq "btnTabFirewall") { $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) }
        if ($s.Name -eq "btnTabUpdates") {
             if ($lstWinget.Items.Count -eq 0) { 
                $btnWingetScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
             }
        }
    })
}

# --- GLOBAL SEARCH ---
$SearchIndex = @{}
function Add-SearchIndexEntry { param($BtnName, $Desc, $ParentTab) $b=Get-Ctrl $BtnName; if($b){ $SearchIndex[$Desc]=@{Button=$b;Tab=$ParentTab} } }
# --- GLOBAL SEARCH INDEX ---

# 1. Updates (Winget)
Add-SearchIndexEntry "btnWingetScan"        "Check for Updates (Winget)"      "btnTabUpdates"
Add-SearchIndexEntry "btnWingetUpdateSel"   "Update Selected Apps"            "btnTabUpdates"
Add-SearchIndexEntry "btnWingetInstall"     "Install Selected Apps"           "btnTabUpdates"
Add-SearchIndexEntry "btnWingetUninstall"   "Uninstall Selected Apps"         "btnTabUpdates"
Add-SearchIndexEntry "btnWingetFind"        "Search Winget Packages"          "btnTabUpdates"

# 2. System Health
Add-SearchIndexEntry "btnSFC"               "SFC Scan (System File Checker)"  "btnTabHealth"
Add-SearchIndexEntry "btnDISMCheck"         "DISM Check Health"               "btnTabHealth"
Add-SearchIndexEntry "btnDISMRestore"       "DISM Restore Health"             "btnTabHealth"
Add-SearchIndexEntry "btnCHKDSK"            "CHKDSK (Check Disk)"             "btnTabHealth"

# 3. Network & DNS
Add-SearchIndexEntry "btnNetInfo"           "Show IP Config / Network Info"   "btnTabNetwork"
Add-SearchIndexEntry "btnFlushDNS"          "Flush DNS Cache"                 "btnTabNetwork"
Add-SearchIndexEntry "btnResetWifi"         "Restart Wi-Fi Adapter"           "btnTabNetwork"
Add-SearchIndexEntry "btnNetRepair"         "Full Network Repair (Reset IP)"  "btnTabNetwork"
Add-SearchIndexEntry "btnRouteTable"        "Save Routing Table"              "btnTabNetwork"
Add-SearchIndexEntry "btnRouteView"         "View Routing Table"              "btnTabNetwork"

# DNS Presets
Add-SearchIndexEntry "btnDnsGoogle"         "Set DNS: Google (8.8.8.8)"       "btnTabNetwork"
Add-SearchIndexEntry "btnDnsCloudflare"     "Set DNS: Cloudflare (1.1.1.1)"   "btnTabNetwork"
Add-SearchIndexEntry "btnDnsQuad9"          "Set DNS: Quad9 (Malware Block)"  "btnTabNetwork"
Add-SearchIndexEntry "btnDnsAuto"           "Reset DNS to Auto (DHCP)"        "btnTabNetwork"
Add-SearchIndexEntry "btnDnsCustom"         "Set Custom DNS Address"          "btnTabNetwork"

# DNS Encryption & Hosts
Add-SearchIndexEntry "btnDohAuto"           "Enable DoH (DNS over HTTPS)"     "btnTabNetwork"
Add-SearchIndexEntry "btnDohDisable"        "Disable DoH"                     "btnTabNetwork"
Add-SearchIndexEntry "btnHostsUpdate"       "Update Hosts (AdBlock)"          "btnTabNetwork"
Add-SearchIndexEntry "btnHostsEdit"         "Edit Hosts File"                 "btnTabNetwork"
Add-SearchIndexEntry "btnHostsBackup"       "Backup Hosts File"               "btnTabNetwork"
Add-SearchIndexEntry "btnHostsRestore"      "Restore Hosts File"              "btnTabNetwork"

# 4. Firewall
Add-SearchIndexEntry "btnFwRefresh"         "Refresh Firewall Rules"          "btnTabFirewall"
Add-SearchIndexEntry "btnFwAdd"             "Add New Firewall Rule"           "btnTabFirewall"
Add-SearchIndexEntry "btnFwEdit"            "Edit/Modify Firewall Rule"       "btnTabFirewall"
Add-SearchIndexEntry "btnFwExport"          "Export Firewall Policy"          "btnTabFirewall"
Add-SearchIndexEntry "btnFwImport"          "Import Firewall Policy"          "btnTabFirewall"
Add-SearchIndexEntry "btnFwDefaults"        "Restore Default Firewall Rules"  "btnTabFirewall"
Add-SearchIndexEntry "btnFwPurge"           "Delete All Firewall Rules"       "btnTabFirewall"

# 5. Drivers
Add-SearchIndexEntry "btnDrvReport"         "Generate Driver Report"          "btnTabDrivers"
Add-SearchIndexEntry "btnDrvBackup"         "Export Drivers"                  "btnTabDrivers"
Add-SearchIndexEntry "btnDrvGhost"          "Remove Ghost Devices"            "btnTabDrivers"
Add-SearchIndexEntry "btnDrvClean"          "Clean Old Drivers (DriverStore)" "btnTabDrivers"
Add-SearchIndexEntry "btnDrvRestore"        "Restore Drivers from Backup"     "btnTabDrivers"
Add-SearchIndexEntry "btnDrvDisableWU"      "Disable Driver Updates"          "btnTabDrivers"
Add-SearchIndexEntry "btnDrvEnableWU"       "Enable Driver Updates"           "btnTabDrivers"
Add-SearchIndexEntry "btnDrvDisableMeta"    "Disable Device Metadata"         "btnTabDrivers"
Add-SearchIndexEntry "btnDrvEnableMeta"     "Enable Device Metadata"          "btnTabDrivers"

# 6. Cleanup
Add-SearchIndexEntry "btnCleanDisk"         "Disk Cleanup Tool"               "btnTabCleanup"
Add-SearchIndexEntry "btnCleanTemp"         "Clean Temporary Files"           "btnTabCleanup"
Add-SearchIndexEntry "btnCleanShortcuts"    "Fix Broken Shortcuts"            "btnTabCleanup"
Add-SearchIndexEntry "btnCleanReg"          "Registry Cleanup & Backup"       "btnTabCleanup"
Add-SearchIndexEntry "btnCleanXbox"         "Clean Xbox Credentials"          "btnTabCleanup"

# 7. Utilities
Add-SearchIndexEntry "btnUtilSysInfo"       "System Info Report"              "btnTabUtils"
Add-SearchIndexEntry "btnUtilTrim"          "Trim SSD (Optimize)"             "btnTabUtils"
Add-SearchIndexEntry "btnUtilMas"           "MAS Activation"                  "btnTabUtils"
Add-SearchIndexEntry "btnUpdateRepair"      "Reset Windows Update Components" "btnTabUtils"
Add-SearchIndexEntry "btnUpdateServices"    "Restart Update Services"         "btnTabUtils"
Add-SearchIndexEntry "btnDotNetEnable"      "Set .NET RollForward"            "btnTabUtils"
Add-SearchIndexEntry "btnDotNetDisable"     "Reset .NET RollForward"          "btnTabUtils"
Add-SearchIndexEntry "btnTaskManager"       "Task Scheduler Manager"          "btnTabUtils"
Add-SearchIndexEntry "btnInstallGpedit"     "Install Group Policy (Home)"     "btnTabUtils"

# 8. Support
Add-SearchIndexEntry "btnSupportDiscord"    "Join Discord Support"            "btnTabSupport"
Add-SearchIndexEntry "btnSupportIssue"      "Report an Issue (GitHub)"        "btnTabSupport"

$txtGlobalSearch.Add_TextChanged({
    $q = $txtGlobalSearch.Text
    if ($q.Length -gt 1) {
        $pnlNavButtons.Visibility = "Collapsed"
        $lstSearchResults.Visibility = "Visible"
        $lstSearchResults.Items.Clear()
        $SearchIndex.GetEnumerator() | Where-Object { $_.Key -match "$q" } | ForEach-Object { [void]$lstSearchResults.Items.Add($_.Key) }
    } else { $pnlNavButtons.Visibility = "Visible"; $lstSearchResults.Visibility = "Collapsed" }
})
$lstSearchResults.Add_SelectionChanged({ if ($lstSearchResults.SelectedItem) { $match=$SearchIndex[$lstSearchResults.SelectedItem]; (Get-Ctrl $match.Tab).RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))); $txtGlobalSearch.Text="" } })

# --- WINGET ---
$txtWingetSearch.Add_GotFocus({ if ($txtWingetSearch.Text -eq "Search new packages...") { $txtWingetSearch.Text="" } })
$txtWingetSearch.Add_TextChanged({
    # If the user starts typing and the only item is our status message, clear it
    if ($lstWinget.Items.Count -eq 1 -and $lstWinget.Items[0].Name -eq "No updates available") {
        $lstWinget.Items.Clear()
    }
})
$txtWingetSearch.Add_KeyDown({ param($s, $e) if ($e.Key -eq "Return") { $btnWingetFind.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })

# 1. SETUP TIMER FOR BACKGROUND POLLING
$script:WingetTimer = New-Object System.Windows.Threading.DispatcherTimer
$script:WingetTimer.Interval = [TimeSpan]::FromMilliseconds(500)

$script:WingetTimer.Add_Tick({
    if ($script:WingetJob) {
        # Fetch available output from the background job
        $results = Receive-Job -Job $script:WingetJob
        
        if ($results) {
            foreach ($line in $results) {
                # Basic cleanup of empty lines
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Write-GuiLog $line
                }
            }
        }
        
        # Check if the job has finished
        if ($script:WingetJob.State -in 'Completed', 'Failed', 'Stopped') {
            $script:WingetTimer.Stop()
            Remove-Job -Job $script:WingetJob -Force
            $script:WingetJob = $null
            
            # Unlock UI
            $btnWingetScan.IsEnabled = $true
            $btnWingetUpdateSel.IsEnabled = $true
            $btnWingetInstall.IsEnabled = $true
            $btnWingetUninstall.IsEnabled = $true
            $lblWingetStatus.Visibility = "Hidden"
            Write-GuiLog "--- Operation Complete ---"
            
            # Auto-refresh list if we modified something
            if ($script:WingetRefreshNeeded) {
                Write-GuiLog "Refreshing list..."
                $btnWingetScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
                $script:WingetRefreshNeeded = $false
            }
        }
    }
})

# 2. HELPER TO START JOB
$Script:StartWingetAction = {
    param($ListItems, $ActionName, $CmdTemplate)
    
    if (-not $ListItems -or $ListItems.Count -eq 0) { return }
    
    # Lock UI
    $btnWingetScan.IsEnabled = $false
    $btnWingetUpdateSel.IsEnabled = $false
    $btnWingetInstall.IsEnabled = $false
    $btnWingetUninstall.IsEnabled = $false
    
    $lblWingetStatus.Text = "$ActionName in progress..."
    $lblWingetStatus.Visibility = "Visible"
    $script:WingetRefreshNeeded = ($ActionName -match "Update|Uninstall")
    
    Write-GuiLog " "
    Write-GuiLog "=== STARTING $ActionName ($($ListItems.Count) Items) ==="
    
    $jobArgs = @{
        Items = $ListItems | Select-Object Name, Id
        Template = $CmdTemplate
        IsUninstall = ($ActionName -eq "Uninstall") # Flag to detect uninstall mode
    }

    $script:WingetJob = Start-Job -ArgumentList $jobArgs -ScriptBlock {
        param($ArgsDict)
        Add-Type -AssemblyName System.Windows.Forms
        
        $items = $ArgsDict.Items
        $tmpl = $ArgsDict.Template
        $isUninstall = $ArgsDict.IsUninstall
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

        foreach ($item in $items) {
            Write-Output "Processing: $($item.Name)..."
            $baseCmd = $tmpl -f $item.Id
            
            # --- BUILD ARGUMENTS ---
            # 'accept-package-agreements' is NOT valid for uninstall and causes errors
            $commonFlags = "--accept-source-agreements"
            if (-not $isUninstall) {
                $commonFlags += " --accept-package-agreements"
            }

            # 1. Attempt Silent Execution First
            $expr = "$baseCmd $commonFlags --disable-interactivity"
            
            $failed = $false
            $adminBlocked = $false
            
            # Capture output first to maintain variable scope in the loop
            $output = Invoke-Expression $expr 
            
            foreach ($line in $output) {
                
                # FILTER: Skip spinner animation lines
                if ($line -match '^\s*[\-\\|/]\s*$') { continue }
                
                Write-Output $line
                
                # Check for Failures
                if ($line -match "Installer failed" -or $line -match "exit code:") {
                    $failed = $true
                }
                if ($line -match "Argument name was not recognized") {
                    $failed = $true
                }
                
                # Check for Admin Context blocks
                if ($line -match "cannot be .* from an admin.* context" -or $line -match "run this installer as a normal user") {
                    $failed = $true
                    $adminBlocked = $true
                }
            }
            
            # 2. Handle Admin Context Error (De-Elevation)
            if ($adminBlocked) {
                $msg = "The installer for '$($item.Name)' refuses to run as Administrator.`n`nDo you want to launch it as a Standard User (via Windows Explorer)?"
                $choice = [System.Windows.Forms.MessageBox]::Show($msg, "Admin Context Blocked", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                
                if ($choice -eq "Yes") {
                    Write-Output ">> Preparing to launch as Standard User..."
                    
                    $tempCmd = Join-Path $env:TEMP "WMT_DeElevate_Install.cmd"
                    # We use the filtered $commonFlags here too
                    $batchContent = "@echo off`nTitle Installing $($item.Name)`necho Launching Winget as Standard User...`n$baseCmd $commonFlags`npause`ndel `"%~f0`" & exit"
                    Set-Content -Path $tempCmd -Value $batchContent -Encoding ASCII
                    
                    Start-Process (Join-Path $env:WinDir "explorer.exe") -ArgumentList "`"$tempCmd`""
                    
                    Write-Output ">> A new terminal window has opened for this operation."
                    $failed = $false # Handled
                } else {
                    Write-Output ">> Skipped by user."
                    $failed = $false
                }
            }
            
            # 3. Handle Generic Failure (Switch to Interactive)
            if ($failed) {
                $msg = "The operation for '$($item.Name)' failed silently.`n`nWould you like to launch it INTERACTIVELY so you can handle the error manually?"
                $choice = [System.Windows.Forms.MessageBox]::Show($msg, "Operation Failed", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Exclamation)
                
                if ($choice -eq "Yes") {
                    # A. NOTIFY USER
                    [System.Windows.Forms.MessageBox]::Show("The interactive installer will now open.`n`nPlease follow the prompts in the new window to complete the process.`n`nThis tool will wait until you are finished.", "Launching Interactive Mode", [System.Windows.Forms.MessageBoxButton]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    
                    Write-Output ">> Launching Interactive Mode... Waiting for user completion..."
                    
                    # B. PREPARE ARGUMENTS
                    # Strip 'winget ' from the start to get raw arguments for Start-Process
                    $argString = $baseCmd -replace "^winget\s+", ""
                    # Add necessary flags
                    $finalArgs = "$argString $commonFlags --interactive"
                    
                    # C. EXECUTE WITH WAIT
                    # -Wait forces the script to pause until the installer closes
                    $proc = Start-Process -FilePath "winget" -ArgumentList $finalArgs -Wait -PassThru -NoNewWindow
                    
                    if ($proc.ExitCode -eq 0) {
                        Write-Output ">> Interactive process finished successfully."
                    } else {
                        Write-Output ">> Interactive process finished (Exit Code: $($proc.ExitCode))."
                    }
                } else {
                    Write-Output ">> Skipped by user."
                }
            }
            
            Write-Output "--------------------------------"
        }
    }
    
    $script:WingetTimer.Start()
}

# 3. EVENT HANDLERS
$btnWingetScan.Add_Click({
    $lblWingetTitle.Text = "Available Updates"
    $lblWingetStatus.Text = "Scanning..."; $lblWingetStatus.Visibility = "Visible"
    $btnWingetUpdateSel.Visibility = "Visible"; $btnWingetInstall.Visibility = "Collapsed"
    $lstWinget.Items.Clear()
    [System.Windows.Forms.Application]::DoEvents()
    
    $tempOut = Join-Path $env:TEMP "winget_upd.txt"
    
    # Capture output
    $psCmd = "chcp 65001 >`$null; `$host.ui.RawUI.BufferSize = New-Object Management.Automation.Host.Size(300, 3000); winget list --upgrade-available --accept-source-agreements 2>&1 | Out-File -FilePath `"$tempOut`" -Encoding UTF8"
    
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command $psCmd" -NoNewWindow -PassThru
    $proc.WaitForExit()
    
    if (Test-Path $tempOut) {
        $lines = Get-Content $tempOut -Encoding UTF8
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            # --- FILTERS (UPDATED) ---
            # 1. Skip headers, separators, and standard messages
            if ($line -eq "" -or $line -match "^Name" -or $line -match "^----" -or $line -match "upgrades\s+available" -or $line -match "No installed package found") { continue }
            
            # 2. Skip Progress Bars (Block characters like █, ▒, etc.)
            if ($line -match "[\u2580-\u259F]") { continue }

            # 3. Skip Download Status lines (e.g., "10.5 MB / 10.5 MB")
            if ($line -match "\d+\s*(KB|MB|GB|TB)") { continue }

            $name=$null; $id=$null; $ver=$null; $avail="-"; $src="winget"

            # STRATEGY: Greedy Match from Right-to-Left
            
            # Case A: 5 Columns (Name, Id, Version, Available, Source)
            if ($line -match '^(.+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$') {
                $name = $matches[1]; $id = $matches[2]; $ver = $matches[3]; $avail = $matches[4]; $src = $matches[5]
            }
            # Case B: 4 Columns (Name, Id, Version, Source) - "Available" missing
            elseif ($line -match '^(.+)\s+(\S+)\s+(\S+)\s+(\S+)$') {
                $name = $matches[1]; $id = $matches[2]; $ver = $matches[3]; $src = $matches[4]
            }
            # Case C: 3 Columns (Name, Id, Version) - "Available" and "Source" missing
            elseif ($line -match '^(.+)\s+(\S+)\s+(\S+)$') {
                $name = $matches[1]; $id = $matches[2]; $ver = $matches[3]
            }

            # Final Safety Check: Ensure ID doesn't look like a leftover file size unit
            if ($name -and $id -notmatch "^(KB|MB|GB|/)$") {
                [void]$lstWinget.Items.Add([PSCustomObject]@{ 
                    Name=$name.Trim(); Id=$id.Trim(); Version=$ver.Trim(); Available=$avail.Trim(); Source=$src.Trim() 
                })
            }
        }
        Remove-Item $tempOut -ErrorAction SilentlyContinue
    }
    
    # Check if list is empty and add placeholder message
    $logCount = $lstWinget.Items.Count
    
    if ($logCount -eq 0) {
        [void]$lstWinget.Items.Add([PSCustomObject]@{ 
            Name="No updates available"; Id=""; Version=""; Available=""; Source="" 
        })
        $logCount = 0 # Correct the log count for the placeholder
    }
    
    $lblWingetStatus.Visibility = "Hidden"
    Write-GuiLog "Scan complete. Found $logCount updates."
})

$btnWingetFind.Add_Click({
    if ($txtWingetSearch.Text -eq "" -or $txtWingetSearch.Text -eq "Search new packages...") { return }
    $lblWingetTitle.Text = "Search Results: " + $txtWingetSearch.Text
    $lblWingetStatus.Text = "Searching..."; $lblWingetStatus.Visibility = "Visible"
    $btnWingetUpdateSel.Visibility = "Collapsed"; $btnWingetInstall.Visibility = "Visible"
    $lstWinget.Items.Clear()
    [System.Windows.Forms.Application]::DoEvents()
    
    $tempOut = Join-Path $env:TEMP "winget_search.txt"
    $psCmd = "chcp 65001 >`$null; winget search `"$($txtWingetSearch.Text)`" --accept-source-agreements | Out-File -FilePath `"$tempOut`" -Encoding UTF8"
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command $psCmd" -NoNewWindow -PassThru
    $proc.WaitForExit()
    
    if (Test-Path $tempOut) {
        $lines = Get-Content $tempOut -Encoding UTF8
        foreach ($line in $lines) {
            if ($line -match '^(\S.{0,35}?)\s{2,}(\S+)\s{2,}(\S+)') {
                if ($matches[1] -notmatch "Name" -and $matches[1] -notmatch "----") {
                     [void]$lstWinget.Items.Add([PSCustomObject]@{ Name=$matches[1].Trim(); Id=$matches[2].Trim(); Version=$matches[3].Trim(); Available="-"; Source="winget" })
                }
            }
        }
        Remove-Item $tempOut -ErrorAction SilentlyContinue
    }
    
    $lblWingetStatus.Visibility = "Hidden"
})

$btnWingetUpdateSel.Add_Click({ 
    & $Script:StartWingetAction -ListItems $lstWinget.SelectedItems -ActionName "Update" -CmdTemplate "winget upgrade --id {0}"
})

$btnWingetInstall.Add_Click({ 
    & $Script:StartWingetAction -ListItems $lstWinget.SelectedItems -ActionName "Install" -CmdTemplate "winget install --id {0}"
})

$btnWingetUninstall.Add_Click({ 
    # 1. Capture selected items immediately to a standard array
    $selected = @($lstWinget.SelectedItems)

    if ($selected.Count -gt 0) { 
        # 2. Confirm action
        $msg = "Are you sure you want to uninstall $($selected.Count) application(s)?"
        $res = [System.Windows.Forms.MessageBox]::Show($msg, "Confirm Uninstall", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        
        if ($res -eq "Yes") { 
            # 3. Pass the array to the action handler with quoted ID template
            & $Script:StartWingetAction -ListItems $selected -ActionName "Uninstall" -CmdTemplate "winget uninstall --id `"{0}`""
        } 
    } 
})

# --- System Health ---
$btnSFC.Add_Click({
    Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command "sfc /scannow; Write-Host; Write-Host ''Execution Complete.'' -ForegroundColor Green; Write-Host ''Press Enter to close...'' -NoNewline -ForegroundColor Gray; Read-Host"' -Verb RunAs -WindowStyle Normal
})
$btnDISMCheck.Add_Click({
    Invoke-UiCommand {
        $output = dism /online /cleanup-image /checkhealth 2>&1
        $text = ($output | Out-String).Trim()
        if ($text) { Write-Output $text }

        $message = "DISM Check completed."
        $needsRepair = $false
        if ($text -match "No component store corruption detected") {
            $message = "DISM Check: no corruption detected."
        } elseif ($text -match "component store is repairable") {
            $message = "DISM Check: corruption detected (repairable)."
            $needsRepair = $true
        } elseif ($text -match "The operation completed successfully") {
            $message = "DISM Check: completed successfully."
        }
        [System.Windows.MessageBox]::Show($message, "DISM CheckHealth", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null

        if ($needsRepair) {
            $prompt = [System.Windows.MessageBox]::Show(
                "DISM found repairable corruption.`n`nRun DISM RestoreHealth now?",
                "DISM CheckHealth",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            if ($prompt -eq "Yes") {
                Write-Output "Launching DISM RestoreHealth..."
                # Run DISM Restore (nested): Fixed newline issue
                Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command "dism /online /cleanup-image /restorehealth; Write-Host; Write-Host ''Execution Complete.'' -ForegroundColor Green; Write-Host ''Press Enter to close...'' -NoNewline -ForegroundColor Gray; Read-Host"' -Verb RunAs -WindowStyle Normal
            }
        }
    } "Running DISM CheckHealth..."
})
$btnDISMRestore.Add_Click({
    Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command "dism /online /cleanup-image /restorehealth; Write-Host; Write-Host ''Execution Complete.'' -ForegroundColor Green; Write-Host ''Press Enter to close...'' -NoNewline -ForegroundColor Gray; Read-Host"' -Verb RunAs -WindowStyle Normal
})
$btnCHKDSK.Add_Click({ Invoke-ChkdskAll })

# --- NETWORK ---
$btnNetInfo.Add_Click({
    Invoke-UiCommand {
        $out = ipconfig /all 2>&1
        $txt = ($out | Out-String)
        Write-Output $txt
        Show-TextDialog -Title "IP Configuration" -Text $txt
    } "Showing IP configuration..."
})
$btnFlushDNS.Add_Click({
    Invoke-UiCommand {
        $out = ipconfig /flushdns 2>&1
        $txt = ($out | Out-String).Trim()
        if ($txt) { Write-Output $txt }
        [System.Windows.MessageBox]::Show("DNS cache flushed.", "Flush DNS", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
    } "Flushing DNS cache..."
})
$btnResetWifi.Add_Click({
    Invoke-UiCommand {
        $wifi = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -match "Wi-Fi|Wireless" }
        $eth  = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch "Wi-Fi|Wireless" -and $_.InterfaceDescription -notmatch "Bluetooth" }

        if (-not $wifi) {
            $msg = "No active Wi-Fi adapters found."
            if ($eth) {
                $ethNames = $eth | Select-Object -ExpandProperty Name
                $msg += "`nYou appear to be on Ethernet: " + ($ethNames -join ", ")
            }
            [System.Windows.MessageBox]::Show($msg, "Restart Wi-Fi", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
            Write-Output $msg
            return
        }

        $names = $wifi | Select-Object -ExpandProperty Name
        foreach ($n in $names) {
            Restart-NetAdapter -Name $n -Confirm:$false -ErrorAction SilentlyContinue
            Write-Output "Restarted Wi-Fi adapter: $n"
        }

        [System.Windows.MessageBox]::Show("Restarted Wi-Fi adapter(s): " + ($names -join ", "), "Restart Wi-Fi", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
    } "Restarting Wi-Fi adapters..."
})

$btnNetRepair.Add_Click({
    $msg = "Full Network Repair will:" +
           "`n- Release/Renew IP" +
           "`n- Flush DNS cache" +
           "`n- Reset Winsock" +
           "`n- Reset IP stack" +
           "`n`nAdapters may briefly disconnect. Continue?"

    $res = [System.Windows.MessageBox]::Show($msg, "Full Network Repair", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    
    if ($res -eq "Yes") {
        Start-NetRepair
    }
})

$btnRouteTable.Add_Click({ Invoke-UiCommand { $path = Join-Path (Get-DataPath) "RouteTable.txt"; route print | Out-File -FilePath $path -Encoding UTF8; Write-Output "Saved to $path" } "Saving routing table..." })
$btnRouteView.Add_Click({
    Invoke-UiCommand {
        $out = route print 2>&1
        $txt = ($out | Out-String)
        Write-Output $txt
        Show-TextDialog -Title "Route Table" -Text $txt
    } "Routing table"
})

$btnDnsGoogle.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Set DNS to Google (8.8.8.8 / 8.8.4.4) on all active adapters?", "DNS Preset", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($res -ne "Yes") { return }
    Set-DnsAddresses -Addresses @("8.8.8.8","8.8.4.4") -Label "Google DNS"
})
$btnDnsCloudflare.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Set DNS to Cloudflare (1.1.1.1 / 1.0.0.1) on all active adapters?", "DNS Preset", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($res -ne "Yes") { return }
    Set-DnsAddresses -Addresses @("1.1.1.1","1.0.0.1") -Label "Cloudflare DNS"
})
$btnDnsQuad9.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Set DNS to Quad9 (9.9.9.9 / 149.112.112.112) on all active adapters?", "DNS Preset", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($res -ne "Yes") { return }
    Set-DnsAddresses -Addresses @("9.9.9.9","149.112.112.112") -Label "Quad9 DNS"
})
$btnDnsAuto.Add_Click({
    Invoke-UiCommand {
        Get-ActiveAdapters | Select-Object -ExpandProperty Name | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_ -ResetServerAddresses }
        Write-Output "DNS reset to automatic (DHCP)."
        [System.Windows.MessageBox]::Show("DNS reset to automatic (DHCP).", "DNS Reset", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
    } "Resetting DNS..."
})
$btnDnsCustom.Add_Click({
    $dnsInput = [Microsoft.VisualBasic.Interaction]::InputBox("Enter DNS addresses (comma separated)", "Custom DNS", "1.1.1.1,8.8.8.8")
    if (-not $dnsInput) { return }
    $addresses = $dnsInput.Split(",", [System.StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $valid = @()
    foreach ($addr in $addresses) { if (Test-Connection -ComputerName $addr -Count 1 -Quiet -ErrorAction SilentlyContinue) { $valid += $addr } else { Write-GuiLog "Unreachable DNS skipped: $addr" } }
    if (-not $valid) { [System.Windows.MessageBox]::Show("No reachable DNS addresses were provided.","Custom DNS",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Warning); return }
    Set-DnsAddresses -Addresses $valid -Label "Custom DNS"
})

$btnDohAuto.Add_Click({ Enable-AllDoh })
$btnDohDisable.Add_Click({ Disable-AllDoh })

$btnHostsUpdate.Add_Click({ Invoke-HostsUpdate })
$btnHostsEdit.Add_Click({ Show-HostsEditor })
$btnHostsBackup.Add_Click({ Invoke-UiCommand { $dest = Join-Path (Get-DataPath) ("hosts_bk_{0}.bak" -f (Get-Date -Format "yyyyMMdd_HHmmss")); Copy-Item "$env:windir\System32\drivers\etc\hosts" $dest; "Backup saved to $dest" } "Backing up hosts file..." })
$btnHostsRestore.Add_Click({
    $o=New-Object System.Windows.Forms.OpenFileDialog
    $o.Filter="*.bak;*.txt|*.bak;*.txt"
    if($o.ShowDialog()-eq"OK"){
        $restoreFile = $o.FileName
        $res = [System.Windows.MessageBox]::Show("Restore hosts file from:`n$restoreFile`n`nThis will overwrite the current hosts file. Continue?","Restore Hosts",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
        if ($res -ne "Yes") { return }
        Invoke-UiCommand{ Copy-Item $restoreFile "$env:windir\System32\drivers\etc\hosts" -Force } "Restored hosts file from $restoreFile"
        [System.Windows.MessageBox]::Show("Hosts file restored from:`n$restoreFile","Restore Hosts",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
    }
})

# --- FIREWALL ---
# --- FIREWALL DOUBLE-CLICK MODIFY ---
$lstFw.Add_MouseDoubleClick({
    $rule = $lstFw.SelectedItem
    if ($null -eq $rule) { return }

    # 1. Open existing dialog with the selected rule
    $result = Show-RuleDialog "Edit Firewall Rule" $rule

    # 2. If user clicked 'Save' (result is not null)
    if ($result) {
        try {
            # 3. Apply changes using the Name (ID) from the original object
            Set-NetFirewallRule -Name $rule.Name `
                -Direction $result.Direction `
                -Action $result.Action `
                -Protocol $result.Protocol `
                -LocalPort $result.Port `
                -ErrorAction Stop

            # 4. Refresh the list to show changes
            $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
        }
        catch {
            [System.Windows.MessageBox]::Show("Failed to update rule:`n$($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
})
# --- FIREWALL CONTEXT MENU ---
$fwCtxMenu = New-Object System.Windows.Controls.ContextMenu

# 1. Option: Copy Rule Name
$mniCopyName = New-Object System.Windows.Controls.MenuItem
$mniCopyName.Header = "Copy Rule Name"
$mniCopyName.Add_Click({
    if ($lstFw.SelectedItem) {
        try {
            [System.Windows.Forms.Clipboard]::SetText($lstFw.SelectedItem.Name)
        } catch { 
            # Fallback if clipboard is busy
        }
    }
})

# 2. Option: Copy Port/Protocol
$mniCopyPort = New-Object System.Windows.Controls.MenuItem
$mniCopyPort.Header = "Copy Port/Protocol"
$mniCopyPort.Add_Click({
    if ($lstFw.SelectedItem) {
        $info = "$($lstFw.SelectedItem.Protocol) : $($lstFw.SelectedItem.LocalPort)"
        try {
            [System.Windows.Forms.Clipboard]::SetText($info)
        } catch {}
    }
})

# 3. Option: Copy Full Details
$mniCopyAll = New-Object System.Windows.Controls.MenuItem
$mniCopyAll.Header = "Copy Full Details"
$mniCopyAll.Add_Click({
    if ($lstFw.SelectedItem) {
        # Create a nice string representation of the rule
        $rule = $lstFw.SelectedItem
        $text = "Name: $($rule.Name)`nEnabled: $($rule.Enabled)`nAction: $($rule.Action)`nDirection: $($rule.Direction)`nProtocol: $($rule.Protocol)`nPort: $($rule.LocalPort)"
        try {
            [System.Windows.Forms.Clipboard]::SetText($text)
        } catch {}
    }
})

# Add items to the menu
[void]$fwCtxMenu.Items.Add($mniCopyName)
[void]$fwCtxMenu.Items.Add($mniCopyPort)
[void]$fwCtxMenu.Items.Add((New-Object System.Windows.Controls.Separator))
[void]$fwCtxMenu.Items.Add($mniCopyAll)

# Attach to the ListView
$lstFw.ContextMenu = $fwCtxMenu
$AllFw = @()
$btnFwRefresh.Add_Click({
    $lblFwStatus.Visibility="Visible"; $lstFw.Items.Clear(); [System.Windows.Forms.Application]::DoEvents()
    $AllFw = Get-NetFirewallRule | Select-Object Name, DisplayName, @{N='Enabled';E={$_.Enabled.ToString()}}, Direction, @{N='Action';E={$_.Action.ToString()}}, @{N='Protocol';E={($_.GetNetworkProtocols().Protocol)}}, @{N='LocalPort';E={($_.GetNetworkProtocols().LocalPort)}}
    $AllFw | ForEach-Object { [void]$lstFw.Items.Add($_) }
    $lblFwStatus.Visibility="Collapsed"
})
$txtFwSearch.Add_TextChanged({
    $q=$txtFwSearch.Text; $lstFw.Items.Clear();
    if($q -ne "Search Rules..." -and $q){
        $AllFw | Where-Object { $_.DisplayName -match $q -or $_.LocalPort -match $q } | ForEach-Object { [void]$lstFw.Items.Add($_) }
    } else {
        $AllFw | ForEach-Object { [void]$lstFw.Items.Add($_) }
    }
})
$txtFwSearch.Add_GotFocus({ $t=$txtFwSearch; if($t.Text -eq "Search Rules..."){$t.Text=""} })
$btnFwAdd.Add_Click({ $d=Show-RuleDialog "Add Rule"; if($d){ try{New-NetFirewallRule -DisplayName $d.Name -Direction $d.Direction -Action $d.Action -Protocol $d.Protocol -LocalPort $d.Port -ErrorAction Stop; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))}catch{[System.Windows.MessageBox]::Show("Err: $_")} } })
$btnFwEdit.Add_Click({ if($lstFw.SelectedItem){ $d=Show-RuleDialog "Edit" $lstFw.SelectedItem; if($d){ try{Set-NetFirewallRule -Name $lstFw.SelectedItem.Name -Direction $d.Direction -Action $d.Action -Protocol $d.Protocol -LocalPort $d.Port; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))}catch{[System.Windows.MessageBox]::Show("Err: $_")} } } })
$btnFwEnable.Add_Click({ if($lstFw.SelectedItem){ Set-NetFirewallRule -Name $lstFw.SelectedItem.Name -Enabled True; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })
$btnFwDisable.Add_Click({ if($lstFw.SelectedItem){ Set-NetFirewallRule -Name $lstFw.SelectedItem.Name -Enabled False; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })
$btnFwDelete.Add_Click({ if($lstFw.SelectedItem){ Remove-NetFirewallRule -Name $lstFw.SelectedItem.Name; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })
$btnFwExport.Add_Click({ Invoke-FirewallExport })
$btnFwImport.Add_Click({ Invoke-FirewallImport; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) })
$btnFwDefaults.Add_Click({ Invoke-FirewallDefaults; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) })
$btnFwPurge.Add_Click({ Invoke-FirewallPurge; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) })

# --- Drivers ---
$btnDrvReport.Add_Click({ Invoke-DriverReport })
$btnDrvBackup.Add_Click({ Invoke-ExportDrivers })
$btnDrvGhost.Add_Click({ Show-GhostDevicesDialog })
$btnDrvClean.Add_Click({ Show-DriverCleanupDialog })
$btnDrvRestore.Add_Click({ Invoke-RestoreDrivers })
$btnDrvDisableWU.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Disable automatic driver updates via Windows Update?", "Driver Updates", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    if ($res -ne "Yes") { return }
    Invoke-DriverUpdates -Enable:$false
})
$btnDrvEnableWU.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Enable automatic driver updates via Windows Update?", "Driver Updates", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($res -ne "Yes") { return }
    Invoke-DriverUpdates -Enable:$true
})
$btnDrvDisableMeta.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Disable device metadata downloads (icons/info) from the internet?", "Device Metadata", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning)
    if ($res -ne "Yes") { return }
    Invoke-DeviceMetadata -Enable:$false
})
$btnDrvEnableMeta.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Enable device metadata downloads (icons/info) from the internet?", "Device Metadata", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
    if ($res -ne "Yes") { return }
    Invoke-DeviceMetadata -Enable:$true
})

# --- Cleanup ---
$btnCleanDisk.Add_Click({ Start-Process cleanmgr })
$btnCleanTemp.Add_Click({ Invoke-TempCleanup })
$btnCleanShortcuts.Add_Click({ Invoke-ShortcutFix })
$btnCleanReg.Add_Click({
    $form = New-Object System.Windows.Forms.Form
    $form.Text="Registry Cleanup"; $form.Size="420,290"; $form.StartPosition="CenterScreen"; $form.BackColor=[System.Drawing.Color]::FromArgb(35,35,35); $form.ForeColor="White"
    $actions = [ordered]@{
        "List Safe Keys (Obsolete)"="List"
        "Delete Safe Keys (Obsolete)"="Delete"
        "Deep Clean (Invalid Paths)"="DeepClean"  # <--- NEW OPTION
        "Backup HKLM Hive"="BackupHKLM"
        "Restore Registry Backup"="Restore"
        "Run SFC/DISM Scan"="Scan"
    }
    $y=10
    foreach ($k in $actions.Keys) {
        $btn = New-Object System.Windows.Forms.Button
        $btn.Text=$k; $btn.Tag=$actions[$k]; $btn.Left=20; $btn.Top=$y; $btn.Width=360; $btn.Height=35; $btn.BackColor="DimGray"; $btn.ForeColor="White"
        $btn.Add_Click({ param($s,$e) $form.Tag = $s.Tag; $form.Close() })
        $form.Controls.Add($btn); $y += 40
    }
    $form.ShowDialog() | Out-Null
    if ($form.Tag) { Invoke-RegistryTask -Action $form.Tag }
})
$btnCleanXbox.Add_Click({
    if ([System.Windows.MessageBox]::Show("Delete stored Xbox credentials? This signs you out of Xbox services.", "Xbox Cleanup", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning) -eq "Yes") { Start-XboxClean }
})

# --- Utilities ---
$btnUpdateServices.Add_Click({
    $confirm = [System.Windows.MessageBox]::Show("Restart Windows Update related services (wuauserv/cryptsvc/bits/appidsvc)?","Restart Update Services",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
    if ($confirm -ne "Yes") { return }
    $script:UpdateSvcResult = $null
    Invoke-UpdateServiceReset
    if ($script:UpdateSvcResult -and $script:UpdateSvcResult -like "OK*") {
        [System.Windows.MessageBox]::Show("Update services restarted successfully.","Restart Update Services",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information) | Out-Null
    } else {
        $msg = if ($script:UpdateSvcResult) { $script:UpdateSvcResult } else { "Unknown error. Check log output." }
        [System.Windows.MessageBox]::Show("Failed to restart update services.`n$msg","Restart Update Services",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Error) | Out-Null
    }
})
$btnDotNetEnable.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Set .NET roll-forward? This forces apps to use the latest installed .NET version (depending on selection).","Set .NET RollForward",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
    if ($res -ne "Yes") { return }
    $form = New-Object System.Windows.Forms.Form
    $form.Text="Set .NET RollForward"; $form.Size="320,210"; $form.StartPosition="CenterScreen"; $form.BackColor=[System.Drawing.Color]::FromArgb(35,35,35); $form.ForeColor="White"
    $opts = @("Runtime","SDK","Both")
    $y=15; $radios=@()
    foreach ($o in $opts) { $rb=New-Object System.Windows.Forms.RadioButton; $rb.Text=$o; $rb.Tag=$o; $rb.Left=20; $rb.Top=$y; $rb.ForeColor="White"; $rb.BackColor=$form.BackColor; $form.Controls.Add($rb); $radios+=$rb; $y+=30 }
    $radios[0].Checked=$true
    $ok=New-Object System.Windows.Forms.Button; $ok.Text="Apply"; $ok.DialogResult="OK"; $ok.Left=20; $ok.Top=120; $ok.Width=260; $ok.BackColor="SeaGreen"; $ok.ForeColor="White"; $form.Controls.Add($ok); $form.AcceptButton=$ok
    if ($form.ShowDialog() -eq "OK") { $choice = ($radios | Where-Object { $_.Checked }).Tag; if ($choice) { Invoke-UiCommand { Set-DotNetRollForward -Mode $choice } "Setting .NET roll-forward ($choice)..." } }
})
$btnDotNetDisable.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Remove .NET roll-forward and revert to default .NET selection?","Reset .NET RollForward",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Warning)
    if ($res -ne "Yes") { return }
    Invoke-UiCommand { Set-DotNetRollForward -Mode "Disable" } "Removing .NET roll-forward..."
})
$btnTaskManager.Add_Click({ Show-TaskManager })
$btnInstallGpedit.Add_Click({ Start-GpeditInstall })
$btnUtilTrim.Add_Click({
    $res = [System.Windows.MessageBox]::Show("Run SSD Trim/ReTrim now? This will optimize all detected SSD volumes.","Trim SSD",[System.Windows.MessageBoxButton]::YesNo,[System.Windows.MessageBoxImage]::Question)
    if ($res -ne "Yes") { return }
    Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile -NoExit -ExecutionPolicy Bypass -Command "Get-PhysicalDisk | Where-Object MediaType -eq ''SSD'' | ForEach-Object { Get-Disk | Where-Object { $_.FriendlyName -eq $_.FriendlyName } | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null | ForEach-Object { Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -Verbose } }"' -Verb RunAs -WindowStyle Normal
})
$btnUtilSysInfo.Add_Click({ Invoke-SystemReports })
$btnUtilMas.Add_Click({ Invoke-MASActivation })
$btnUpdateRepair.Add_Click({ Invoke-WindowsUpdateRepairFull })


# --- Support ---
$btnSupportDiscord.Add_Click({ Start-Process "https://discord.gg/bCQqKHGxja" })
$btnSupportIssue.Add_Click({ Start-Process "https://github.com/ios12checker/Windows-Maintenance-Tool/issues/new/choose" })
$btnDonateIos12.Add_Click({ Start-Process "https://github.com/sponsors/ios12checker" })
$btnCreditLilBattiCLI.Add_Click({ Start-Process "https://github.com/ios12checker" })
$btnCreditChaythonFeatures.Add_Click({ Start-Process "https://github.com/Chaython" })
$btnCreditChaythonCLI.Add_Click({ Start-Process "https://github.com/Chaython" })
$btnCreditChaythonGUI.Add_Click({ Start-Process "https://github.com/Chaython" })
$btnCreditIos12checker.Add_Click({ Start-Process "https://github.com/ios12checker" })
$btnDonate.Add_Click({ Start-Process "https://github.com/sponsors/Chaython" })

$btnNavDownloads.Add_Click({ Show-DownloadStats })

# --- LAUNCH ---
Invoke-UpdateCheck
$window.Add_Loaded({ (Get-Ctrl "btnTabUpdates").RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) })
$window.ShowDialog() | Out-Null