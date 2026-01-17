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
$AppVersion = "4.11"
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

# ENABLE HIGH-DPI AWARENESS (Fixes blurry text on 4K screens)
if ([Environment]::OSVersion.Version.Major -ge 6) {
    $code = @'
    [DllImport("user32.dll")]
    public static extern bool SetProcessDPIAware();
'@
    $Win32Dpi = Add-Type -MemberDefinition $code -Name "Win32Dpi" -PassThru
    $Win32Dpi::SetProcessDPIAware() | Out-Null
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
    param(
        [scriptblock]$Sb, 
        $Msg="Processing...", 
        [object[]]$ArgumentList = @()
    )
    [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
    Write-GuiLog $Msg
    try { 
        # Pass arguments to the scriptblock using splatting
        $res = & $Sb @ArgumentList | Out-String
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

# --- SETTINGS MANAGER ---
function Save-WmtSettings {
    param($Settings)
    $path = Join-Path (Get-DataPath) "settings.json"
    try {
        # Convert Hashtable/OrderedDictionary to generic Object for cleaner JSON
        $saveObj = [PSCustomObject]@{
            TempCleanup  = $Settings.TempCleanup
            RegistryScan = $Settings.RegistryScan
            WingetIgnore = $Settings.WingetIgnore
            LoadWinapp2  = [bool]$Settings.LoadWinapp2 # Ensure Boolean
        }
        $saveObj | ConvertTo-Json -Depth 5 | Set-Content $path -Force
    } catch {
        Write-Warning "Failed to save settings: $_"
    }
}

function Get-WmtSettings {
    $path = Join-Path (Get-DataPath) "settings.json"
    
    # Default Structure
    $defaults = @{
        TempCleanup  = @{}
        RegistryScan = @{}
        WingetIgnore = @()
        LoadWinapp2  = $false 
    }
    
    if (Test-Path $path) {
        try {
            $json = Get-Content $path -Raw | ConvertFrom-Json
            
            if ($json.TempCleanup) { 
                foreach ($p in $json.TempCleanup.PSObject.Properties) { $defaults.TempCleanup[$p.Name] = $p.Value } 
            }
            if ($json.RegistryScan) { 
                foreach ($p in $json.RegistryScan.PSObject.Properties) { $defaults.RegistryScan[$p.Name] = $p.Value } 
            }
            
            # --- FIX: Force clean string array ---
            if ($json.PSObject.Properties["WingetIgnore"]) {
                $raw = $json.WingetIgnore
                $clean = New-Object System.Collections.ArrayList
                if ($raw) {
                    foreach ($item in $raw) {
                        # "$item" forces it to be text, removing any object wrappers
                        [void]$clean.Add("$item".Trim())
                    }
                }
                $defaults.WingetIgnore = $clean.ToArray()
            }
            
            if ($json.PSObject.Properties["LoadWinapp2"]) { 
                $defaults.LoadWinapp2 = [bool]$json.LoadWinapp2
            }
        } catch { 
            Write-GuiLog "Error loading settings: $($_.Exception.Message)" 
        }
    }
    return $defaults
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
function Start-UpdateCheckBackground {
    # 1. Access LogBox
    $lbStart = Get-Ctrl "LogBox"
    if ($lbStart) { 
        $lbStart.AppendText("`n[UPDATE] Checking for updates...`n") 
        $lbStart.ScrollToEnd()
    }

    $localVersionStr = $script:AppVersion

    # 2. Start Background Job
    $script:UpdateJob = Start-Job -ScriptBlock {
        param($CurrentVer)
        
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        $jobRes = @{
            Status        = "Failed"
            RemoteVersion = "0.0"
            Content       = ""
            Error         = ""
        }

        try {
            $time = Get-Date -Format "yyyyMMddHHmmss"
            $url  = "https://raw.githubusercontent.com/ios12checker/Windows-Maintenance-Tool/main/WMT-GUI.ps1?t=$time"
            
            $req = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 15
            $content = $req.Content
            $jobRes.Content = $content

            if ($content -match '\$AppVersion\s*=\s*"(\d+(\.\d+)+)"') {
                $jobRes.RemoteVersion = $matches[1]
                $jobRes.Status = "Success"
            }
            elseif ($content -match "Windows Maintenance Tool.*v(\d+(\.\d+)+)") {
                $jobRes.RemoteVersion = $matches[1]
                $jobRes.Status = "Success"
            } else {
                $jobRes.Error = "Version string not found."
            }
        } catch {
            $jobRes.Error = $_.Exception.Message
        }

        return ($jobRes | ConvertTo-Json -Depth 2 -Compress)

    } -ArgumentList $localVersionStr

    # 3. Setup Timer
    $script:UpdateTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:UpdateTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:UpdateTicks = 0
    
    $script:UpdateTimer.Add_Tick({
        $lb = Get-Ctrl "LogBox"
        $script:UpdateTicks++
        
        # A. Timeout Check (30s)
        if ($script:UpdateTicks -gt 60) {
            $script:UpdateTimer.Stop()
            if ($script:UpdateJob) { Stop-Job -Job $script:UpdateJob; Remove-Job -Job $script:UpdateJob }
            $script:UpdateJob = $null
            if ($lb) { $lb.AppendText("[UPDATE] Error: Request timed out.`n"); $lb.ScrollToEnd() }
            return
        }

        # B. Check Job Status
        if ($script:UpdateJob.State -ne 'Running') {
            $script:UpdateTimer.Stop()
            
            $rawOutput = Receive-Job -Job $script:UpdateJob
            Remove-Job -Job $script:UpdateJob
            $script:UpdateJob = $null
            
            if (-not $rawOutput) {
                 if ($lb) { $lb.AppendText("[UPDATE] Error: Job returned no data.`n"); $lb.ScrollToEnd() }
                 return
            }

            try {
                $jsonStr = $rawOutput | Select-Object -Last 1
                $jobResult = $jsonStr | ConvertFrom-Json
                
                if ($jobResult.Status -eq "Success") {
                    $localVer  = [Version]$script:AppVersion
                    $remoteVer = [Version]$jobResult.RemoteVersion
                    
                    if ($lb) { 
                        $lb.AppendText("[UPDATE] Local: v$localVer | Remote: v$remoteVer`n")
                        $lb.ScrollToEnd()
                    }

                    if ($remoteVer -gt $localVer) {
                        if ($lb) { $lb.AppendText(" -> Update Available!`n"); $lb.ScrollToEnd() }
                        
                        $msg = "A new version is available!`n`nLocal Version:  v$localVer`nRemote Version: v$remoteVer`n`nDo you want to update now?"
                        $mbRes = [System.Windows.MessageBox]::Show($msg, "Update Available", [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Information)
                        
                        if ($mbRes -eq "Yes") {
                            $remoteContent = $jobResult.Content
                            $backupName = "$(Split-Path $PSCommandPath -Leaf).bak"
                            $backupPath = Join-Path (Get-DataPath) $backupName
                            Copy-Item -Path $PSCommandPath -Destination $backupPath -Force
                            Set-Content -Path $PSCommandPath -Value $remoteContent -Encoding UTF8
                            
                            [System.Windows.MessageBox]::Show("Update complete! Restarting...", "Updated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
                            Start-Process powershell.exe -ArgumentList "-File `"$PSCommandPath`""
                            exit
                        }
                    } else {
                        if ($lb) { $lb.AppendText(" -> System is up to date.`n"); $lb.ScrollToEnd() }
                    }
                } else {
                    if ($lb) { $lb.AppendText("[UPDATE] Failed: $($jobResult.Error)`n"); $lb.ScrollToEnd() }
                }
            } catch {
                if ($lb) { $lb.AppendText("[UPDATE] Processing Error: $($_.Exception.Message)`n"); $lb.ScrollToEnd() }
            }
        }
    })
    
    $script:UpdateTimer.Start()
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
        param($addrList, $labelText)
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
    } "Applying $labelText..." -ArgumentList (,$addrList), $labelText
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
    } "Enabling DoH for known DNS providers..." -ArgumentList (,$dnsServers)
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
    } "Disabling DoH entries..." -ArgumentList (,$dnsServers)
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
# ==========================================
# WINAPP2.INI INTEGRATION
# ==========================================

function Expand-EnvPath {
    param($Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    # Expand standard vars (%AppData%, etc)
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    # Handle common Winapp2 specific variables if needed (e.g. %ProgramFiles%)
    return $expanded
}

function Get-Winapp2Rules {
    param([switch]$Download)

    $dataPath  = Get-DataPath
    $iniPath   = Join-Path $dataPath "winapp2.ini"
    $cachePath = Join-Path $dataPath "winapp2_cache.json" 

    # --- 1. SMART CACHE CHECK ---
    $forceRebuild = $false
    
    if (Test-Path $cachePath) {
        if ($PSCommandPath -and (Test-Path $PSCommandPath)) {
            $scriptTime = (Get-Item $PSCommandPath).LastWriteTime
            $cacheTime  = (Get-Item $cachePath).LastWriteTime
            if ($scriptTime -gt $cacheTime) { 
                $forceRebuild = $true 
            }
        }
    }

    # --- 2. DOWNLOAD ---
    if ($Download) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Add-Type -AssemblyName System.Net.Http
            $client = New-Object System.Net.Http.HttpClient
            $client.Timeout = [TimeSpan]::FromSeconds(15)
            
            $url = "https://cdn.jsdelivr.net/gh/MoscaDotTo/Winapp2@master/Winapp2.ini"
            $response = $client.GetAsync($url).Result
            if ($response.IsSuccessStatusCode) {
                $contentBytes = $response.Content.ReadAsByteArrayAsync().Result
                $iniContent = [System.Text.Encoding]::UTF8.GetString($contentBytes)
                [System.IO.File]::WriteAllText($iniPath, $iniContent)
                $forceRebuild = $true
            }
            $client.Dispose()
        } catch { Write-GuiLog "Download Warning: $($_.Exception.Message)" }
    }

    # --- 3. CACHE LOAD ---
    if (-not $forceRebuild -and (Test-Path $cachePath)) {
        try { 
            $cachedRules = Get-Content $cachePath -Raw | ConvertFrom-Json
            if ($cachedRules.Count -gt 5) { return $cachedRules }
        } catch {}
    }

    # --- 4. PARSE INI ---
    $iniContent = $null
    if (Test-Path $iniPath) { $iniContent = Get-Content $iniPath -Raw }
    if ([string]::IsNullOrWhiteSpace($iniContent)) { return @() }

    $rules = New-Object System.Collections.Generic.List[Object]
    
    $envVars = @{ 
        "%Documents%" = [Environment]::GetFolderPath("MyDocuments")
        "%ProgramFiles%" = $env:ProgramFiles
        "%ProgramFiles(x86)%" = ${env:ProgramFiles(x86)}
        "%SystemDrive%" = $env:SystemDrive
        "%AppData%" = $env:APPDATA
        "%LocalAppData%" = $env:LOCALAPPDATA
        "%CommonAppData%" = $env:ProgramData
        "%UserProfile%" = $env:USERPROFILE
    }
    $dirCache = @{} 

    $lines = $iniContent -split "\r?\n"
    $currentApp = $null; $skipApp = $false; $hasDetect = $false

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line[0] -eq ';') { continue }

        if ($line[0] -eq '[') {
            if ($currentApp -and -not $skipApp) { $rules.Add([PSCustomObject]$currentApp) }
            $appName = $line.Trim(" []")
            $currentApp = [ordered]@{ 
                Name = $appName
                ID = "Winapp2_" + ($appName -replace '[^a-zA-Z0-9]','')
                Section = "Applications"
                AppGroup = "General"
                Paths = New-Object System.Collections.Generic.List[Object]
                Desc = ""
                IsInternal = $false
            }
            $skipApp = $false; $hasDetect = $false
            continue
        }

        $eqIndex = $line.IndexOf('=')
        if ($eqIndex -le 0) { continue }
        if ($skipApp) { continue }

        $key = $line.Substring(0, $eqIndex).Trim()
        $val = $line.Substring($eqIndex + 1).Trim()

        if ($key -eq "Section") { $currentApp.Section = $val }
        elseif ($key.StartsWith("Detect")) {
            if (-not $hasDetect) { $hasDetect = $true; $skipApp = $true } 
            
            if ($val.IndexOf('%') -ge 0) { 
                foreach ($k in $envVars.Keys) { 
                    if ($val.Contains($k)) { $val = $val.Replace($k, $envVars[$k]) } 
                } 
            }

            # Registry Detection
            if ($val -match "^HK") {
                $regPath = $val -replace "^(?i)HKCU", "Registry::HKEY_CURRENT_USER" `
                                -replace "^(?i)HKLM", "Registry::HKEY_LOCAL_MACHINE" `
                                -replace "^(?i)HKCR", "Registry::HKEY_CLASSES_ROOT" `
                                -replace "^(?i)HKU",  "Registry::HKEY_USERS"
                if (Test-Path $regPath) { $skipApp = $false }
            } 
            # File Detection
            else {
                try {
                    $parent = [System.IO.Path]::GetDirectoryName($val)
                    if (-not [string]::IsNullOrWhiteSpace($parent)) {
                        if (-not $dirCache.ContainsKey($parent)) { $dirCache[$parent] = (Test-Path $parent) }
                        if ($dirCache[$parent]) { 
                            if (Test-Path $val) { $skipApp = $false } 
                        }
                    }
                } catch { 
                    if (Test-Path $val) { $skipApp = $false } 
                }
            }
        }
        elseif ($key.StartsWith("FileKey")) {
            $parts = $val -split "\|"
            if ($parts.Count -ge 2) {
                $rawPath = $parts[0]
                if ($rawPath.IndexOf('%') -ge 0) { foreach ($k in $envVars.Keys) { if ($rawPath.Contains($k)) { $rawPath = $rawPath.Replace($k, $envVars[$k]) } } }
                $rawPath = [Environment]::ExpandEnvironmentVariables($rawPath)
                if (-not $skipApp) { $currentApp.Paths.Add(@{ Path = $rawPath; Pattern = $parts[1]; Options = if ($parts.Count -gt 2) { $parts[2] } else { "" } }) }
            }
        }
        elseif ($key -eq "Description") { $currentApp.Desc = $val }
    }
    if ($currentApp -and -not $skipApp) { $rules.Add([PSCustomObject]$currentApp) }

    # --- 5. CATEGORIZATION ---
    $finalList = $rules | Where-Object { $_.Paths.Count -gt 0 }
    
    foreach ($app in $finalList) {
        $name = $app.Name

        # 1. BROWSERS
        if ($name -match "^Google Chrome") { $app.AppGroup = "Google Chrome"; $app.Section = "Browsers / Internet"; $app.Name = $name -replace "Google Chrome\s*", "" }
        elseif ($name -match "^Microsoft Edge") { $app.AppGroup = "Microsoft Edge"; $app.Section = "Browsers / Internet"; $app.Name = $name -replace "Microsoft Edge\s*", "" }
        elseif ($name -match "^Mozilla Firefox") { $app.AppGroup = "Mozilla Firefox"; $app.Section = "Browsers / Internet"; $app.Name = $name -replace "Mozilla Firefox\s*", "" }
        elseif ($name -match "^Opera") { $app.AppGroup = "Opera"; $app.Section = "Browsers / Internet" }
        elseif ($name -match "^Brave") { $app.AppGroup = "Brave"; $app.Section = "Browsers / Internet" }

        # 2. SPECIFIC PRODUCTIVITY
        elseif ($name -match "PowerToys") { 
            $app.Section = "Productivity"
            $app.AppGroup = "Microsoft PowerToys"
            $app.Name = $name -replace "^Microsoft\s*PowerToys\s*", "" 
        }
        elseif ($name -match "^Microsoft\sOffice|^Office\s") { $app.Section = "Productivity"; $app.AppGroup = "Microsoft Office" }
        elseif ($name -match "^Adobe\s") { $app.Section = "Productivity"; $app.AppGroup = "Adobe"; $app.Name = $name -replace "^Adobe\s+", "" }
        
        # 3. GAMES (New Category)
        elseif ($name -match "(?i)\b(Steam|Epic Games|Origin|Uplay|Ubisoft Connect|Battle.net|GOG Galaxy)\b") {
            $app.Section = "Games"
            $app.AppGroup = $name -split " " | Select-Object -First 1
        }

        # 4. CHAT APPS
        elseif ($name -match "(?i)\b(Discord|Spotify|Skype|TeamViewer|Zoom|Slack|Telegram|WhatsApp)\b") { 
            $app.Section = "Internet & Chat"
            $app.AppGroup = $name -split " " | Select-Object -First 1 
        }

        # 5. SYSTEM CATCH-ALL
        elseif ($name -match "^Windows\s" -or $name -eq "Windows" -or $name -match "Defender|Explorer|Store|Management Console") {
            $app.Section = "System"
            $app.AppGroup = "Windows"
            $app.Name = $name -replace "^Windows\s+", "" 
        }
    }

    try { $finalList | ConvertTo-Json -Depth 5 | Set-Content $cachePath -Force } catch {}
    
    return $finalList
}

function Show-AdvancedCleanupSelection {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $currentSettings = Get-WmtSettings
    $savedStates = $currentSettings.TempCleanup
    $isWinapp2Enabled = $currentSettings.LoadWinapp2

    # --- FORM SETUP ---
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Advanced Cleanup Selection"
    $form.Size = New-Object System.Drawing.Size(650, 850)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $form.ForeColor = "White"

    # --- 1. TOP PANEL (Search) ---
    $topPanel = New-Object System.Windows.Forms.Panel
    $topPanel.Dock = "Top"; $topPanel.Height = 50
    $topPanel.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40)

    $chkToggleWinapp2 = New-Object System.Windows.Forms.CheckBox
    $chkToggleWinapp2.Text = "Load Community Rules *"
    $chkToggleWinapp2.Size = "220, 30"; $chkToggleWinapp2.Location = "15, 10"
    $chkToggleWinapp2.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $chkToggleWinapp2.ForeColor = "White"
    $chkToggleWinapp2.Checked = $isWinapp2Enabled
    $tt = New-Object System.Windows.Forms.ToolTip
    $tt.SetToolTip($chkToggleWinapp2, "Enables 1000+ extra rules from Winapp2.ini")
    $topPanel.Controls.Add($chkToggleWinapp2)

    $txtSearch = New-Object System.Windows.Forms.TextBox
    $txtSearch.Size = "200, 25"; $txtSearch.Location = "420, 12"
    $txtSearch.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
    $txtSearch.ForeColor = "White"
    $txtSearch.BorderStyle = "FixedSingle"
    $topPanel.Controls.Add($txtSearch)
    
    $lblSearch = New-Object System.Windows.Forms.Label
    $lblSearch.Text = "Search:"
    $lblSearch.AutoSize = $true; $lblSearch.Location = "370, 15"
    $topPanel.Controls.Add($lblSearch)

    # --- 2. BOTTOM PANEL (Buttons) ---
    $btnPanel = New-Object System.Windows.Forms.Panel
    $btnPanel.Dock = "Bottom"; $btnPanel.Height = 60
    $btnPanel.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 25)

    $btnClean = New-Object System.Windows.Forms.Button
    $btnClean.Text = "Clean Selected"
    $btnClean.Size = "140, 35"; $btnClean.Location = "470, 12"
    $btnClean.BackColor = "SeaGreen"; $btnClean.ForeColor = "White"; $btnClean.FlatStyle = "Flat"
    $btnClean.DialogResult = "OK"
    $btnPanel.Controls.Add($btnClean)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Size = "100, 35"; $btnCancel.Location = "360, 12"
    $btnCancel.BackColor = "DimGray"; $btnCancel.ForeColor = "White"; $btnCancel.FlatStyle = "Flat"
    $btnCancel.DialogResult = "Cancel"
    $btnPanel.Controls.Add($btnCancel)

    # --- 3. MAIN CONTENT PANEL ---
    $mainPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $mainPanel.FlowDirection = "TopDown"; $mainPanel.WrapContents = $false
    $mainPanel.AutoScroll = $true; $mainPanel.Dock = "Fill"
    $mainPanel.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $mainPanel.Padding = New-Object System.Windows.Forms.Padding(5, 10, 0, 0)

    $form.Controls.Add($btnPanel)
    $form.Controls.Add($topPanel)
    $form.Controls.Add($mainPanel)
    $mainPanel.BringToFront()

    # --- INTERNAL RULES ---
    $internalRules = @(
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Windows"; Name="Temporary Files"; Key="TempFiles"; Desc="User and System Temp"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Windows"; Name="Recycle Bin"; Key="RecycleBin"; Desc="Empties Recycle Bin"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Windows"; Name="Error Logs (WER)"; Key="WER"; Desc="Crash dumps"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Windows"; Name="DNS Cache"; Key="DNS"; Desc="Network cache"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Explorer"; Name="Thumbnail Cache"; Key="Thumbnails"; Desc="Explorer thumbnails"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Explorer"; Name="Recent Items"; Key="Recent"; Desc="Recent files list"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="System"; AppGroup="Explorer"; Name="Run History"; Key="RunMRU"; Desc="Run dialog history"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="Browsers / Internet"; AppGroup="Google Chrome"; Name="Cache (Internal)"; Key="Chrome"; Desc="Standard Cache"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="Browsers / Internet"; AppGroup="Microsoft Edge"; Name="Cache (Internal)"; Key="Edge"; Desc="Standard Cache"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="Browsers / Internet"; AppGroup="Mozilla Firefox"; Name="Cache (Internal)"; Key="Firefox"; Desc="Standard Cache"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="Browsers / Internet"; AppGroup="Brave"; Name="Cache (Internal)"; Key="Brave"; Desc="Standard Cache"; IsInternal=$true }
        [PSCustomObject][ordered]@{ Section="Browsers / Internet"; AppGroup="Opera"; Name="Cache (Internal)"; Key="Opera"; Desc="Standard Cache"; IsInternal=$true }
    )

    $RenderList = {
        param($IncludeWinapp2, $InteractiveMode)
        
        $mainPanel.SuspendLayout()
        $mainPanel.Controls.Clear()
        
        $allRules = @($internalRules)

        if ($IncludeWinapp2) {
            $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = "Loading..."; $lbl.ForeColor = "Yellow"; $lbl.AutoSize = $true; $lbl.Margin = "10,0,0,0"
            $mainPanel.Controls.Add($lbl); $form.Update()

            $iniPath = Join-Path (Get-DataPath) "winapp2.ini"
            $shouldDownload = $false
            if (Test-Path $iniPath) {
                if ((Get-Item $iniPath).LastWriteTime -lt (Get-Date).AddDays(-7) -and $InteractiveMode) {
                   if ([System.Windows.Forms.MessageBox]::Show("Update Rules?", "Update", "YesNo") -eq "Yes") { $shouldDownload = $true }
                }
            } elseif ($InteractiveMode) { $shouldDownload = $true }

            try { $winRules = Get-Winapp2Rules -Download:$shouldDownload; $allRules += $winRules } catch {}
            if ($mainPanel.Controls.Count -gt 0) { $mainPanel.Controls.RemoveAt(0) }
        }

        $global:checkboxes = @{}
        $global:sections = @()

        $sections = $allRules | Select-Object -ExpandProperty Section -Unique | Sort-Object

        foreach ($sec in $sections) {
            $secPanel = New-Object System.Windows.Forms.Panel
            $secPanel.Size = "600, 35"; $secPanel.Margin = "5, 10, 0, 0"
            $secPanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
            $secPanel.Tag = "HEADER"
            
            $secChk = New-Object System.Windows.Forms.CheckBox
            $secChk.Text = $sec
            $secChk.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
            $secChk.ForeColor = [System.Drawing.Color]::DeepSkyBlue
            $secChk.AutoSize = $true; $secChk.Location = "5, 5"
            $secPanel.Controls.Add($secChk)
            $mainPanel.Controls.Add($secPanel)
            
            $global:sections += $secPanel

            $itemFlow = New-Object System.Windows.Forms.FlowLayoutPanel
            $itemFlow.FlowDirection = "TopDown"; $itemFlow.AutoSize = $true
            $itemFlow.Margin = "25, 0, 0, 0"
            $itemFlow.Tag = "FLOW"

            $secItems = $allRules | Where-Object { $_.Section -eq $sec } | Sort-Object AppGroup, Name
            $childChecks = @()
            $currentGroup = $null
            $isSecChecked = $true

            foreach ($item in $secItems) {
                if ($item.AppGroup -ne $currentGroup) {
                    $currentGroup = $item.AppGroup
                    $grpLbl = New-Object System.Windows.Forms.Label
                    $grpLbl.Text = $currentGroup
                    $grpLbl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                    $grpLbl.ForeColor = [System.Drawing.Color]::LightGray
                    $grpLbl.AutoSize = $true; $grpLbl.Margin = "0, 10, 0, 2"
                    $grpLbl.Tag = "GROUPHEADER"
                    $itemFlow.Controls.Add($grpLbl)
                }

                $itemKey = if ($item.Key) { $item.Key } else { $item.ID }
                $chk = New-Object System.Windows.Forms.CheckBox
                
                if ($item.IsInternal) {
                    $chk.Text = $item.Name
                } else {
                    $cleanName = $item.Name.Trim(" *")
                    $chk.Text = "$cleanName (*)"
                    $chk.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 255)
                }
                
                $chk.AutoSize = $true; $chk.Margin = "10, 0, 0, 2"
                $chk.Tag = if ($item.IsInternal) { $itemKey } else { $item }
                
                if ($savedStates.ContainsKey($itemKey)) { $chk.Checked = $savedStates[$itemKey] }
                else { $chk.Checked = ($item.IsInternal -eq $true) }
                
                if (-not $chk.Checked) { $isSecChecked = $false }
                if ($item.Desc) { $tt.SetToolTip($chk, $item.Desc) }

                $itemFlow.Controls.Add($chk)
                $global:checkboxes[$itemKey] = $chk
                $childChecks += $chk
            }

            $secChk.Checked = $isSecChecked
            $mainPanel.Controls.Add($itemFlow)
            $secChk.Add_Click({ param($s,$e) foreach ($c in $childChecks) { $c.Checked = $s.Checked } }.GetNewClosure())
        }
        $mainPanel.ResumeLayout()
    }

    & $RenderList -IncludeWinapp2 $isWinapp2Enabled -InteractiveMode $false

    # --- SEARCH LOGIC ---
    $txtSearch.Add_TextChanged({
        $q = $txtSearch.Text.ToLower()
        $mainPanel.SuspendLayout()
        
        for ($i = 0; $i -lt $mainPanel.Controls.Count; $i++) {
            $ctrl = $mainPanel.Controls[$i]
            
            if ($ctrl.Tag -eq "FLOW") {
                $hasVisibleChildren = $false
                foreach ($child in $ctrl.Controls) {
                    if ($child -is [System.Windows.Forms.CheckBox]) {
                        if ($child.Text.ToLower().Contains($q)) {
                            $child.Visible = $true
                            $hasVisibleChildren = $true
                        } else {
                            $child.Visible = $false
                        }
                    } 
                    elseif ($child.Tag -eq "GROUPHEADER") {
                        # Hide group headers during search to save space
                        $child.Visible = ($q.Length -eq 0) 
                    }
                }
                $ctrl.Visible = $hasVisibleChildren
                # Toggle SECTION Header
                if ($i -gt 0) { $mainPanel.Controls[$i-1].Visible = $hasVisibleChildren }
            }
        }
        $mainPanel.ResumeLayout()
    })

    $chkToggleWinapp2.Add_Click({
        $currentSettings.LoadWinapp2 = $chkToggleWinapp2.Checked
        Save-WmtSettings -Settings $currentSettings
        & $RenderList -IncludeWinapp2 $chkToggleWinapp2.Checked -InteractiveMode $true
    })

    $form.AcceptButton = $btnClean
    $form.CancelButton = $btnCancel

    if ($form.ShowDialog() -eq "OK") {
        $selectedItems = @()
        foreach ($key in $global:checkboxes.Keys) {
            $cb = $global:checkboxes[$key]
            # --- FIX APPLIED HERE ---
            # Removed "-and $cb.Visible". If it is Checked, we clean it, 
            # regardless of whether the user has currently filtered it out via Search.
            if ($cb.Checked) { $selectedItems += $cb.Tag }
            $currentSettings.TempCleanup[$key] = $cb.Checked
        }
        $currentSettings.LoadWinapp2 = $chkToggleWinapp2.Checked
        Save-WmtSettings -Settings $currentSettings
        return $selectedItems
    }
    return $null
}

function Invoke-TempCleanup {
    # 1. GET SELECTION
    $selections = Show-AdvancedCleanupSelection
    if (-not $selections -or $selections.Count -eq 0) { 
        Write-GuiLog "Cleanup canceled: No items selected."
        return 
    }

    # 2. SETUP PROGRESS UI
    $pForm = New-Object System.Windows.Forms.Form
    $pForm.Text = "Deep Cleaning System"
    $pForm.Size = "500,160"
    $pForm.StartPosition = "CenterScreen"
    $pForm.ControlBox = $false
    $pForm.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $pForm.ForeColor = "White"

    $pLabel = New-Object System.Windows.Forms.Label
    $pLabel.Location = "20,15"; $pLabel.Size = "460,20"
    $pLabel.Text = "Initializing..."
    $pForm.Controls.Add($pLabel)

    $pStatus = New-Object System.Windows.Forms.Label
    $pStatus.Location = "20,40"; $pStatus.Size = "460,20"
    $pStatus.ForeColor = "Gray"
    $pStatus.Text = "Preparing..."
    $pForm.Controls.Add($pStatus)

    $pBar = New-Object System.Windows.Forms.ProgressBar
    $pBar.Location = "20,70"; $pBar.Size = "440,20"
    $pForm.Controls.Add($pBar)

    $pForm.Show()
    [System.Windows.Forms.Application]::DoEvents()

    # 3. STATS TRACKING
    $stats = @{
        Deleted = 0
        Bytes   = 0
        Progress = 0.0
    }
    
    $ruleWeight = 100.0 / ($selections.Count)

    # --- HELPER: ROBUST CLEANER ---
    function Invoke-RobustClean {
        param($Path, $Pattern="*", $Recurse=$true)
        
        $Path = [Environment]::ExpandEnvironmentVariables($Path)
        if (-not (Test-Path $Path)) { return }

        $pStatus.Text = "Scanning: $(Split-Path $Path -Leaf)"
        [System.Windows.Forms.Application]::DoEvents()

        try {
            $items = Get-ChildItem -Path $Path -Filter $Pattern -Recurse:$Recurse -Force -File -ErrorAction SilentlyContinue
            
            foreach ($item in $items) {
                try {
                    $size = $item.Length
                    $item.Delete()
                    
                    $stats.Deleted++
                    $stats.Bytes += $size
                    
                    if ($stats.Deleted % 50 -eq 0) {
                        $mb = [math]::Round($stats.Bytes / 1MB, 2)
                        $pLabel.Text = "Removed: $($stats.Deleted) | Recovered: $mb MB"
                        [System.Windows.Forms.Application]::DoEvents()
                    }
                } catch {}
            }

            if ($Recurse) {
                Get-ChildItem -Path $Path -Recurse -Directory -Force -ErrorAction SilentlyContinue | 
                    Sort-Object FullName -Descending | 
                    ForEach-Object { try { if ((Get-ChildItem -Path $_.FullName -Force).Count -eq 0) { Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue } } catch {} }
            }
        } catch {}
    }

    # 4. MAIN EXECUTION LOOP
    Write-GuiLog "--- Starting Cleanup ---"
    
    try {
        foreach ($item in $selections) {
            if ($pForm.IsDisposed) { break }

            # Snapshot bytes BEFORE this item
            $startBytes = $stats.Bytes

            # Update UI
            $stats.Progress += $ruleWeight
            $pBar.Value = [int]$stats.Progress
            
            # Determine Name for Logging
            $itemName = if ($item -is [string]) { $item } else { $item.Name }
            $pLabel.Text = "Cleaning: $itemName"

            # --- A. WINAPP2 RULES (Object) ---
            if ($item -is [System.Collections.IDictionary] -or $item -is [PSCustomObject]) {
                foreach ($rule in $item.Paths) {
                    $isRecurse = ($rule.Options -notmatch "REMOVESELF")
                    Invoke-RobustClean -Path $rule.Path -Pattern $rule.Pattern -Recurse $isRecurse
                }
            }
            # --- B. INTERNAL RULES (String) ---
            else {
                switch ($item) {
                    "TempFiles" { 
                        Invoke-RobustClean $env:TEMP
                        Invoke-RobustClean "$env:SystemRoot\Temp"
                    }
                    "RecycleBin" { 
                        # Recycle Bin is tricky to measure file-by-file without permission errors,
                        # so we often rely on Windows API. For now, we attempt standard clear.
                        try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch {}
                    }
                    "WER" { Invoke-RobustClean "$env:ProgramData\Microsoft\Windows\WER" }
                    "DNS" { Clear-DnsClientCache -ErrorAction SilentlyContinue }
                    "Thumbnails" { Invoke-RobustClean "$env:LOCALAPPDATA\Microsoft\Windows\Explorer" -Pattern "thumbcache_*.db" -Recurse:$false }
                    "Recent" { Invoke-RobustClean "$env:APPDATA\Microsoft\Windows\Recent" }
                    "RunMRU" { Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue }
                    "Edge"    { Invoke-RobustClean "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" }
                    "Chrome"  { Invoke-RobustClean "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" }
                    "Brave"   { Invoke-RobustClean "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache" }
                    "Firefox" { 
                        if (Test-Path "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles") {
                            Get-ChildItem "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles" -Directory | ForEach-Object { Invoke-RobustClean "$($_.FullName)\cache2\entries" }
                        }
                    }
                    "Opera"   { Invoke-RobustClean "$env:APPDATA\Opera Software\Opera Stable\Cache" }
                    "OperaGX" { Invoke-RobustClean "$env:APPDATA\Opera Software\Opera GX Stable\Cache" }
                }
            }

            # Calculate difference for this specific item
            $diffBytes = $stats.Bytes - $startBytes
            
            # Log it if we actually removed something
            if ($diffBytes -gt 0) {
                $itemMB = [math]::Round($diffBytes / 1MB, 2)
                Write-GuiLog "Cleaned $itemName : $itemMB MB"
            }
        }
    } catch {
        Write-GuiLog "Error: $($_.Exception.Message)"
    } finally {
        $pForm.Close()
    }

    # 5. FINAL REPORT
    $finalMB = [math]::Round($stats.Bytes / 1MB, 2)
    Write-GuiLog "Total Removed: $finalMB MB"
    
    $msg = "Cleanup Complete.`n`nFiles Removed: $($stats.Deleted)`nSpace Recovered: $finalMB MB"
    [System.Windows.Forms.MessageBox]::Show($msg, "Cleanup Results", [System.Windows.Forms.MessageBoxButton]::OK, [System.Windows.Forms.MessageBoxImage]::Information) | Out-Null
}

# --- Registry Scan Selection UI ---
function Show-RegScanSelection {
    # 1. LOAD SETTINGS
    $currentSettings = Get-WmtSettings
    $savedStates = $currentSettings.RegistryScan

    # --- Form Setup ---
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Select Registry Scan Targets"
    $f.Size = "600, 550"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $f.ForeColor = "White"
    $f.FormBorderStyle = "FixedDialog"
    $f.MaximizeBox = $false

    # --- Header Label ---
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Select areas to scan:"
    $lbl.AutoSize = $true; $lbl.Location = "20, 15"
    $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $f.Controls.Add($lbl)

    # --- Scrollable Panel for Checkboxes ---
    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Location = "20, 50"; $pnl.Size = "550, 380"; $pnl.AutoScroll = $true
    $f.Controls.Add($pnl)

    # --- Define Categories ---
    $categories = [ordered]@{
        "Missing Shared DLLs"            = "SharedDLLs"
        "Unused File Extensions (System)"= "Ext"
        "Unused File Extensions (User)"  = "FileExts"
        "ActiveX & COM Issues"           = "ActiveX"
        "Type Libraries (TLB)"           = "TypeLib"
        "Application Paths"              = "AppPaths"
        "Applications (Registered)"      = "Apps"
        "Installer Folders"              = "Installer"
        "Obsolete Software (Uninstall)"  = "Uninstall"
        "Run At Startup"                 = "Startup"
        "Invalid Default Icons"          = "Icons"
        "File Associations"              = "ProgIDs"
        "Windows Services"               = "Services"
        "MUI Cache (MRU Lists)"          = "MuiCache"
        "Compatibility Store (Flags)"    = "AppCompat"
        "Firewall Rules"                 = "Firewall"
    }

    # --- Generate Checkboxes Dynamically ---
    $chkBoxes = @(); $y = 0; $count = 0
    foreach ($key in $categories.Keys) {
        $tag = $categories[$key]
        $chk = New-Object System.Windows.Forms.CheckBox
        $chk.Text = $key
        $chk.Tag = $tag
        $chk.AutoSize = $true
        
        # APPLY SAVED STATE (Default to True)
        if ($savedStates.ContainsKey($tag)) {
            $chk.Checked = $savedStates[$tag]
        } else {
            $chk.Checked = $true
        }
        
        # Grid Layout: 2 Columns
        if ($count % 2 -eq 0) { $x = 0 } else { $x = 280 }
        $chk.Location = "$x, $y"
        
        if ($count % 2 -ne 0) { $y += 30 }
        
        $pnl.Controls.Add($chk); $chkBoxes += $chk; $count++
    }

    # --- Buttons ---
    $btnScan = New-Object System.Windows.Forms.Button
    $btnScan.Text = "Start Deep Scan"
    $btnScan.Location = "340, 450"; $btnScan.Width = 200; $btnScan.Height = 40
    $btnScan.BackColor = "SeaGreen"; $btnScan.ForeColor = "White"; $btnScan.FlatStyle = "Flat"
    $btnScan.DialogResult = "OK"
    $f.Controls.Add($btnScan)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = "20, 450"; $btnCancel.Width = 100; $btnCancel.Height = 40
    $btnCancel.BackColor = "DimGray"; $btnCancel.ForeColor = "White"; $btnCancel.FlatStyle = "Flat"
    $f.Controls.Add($btnCancel)
    
    $f.AcceptButton = $btnScan; $f.CancelButton = $btnCancel

    if ($f.ShowDialog() -eq "OK") {
        $selected = @()
        
        # SAVE SETTINGS
        foreach ($c in $chkBoxes) { 
            if ($c.Checked) { $selected += $c.Tag }
            $currentSettings.RegistryScan[$c.Tag] = $c.Checked
        }
        Save-WmtSettings -Settings $currentSettings

        return $selected
    }
    return $null
}
# --- Registry Results UI ---
function Show-RegistryCleaner {
    param($ScanResults)

    # --- 1. Form Setup ---
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Deep Registry Cleaner"
    $f.Size = "1100, 600"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = [System.Drawing.Color]::White
    
    # --- 2. Header Panel ---
    $pnlHead = New-Object System.Windows.Forms.Panel
    $pnlHead.Dock = "Top"; $pnlHead.Height = 60
    $pnlHead.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $f.Controls.Add($pnlHead)

    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = "Scan Complete. Issues found: $($ScanResults.Count)"
    $lblStatus.AutoSize = $true; $lblStatus.Top = 18; $lblStatus.Left = 15
    $lblStatus.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
    $pnlHead.Controls.Add($lblStatus)

    # --- 3. Data Grid Configuration ---
    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Fill"
    $dg.BackgroundColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.ForeColor = [System.Drawing.Color]::White
    $dg.GridColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")
    $dg.BorderStyle = "None"
    $dg.RowHeadersVisible = $false
    $dg.AllowUserToAddRows = $false
    $dg.SelectionMode = "FullRowSelect"
    $dg.MultiSelect = $true
    
    # Header Styling
    $dg.EnableHeadersVisualStyles = $false
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 4)
    $dg.ColumnHeadersHeight = 35
    $dg.ColumnHeadersBorderStyle = "Single"

    # Row Styling
    $dg.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC")
    $dg.DefaultCellStyle.SelectionForeColor = "White"
    
    $f.Controls.Add($dg)
    $dg.BringToFront()

    # --- 4. Define Columns ---
    # Checkbox Column
    $colChk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $colChk.HeaderText = " "
    $colChk.Width = 30; $colChk.Name = "Check"; $colChk.TrueValue = $true; $colChk.FalseValue = $false
    [void]$dg.Columns.Add($colChk)

    # Visible Columns
    [void]$dg.Columns.Add("Problem", "Problem"); $dg.Columns["Problem"].Width = 200
    [void]$dg.Columns.Add("Data", "Data (Path/Value)"); $dg.Columns["Data"].AutoSizeMode = "Fill"; $dg.Columns["Data"].FillWeight = 50
    [void]$dg.Columns.Add("Key", "Registry Key"); $dg.Columns["Key"].AutoSizeMode = "Fill"; $dg.Columns["Key"].FillWeight = 50
    
    # Hidden Columns (Data needed for fixing)
    [void]$dg.Columns.Add("FullPath", "FullPath"); $dg.Columns["FullPath"].Visible = $false
    [void]$dg.Columns.Add("ValueName", "ValueName"); $dg.Columns["ValueName"].Visible = $false
    [void]$dg.Columns.Add("Type", "Type"); $dg.Columns["Type"].Visible = $false

    # --- 5. Populate Data ---
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

    # --- 6. Footer Panel & Buttons ---
    $pnlBot = New-Object System.Windows.Forms.Panel
    $pnlBot.Dock = "Bottom"; $pnlBot.Height = 60
    $pnlBot.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.Controls.Add($pnlBot)

    $btnFix = New-Object System.Windows.Forms.Button
    $btnFix.Text = "Fix Selected Issues..."
    $btnFix.Width = 200; $btnFix.Height = 35; $btnFix.Top = 12; $btnFix.Left = 860
    $btnFix.Anchor = "Right, Bottom"
    $btnFix.FlatStyle = "Flat"; $btnFix.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC"); $btnFix.ForeColor = "White"
    $pnlBot.Controls.Add($btnFix)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Close"
    $btnCancel.Width = 100; $btnCancel.Height = 35; $btnCancel.Top = 12; $btnCancel.Left = 20
    $btnCancel.FlatStyle = "Flat"; $btnCancel.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#333333"); $btnCancel.ForeColor = "White"
    $btnCancel.Add_Click({ $f.Close() })
    $pnlBot.Controls.Add($btnCancel)

    # --- 7. Fix Button Logic ---
    $btnFix.Add_Click({
        $toFix = @()
        foreach ($row in $dg.Rows) {
            if ($row.Cells["Check"].Value -eq $true) {
                $toFix += [PSCustomObject]@{
                    RegPath    = $row.Cells["FullPath"].Value
                    ValueName  = $row.Cells["ValueName"].Value
                    Type       = $row.Cells["Type"].Value
                    DisplayKey = $row.Cells["Key"].Value
                }
            }
        }

        if ($toFix.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No issues selected.", "Registry Cleaner", "OK", "Information") | Out-Null
            return
        }

        # Return results to the main controller
        $f.Tag = $toFix
        $f.DialogResult = "OK"
        $f.Close()
    })

    [void]$f.ShowDialog()
    return $f.Tag
}
# --- Registry Engine ---
function Invoke-RegistryTask {
    param([string]$Action)

    $bkDir = Join-Path (Get-DataPath) "RegistryBackups"
    if (-not (Test-Path $bkDir)) { New-Item -Path $bkDir -ItemType Directory | Out-Null }

    # --- 1. PRIVILEGE BOOSTER ---
    if (-not ([System.Management.Automation.PSTypeName]'Win32.TokenManipulator').Type) {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class Win32 {
            public class TokenManipulator {
                [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
                internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
                [DllImport("kernel32.dll", ExactSpelling = true)]
                internal static extern IntPtr GetCurrentProcess();
                [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
                internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
                [DllImport("advapi32.dll", SetLastError = true)]
                internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
                [StructLayout(LayoutKind.Sequential, Pack = 1)]
                internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
                internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
                internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
                internal const int TOKEN_QUERY = 0x00000008;
                public static bool EnablePrivilege(string privilege) {
                    try {
                        IntPtr htok = IntPtr.Zero;
                        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok)) return false;
                        TokPriv1Luid tp; tp.Count = 1; tp.Attr = SE_PRIVILEGE_ENABLED; tp.Luid = 0;
                        if (!LookupPrivilegeValue(null, privilege, ref tp.Luid)) return false;
                        if (!AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero)) return false;
                        return true;
                    } catch { return false; }
                }
            }
        }
"@
    }
    [Win32.TokenManipulator]::EnablePrivilege("SeTakeOwnershipPrivilege") | Out-Null
    [Win32.TokenManipulator]::EnablePrivilege("SeRestorePrivilege") | Out-Null

    # --- 2. HELPER FUNCTIONS ---
    function Test-PathExists {
        param($Path)
        if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
        if ($Path -match "%.*%" -or $Path -match "\$\(.*\)") { return $true }
        if (Test-Path -Path $Path) { return $true }
        if ($Path -match "(?i)System32") {
            $nativePath = $Path -replace "(?i)System32", "Sysnative"
            if (Test-Path -Path $nativePath) { return $true }
        }
        return $false
    }

    function Test-IsWhitelisted {
        param($Path)
        if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
        $SafeList = @("TetheringSettingHandler", "CrossDevice", "Windows.Media.Protection", "psmachine", "WebView2", "System.Data.dll", "System.EnterpriseServices", "rundll32", "explorer.exe", "svchost", "dllhost", "wmiprvse", "mmgaserver", "pickerhost", "castsrv", "uihelper", "backgroundtaskhost", "smartscreen", "runtimebroker", "mousocoreworker", "spatialaudiolicensesrv", "speechruntime", "mstsc.exe", "searchprotocolhost", "AppX", "WindowsApps", "UIEOrchestrator", "control.exe", "sdclt.exe", "provtool.exe", "perfmon", "Diagnostic.Perfmon")
        foreach ($safe in $SafeList) { if ($Path -match "(?i)$safe") { return $true } }
        return $false
    }

    function Get-RealExePath {
        param($RawString)
        if ([string]::IsNullOrWhiteSpace($RawString)) { return $null }
        $clean = $RawString.Trim()
        if ($clean -match "^(.*?),\s*-?\d+$") { $clean = $matches[1].Trim() }
        if ($clean.StartsWith('"')) {
            $endQuote = $clean.IndexOf('"', 1)
            if ($endQuote -gt 1) {
                $quotedPart = $clean.Substring(1, $endQuote - 1)
                if (Test-PathExists $quotedPart) { return $quotedPart }
                $clean = $quotedPart 
            }
        }
        if (Test-PathExists $clean) { return $clean }
        if ($clean.Contains(" ")) {
            $parts = $clean -split " "
            $candidate = $parts[0]
            $Check = { param($p) if (Test-PathExists $p) { return $true }; if (Test-PathExists "$p.exe") { return $true }; return $false }
            if (& $Check $candidate) { return $candidate }
            for ($i = 1; $i -lt $parts.Count; $i++) {
                $candidate += " " + $parts[$i]
                if (& $Check $candidate) { return $candidate }
            }
        }
        return $clean
    }

    function Remove-RegKeyForced {
        param($Path, $IsKey, $ValName)
        
        # === FIX: Normalize Registry Paths (Added this section) ===
        if ($Path -match "^HKEY_CLASSES_ROOT") { $Path = $Path -replace "^HKEY_CLASSES_ROOT", "HKCR:" }
        if ($Path -match "^HKEY_LOCAL_MACHINE") { $Path = $Path -replace "^HKEY_LOCAL_MACHINE", "HKLM:" }
        if ($Path -match "^HKEY_CURRENT_USER") { $Path = $Path -replace "^HKEY_CURRENT_USER", "HKCU:" }
        # ==========================================================

        $realPaths = @()
        if ($Path -match "^HKLM" -or $Path -match "^HKCU") { $realPaths += $Path }
        elseif ($Path -match "^HKCR:\\(?<SubPath>.*)") {
            $sub = $Matches.SubPath
            if (Test-Path "HKLM:\SOFTWARE\Classes\$sub") { $realPaths += "HKLM:\SOFTWARE\Classes\$sub" }
            if (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Classes\$sub") { $realPaths += "HKLM:\SOFTWARE\WOW6432Node\Classes\$sub" }
            if (Test-Path "HKCU:\Software\Classes\$sub") { $realPaths += "HKCU:\Software\Classes\$sub" }
        }
        if ($realPaths.Count -eq 0) { $realPaths += $Path }

        $globalSuccess = $true
        foreach ($targetPath in $realPaths) {
            try {
                if ($IsKey) { Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop }
                else { Remove-ItemProperty -Path $targetPath -Name $ValName -ErrorAction Stop }
                continue
            } catch {}
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
                $adminUser = $sid.Translate([System.Security.Principal.NTAccount])
                $rule = New-Object System.Security.AccessControl.RegistryAccessRule($adminUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
                $UnlockItem = { 
                    param($p) 
                    try { 
                        $acl=Get-Acl $p; $acl.SetOwner($adminUser); Set-Acl $p $acl -ErrorAction SilentlyContinue; 
                        $acl=Get-Acl $p; $acl.SetAccessRule($rule); Set-Acl $p $acl -ErrorAction SilentlyContinue 
                    } catch {} 
                }
                if ($IsKey) { $children = Get-ChildItem -Path $targetPath -Recurse -ErrorAction SilentlyContinue; foreach ($c in $children) { & $UnlockItem -p $c.PSPath } }
                & $UnlockItem -p $targetPath
                if ($IsKey) { Remove-Item -Path $targetPath -Recurse -Force -ErrorAction Stop }
                else { Remove-ItemProperty -Path $targetPath -Name $ValName -ErrorAction Stop }
            } catch { $globalSuccess = $false }
        }
        return $globalSuccess
    }

    function Backup-RegKey {
        param($ItemObj, $FilePath)
        $path = $ItemObj.RegPath; $targetValue = $ItemObj.ValueName; $type = $ItemObj.Type
        if ([string]::IsNullOrWhiteSpace($path)) { return }
        $regKeyPath = $path -replace "^HKLM:?\\", "HKEY_LOCAL_MACHINE\" -replace "^HKCU:?\\", "HKEY_CURRENT_USER\" -replace "^HKCR:?\\", "HKEY_CLASSES_ROOT\"
        $sb = [System.Text.StringBuilder]::new(); [void]$sb.AppendLine("[$regKeyPath]")
        try {
            if ($type -eq "Value") {
                $val = Get-ItemProperty -Path $path -Name $targetValue -ErrorAction SilentlyContinue
                if ($val) { $vData = $val.$targetValue; if ($vData -is [string]) { $vData = '"' + ($vData -replace '\\', '\\' -replace '"', '\"') + '"' } elseif ($vData -is [int]) { $vData = "dword:{0:x8}" -f $vData }; [void]$sb.AppendLine("`"$targetValue`"=$vData") }
            }
            [void]$sb.AppendLine(""); Add-Content -Path $FilePath -Value $sb.ToString() -Encoding Unicode
        } catch {}
    }

    function Show-SafetyDialog {
        param($Count)
        $f = New-Object System.Windows.Forms.Form
        $f.Text = "Safety Pre-Check"; $f.Size = "450, 320"; $f.StartPosition = "CenterScreen"
        $f.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32); $f.ForeColor = "White"
        $f.FormBorderStyle = "FixedDialog"; $f.ControlBox = $false
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Location = "20, 20"; $lbl.Size = "400, 80"; $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $lbl.Text = "You are about to force-delete $Count invalid registry keys.`n`nThese keys are locked by the system. Deleting them is generally safe for cleanup, but carries a small risk."
        $f.Controls.Add($lbl)
        $b1 = New-Object System.Windows.Forms.Button; $b1.Text = "Create Restore Point && Force Clean"; $b1.DialogResult = "Yes"; $b1.Location = "50, 110"; $b1.Size = "340, 45"; $b1.BackColor = "SeaGreen"; $b1.ForeColor = "White"; $b1.FlatStyle = "Flat"; $f.Controls.Add($b1)
        $b2 = New-Object System.Windows.Forms.Button; $b2.Text = "Force Clean (No Backup)"; $b2.DialogResult = "No"; $b2.Location = "50, 165"; $b2.Size = "340, 40"; $b2.BackColor = "IndianRed"; $b2.ForeColor = "White"; $b2.FlatStyle = "Flat"; $f.Controls.Add($b2)
        $b3 = New-Object System.Windows.Forms.Button; $b3.Text = "Cancel"; $b3.DialogResult = "Cancel"; $b3.Location = "50, 220"; $b3.Size = "340, 40"; $b3.BackColor = "DimGray"; $b3.ForeColor = "White"; $b3.FlatStyle = "Flat"; $f.Controls.Add($b3)
        return $f.ShowDialog()
    }

    # --- 3. MAIN LOGIC ---
    if ($Action -eq "DeepClean") {
        $selectedScans = Show-RegScanSelection
        if (-not $selectedScans) { return }

        $pForm = New-Object System.Windows.Forms.Form; $pForm.Text="Scanning Registry"; $pForm.Size="500,120"; $pForm.StartPosition="CenterScreen"; $pForm.ControlBox=$false
        $pForm.BackColor=[System.Drawing.Color]::FromArgb(30,30,30); $pForm.ForeColor="White"
        $pLabel = New-Object System.Windows.Forms.Label; $pLabel.Location="20,15"; $pLabel.Size="460,20"; $pLabel.Text="Initializing..."; $pForm.Controls.Add($pLabel)
        $pBar = New-Object System.Windows.Forms.ProgressBar; $pBar.Location="20,45"; $pBar.Size="440,20"; $pForm.Controls.Add($pBar)
        $pForm.Show(); [System.Windows.Forms.Application]::DoEvents()

        $findings = New-Object System.Collections.Generic.List[PSObject]
        
        # FIX: We track total progress (0-100) using floats
        $script:currentProgress = 0.0
        
        # Calculate how much percentage each category is worth
        # e.g., if 5 scans selected, each is worth 20%
        $categoryWeight = 100.0 / ($selectedScans.Count)

        try {
            # Helper to setup category
            $StartCategory = {
                param($Name) 
                $pLabel.Text = "Scanning $Name..."
                $pForm.Refresh()
                [System.Windows.Forms.Application]::DoEvents()
            }

            # NEW: Helper that fills the bar based on the *actual* loop count
            # We assume a large number (e.g., 5000) for "infinite" loops like ActiveX
            $Tick = {
                param($DetailText, $CurrentIndex, $TotalEstimated)
                
                # Update UI every 50 items to keep speed high
                if ($CurrentIndex % 50 -eq 0) {
                    if ($DetailText.Length -gt 60) { $DetailText = $DetailText.Substring(0, 57) + "..." }
                    $pLabel.Text = $DetailText

                    # Calculate progress WITHIN this specific category (0.0 to 1.0)
                    $fraction = [math]::Min(($CurrentIndex / $TotalEstimated), 1.0)
                    
                    # Add that fraction to the global base progress
                    # e.g. if we are in category 1 of 5 (base 0%), and we are 50% done:
                    # Total = 0 + (0.5 * 20) = 10%
                    $realVal = $script:currentProgress + ($fraction * $categoryWeight)
                    
                    $pBar.Value = [int]$realVal
                    [System.Windows.Forms.Application]::DoEvents()
                }
            }
            
            # Helper to finalize a category and lock in its progress
            $EndCategory = {
                $script:currentProgress += $categoryWeight
                $pBar.Value = [int]$script:currentProgress
                [System.Windows.Forms.Application]::DoEvents()
            }

            # 1. ACTIVEX & COM
            if ($selectedScans -contains "ActiveX") { 
                & $StartCategory "ActiveX/COM"
                $root = [Microsoft.Win32.Registry]::ClassesRoot
                $clsidKey = $root.OpenSubKey("CLSID", $false)
                if ($clsidKey) { 
                    $subKeys = $clsidKey.GetSubKeyNames()
                    $total = $subKeys.Count
                    $i = 0
                    foreach ($id in $subKeys) { 
                        $i++
                        & $Tick "Scanning CLSID: $id" $i $total
                        try { 
                            $sub = $clsidKey.OpenSubKey("$id\InProcServer32", $false)
                            if ($sub) { 
                                $dll = $sub.GetValue($null)
                                if ($dll -and $dll -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $dll)) { 
                                    $cleanDll = Get-RealExePath $dll
                                    if (-not (Test-PathExists $cleanDll)) {
                                        $findings.Add([PSCustomObject]@{ Problem="ActiveX Issue"; Data=$cleanDll; DisplayKey=$id; RegPath="HKCR:\CLSID\$id\InProcServer32"; ValueName=$null; Type="Key" }) 
                                    }
                                }
                                $sub.Close() 
                            }
                            $sub2 = $clsidKey.OpenSubKey("$id\LocalServer32", $false)
                            if ($sub2) {
                                $exe = $sub2.GetValue($null)
                                if ($exe -and $exe -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $exe)) {
                                    $cleanExe = Get-RealExePath $exe
                                    if (-not (Test-PathExists $cleanExe)) {
                                        $findings.Add([PSCustomObject]@{ Problem="ActiveX Issue"; Data=$cleanExe; DisplayKey=$id; RegPath="HKCR:\CLSID\$id\LocalServer32"; ValueName=$null; Type="Key" })
                                    }
                                }
                                $sub2.Close()
                            }
                        } catch {} 
                    }
                    $clsidKey.Close() 
                }
                & $EndCategory
            }

            # 2. FILE EXTENSIONS
            if ($selectedScans -contains "Ext") { 
                & $StartCategory "File Extensions"
                $root=[Microsoft.Win32.Registry]::ClassesRoot
                $names = $root.GetSubKeyNames()
                $total = $names.Count
                $i = 0
                foreach ($ext in $names) { 
                    $i++
                    & $Tick "Scanning Ext: $ext" $i $total
                    if($ext.StartsWith(".")) { 
                        try { 
                            $sub=$root.OpenSubKey($ext)
                            if($sub.SubKeyCount -eq 0 -and $null -eq $sub.GetValue($null)){ 
                                $findings.Add([PSCustomObject]@{ Problem="Unused Extension"; Data=$ext; DisplayKey=$ext; RegPath="HKCR:\$ext"; ValueName=$null; Type="Key" }) 
                            }; $sub.Close() 
                        } catch {} 
                    } 
                }
                & $EndCategory
            }

            # 3. USER FILE EXTS
            if ($selectedScans -contains "FileExts") {
                & $StartCategory "User File Associations"
                $path = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
                $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($path)
                if ($root) {
                    $names = $root.GetSubKeyNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($ext in $names) {
                        $i++
                        & $Tick "Scanning UserExt: $ext" $i $total
                        $owl = $root.OpenSubKey("$ext\OpenWithList")
                        if ($owl) {
                            foreach ($valName in $owl.GetValueNames()) {
                                if ($valName -match "^[a-z]$") { 
                                    $val = $owl.GetValue($valName)
                                    if ($val -match '^[a-zA-Z]:\\') {
                                        $cleanPath = Get-RealExePath $val
                                        if (-not (Test-PathExists $cleanPath)) {
                                            $findings.Add([PSCustomObject]@{ Problem="Invalid FileExt MRU"; Data=$cleanPath; DisplayKey=$ext; RegPath="HKCU:\$path\$ext\OpenWithList"; ValueName=$valName; Type="Value" })
                                        }
                                    }
                                }
                            }
                            $owl.Close()
                        }
                    }
                    $root.Close()
                }
                & $EndCategory
            }

            # 4. APP PATHS
            if ($selectedScans -contains "AppPaths") {
                & $StartCategory "Application Paths"
                $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
                $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key)
                if ($root) {
                    $names = $root.GetSubKeyNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($app in $names) {
                        $i++
                        & $Tick "Scanning AppPath: $app" $i $total
                        try {
                            $sub = $root.OpenSubKey($app)
                            $path = $sub.GetValue($null)
                            if ($path -and $path -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $path)) {
                                $clean = Get-RealExePath $path
                                if (-not (Test-PathExists $clean)) {
                                    $findings.Add([PSCustomObject]@{ Problem="Missing App Path"; Data=$clean; DisplayKey=$app; RegPath="HKLM:\$key\$app"; ValueName=$null; Type="Key" })
                                }
                            }
                            $sub.Close()
                        } catch {}
                    }
                    $root.Close()
                }
                & $EndCategory
            }

            # 5. APPLICATIONS & PROGIDs
            if ($selectedScans -contains "Apps" -or $selectedScans -contains "ProgIDs") {
                & $StartCategory "Applications & ProgIDs"
                $searchRoots = @()
                if ($selectedScans -contains "Apps") { $searchRoots += [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("Applications") }
                if ($selectedScans -contains "ProgIDs") { $searchRoots += [Microsoft.Win32.Registry]::ClassesRoot }

                foreach ($root in $searchRoots) {
                    if ($root) {
                        $names = $root.GetSubKeyNames()
                        $total = $names.Count
                        $i = 0
                        foreach ($app in $names) {
                            $i++
                            & $Tick "Scanning App: $app" $i $total
                            try {
                                $appKey = $root.OpenSubKey($app)
                                $shellKey = $appKey.OpenSubKey("shell")
                                if ($shellKey) {
                                    foreach ($verb in $shellKey.GetSubKeyNames()) {
                                        try {
                                            $cmdKey = $shellKey.OpenSubKey("$verb\command")
                                            if ($cmdKey) {
                                                $cmd = $cmdKey.GetValue($null)
                                                if ($cmd) {
                                                    $clean = Get-RealExePath $cmd
                                                    if ($clean -and $clean -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $clean)) {
                                                        if (-not (Test-PathExists $clean) -and $clean -notmatch "%1") {
                                                            $findings.Add([PSCustomObject]@{ Problem="Invalid App Command ($verb)"; Data=$clean; DisplayKey=$app; RegPath="$($root.Name)\$app\shell\$verb\command"; ValueName=$null; Type="Key" })
                                                        }
                                                    }
                                                }
                                                $cmdKey.Close()
                                            }
                                        } catch {}
                                    }
                                    $shellKey.Close()
                                }
                                $appKey.Close()
                            } catch {}
                        }
                    }
                }
                & $EndCategory
            }

            # 6. UNINSTALLERS
            if ($selectedScans -contains "Uninstall") {
                & $StartCategory "Uninstallers"
                $paths = @(
                    "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                )
                $hives = @([Microsoft.Win32.Registry]::LocalMachine, [Microsoft.Win32.Registry]::CurrentUser)
                
                # We do a rough estimate of 500 items to avoid double scanning for count
                $total = 500 
                $i = 0

                foreach ($h in $hives) {
                    foreach ($p in $paths) {
                        try {
                            $rk = $h.OpenSubKey($p)
                            if ($rk) {
                                foreach ($subName in $rk.GetSubKeyNames()) {
                                    $i++
                                    & $Tick "Scanning Uninstaller: $subName" $i $total
                                    $sub = $rk.OpenSubKey($subName)
                                    $uString = $sub.GetValue("UninstallString")
                                    if ($uString -and $uString -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $uString)) {
                                        if ($uString -notmatch "(?i)MsiExec.exe") {
                                            $clean = Get-RealExePath $uString
                                            if (-not (Test-PathExists $clean)) {
                                                $rootName = if ($h.Name -match "LocalMachine") { "HKLM" } else { "HKCU" }
                                                $findings.Add([PSCustomObject]@{ Problem="Missing Uninstaller"; Data=$clean; DisplayKey=$subName; RegPath="$rootName`:\$p\$subName"; ValueName=$null; Type="Key" })
                                            }
                                        }
                                    }
                                    $sub.Close()
                                }
                                $rk.Close()
                            }
                        } catch {}
                    }
                }
                & $EndCategory
            }

            # 7. MUI CACHE
            if ($selectedScans -contains "MuiCache") {
                & $StartCategory "MuiCache"
                $key = "Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
                $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($key)
                if ($root) {
                    $names = $root.GetValueNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($valName in $names) {
                        $i++
                        & $Tick "Scanning MuiCache: $valName" $i $total
                        $cleanPath = $valName -replace '\.(FriendlyAppName|ApplicationCompany)$', ''
                        if ($cleanPath -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $cleanPath)) {
                            if (-not (Test-PathExists $cleanPath)) {
                                $findings.Add([PSCustomObject]@{ Problem="Obsolete MuiCache"; Data=$cleanPath; DisplayKey="MuiCache"; RegPath="HKCU:\$key"; ValueName=$valName; Type="Value" })
                            }
                        }
                    }
                    $root.Close()
                }
                & $EndCategory
            }

            # 8. APPCOMPAT FLAGS
            if ($selectedScans -contains "AppCompat") {
                & $StartCategory "Compatibility Store"
                $key = "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
                $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($key)
                if ($root) {
                    $names = $root.GetValueNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($valName in $names) {
                        $i++
                        & $Tick "Scanning AppCompat: $valName" $i $total
                        if ($valName -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $valName)) {
                            if (-not (Test-PathExists $valName)) {
                                $findings.Add([PSCustomObject]@{ Problem="Obsolete Compatibility Ref"; Data=$valName; DisplayKey="AppCompat"; RegPath="HKCU:\$key"; ValueName=$valName; Type="Value" })
                            }
                        }
                    }
                    $root.Close()
                }
                & $EndCategory
            }

            # 9. FIREWALL
            if ($selectedScans -contains "Firewall") {
                & $StartCategory "Firewall Rules"
                $key = "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
                $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key)
                if ($root) {
                    $names = $root.GetValueNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($valName in $names) {
                        $i++
                        & $Tick "Scanning Firewall: $valName" $i $total
                        $data = $root.GetValue($valName)
                        if ($data -match "App=([^|]+)") {
                            $appPath = $matches[1]
                            $expanded = [Environment]::ExpandEnvironmentVariables($appPath)
                            if ($expanded -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $expanded)) {
                                if (-not (Test-PathExists $expanded)) {
                                    $findings.Add([PSCustomObject]@{ Problem="Invalid Firewall Rule"; Data=$expanded; DisplayKey=$valName; RegPath="HKLM:\$key"; ValueName=$valName; Type="Value" })
                                }
                            }
                        }
                    }
                    $root.Close()
                }
                & $EndCategory
            }

            # 10. SERVICES
            if ($selectedScans -contains "Services") {
                & $StartCategory "Services"
                $key = "SYSTEM\CurrentControlSet\Services"
                $root = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key)
                if ($root) {
                    $names = $root.GetSubKeyNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($svc in $names) {
                        $i++
                        & $Tick "Scanning Service: $svc" $i $total
                        try {
                            $sub = $root.OpenSubKey($svc)
                            $img = $sub.GetValue("ImagePath")
                            if ($img -and $img -match '^[a-zA-Z]:\\' -and $img -notmatch "\\drivers\\") {
                                $clean = Get-RealExePath $img
                                if (-not (Test-PathExists $clean)) {
                                    $findings.Add([PSCustomObject]@{ Problem="Missing Service Binary"; Data=$clean; DisplayKey=$svc; RegPath="HKLM:\$key\$svc"; ValueName="ImagePath"; Type="Value" })
                                }
                            }
                            $sub.Close()
                        } catch {}
                    }
                    $root.Close()
                }
                & $EndCategory
            }

            # 11. TYPE LIBRARIES
            if ($selectedScans -contains "TypeLib") {
                & $StartCategory "Type Libraries"
                $root = [Microsoft.Win32.Registry]::ClassesRoot
                $tlKey = $root.OpenSubKey("TypeLib", $false)
                if ($tlKey) {
                    $names = $tlKey.GetSubKeyNames()
                    $total = $names.Count
                    $i = 0
                    foreach ($guid in $names) {
                        $i++
                        & $Tick "Scanning TypeLib: $guid" $i $total
                        try {
                            $verKey = $tlKey.OpenSubKey($guid)
                            if ($verKey) {
                                foreach ($ver in $verKey.GetSubKeyNames()) {
                                    $numKey = $verKey.OpenSubKey($ver)
                                    $helpDir = $numKey.GetValue("HELPDIR")
                                    if ($helpDir -and $helpDir -match '^[a-zA-Z]:\\' -and -not (Test-PathExists $helpDir)) {
                                        $findings.Add([PSCustomObject]@{ Problem="Missing HelpDir"; Data=$helpDir; DisplayKey="$guid"; RegPath="HKCR:\TypeLib\$guid\$ver"; ValueName="HELPDIR"; Type="Value" }) 
                                    }
                                    $numKey.Close()
                                }
                                $verKey.Close()
                            }
                        } catch {}
                    }
                    $tlKey.Close()
                }
                & $EndCategory
            }

            # 12. DEFAULT ICONS
            if ($selectedScans -contains "Icons") {
                & $StartCategory "Default Icons"
                $root = [Microsoft.Win32.Registry]::ClassesRoot
                $names = $root.GetSubKeyNames()
                $total = $names.Count
                $i = 0
                foreach ($ext in $names) {
                    $i++
                    & $Tick "Scanning Icon: $ext" $i $total
                    try {
                        $iconKey = $root.OpenSubKey("$ext\DefaultIcon")
                        if ($iconKey) {
                            $val = $iconKey.GetValue($null)
                            if ($val) {
                                $cleanPath = Get-RealExePath $val
                                if ($cleanPath -match '^[a-zA-Z]:\\' -and -not (Test-IsWhitelisted $cleanPath) -and -not (Test-PathExists $cleanPath) -and $cleanPath -notmatch "%1") {
                                    $findings.Add([PSCustomObject]@{ Problem="Invalid Default Icon"; Data=$cleanPath; DisplayKey=$ext; RegPath="HKCR:\$ext\DefaultIcon"; ValueName=$null; Type="Key" })
                                }
                            }
                            $iconKey.Close()
                        }
                    } catch {}
                }
                & $EndCategory
            }

            # 13. SHARED DLLs
            if ($selectedScans -contains "SharedDLLs") { 
                & $StartCategory "Shared DLLs"
                $keys = @("SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls", "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDlls")
                foreach ($k in $keys) {
                    $rk=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($k)
                    if($rk){ 
                        $names = $rk.GetValueNames()
                        $total = $names.Count
                        $i = 0
                        foreach($val in $names){ 
                            $i++
                            & $Tick "Scanning DLL: $val" $i $total
                            if($val -match '^[a-zA-Z]:\\' -and -not(Test-PathExists $val)){ 
                                $findings.Add([PSCustomObject]@{ Problem="Missing Shared Ref"; Data=$val; DisplayKey="SharedDlls"; RegPath="HKLM:\$k"; ValueName=$val; Type="Value" }) 
                            } 
                        }; $rk.Close() 
                    }
                }
                & $EndCategory
            }

            # 14. STARTUP
            if ($selectedScans -contains "Startup") { 
                & $StartCategory "Startup Items"
                $paths = @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
                foreach ($p in $paths) { 
                    if(Test-Path $p){ 
                        $props = Get-ItemProperty $p
                        $names = $props.PSObject.Properties.Name
                        $total = $names.Count
                        $i = 0
                        foreach($n in $names){ 
                            $i++
                            & $Tick "Scanning Startup: $n" $i $total
                            $v=$props.$n
                            if($v -is [string] -and $v -match '^[a-zA-Z]:\\'){ 
                                $cleanExe = Get-RealExePath $v
                                if(-not (Test-PathExists $cleanExe)){ 
                                    $findings.Add([PSCustomObject]@{ Problem="Broken Startup"; Data=$cleanExe; DisplayKey=$n; RegPath=$p; ValueName=$n; Type="Value" }) 
                                } 
                            } 
                        } 
                    } 
                } 
                & $EndCategory
            }

            # 15. INSTALLER FOLDERS
            if ($selectedScans -contains "Installer") { 
                & $StartCategory "Installer Folders"
                $k="SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders"
                $rk=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($k)
                if($rk){ 
                    $names = $rk.GetValueNames()
                    $total = $names.Count
                    $i = 0
                    foreach($val in $names){ 
                        $i++
                        & $Tick "Scanning Installer: $val" $i $total
                        if($val -match '^[a-zA-Z]:\\' -and -not(Test-PathExists $val)){ 
                            $findings.Add([PSCustomObject]@{ Problem="Missing Installer Folder"; Data=$val; DisplayKey="Installer"; RegPath="HKLM:\$k"; ValueName=$val; Type="Value" }) 
                        } 
                    }; $rk.Close() 
                } 
                & $EndCategory
            }

            $pForm.Close()
            
            # --- RESULTS PROCESSING ---
            if ($findings.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("Registry Cleaner: No issues found!", "Scan Complete", "OK", "Information") | Out-Null
                return
            }
            
            $rawSelection = Show-RegistryCleaner -ScanResults ($findings | Select-Object *)
            
            $toDelete = @()
            if ($rawSelection) {
                # FIXED: $null on the left side
                $toDelete = $rawSelection | Where-Object { $null -ne $_ -and $null -ne $_.RegPath }
            }

            if ($toDelete.Count -eq 0) { return }

            # --- SAFETY PROMPT ---
            $res = Show-SafetyDialog -Count $toDelete.Count
            if ($res -eq "Cancel") { return }
            if ($res -eq "Yes") {
                Invoke-UiCommand { try { Checkpoint-Computer -Description "WMT DeepClean" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop; "Restore Point created." } catch { "Restore Point failed (Disabled?). Continuing..." } } "Creating Restore Point..."
            }

            # --- EXECUTE FIX ---
            Invoke-UiCommand {
                param($toDelete, $bkDir) 
                
                $bkFile = Join-Path $bkDir ("DeepClean_Backup_{0}.reg" -f (Get-Date -Format "yyyyMMdd_HHmm"))
                $fixed=0; $skipped=0; $backedUpKeys=@()
                
                Set-Content -Path $bkFile -Value "Windows Registry Editor Version 5.00`r`n`r`n" -Encoding Unicode

                foreach ($item in $toDelete) {
                    $uid = "$($item.RegPath):$($item.ValueName)"
                    if ($uid -notin $backedUpKeys) { Backup-RegKey -ItemObj $item -FilePath $bkFile; $backedUpKeys += $uid }
                    
                    Write-GuiLog "Removing: $($item.DisplayKey)"
                    $isKey = ($item.Type -eq "Key")
                    $success = Remove-RegKeyForced -Path $item.RegPath -IsKey $isKey -ValName $item.ValueName
                    
                    if ($success) { $fixed++ } else { $skipped++ }
                }
                
                $finalMsg = "Cleanup Complete.`n`nFixed: $fixed item(s)"
                if ($skipped -gt 0) { $finalMsg += "`nSkipped: $skipped (System Protected)" }
                $finalMsg += "`n`nBackup: $bkFile"
                [System.Windows.Forms.MessageBox]::Show($finalMsg, "Result", "OK", "Information") | Out-Null
                
            } "Deep Cleaning..." -ArgumentList $toDelete, $bkDir

        } catch { $pForm.Close(); [System.Windows.Forms.MessageBox]::Show($_.Exception.Message) }
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
                # FIX: Use scriptblock for null check
                $vols = $disk | Get-Partition | Get-Volume | Where-Object { $null -ne $_.DriveLetter }
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
    Invoke-UiCommand { param($target) netsh advfirewall export "$target" } "Exporting firewall rules..." -ArgumentList $target
}

function Invoke-FirewallImport {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = "Windows Firewall Policy (*.wfw)|*.wfw"
    if ($dlg.ShowDialog() -ne "OK") { return }
    $file = $dlg.FileName
    Invoke-UiCommand { param($file) netsh advfirewall import "$file" } "Importing firewall rules..." -ArgumentList $file
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
    } "Updating driver update policy..." -ArgumentList $value, $msg
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
    } "Updating device metadata policy..." -ArgumentList $value, $msg
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

    # --- LAYOUT FIX: PANEL FIRST (Dock Bottom) --- 
    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"
    $pnl.Height = 60 # Reduced height for cleaner look
    $pnl.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    
    # Draw a subtle top border on the panel
    $pnl.Add_Paint({
        param($s, $e) # Renamed from $sender to $s
        $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(60,60,60), 1)
        $e.Graphics.DrawLine($pen, 0, 0, $s.Width, 0)
    })
    $f.Controls.Add($pnl)

    # --- GRID SECOND (Dock Fill) ---
    $dg = New-Object System.Windows.Forms.DataGridView
    $dg.Dock = "Fill" 
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
    $dg.BringToFront() # Ensures grid fills the remaining space above the panel

    # Helper for Themed Buttons with Tooltips AND Anchor support
    function New-DrvBtn($text, $x, $color=$null, $tooltipText="", $anchor="Top, Left"){
        $b=New-Object System.Windows.Forms.Button
        $b.Text=$text
        $b.Left=$x
        $b.Top=12 # Vertically centered in 60px panel
        $b.Width=160
        $b.Height=35
        $b.FlatStyle="Flat"
        $b.FlatAppearance.BorderSize=1
        $b.Anchor = $anchor
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

    # --- CHANGED: Renamed "Remove (Options...)" to "Remove All" ---
    $btnBackupClean = New-DrvBtn "Remove All" 20 "#006600" "Select removal options (Backup vs No Backup) for ALL duplicates."
    
    $btnRemoveSel   = New-DrvBtn "Remove Selected" 190 "#802020" "Removes only the currently highlighted driver(s) from the list."
    
    # Place Close button aligned to the Right
    $closeX = $pnl.Width - 180
    $btnClose = New-DrvBtn "Close" $closeX $null "Close this window." "Top, Right"

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
        
        # --- NEW CUSTOM CONFIRMATION DIALOG ---
        $cf = New-Object System.Windows.Forms.Form
        $cf.Text = "Confirm Driver Cleanup"
        $cf.Size = "450, 240"
        $cf.StartPosition = "CenterParent"
        $cf.FormBorderStyle = "FixedDialog"
        $cf.ControlBox = $false
        $cf.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
        $cf.ForeColor = "White"

        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text = "You are about to remove $count driver(s).`n`nHow would you like to proceed?"
        $lbl.Location = "20, 20"; $lbl.Size = "400, 50"; $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
        $cf.Controls.Add($lbl)

        $bBackup = New-Object System.Windows.Forms.Button
        $bBackup.Text = "Backup && Clean"
        $bBackup.DialogResult = "Yes"
        $bBackup.Location = "20, 90"; $bBackup.Width = 130; $bBackup.Height = 35
        $bBackup.BackColor = "SeaGreen"; $bBackup.ForeColor = "White"; $bBackup.FlatStyle = "Flat"
        $cf.Controls.Add($bBackup)

        $bNoBackup = New-Object System.Windows.Forms.Button
        $bNoBackup.Text = "Clean (No Backup)"
        $bNoBackup.DialogResult = "No"
        $bNoBackup.Location = "160, 90"; $bNoBackup.Width = 130; $bNoBackup.Height = 35
        $bNoBackup.BackColor = "IndianRed"; $bNoBackup.ForeColor = "White"; $bNoBackup.FlatStyle = "Flat"
        $cf.Controls.Add($bNoBackup)

        $bCancel = New-Object System.Windows.Forms.Button
        $bCancel.Text = "Cancel"
        $bCancel.DialogResult = "Cancel"
        $bCancel.Location = "300, 90"; $bCancel.Width = 110; $bCancel.Height = 35
        $bCancel.BackColor = "DimGray"; $bCancel.ForeColor = "White"; $bCancel.FlatStyle = "Flat"
        $cf.Controls.Add($bCancel)

        $result = $cf.ShowDialog()
        
        if ($result -eq "Cancel") { return }

        # A. BACKUP (Only if Yes selected)
        $backupCount = 0
        $timestamp = Get-Date -f 'yyyyMMdd_HHmm'
        $mainBkPath = Join-Path (Get-DataPath) "Drivers_Backup_$timestamp"

        if ($result -eq "Yes") {
            if (-not (Test-Path $mainBkPath)) { New-Item -Path $mainBkPath -ItemType Directory -Force | Out-Null }
            
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
        $resMsg = "Done.`nDeleted: $deleted"
        if ($result -eq "Yes") { $resMsg += "`nBackups: $backupCount`nPath: $mainBkPath" }
        
        [System.Windows.MessageBox]::Show($resMsg, "Result", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null

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

# --- RESTORE DRIVERS ---
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
    # CHANGE IS HERE: Passing the argument explicitly
    } "Restoring drivers..." -ArgumentList $selectedPath
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
    # CHANGE IS HERE: Passing the argument explicitly
    } "Generating system reports..." -ArgumentList $outdir
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

function Show-ContextMenuBuilder {
    # Ensure libraries are loaded
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    # --- SETUP FORM ---
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Custom Context Menu Builder"
    $f.Size = New-Object System.Drawing.Size(600, 420) # Increased height for description
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.Color]::FromArgb(32, 32, 32)
    $f.ForeColor = "White"
    $f.FormBorderStyle = "FixedDialog"
    $f.MaximizeBox = $false

    # --- HEADER / WARNING ---
    $lblWarn = New-Object System.Windows.Forms.Label
    $lblWarn.Text = "NOTE: This tool replaces the 'Set as desktop background' option to force your custom action into the top-level Windows 11 menu."
    $lblWarn.Location = "20, 10"; $lblWarn.Size = "540, 40"
    $lblWarn.ForeColor = "Yellow" # Highlight the warning
    $lblWarn.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $f.Controls.Add($lblWarn)

    # --- UI INPUTS ---
    $lbl1 = New-Object System.Windows.Forms.Label; $lbl1.Text = "Menu Name:"; $lbl1.Location = "20, 50"; $lbl1.ForeColor = "LightGray"; $lbl1.AutoSize = $true; $f.Controls.Add($lbl1)
    
    $txtName = New-Object System.Windows.Forms.TextBox; $txtName.Location = "20, 75"; $txtName.Width = 540; 
    $txtName.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40); $txtName.ForeColor = "White"
    $txtName.Text = "Take Ownership" # DEFAULT VALUE
    $f.Controls.Add($txtName)

    $lbl2 = New-Object System.Windows.Forms.Label; $lbl2.Text = "Command:"; $lbl2.Location = "20, 115"; $lbl2.ForeColor = "LightGray"; $lbl2.AutoSize = $true; $f.Controls.Add($lbl2)
    
    $txtCmd = New-Object System.Windows.Forms.TextBox; $txtCmd.Location = "20, 140"; $txtCmd.Width = 450; 
    $txtCmd.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40); $txtCmd.ForeColor = "White"
    # DEFAULT COMMAND (Take Ownership)
    $txtCmd.Text = 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t'' -Verb runAs"'
    $f.Controls.Add($txtCmd)
    
    $btnBrowseCmd = New-Object System.Windows.Forms.Button; $btnBrowseCmd.Text = "Browse..."; $btnBrowseCmd.Location = "480, 138"; $btnBrowseCmd.Width = 80; $btnBrowseCmd.BackColor = "DimGray"; $btnBrowseCmd.ForeColor = "White"; $btnBrowseCmd.FlatStyle = "Flat"; $f.Controls.Add($btnBrowseCmd)

    $lbl3 = New-Object System.Windows.Forms.Label; $lbl3.Text = "Icon Path (Optional):"; $lbl3.Location = "20, 180"; $lbl3.ForeColor = "LightGray"; $lbl3.AutoSize = $true; $f.Controls.Add($lbl3)
    
    $txtIcon = New-Object System.Windows.Forms.TextBox; $txtIcon.Location = "20, 205"; $txtIcon.Width = 450; 
    $txtIcon.BackColor = [System.Drawing.Color]::FromArgb(40, 40, 40); $txtIcon.ForeColor = "White"
    $txtIcon.Text = "imageres.dll,-78" # DEFAULT ICON (Shield)
    $f.Controls.Add($txtIcon)
    
    $btnBrowseIcon = New-Object System.Windows.Forms.Button; $btnBrowseIcon.Text = "Browse..."; $btnBrowseIcon.Location = "480, 203"; $btnBrowseIcon.Width = 80; $btnBrowseIcon.BackColor = "DimGray"; $btnBrowseIcon.ForeColor = "White"; $btnBrowseIcon.FlatStyle = "Flat"; $f.Controls.Add($btnBrowseIcon)

    $lblHint = New-Object System.Windows.Forms.Label; $lblHint.Text = "Hint: Use `"%1`" for the selected file.`nExample: `"C:\Apps\App.exe`" `"%1`""; $lblHint.Location = "20, 240"; $lblHint.AutoSize = $true; $lblHint.ForeColor = "Gray"; $f.Controls.Add($lblHint)

    # --- BUTTONS ---
    $btnApply = New-Object System.Windows.Forms.Button; $btnApply.Text = "Apply to Menu"; $btnApply.Location = "20, 290"; $btnApply.Width = 160; $btnApply.Height = 35; $btnApply.BackColor = "SeaGreen"; $btnApply.ForeColor = "White"; $btnApply.FlatStyle = "Flat"; $f.Controls.Add($btnApply)
    
    $btnRemove = New-Object System.Windows.Forms.Button; $btnRemove.Text = "Remove from Menu"; $btnRemove.Location = "200, 290"; $btnRemove.Width = 160; $btnRemove.Height = 35; $btnRemove.BackColor = "IndianRed"; $btnRemove.ForeColor = "White"; $btnRemove.FlatStyle = "Flat"; $f.Controls.Add($btnRemove)
    
    $btnClose = New-Object System.Windows.Forms.Button; $btnClose.Text = "Cancel"; $btnClose.Location = "460, 290"; $btnClose.Width = 100; $btnClose.Height = 35; $btnClose.BackColor = "DimGray"; $btnClose.ForeColor = "White"; $btnClose.FlatStyle = "Flat"; $f.Controls.Add($btnClose)

    # --- LOGIC ---
    $f.AcceptButton = $btnApply 
    $f.CancelButton = $btnClose

    $btnBrowseCmd.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = "Programs|*.exe;*.bat;*.cmd|All Files|*.*"
        if ($dlg.ShowDialog() -eq "OK") { $txtCmd.Text = "`"$($dlg.FileName)`" `"%1`"" }
    })
    $btnBrowseIcon.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = "Icons|*.ico;*.exe;*.dll|All Files|*.*"
        if ($dlg.ShowDialog() -eq "OK") { $txtIcon.Text = $dlg.FileName }
    })

    $btnApply.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtName.Text) -or [string]::IsNullOrWhiteSpace($txtCmd.Text)) { [System.Windows.Forms.MessageBox]::Show("Name and Command are required."); return }
        
        $targets = @("HKCU:\Software\Classes\*\shell\SetDesktopWallpaper", "HKCU:\Software\Classes\Directory\shell\SetDesktopWallpaper")
        try {
            foreach ($key in $targets) {
                if (-not (Test-Path -LiteralPath $key)) { New-Item -Path $key -Force | Out-Null }
                Set-ItemProperty -LiteralPath $key -Name "MUIVerb" -Value $txtName.Text
                Set-ItemProperty -LiteralPath $key -Name "MultiSelectModel" -Value "Player"
                if (-not [string]::IsNullOrWhiteSpace($txtIcon.Text)) { Set-ItemProperty -LiteralPath $key -Name "Icon" -Value $txtIcon.Text }
                
                $cmdKey = Join-Path $key "command"
                if (-not (Test-Path -LiteralPath $cmdKey)) { New-Item -Path $cmdKey -Force | Out-Null }
                Set-Item -LiteralPath $cmdKey -Value $txtCmd.Text
            }
            [System.Windows.Forms.MessageBox]::Show("Context Menu updated successfully!", "Success", "OK", "Information")
            $f.Close()
        } catch { [System.Windows.Forms.MessageBox]::Show($_.Exception.Message) }
    })

    $btnRemove.Add_Click({
        if ([System.Windows.Forms.MessageBox]::Show("Remove the custom menu item?", "Confirm", "YesNo") -eq "Yes") {
            $targets = @("HKCU:\Software\Classes\*\shell\SetDesktopWallpaper", "HKCU:\Software\Classes\Directory\shell\SetDesktopWallpaper")
            foreach ($key in $targets) { if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue } }
            [System.Windows.Forms.MessageBox]::Show("Item removed.", "Success")
            $f.Close()
        }
    })
    
    $btnClose.Add_Click({ $f.Close() })
    $f.ShowDialog() | Out-Null
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
                        <Button Name="btnWingetIgnore" Content="Ignore Selected" Width="140" Style="{StaticResource ActionBtn}" Background="#B8860B" ToolTip="Hide selected updates from future scans"/>
                        <Button Name="btnWingetUnignore" Content="Manage Ignored" Width="140" Style="{StaticResource ActionBtn}" ToolTip="View and restore ignored updates"/>
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
                        <Button Name="btnCtxBuilder" Content="Custom Context Menu" Width="200" Style="{StaticResource ActionBtn}" Background="#004444"/>
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
$btnWingetIgnore = Get-Ctrl "btnWingetIgnore"
$btnWingetUnignore = Get-Ctrl "btnWingetUnignore"
# (Ban Icon for Ignore)
Set-ButtonIcon "btnWingetIgnore" "M12,2A10,10 0 0,1 22,12A10,10 0 0,1 12,22A10,10 0 0,1 2,12A10,10 0 0,1 12,2M12,4A8,8 0 0,0 4,12C4,13.85 4.63,15.55 5.68,16.91L16.91,5.68C15.55,4.63 13.85,4 12,4M12,20A8,8 0 0,0 20,12C20,10.15 19.37,8.45 18.32,7.09L7.09,18.32C8.45,19.37 10.15,20 12,20Z" "Ignore Selected" "Hide selected updates from future scans" 16 "#FFD700"
# (List/Restore Icon for Unignore)
Set-ButtonIcon "btnWingetUnignore" "M2,5H22V7H2V5M2,9H22V11H2V9M2,13H22V15H2V13M2,17H22V19H2V17" "Manage Ignored" "View and restore ignored updates"

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
Set-ButtonIcon "btnCtxBuilder" "M19,3H5C3.89,3 3,3.89 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V5C21,3.89 20.1,3 19,3M19,19H5V5H19V19M10,17L5,12L6.41,10.59L10,14.17L17.59,6.58L19,8L10,17Z" "Context Menu Builder" "Create a custom right-click action for Windows 11"
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
$btnCtxBuilder = Get-Ctrl "btnCtxBuilder"

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
Add-SearchIndexEntry "btnCtxBuilder" "Custom Context Menu Builder" "btnTabUtils"

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


# WINGET CONTEXT MENU (Right-Click)
$ctxMenu = New-Object System.Windows.Controls.ContextMenu

# 1. Update Selected
$miUpdate = New-Object System.Windows.Controls.MenuItem
$miUpdate.Header = "Update Selected"
# We reference the button variable directly to ensure it works
$miUpdate.Add_Click({ 
    $btnWingetUpdateSel.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
})
[void]$ctxMenu.Items.Add($miUpdate)

# 2. Uninstall Selected
$miUninstall = New-Object System.Windows.Controls.MenuItem
$miUninstall.Header = "Uninstall Selected"
$miUninstall.Add_Click({ 
    $btnWingetUninstall.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
})
[void]$ctxMenu.Items.Add($miUninstall)

# --- Separator ---
[void]$ctxMenu.Items.Add((New-Object System.Windows.Controls.Separator))

# 3. Ignore Selected
$miIgnore = New-Object System.Windows.Controls.MenuItem
$miIgnore.Header = "Ignore Selected"
$miIgnore.Add_Click({ 
    $btnWingetIgnore.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
})
[void]$ctxMenu.Items.Add($miIgnore)

# 4. Manage Ignored
$miManage = New-Object System.Windows.Controls.MenuItem
$miManage.Header = "Manage Ignored List..."
$miManage.Add_Click({ 
    $btnWingetUnignore.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
})
[void]$ctxMenu.Items.Add($miManage)

# --- Separator ---
[void]$ctxMenu.Items.Add((New-Object System.Windows.Controls.Separator))

# 5. Refresh Updates
$miRefresh = New-Object System.Windows.Controls.MenuItem
$miRefresh.Header = "Refresh Updates"
$miRefresh.Add_Click({ 
    $btnWingetScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
})
[void]$ctxMenu.Items.Add($miRefresh)

# 6. Attach to List
$lstWinget.ContextMenu = $ctxMenu

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
        IsUninstall = ($ActionName -eq "Uninstall")
        LocalAppData = $env:LOCALAPPDATA 
        TempDir = $env:TEMP
    }

    $script:WingetJob = Start-Job -ArgumentList $jobArgs -ScriptBlock {
        param($ArgsDict)
        Add-Type -AssemblyName System.Windows.Forms
        
        $items = $ArgsDict.Items
        $tmpl = $ArgsDict.Template
        $isUninstall = $ArgsDict.IsUninstall
        $localAppData = $ArgsDict.LocalAppData
        $tempDir = $ArgsDict.TempDir
        
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

        # --- 1. COMPREHENSIVE ERROR CODE DATABASE ---
        $ErrorCodes = @{
            # Success
            "0"          = "Success"
            "0x0"        = "Success"

            # WinGet Specific (0x8A15xxxx)
            "0x8a150001" = "Invalid Argument (WinGet parameter error)";
            "0x8a150002" = "Command Failed (General internal failure)";
            "0x8a150003" = "Source Not Found (Repo missing or corrupted)";
            "0x8a150004" = "Installer Failed (Generic installer error)";
            "0x8a150005" = "Download Hash Mismatch (File corrupted/altered)";
            "0x8a150006" = "No Applicable Installer (Not supported on this OS/Arch)";
            "0x8a150007" = "Installer Failed to Start (Exe/MSI launch failed)";
            "0x8a150008" = "Manifest Not Found (Package info missing)";
            "0x8a150009" = "Invalid Manifest (Package data malformed)";
            "0x8a15000a" = "Unsupported Installer Type";
            "0x8a15000b" = "Package Not Found (ID does not exist)";
            "0x8a15000c" = "Installer Failed (Vendor returned error)";
            "0x8a15000d" = "Download Failed (Network/Server error)";
            "0x8a15000e" = "Installer Hash Mismatch (Validation failed)";
            "0x8a15000f" = "Data Missing (Source broken/outdated)";
            "0x8a150014" = "Network Error (Server disconnected)";

            # Windows System Errors (0x8007xxxx)
            "0x80070002" = "File Not Found (System cannot find file)";
            "0x80070003" = "Path Not Found (Cache corruption or missing file)";
            "0x80070005" = "Access Denied (Try running as Admin)";
            "0x80070490" = "Element Not Found (Windows Update/MSIX issue)";
            "0x80072ee7" = "DNS Lookup Failure (Check internet)";
            "0x80072f8f" = "SSL/TLS Certificate Error (Check Date/Time)";
            "0x800401f5" = "Application Not Found (Ghost Registry Entry)";

            # Installer / MSI Codes
            "1603"       = "Fatal Error (Generic MSI Failure)";
            "1618"       = "Installation in Progress (Another installer running)";
            "1619"       = "Package Error (Could not open package)";
            "1602"       = "Cancelled by User";
            "1639"       = "Invalid Command Line Argument"
        }

        foreach ($item in $items) {
            Write-Output "Processing: $($item.Name)..."
            $baseCmd = $tmpl -f $item.Id
            
            $commonFlags = "--accept-source-agreements"
            if (-not $isUninstall) {
                $commonFlags += " --accept-package-agreements"
            }

            # 2. Attempt Silent Execution
            $expr = "$baseCmd $commonFlags --disable-interactivity"
            
            # Capture both STDOUT and STDERR merged
            $output = Invoke-Expression "$expr 2>&1"
            
            $failed = $false
            $adminBlocked = $false
            $detectedLog = $null
            $failureReason = ""

            # 3. Analyze Output Line-by-Line
            foreach ($line in $output) {
                $lineStr = $line.ToString()
                if ($lineStr -match '^\s*[\-\\|/]\s*$') { continue }
                
                # A. Detect Log File Paths in Output
                if ($lineStr -match "Log file.*:\s*(.*\.log)") {
                    $detectedLog = $matches[1].Trim()
                }

                # B. Translate Error Codes
                # Matches Hex (0x...) OR 4-digit Windows Installer codes (16xx)
                if ($lineStr -match "(0x[0-9a-fA-F]{8}|16[0-9]{2})") {
                    $code = $matches[1].ToLower()
                    if ($ErrorCodes.ContainsKey($code)) {
                        $desc = $ErrorCodes[$code]
                        $lineStr += " < $desc >"
                        $lineStr += "`n   [!] NOTE: This error is from WinGet or the App Installer, NOT the Windows Maintenance Tool."
                        
                        if ($code -ne "0" -and $code -ne "0x0") { 
                            $failureReason = "$desc ($code)" 
                        }
                    }
                }

                Write-Output $lineStr
                
                # C. Detect Failure Keywords
                if ($lineStr -match "Installer failed" -or $lineStr -match "exit code:") { $failed = $true }
                if ($lineStr -match "Argument name was not recognized") { $failed = $true }
                if ($lineStr -match "cannot be .* from an admin.* context" -or $lineStr -match "run this installer as a normal user") {
                    $failed = $true; $adminBlocked = $true
                }
            }
            
            # 4. Special "Deep Scan" for Silent .NET/Burn Logs (if no log found yet)
            if (-not $detectedLog -and ($item.Id -match "Microsoft.DotNet" -or $failed)) {
                $logPaths = @($tempDir)
                $wingetDir = Get-ChildItem -Path "$localAppData\Packages\Microsoft.DesktopAppInstaller_*" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
                if ($wingetDir) { $logPaths += "$wingetDir\LocalState\DiagOutputDir" }
                
                # Find recent log (last 3 mins) matching the ID or SDK pattern
                $foundLog = Get-ChildItem -Path $logPaths -Recurse -ErrorAction SilentlyContinue | 
                            Where-Object { 
                                $_.LastWriteTime -gt (Get-Date).AddMinutes(-3) -and 
                                ($_.Name -match "Microsoft.DotNet.SDK" -or $_.Name -match "WinGet")
                            } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                
                if ($foundLog) {
                    $content = Get-Content -Path $foundLog.FullName -Raw -ErrorAction SilentlyContinue
                    # Check for the known "Pseudo Bundle" corruption
                    if ($content -match "Error 0x80070003" -or $content -match "Failed to get size of pseudo bundle") {
                        $failureReason = "Installer Cache Corruption (0x80070003)"
                        $failed = $true
                        Write-Output ">> [CRITICAL] Detected silent cache corruption in log."
                    }
                    $detectedLog = $foundLog.FullName
                }
            }

            # 5. Handle Failures & User Interaction
            
            # Case A: Admin Context Blocked
            if ($adminBlocked) {
                $msg = "The installer for '$($item.Name)' refuses to run as Administrator.`n`nLaunch as Standard User?"
                $choice = [System.Windows.Forms.MessageBox]::Show($msg, "Admin Context Blocked", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                if ($choice -eq "Yes") {
                    Write-Output ">> Preparing to launch as Standard User..."
                    $tempCmd = Join-Path $tempDir "WMT_DeElevate_Install.cmd"
                    $batchContent = "@echo off`nTitle Installing $($item.Name)`necho Launching Winget as Standard User...`n$baseCmd $commonFlags`npause`ndel `"%~f0`" & exit"
                    Set-Content -Path $tempCmd -Value $batchContent -Encoding ASCII
                    Start-Process (Join-Path $env:WinDir "explorer.exe") -ArgumentList "`"$tempCmd`""
                    $failed = $false 
                }
            }
            # Case B: General Failure (Silent or Explicit)
            elseif ($failed) {
                # B1. Offer Log Link (If found)
                if ($detectedLog) {
                    $logMsg = "The operation failed.`n"
                    if ($failureReason) { $logMsg += "Reason: $failureReason`n" }
                    $logMsg += "`nA log file was detected. Would you like to open it to see why?"
                    
                    $logChoice = [System.Windows.Forms.MessageBox]::Show($logMsg, "Installation Failed", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Error)
                    if ($logChoice -eq "Yes") {
                        Invoke-Item $detectedLog
                    }
                }

                # B2. Offer Interactive Mode
                $retryMsg = "Silent installation failed for '$($item.Name)'."
                if ($failureReason) { $retryMsg += "`nError: $failureReason" }
                $retryMsg += "`n`nWould you like to try running the installer INTERACTIVELY so you can see the error messages?"
                
                $retryChoice = [System.Windows.Forms.MessageBox]::Show($retryMsg, "Retry Interactively?", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
                
                if ($retryChoice -eq "Yes") {
                    [System.Windows.Forms.MessageBox]::Show("The installer UI will now open.`nPlease follow the prompts manually.", "Launching Interactive Mode", [System.Windows.Forms.MessageBoxButton]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    Write-Output ">> Launching Interactive Mode..."
                    $argString = $baseCmd -replace "^winget\s+", ""
                    $finalArgs = "$argString $commonFlags --interactive"
                    $proc = Start-Process -FilePath "winget" -ArgumentList $finalArgs -Wait -PassThru -NoNewWindow
                    Write-Output ">> Interactive process finished (Exit Code: $($proc.ExitCode))."
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
    
    # 1. LOAD IGNORE LIST
    $currentSettings = Get-WmtSettings
    $ignoreList = if ($currentSettings.WingetIgnore) { $currentSettings.WingetIgnore } else { @() }

    $tempOut = Join-Path $env:TEMP "winget_upd.txt"
    
    # Capture output
    $psCmd = "chcp 65001 >`$null; `$host.ui.RawUI.BufferSize = New-Object Management.Automation.Host.Size(300, 3000); winget list --upgrade-available --accept-source-agreements 2>&1 | Out-File -FilePath `"$tempOut`" -Encoding UTF8"
    
    $proc = Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -Command $psCmd" -NoNewWindow -PassThru
    $proc.WaitForExit()
    
    if (Test-Path $tempOut) {
        $lines = Get-Content $tempOut -Encoding UTF8
        
        foreach ($line in $lines) {
            $line = $line.Trim()
            
            if ($line -eq "" -or $line -match "^Name" -or $line -match "^----" -or $line -match "upgrades\s+available" -or $line -match "No installed package found") { continue }
            if ($line -match "[\u2580-\u259F]") { continue }
            if ($line -match "\d+\s*(KB|MB|GB|TB)") { continue }

            $name=$null; $id=$null; $ver=$null; $avail="-"; $src="winget"

            if ($line -match '^(.+)\s+([^<\s]\S*)\s+((?:<\s+)?\S+)\s+(\S+)\s+(\S+)$') {
                $name = $matches[1]; $id = $matches[2]; $ver = $matches[3]; $avail = $matches[4]; $src = $matches[5]
            }
            elseif ($line -match '^(.+)\s+([^<\s]\S*)\s+((?:<\s+)?\S+)\s+(\S+)$') {
                $name = $matches[1]; $id = $matches[2]; $ver = $matches[3]; $src = $matches[4]
            }
            elseif ($line -match '^(.+)\s+([^<\s]\S*)\s+((?:<\s+)?\S+)$') {
                $name = $matches[1]; $id = $matches[2]; $ver = $matches[3]
            }

            if ($name -and $id -notmatch "^(KB|MB|GB|/)$") {
                # 2. FILTER: Only add if ID is NOT in ignore list
                if ($id.Trim() -notin $ignoreList) {
                    [void]$lstWinget.Items.Add([PSCustomObject]@{ 
                        Name=$name.Trim(); Id=$id.Trim(); Version=$ver.Trim(); Available=$avail.Trim(); Source=$src.Trim() 
                    })
                }
            }
        }
        Remove-Item $tempOut -ErrorAction SilentlyContinue
    }
    
    $logCount = $lstWinget.Items.Count
    if ($logCount -eq 0) {
        [void]$lstWinget.Items.Add([PSCustomObject]@{ 
            Name="No updates available"; Id=""; Version=""; Available=""; Source="" 
        })
        $logCount = 0
    }
    
    $lblWingetStatus.Visibility = "Hidden"
    Write-GuiLog "Scan complete. Found $logCount updates."
})

# --- IGNORE SELECTED ---
$btnWingetIgnore.Add_Click({
    $selected = @($lstWinget.SelectedItems)
    if ($selected.Count -eq 0) { return }

    $msg = "Ignore $($selected.Count) package(s)?`n`nThese updates will be hidden from future scans."
    if ([System.Windows.Forms.MessageBox]::Show($msg, "Ignore Updates", "YesNo", "Question") -eq "Yes") {
        
        # 1. Get fresh settings
        $settings = Get-WmtSettings
        
        # 2. Create a fresh ArrayList to ensure it is editable
        $newList = New-Object System.Collections.ArrayList
        
        # Add existing items (checking for nulls)
        if ($settings.WingetIgnore) {
            foreach ($existing in $settings.WingetIgnore) {
                if (-not [string]::IsNullOrWhiteSpace($existing)) {
                    [void]$newList.Add($existing.ToString())
                }
            }
        }

        # 3. Add NEW items
        foreach ($item in $selected) {
            $id = $item.Id
            # Avoid duplicates
            if ($id -and ($id -notin $newList)) {
                [void]$newList.Add($id)
            }
            # Remove from GUI immediately
            $lstWinget.Items.Remove($item)
        }

        # 4. Save back as a standard array
        $settings.WingetIgnore = $newList.ToArray()
        Save-WmtSettings -Settings $settings
        
        Write-GuiLog "Ignored $($selected.Count) packages. Saved to settings.json."
    }
})

# --- MANAGE IGNORED (UNIGNORE) ---
$btnWingetUnignore.Add_Click({
    # 1. READ SETTINGS (Direct & Simple)
    $jsonPath = Join-Path (Get-DataPath) "settings.json"
    $listItems = @()

    if (Test-Path $jsonPath) {
        try {
            $json = Get-Content $jsonPath -Raw | ConvertFrom-Json
            if ($json.WingetIgnore) {
                # Force array and string conversion immediately
                $listItems = @($json.WingetIgnore) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -ne "" }
            }
        } catch { Write-GuiLog "Error: $($_.Exception.Message)" }
    }

    if ($listItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No ignored packages found.", "Manage Ignored", "OK", "Information") | Out-Null
        return
    }

    # 2. UI SETUP
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Manage Ignored Updates"
    $f.Size = "500, 400"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.Color]::FromArgb(32,32,32)
    $f.ForeColor = "White"

    # 3. CONTROLS (Critical Order for Docking)
    # Add Dock=Bottom/Top controls FIRST so they claim space. Add Dock=Fill LAST.

    # -- Bottom Panel --
    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"; $pnl.Height = 50
    $f.Controls.Add($pnl)

    # -- Top Label --
    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Select packages to restore (Un-ignore):"
    $lbl.Dock = "Top"; $lbl.Height = 30; $lbl.Padding = "10,10,0,0"
    $f.Controls.Add($lbl)

    # -- ListBox (Fill) --
    $lb = New-Object System.Windows.Forms.ListBox
    $lb.Dock = "Fill"
    $lb.BackColor = [System.Drawing.Color]::FromArgb(20,20,20)
    $lb.ForeColor = "White"
    $lb.BorderStyle = "FixedSingle"
    $lb.SelectionMode = "MultiExtended"
    
    # Manual Add (Fail-safe)
    $lb.BeginUpdate()
    foreach ($item in $listItems) {
        [void]$lb.Items.Add($item)
    }
    $lb.EndUpdate()
    
    $f.Controls.Add($lb)
    
    # CRITICAL: Ensure ListBox is at the 'top' of Z-order so it fills remaining space correctly
    $lb.BringToFront()

    # -- Buttons --
    $btnRestore = New-Object System.Windows.Forms.Button
    $btnRestore.Text = "Un-Ignore Selected"
    $btnRestore.Size = "150, 30"; $btnRestore.Location = "20, 10"
    $btnRestore.BackColor = "SeaGreen"; $btnRestore.ForeColor = "White"; $btnRestore.FlatStyle = "Flat"
    $pnl.Controls.Add($btnRestore)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Size = "100, 30"; $btnClose.Location = "360, 10"
    $btnClose.BackColor = "DimGray"; $btnClose.ForeColor = "White"; $btnClose.FlatStyle = "Flat"
    $btnClose.Add_Click({ $f.Close() })
    $pnl.Controls.Add($btnClose)

    # 4. ACTION
    $script:RefreshNeeded = $false

    $btnRestore.Add_Click({
        $selected = @($lb.SelectedItems)
        if ($selected.Count -gt 0) {
            # Read fresh, remove items, save
            $s = Get-WmtSettings
            $current = [System.Collections.ArrayList]@($s.WingetIgnore)
            
            foreach ($item in $selected) {
                if ($current.Contains($item)) { $current.Remove($item) }
                $lb.Items.Remove($item)
            }
            
            $s.WingetIgnore = $current.ToArray()
            Save-WmtSettings -Settings $s
            $script:RefreshNeeded = $true
        }
    })

    $f.ShowDialog() | Out-Null
    
    if ($script:RefreshNeeded) {
        Write-GuiLog "List updated. Refreshing..."
        $btnWingetScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))
    }
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
    
    if ($form.ShowDialog() -eq "OK") { 
        $choice = ($radios | Where-Object { $_.Checked }).Tag; 
        if ($choice) { 
            # FIXED LINE BELOW: Added param block and ArgumentList
            Invoke-UiCommand { param($choice) Set-DotNetRollForward -Mode $choice } "Setting .NET roll-forward ($choice)..." -ArgumentList $choice
        } 
    }
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
$btnCtxBuilder.Add_Click({ Show-ContextMenuBuilder })

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
$window.Add_Loaded({ 
    # 1. Click the Updates tab by default
    (Get-Ctrl "btnTabUpdates").RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) 
    
    # 2. Trigger the background update check
    Start-UpdateCheckBackground
})

# 3. Show the Window
$window.ShowDialog() | Out-Null