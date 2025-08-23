# ===== ADMIN AND CERTIFICATE BYPASS =====
if (-NOT (whoami /groups | Select-String 'S-1-5-32-544')) {
    Start-Process pwsh -Args "-NoExit -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
# ===== Main Content =====
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Pause-Menu {
    Write-Host
    Read-Host "Press ENTER to return to menu"
}

function Show-Menu {
    Clear-Host
    Write-Host "====================================================="
    Write-Host "         WINDOWS MAINTENANCE TOOL V3.6.0 - By Lil_Batti & Chaython"
    Write-Host "====================================================="
    Write-Host
    Write-Host "     === WINDOWS UPDATES ==="
    Write-Host "  [1]  Update Windows Apps / Programs (Winget upgrade)"
    Write-Host
    Write-Host "     === SYSTEM HEALTH CHECKS ==="
    Write-Host "  [2]  Scan for corrupt files (SFC /scannow) [Admin]"
    Write-Host "  [3]  Windows CheckHealth (DISM) [Admin]"
    Write-Host "  [4]  Restore Windows Health (DISM /RestoreHealth) [Admin]"
    Write-Host
    Write-Host "     === NETWORK TOOLS ==="
    Write-Host "  [5]  DNS Options (Flush/Set/Reset, IPv4/IPv6, DoH)"
    Write-Host "  [6]  Show network information (ipconfig /all)"
    Write-Host "  [7]  Restart Wi-Fi Adapters"
    Write-Host "  [8]  Network Repair - Automatic Troubleshooter"
    Write-Host "  [9]  Firewall Manager [Admin]"
    Write-Host 
    Write-Host "     === CLEANUP & OPTIMIZATION ==="
    Write-Host " [10]  Disk Cleanup (cleanmgr)"
    Write-Host " [11]  Run Advanced Error Scan (CHKDSK) [Admin]"
    Write-Host " [12]  Perform System Optimization (Delete Temporary Files)"
    Write-Host " [13]  Advanced Registry Cleanup-Optimization"
    Write-Host " [14]  Optimize SSDs (ReTrim)"
    Write-Host " [15]  Task Management (Scheduled Tasks) [Admin]"
    Write-Host
    Write-Host "     === UTILITIES & EXTRAS ==="
    Write-Host " [20]  Show installed drivers"
    Write-Host " [21]  Windows Update Repair Tool"
    Write-Host " [22]  Generate Full System Report"
    Write-Host " [23]  Windows Update Utility & Service Reset"
    Write-Host " [24]  View Network Routing Table [Advanced]"
    Write-Host " [25]  .NET RollForward Settings [Reduces apps requesting you to install older .NET versions]"
    Write-Host
    Write-Host "     === SUPPORT ==="
    Write-Host " [30]  Contact and Support information (Discord) [h, help]"
    Write-Host
    Write-Host " [0]  EXIT"
    Write-Host "------------------------------------------------------"
}

function Choice-1 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Windows Update (via Winget)"
    Write-Host "==============================================="
    
    # Check if Winget is installed
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Winget is not installed. Attempting to install it automatically..."
        Write-Host
        
        try {
            # Method 1: Try installing via Microsoft Store (App Installer)
            Write-Host "Installing Winget via Microsoft Store..."
            $result = Start-Process "ms-windows-store://pdp/?productid=9NBLGGH4NNS1" -Wait -PassThru
            
            if ($result.ExitCode -eq 0) {
                Write-Host "Microsoft Store opened successfully. Please complete the installation."
                Write-Host "After installation, restart this tool to use Winget features."
                Pause-Menu
                return
            } else {
                # Method 2: Alternative direct download if Store method fails
                Write-Host "Microsoft Store method failed, trying direct download..."
                $wingetUrl = "https://aka.ms/getwinget"
                $installerPath = "$env:TEMP\winget-cli.msixbundle"
                
                # Download the installer
                Invoke-WebRequest -Uri $wingetUrl -OutFile $installerPath
                
                # Install Winget
                Add-AppxPackage -Path $installerPath
                
                # Verify installation
                if (Get-Command winget -ErrorAction SilentlyContinue) {
                    Write-Host "Winget installed successfully!"
                    Start-Sleep -Seconds 2
                } else {
                    Write-Host "Installation failed. Please install manually from Microsoft Store."
                    Pause-Menu
                    return
                }
            }
        } catch {
            Write-Host "Failed to install Winget automatically. Error: $_"
            Write-Host "Please install 'App Installer' from Microsoft Store manually."
            Pause-Menu
            return
        }
    }

    # Main Winget functionality
    Write-Host "Listing available upgrades..."
    Write-Host
    winget upgrade --include-unknown
    Write-Host

    while ($true) {
        Write-Host "==============================================="
        Write-Host "Options:"
        Write-Host "[1] Upgrade all packages"
        Write-Host "[0] Cancel"
        Write-Host
        Write-Host "Or simply enter a package ID to upgrade it directly"
        Write-Host
        $input = Read-Host "Enter your choice or package ID"
        $input = $input.Trim()
        
        if ($input -eq "0") {
            Write-Host "Cancelled. Returning to menu..."
            Start-Sleep -Seconds 1
            return
        }
        elseif ($input -eq "1") {
            Write-Host "Running full upgrade..."
            winget upgrade --all --include-unknown
            Pause-Menu
            return
        }
        elseif (-not [string]::IsNullOrWhiteSpace($input)) {
            # Treat as package ID
            Write-Host "Upgrading $input..."
            winget upgrade --id $input --include-unknown
            Pause-Menu
            return
        }
        else {
            Write-Host "Invalid input. Please enter a package ID, 1, or 0."
        }
    }
}

function Choice-2 {
    Clear-Host
    Write-Host "Scanning for corrupt files (SFC /scannow)..."
    sfc /scannow
    Pause-Menu
}

function Choice-3 {
    Clear-Host
    Write-Host "Checking Windows health status (DISM /CheckHealth)..."
    dism /online /cleanup-image /checkhealth
    Pause-Menu
}

function Choice-4 {
    Clear-Host
    Write-Host "Restoring Windows health status (DISM /RestoreHealth)..."
    dism /online /cleanup-image /restorehealth
    Pause-Menu
}

function Choice-5 {
    function Get-ActiveAdapters {
        # Exclude virtual adapters like vEthernet
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*' -and $_.Name -notlike '*vEthernet*' } | Select-Object -ExpandProperty Name
    }

    # Check if DoH is supported (Windows 11 or recent Windows 10)
    function Test-DoHSupport {
        $osVersion = [System.Environment]::OSVersion.Version
        return ($osVersion.Major -eq 10 -and $osVersion.Build -ge 19041) -or ($osVersion.Major -gt 10)
    }

    # Check if running as Administrator
    function Test-Admin {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Function to enable DoH for all known DNS servers using netsh
    function Enable-DoHAllServers {
        $dnsServers = @(
            # Cloudflare DNS
            @{ Server = "1.1.1.1"; Template = "https://cloudflare-dns.com/dns-query" },
            @{ Server = "1.0.0.1"; Template = "https://cloudflare-dns.com/dns-query" },
            @{ Server = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query" },
            @{ Server = "2606:4700:4700::1001"; Template = "https://cloudflare-dns.com/dns-query" },
            # Google DNS
            @{ Server = "8.8.8.8"; Template = "https://dns.google/dns-query" },
            @{ Server = "8.8.4.4"; Template = "https://dns.google/dns-query" },
            @{ Server = "2001:4860:4860::8888"; Template = "https://dns.google/dns-query" },
            @{ Server = "2001:4860:4860::8844"; Template = "https://dns.google/dns-query" },
            # Quad9 DNS
            @{ Server = "9.9.9.9"; Template = "https://dns.quad9.net/dns-query" },
            @{ Server = "149.112.112.112"; Template = "https://dns.quad9.net/dns-query" },
            @{ Server = "2620:fe::fe"; Template = "https://dns.quad9.net/dns-query" },
            @{ Server = "2620:fe::fe:9"; Template = "https://dns.quad9.net/dns-query" },
            # AdGuard DNS
            @{ Server = "94.140.14.14"; Template = "https://dns.adguard.com/dns-query" },
            @{ Server = "94.140.15.15"; Template = "https://dns.adguard.com/dns-query" },
            @{ Server = "2a10:50c0::ad1:ff"; Template = "https://dns.adguard.com/dns-query" },
            @{ Server = "2a10:50c0::ad2:ff"; Template = "https://dns.adguard.com/dns-query" }
        )
        Write-Host "Enabling DoH for all known DNS servers..."
        $successCount = 0
        foreach ($dns in $dnsServers) {
            try {
                $command = "netsh dns add encryption server=$($dns.Server) dohtemplate=$($dns.Template) autoupgrade=yes udpfallback=no"
                $result = Invoke-Expression $command 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  - DoH enabled for $($dns.Server) with template $($dns.Template)" -ForegroundColor Green
                    $successCount++
                } else {
                    Write-Host "  - Failed to enable DoH for $($dns.Server): $result" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  - Failed to enable DoH for $($dns.Server): $_" -ForegroundColor Yellow
            }
        }
        if ($successCount -eq 0) {
            Write-Host "  - No DoH settings were applied successfully. Check system permissions or Windows version." -ForegroundColor Red
            return $false
        }
        # Flush DNS cache to ensure changes are applied
        try {
            Invoke-Expression "ipconfig /flushdns" | Out-Null
            Write-Host "  - DNS cache flushed to apply changes" -ForegroundColor Green
        } catch {
            Write-Host "  - Failed to flush DNS cache: $_" -ForegroundColor Yellow
        }
        # Attempt to restart DNS client service if running as Administrator
        if (Test-Admin) {
            $service = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
            if ($service.Status -eq "Running" -and $service.StartType -ne "Disabled") {
                try {
                    Restart-Service -Name Dnscache -Force -ErrorAction Stop
                    Write-Host "  - DNS client service restarted to apply DoH settings" -ForegroundColor Green
                } catch {
                    Write-Host "  - Failed to restart DNS client service: $_" -ForegroundColor Yellow
                    try {
                        $stopResult = Invoke-Expression "net stop dnscache" 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Start-Sleep -Seconds 2
                            $startResult = Invoke-Expression "net start dnscache" 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "  - DNS client service restarted using net stop/start" -ForegroundColor Green
                            } else {
                                Write-Host "  - Failed to start DNS client service: $startResult" -ForegroundColor Yellow
                            }
                        } else {
                            Write-Host "  - Failed to stop DNS client service: $stopResult" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "  - Failed to restart DNS client service via net commands: $_" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "  - DNS client service is not running or is disabled. Please enable and start it manually." -ForegroundColor Yellow
            }
            Write-Host "  - Please reboot your system to apply DoH settings or manually restart the 'DNS Client' service in services.msc." -ForegroundColor Yellow
        } else {
            Write-Host "  - Not running as Administrator. Cannot restart DNS client service. Please reboot to apply DoH settings." -ForegroundColor Yellow
        }
        return $true
    }

    # Function to check DoH status
    function Check-DoHStatus {
        try {
            $netshOutput = Invoke-Expression "netsh dns show encryption" | Out-String
            if ($netshOutput -match "cloudflare-dns\.com|dns\.google|dns\.quad9\.net|dns\.adguard\.com") {
                Write-Host "DoH Status:"
                Write-Host $netshOutput -ForegroundColor Green
                Write-Host "DoH is enabled for at least one known DNS server." -ForegroundColor Green
            } else {
                Write-Host "DoH Status:"
                Write-Host $netshOutput -ForegroundColor Yellow
                Write-Host "No DoH settings detected. Ensure DNS servers are set and DoH was applied successfully." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Failed to check DoH status: $_" -ForegroundColor Red
        }
        Pause-Menu
    }

    # Function to update hosts file with ad-blocking entries
function Update-HostsFile {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "   Updating Windows Hosts File with Ad-Blocking"
    Write-Host "==============================================="
    
    # Check for admin privileges
    if (-not (Test-Admin)) {
        Write-Host "Error: This operation requires administrator privileges." -ForegroundColor Red
        Write-Host "Please run the script as Administrator and try again."
        Pause-Menu
        return
    }
    
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $backupDir = "$env:windir\System32\drivers\etc\hosts_backups"
    $dnsService = "Dnscache"
    $maxRetries = 3
    $retryDelay = 2 # seconds

    # List of mirrors to try (in order)
    $mirrors = @(
        "https://o0.pages.dev/Lite/hosts.win",
        "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/hosts.win",
        "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.win"
    )

    try {
        # ===== ENSURE BACKUP DIRECTORY EXISTS =====
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            Write-Host "Created backup directory: $backupDir" -ForegroundColor Green
        }

        # ===== CREATE BACKUP =====
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $uniqueBackupPath = "$backupDir\hosts_$timestamp.bak"
        
        if (Test-Path $hostsPath) {
            Write-Host "Creating backup of hosts file..."
            try {
                Copy-Item $hostsPath $uniqueBackupPath -Force
                Write-Host "Backup created at: $uniqueBackupPath" -ForegroundColor Green
            } catch {
                Write-Host "Warning: Could not create backup - $($_.Exception.Message)" -ForegroundColor Yellow
                $uniqueBackupPath = $null
            }
        } else {
            Write-Host "No existing hosts file found - will create new one" -ForegroundColor Yellow
            $uniqueBackupPath = $null
        }

        # ===== DOWNLOAD WITH MIRROR FALLBACK =====
        $adBlockContent = $null
        $successfulMirror = $null

        foreach ($mirror in $mirrors) {
            Write-Host "`nAttempting download from: $mirror"
            
            try {
                $webClient = New-Object System.Net.WebClient
                $adBlockContent = $webClient.DownloadString($mirror)
                $successfulMirror = $mirror
                Write-Host "Successfully downloaded hosts file" -ForegroundColor Green
                break
            } catch [System.Net.WebException] {
                Write-Host "Download failed: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            } catch {
                Write-Host "Unexpected error: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            } finally {
                if ($webClient -ne $null) {
                    $webClient.Dispose()
                }
            }
        }

        if (-not $adBlockContent) {
            throw "All mirrors failed! Could not download ad-blocking hosts file."
        }

        # ===== PREPARE NEW CONTENT =====
        $existingContent = if ($uniqueBackupPath -and (Test-Path $uniqueBackupPath)) {
            Get-Content $uniqueBackupPath | Where-Object {
                $_ -notmatch "^# Ad-blocking entries" -and 
                $_ -notmatch "^0\.0\.0\.0" -and 
                $_ -notmatch "^127\.0\.0\.1" -and
                $_ -notmatch "^::1" -and
                $_ -notmatch "^$"
            }
        } else { "" }
        
        $newContent = @"
# Ad-blocking entries - Updated $(Get-Date)
# Downloaded from: $successfulMirror
# Original hosts file backed up to: $(if ($uniqueBackupPath) { $uniqueBackupPath } else { "No backup created" })

$existingContent

$adBlockContent
"@

        # ===== UPDATE HOSTS FILE =====
        Write-Host "`nPreparing to update hosts file..."
        
        # Write new content with retry logic
        $attempt = 0
        $success = $false
        
        while (-not $success -and $attempt -lt $maxRetries) {
            $attempt++
            try {
                # Create temporary file
                $tempFile = [System.IO.Path]::GetTempFileName()
                [System.IO.File]::WriteAllText($tempFile, $newContent, [System.Text.Encoding]::UTF8)
                
                # Replace hosts file using cmd.exe for maximum reliability
                $tempDest = "$hostsPath.tmp"
                $copyCommand = @"
@echo off
if exist "$hostsPath" move /Y "$hostsPath" "$tempDest"
move /Y "$tempFile" "$hostsPath"
if exist "$tempDest" del /F /Q "$tempDest"
"@
                $batchFile = [System.IO.Path]::GetTempFileName() + ".cmd"
                [System.IO.File]::WriteAllText($batchFile, $copyCommand)
                
                Start-Process "cmd.exe" -ArgumentList "/c `"$batchFile`"" -Wait -WindowStyle Hidden
                Remove-Item $batchFile -Force
                
                if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                if (Test-Path $tempDest) { Remove-Item $tempDest -Force }
                
                $success = $true
                $entryCount = ($adBlockContent -split "`n").Count
                Write-Host "Successfully updated hosts file with $entryCount ad-blocking entries." -ForegroundColor Green
            } catch {
                Write-Host "Attempt $attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
                if ($attempt -lt $maxRetries) {
                    Write-Host "Retrying in $retryDelay seconds..."
                    Start-Sleep -Seconds $retryDelay
                }
                # Clean up any temp files
                if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                if (Test-Path $tempDest) { Remove-Item $tempDest -Force }
            }
        }

        if (-not $success) {
            throw "Failed to update hosts file after $maxRetries attempts."
        }

        # ===== FLUSH DNS =====
        Write-Host "Flushing DNS cache..."
        try {
            ipconfig /flushdns | Out-Null
            Write-Host "DNS cache flushed successfully." -ForegroundColor Green
        } catch {
            Write-Host "Warning: Could not flush DNS cache. Changes may require a reboot." -ForegroundColor Yellow
        }

        # ===== CLEAN UP ALL BACKUPS =====
        if ($success -and $uniqueBackupPath) {
            Write-Host "`nChecking for backup files in $backupDir..."
            
            # Get all backup files
            $allBackups = Get-ChildItem -Path $backupDir -Filter "hosts_*.bak" | 
                         Sort-Object CreationTime -Descending
            
            if ($allBackups.Count -gt 0) {
                Write-Host "Found $($allBackups.Count) backup files:"
                $allBackups | ForEach-Object {
                    Write-Host "  - $($_.Name) (Created: $($_.CreationTime))" -ForegroundColor Yellow
                }
                
                Write-Host "`nWARNING: Deleting these backup files is permanent and they CANNOT be restored!" -ForegroundColor Red
                $confirm = Read-Host "Are you sure you want to delete ALL $($allBackups.Count) backup files? (Y/1 for Yes, N/0 for No)"
                if ($confirm -match '^[Yy1]$') {
                    $deletedCount = 0
                    $allBackups | ForEach-Object {
                        try {
                            Remove-Item $_.FullName -Force
                            Write-Host "Deleted: $($_.Name)" -ForegroundColor Green
                            $deletedCount++
                        } catch {
                            Write-Host "Failed to delete $($_.Name): $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    Write-Host "Deleted $deletedCount backup files." -ForegroundColor Green
                } else {
                    Write-Host "Keeping all backup files." -ForegroundColor Yellow
                }
            } else {
                Write-Host "No backup files found in $backupDir." -ForegroundColor Green
            }
        }

    } catch {
        Write-Host "`nERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Hosts file update failed!" -ForegroundColor Red
        
        # Attempt to restore from backup
        if ($uniqueBackupPath -and (Test-Path $uniqueBackupPath)) {
            Write-Host "Attempting to restore from backup..."
            try {
                # Use cmd.exe for reliable file replacement
                $restoreCommand = @"
@echo off
if exist "$hostsPath" del /F /Q "$hostsPath"
copy /Y "$uniqueBackupPath" "$hostsPath"
"@
                $batchFile = [System.IO.Path]::GetTempFileName() + ".cmd"
                [System.IO.File]::WriteAllText($batchFile, $restoreCommand)
                
                Start-Process "cmd.exe" -ArgumentList "/c `"$batchFile`"" -Wait -WindowStyle Hidden
                Remove-Item $batchFile -Force
                
                Write-Host "Original hosts file restored from backup." -ForegroundColor Green
            } catch {
                Write-Host "CRITICAL ERROR: Could not restore backup!" -ForegroundColor Red
                Write-Host "Manual recovery required. Backup exists at:" -ForegroundColor Yellow
                Write-Host $uniqueBackupPath -ForegroundColor Yellow
                Write-Host "You may need to copy this file to $hostsPath manually" -ForegroundColor Yellow
            }
        } else {
            Write-Host "No backup available to restore." -ForegroundColor Red
            if (-not (Test-Path $hostsPath)) {
                Write-Host "The hosts file does not exist at $hostsPath" -ForegroundColor Yellow
            }
        }
    }
    
    Pause-Menu
}
    # End of Function to update hosts file with ad-blocking entries, start of settings

    $dohSupported = Test-DoHSupport
    if (-not $dohSupported) {
        Write-Host "Warning: DNS over HTTPS (DoH) is not supported on this system. Option 5 will not be available." -ForegroundColor Yellow
    }

    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host "DNS / Network Tool"
        Write-Host "======================================================"
        Write-Host "[1] Set DNS to Google (8.8.8.8 / 8.8.4.4, IPv6)"
        Write-Host "[2] Set DNS to Cloudflare (1.1.1.1 / 1.0.0.1, IPv6)"
        Write-Host "[3] Restore automatic DNS (DHCP)"
        Write-Host "[4] Use your own DNS (IPv4/IPv6)"
        if ($dohSupported) {
            Write-Host "[5] Encrypt DNS: Enable DoH using netsh on all known DNS servers"
        }
        Write-Host "[6] Update Windows Hosts File with Ad-Blocking"
        Write-Host "[0] Return to menu"
        Write-Host "======================================================"
        $dns_choice = Read-Host "Enter your choice"
        switch ($dns_choice) {
            "1" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!" -ForegroundColor Red; Pause-Menu; return }
                Write-Host "Applying Google DNS (IPv4: 8.8.8.8/8.8.4.4, IPv6: 2001:4860:4860::8888/2001:4860:4860::8844) to:"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    $dnsAddresses = @("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844")
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $dnsAddresses -ErrorAction Stop
                        Write-Host "  - Google DNS applied successfully on $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Failed to configure Google DNS on $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host "Done. Google DNS set with IPv4 and IPv6."
                Write-Host "To enable DoH, use option [5] or configure manually in Settings."
                Pause-Menu
                return
            }
            "2" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!" -ForegroundColor Red; Pause-Menu; return }
                Write-Host "Applying Cloudflare DNS (IPv4: 1.1.1.1/1.0.0.1, IPv6: 2606:4700:4700::1111/2606:4700:4700::1001) to:"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    $dnsAddresses = @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $dnsAddresses -ErrorAction Stop
                        Write-Host "  - Cloudflare DNS applied successfully on $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Failed to configure Cloudflare DNS on $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host "Done. Cloudflare DNS set with IPv4 and IPv6."
                Write-Host "To enable DoH, use option [5] or configure manually in Settings."
                Pause-Menu
                return
            }
            "3" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!" -ForegroundColor Red; Pause-Menu; return }
                Write-Host "Restoring automatic DNS (DHCP) on:"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ResetServerAddresses -ErrorAction Stop
                        Write-Host "  - DNS set to automatic on $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Failed to reset DNS on $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host "Done. DNS set to automatic."
                Pause-Menu
                return
            }
            "4" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "No active network adapters found!" -ForegroundColor Red; Pause-Menu; return }
                while ($true) {
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "          Enter your custom DNS"
                    Write-Host "==============================================="
                    Write-Host "Enter at least one DNS server (IPv4 or IPv6). Multiple addresses can be comma-separated."
                    $customDNS = Read-Host "Enter DNS addresses (e.g., 8.8.8.8,2001:4860:4860::8888)"
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "         Validating DNS addresses..."
                    Write-Host "==============================================="
                    $dnsAddresses = $customDNS.Split(",", [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() }
                    if ($dnsAddresses.Count -eq 0) {
                        Write-Host "[!] ERROR: No DNS addresses entered." -ForegroundColor Red
                        Pause-Menu
                        continue
                    }
                    $validDnsAddresses = @()
                    $allValid = $true
                    foreach ($dns in $dnsAddresses) {
                        $isIPv6 = $dns -match ":"
                        $reachable = Test-Connection -ComputerName $dns -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($reachable) {
                            $validDnsAddresses += $dns
                            Write-Host "Validated: $dns" -ForegroundColor Green
                        } else {
                            Write-Host "[!] ERROR: The DNS address `"$dns`" is not reachable and will be skipped." -ForegroundColor Yellow
                            $allValid = $false
                        }
                    }
                    if ($validDnsAddresses.Count -eq 0) {
                        Write-Host "[!] ERROR: No valid DNS addresses provided." -ForegroundColor Red
                        Pause-Menu
                        continue
                    }
                    break
                }
                Clear-Host
                Write-Host "==============================================="
                Write-Host "    Setting DNS for all active adapters..."
                Write-Host "==============================================="
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $validDnsAddresses -ErrorAction Stop
                        Write-Host "  - Custom DNS applied successfully on $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Failed to configure custom DNS on $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host
                Write-Host "==============================================="
                Write-Host "    DNS has been successfully updated:"
                foreach ($dns in $validDnsAddresses) {
                    Write-Host "      - $dns"
                }
                Write-Host "To enable DoH, use option [5] or configure manually in Settings."
                Write-Host "==============================================="
                Pause-Menu
                return
            }
            "5" {
                if (-not $dohSupported) {
                    Write-Host "Error: DoH is not supported on this system. Option 5 is unavailable." -ForegroundColor Red
                    Pause-Menu
                    return
                }
                $dohApplied = Enable-DoHAllServers
                while ($true) {
                    Clear-Host
                    Write-Host "======================================================"
                    Write-Host "DoH Configuration Menu"
                    Write-Host "======================================================"
                    if ($dohApplied) {
                        Write-Host "DoH was applied for $successCount DNS servers."
                    } else {
                        Write-Host "DoH application failed. Check system permissions or Windows version."
                    }
                    Write-Host "[1] Check DoH status"
                    Write-Host "[0] Return to menu"
                    Write-Host "======================================================"
                    $doh_choice = Read-Host "Enter your choice"
                    switch ($doh_choice) {
                        "1" { Check-DoHStatus }
                        "2" { return }
                        default { Write-Host "Invalid choice, please try again." -ForegroundColor Red; Pause-Menu }
                    }
                }
            }
            "6" { Update-HostsFile }
            "0" { return }
            default { Write-Host "Invalid choice, please try again." -ForegroundColor Red; Pause-Menu }
        }
    }
}
function Choice-6 { Clear-Host; Write-Host "Displaying Network Information..."; ipconfig /all; Pause-Menu }

function Choice-7 {
    Clear-Host
    Write-Host "=========================================="
    Write-Host "    Restarting all Wi-Fi adapters..."
    Write-Host "=========================================="

    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless" -and $_.Status -eq "Up" -or $_.Status -eq "Disabled" }

    if (-not $wifiAdapters) {
        Write-Host "No Wi-Fi adapters found!"
        Pause-Menu
        return
    }

    foreach ($adapter in $wifiAdapters) {
        Write-Host "Restarting '$($adapter.Name)'..."

        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 5

        # Check connection
        $status = Get-NetAdapter -Name $adapter.Name
        if ($status.Status -eq "Up") {
            Write-Host "SUCCESS: '$($adapter.Name)' is back online!" -ForegroundColor Green
        } else {
            Write-Host "WARNING: '$($adapter.Name)' is still offline!" -ForegroundColor Yellow
        }
    }

    Pause-Menu
}

function Choice-8 {
    $Host.UI.RawUI.WindowTitle = "Network Repair - Automatic Troubleshooter"
    Clear-Host
    Write-Host
    Write-Host "==============================="
    Write-Host "    Automatic Network Repair"
    Write-Host "==============================="
    Write-Host
    Write-Host "Step 1: Renewing your IP address..."
    ipconfig /release | Out-Null
    ipconfig /renew  | Out-Null
    Write-Host
    Write-Host "Step 2: Refreshing DNS settings..."
    ipconfig /flushdns | Out-Null
    Write-Host
    Write-Host "Step 3: Resetting network components..."
    netsh winsock reset | Out-Null
    netsh int ip reset  | Out-Null
    Write-Host
    Write-Host "Your network settings have been refreshed."
    Write-Host "A system restart is recommended for full effect."
    Write-Host
    while ($true) {
        $restart = Read-Host "Would you like to restart now? (Y/N)"
        switch ($restart.ToUpper()) {
            "Y" { shutdown /r /t 5; return }
            "N" { return }
            default { Write-Host "Invalid input. Please enter Y or N." }
        }
    }
}

function Choice-9 {
    $Host.UI.RawUI.WindowTitle = "Firewall Manager"
    Clear-Host
    Write-Host
    Write-Host "==============================="
    Write-Host "      Firewall Manager"
    Write-Host "==============================="
    Write-Host
    
    # Main program loop - adapted from the original script
    do {
        Write-Host
        Write-Host "1: View and Manage Firewall Rules"
        Write-Host "2: Export firewall rules to CSV"
        Write-Host "3: Import firewall rules from CSV"
        Write-Host "0: Back to main menu"
        Write-Host
        
        $selection = Read-Host "Please make a selection"
        
        switch ($selection.ToUpper()) {
            '1' {
                do {
                    Clear-Host
                    Write-Host
                    Write-Host "==============================="
                    Write-Host "      Firewall Rules"
                    Write-Host "==============================="
                    Write-Host
                    
                    # Sort rules alphabetically by DisplayName
                    $rules = Get-NetFirewallRule | Sort-Object -Property DisplayName
                    $count = 1
                    
                    Write-Host "#  Action   Enabled   Rule Name"
                    Write-Host "--  ------   -------   ---------"
                    
                    foreach ($rule in $rules) {
                        $action = $rule.Action.ToString().PadRight(6)
                        $enabled = if ($rule.Enabled -eq $true) { "Yes" } else { "No" }
                        $cleanName = Get-CleanRuleName -name $rule.DisplayName
                        if ([string]::IsNullOrWhiteSpace($cleanName)) {
                            $cleanName = Get-CleanRuleName -name $rule.Name
                        }
                        Write-Host "$($count.ToString().PadLeft(2))  $action   $($enabled.PadRight(7))   $cleanName"
                        $count++
                    }
                    
                    Write-Host
                    Write-Host "1: Enable a rule (type '1 NUMBER')"
                    Write-Host "2: Disable a rule (type '2 NUMBER')"
                    Write-Host "3: Add new rule"
                    Write-Host "4: Remove a rule (type '4 NUMBER')"
                    Write-Host "0: Back"
                    Write-Host
                    
                    $input = Read-Host "Enter action and number (e.g., '2 5') or 0 to return"
                    
                    if ($input -eq '0') { break }
                    
                    $parts = $input -split '\s+'
                    $action = $parts[0]
                    $ruleNum = if ($parts.Count -gt 1) { $parts[1] } else { $null }
                    
                    if (@('1','2','4') -contains $action -and ($ruleNum -notmatch '^\d+$')) {
                        Write-Host "Invalid rule number" -ForegroundColor Red
                        Write-Host "Press any key to continue..."
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        continue
                    }
                    
                    switch ($action) {
                        '1' { 
                            $rules = @(Get-NetFirewallRule | Sort-Object -Property DisplayName)
                            if ($ruleNum -gt 0 -and $ruleNum -le $rules.Count) {
                                $rule = $rules[$ruleNum - 1]
                                $ruleName = Get-CleanRuleName -name $rule.DisplayName
                                try {
                                    Set-NetFirewallRule -Name $rule.Name -Enabled True -ErrorAction Stop
                                    Write-Host "Enabled rule: $ruleName" -ForegroundColor Green
                                } catch {
                                    Write-Host "Failed to enable rule $ruleName`: $_" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Invalid rule number" -ForegroundColor Red
                            }
                            Write-Host "Press any key to continue..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        '2' { 
                            $rules = @(Get-NetFirewallRule | Sort-Object -Property DisplayName)
                            if ($ruleNum -gt 0 -and $ruleNum -le $rules.Count) {
                                $rule = $rules[$ruleNum - 1]
                                $ruleName = Get-CleanRuleName -name $rule.DisplayName
                                try {
                                    Set-NetFirewallRule -Name $rule.Name -Enabled False -ErrorAction Stop
                                    Write-Host "Disabled rule: $ruleName" -ForegroundColor Green
                                } catch {
                                    Write-Host "Failed to disable rule $ruleName`: $_" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Invalid rule number" -ForegroundColor Red
                            }
                            Write-Host "Press any key to continue..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        '3' { 
                            Clear-Host
                            Write-Host
                            Write-Host "==============================="
                            Write-Host "      Add New Firewall Rule"
                            Write-Host "==============================="
                            Write-Host
                            
                            $displayName = Read-Host "Enter a display name for the rule"
                            $name = Read-Host "Enter a unique name for the rule (no spaces, use hyphens)"
                            $description = Read-Host "Enter a description for the rule"
                            
                            do {
                                $direction = Read-Host "Enter direction (Inbound/Outbound)"
                            } while ($direction -notin "Inbound", "Outbound")
                            
                            do {
                                $action = Read-Host "Enter action (Allow/Block)"
                            } while ($action -notin "Allow", "Block")
                            
                            do {
                                $profile = Read-Host "Enter profile (Domain, Private, Public, Any)"
                            } while ($profile -notin "Domain", "Private", "Public", "Any")
                            
                            do {
                                $protocol = Read-Host "Enter protocol (TCP, UDP, ICMP, Any)"
                            } while ($protocol -notin "TCP", "UDP", "ICMP", "Any")
                            
                            $localPort = Read-Host "Enter local port (leave blank for any)"
                            $remotePort = Read-Host "Enter remote port (leave blank for any)"
                            $program = Read-Host "Enter program path (leave blank for any)"
                            
                            try {
                                $params = @{
                                    DisplayName = $displayName
                                    Name        = $name
                                    Description = $description
                                    Direction   = $direction
                                    Action      = $action
                                    Profile     = $profile
                                    Protocol    = $protocol
                                }
                                
                                if ($localPort) { $params['LocalPort'] = $localPort }
                                if ($remotePort) { $params['RemotePort'] = $remotePort }
                                if ($program) { $params['Program'] = $program }
                                
                                New-NetFirewallRule @params
                                Write-Host "Firewall rule created: $displayName" -ForegroundColor Green
                            } catch {
                                Write-Host "Failed to create rule: $_" -ForegroundColor Red
                            }
                            Write-Host "Press any key to continue..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        '4' { 
                            $rules = @(Get-NetFirewallRule | Sort-Object -Property DisplayName)
                            if ($ruleNum -gt 0 -and $ruleNum -le $rules.Count) {
                                $rule = $rules[$ruleNum - 1]
                                $ruleName = Get-CleanRuleName -name $rule.DisplayName
                                try {
                                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                                    Write-Host "Removed rule: $ruleName" -ForegroundColor Green
                                } catch {
                                    Write-Host "Failed to remove rule $ruleName`: $_" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Invalid rule number" -ForegroundColor Red
                            }
                            Write-Host "Press any key to continue..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        default { 
                            Write-Host "Invalid action" -ForegroundColor Red
                            Write-Host "Press any key to continue..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                    }
                } while ($true)
            }
            '2' {
                Clear-Host
                Write-Host
                Write-Host "==============================="
                Write-Host "      Export Firewall Rules"
                Write-Host "==============================="
                Write-Host
                
                $defaultPath = "$env:USERPROFILE\Desktop\firewall_rules_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $filePath = Read-Host "Enter the file path to save the CSV (default: $defaultPath)"
                
                if ([string]::IsNullOrWhiteSpace($filePath)) {
                    $filePath = $defaultPath
                }
                
                try {
                    Get-NetFirewallRule | Sort-Object -Property DisplayName | Export-Csv -Path $filePath -NoTypeInformation
                    Write-Host "Rules exported to $filePath" -ForegroundColor Green
                } catch {
                    Write-Host "Export failed: $_" -ForegroundColor Red
                }
                Write-Host "Press any key to continue..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '3' {
                Clear-Host
                Write-Host
                Write-Host "==============================="
                Write-Host "      Import Firewall Rules"
                Write-Host "==============================="
                Write-Host
                
                $defaultPath = "$env:USERPROFILE\Desktop\firewall_rules.csv"
                $filePath = Read-Host "Enter the file path of the CSV to import (default looks on Desktop for firewall_rules.csv)"
                
                if ([string]::IsNullOrWhiteSpace($filePath)) {
                    $filePath = $defaultPath
                }
                
                if (Test-Path $filePath) {
                    try {
                        $rules = Import-Csv -Path $filePath
                        $successCount = 0
                        $errorCount = 0
                        
                        foreach ($rule in $rules) {
                            try {
                                $params = @{
                                    DisplayName = $rule.DisplayName
                                    Name        = $rule.Name
                                    Description = $rule.Description
                                    Direction   = $rule.Direction
                                    Action      = $rule.Action
                                    Profile     = $rule.Profile
                                    Enabled     = if ($rule.Enabled -eq "True") { $true } else { $false }
                                }
                                
                                New-NetFirewallRule @params
                                $successCount++
                            } catch {
                                $errorCount++
                                Write-Host "Error importing rule $($rule.DisplayName): $_" -ForegroundColor Yellow
                            }
                        }
                        
                        Write-Host "Import completed: $successCount succeeded, $errorCount failed" -ForegroundColor Green
                    } catch {
                        Write-Host "Import failed: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "File not found: $filePath" -ForegroundColor Red
                }
                Write-Host "Press any key to continue..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '0' { return }
            default { 
                Write-Host "Invalid selection" -ForegroundColor Red
                Write-Host "Press any key to continue..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

# Helper function needed by Choice-9
function Get-CleanRuleName {
    param ([string]$name)
    if ($name -match '@{.+?}\(?(.+?)\)?$') { $name = $matches[1] }
    if ($name -match '(.+?)_\d+\.\d+\.\d+\.\d+_x64__.+') { $name = $matches[1] + "_x64" }
    elseif ($name -match '(.+?)_\d+\.\d+\.\d+\.\d+_.+') { $name = $matches[1] }
    $name = $name -replace '({[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}})', ''
    return $name.Trim()
}

function Choice-10 { Clear-Host; Write-Host "Running Disk Cleanup..."; Start-Process "cleanmgr.exe"; Pause-Menu }

function Choice-11 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "Running advanced error scan on all drives..."
    Write-Host "==============================================="
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | Select-Object -ExpandProperty Name
    foreach ($drive in $drives) {
        Write-Host
        Write-Host "Scanning drive $drive`:" ...
        chkdsk "${drive}:" /f /r /x
    }
    Write-Host
    Write-Host "All drives scanned."
    Pause-Menu
}

function Choice-12 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "   Delete Temporary Files and System Cache"
    Write-Host "==============================================="
    Write-Host
    Write-Host "This will permanently delete temporary files for your user and Windows."
    Write-Host "Warning: Close all applications to avoid file conflicts."
    Write-Host

    $deleteOption = ""
    while ($true) {
        Write-Host "==============================================="
        Write-Host "   Choose Cleanup Option"
        Write-Host "==============================================="
        Write-Host "[1] Permanently delete temporary files"
        Write-Host "[2] Permanently delete temporary files and empty Recycle Bin"
        Write-Host "[3] Advanced Privacy Cleanup (includes temp files + privacy data)"
        Write-Host "[0] Cancel"
        Write-Host
        $optionChoice = Read-Host "Select an option"
        switch ($optionChoice) {
            "1" { $deleteOption = "DeleteOnly"; break }
            "2" { $deleteOption = "DeleteAndEmpty"; break }
            "3" { $deleteOption = "PrivacyCleanup"; break }
            "0" {
                Write-Host "Operation cancelled." -ForegroundColor Yellow
                Pause-Menu
                return
            }
            default { Write-Host "Invalid input. Please enter 1, 2, 3, or 0." -ForegroundColor Red }
        }
        if ($deleteOption) { break }
    }

    # Define paths to clean (remove redundant paths)
    $paths = @(
        $env:TEMP,              # User temp folder
        "C:\Windows\Temp"       # System temp folder
    )

    # Remove duplicates
    $paths = $paths | Select-Object -Unique

    # Load assembly for Recycle Bin if needed (only for DeleteAndEmpty option)
    if ($deleteOption -eq "DeleteAndEmpty" -or $deleteOption -eq "PrivacyCleanup") {
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        } catch {
            Write-Host "[ERROR] Failed to load Microsoft.VisualBasic assembly for Recycle Bin operations." -ForegroundColor Red
            Write-Host "Proceeding with deletion only (Recycle Bin will not be emptied)." -ForegroundColor Yellow
            $deleteOption = "DeleteOnly"
        }
    }

    $deletedCount = 0
    $skippedCount = 0

    # Perform permanent deletion
    foreach ($path in $paths) {
        # Validate path
        if (-not (Test-Path $path)) {
            Write-Host "[ERROR] Path does not exist: $path" -ForegroundColor Red
            continue
        }

        # Additional safety check for user temp path
        if ($path -eq $env:TEMP -and -not ($path.ToLower() -like "*$($env:USERNAME.ToLower())*")) {
            Write-Host "[ERROR] TEMP path unsafe or invalid: $path" -ForegroundColor Red
            Write-Host "Skipping to prevent system damage." -ForegroundColor Red
            continue
        }

        Write-Host "Cleaning path: $path"
        try {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction Stop | ForEach-Object {
                try {
                    Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                    if ($_.PSIsContainer) {
                        Write-Host "Permanently deleted directory: $($_.FullName)" -ForegroundColor Green
                    } else {
                        Write-Host "Permanently deleted file: $($_.FullName)" -ForegroundColor Green
                    }
                    $deletedCount++
                } catch {
                    $skippedCount++
                    Write-Host "Skipped: $($_.FullName) ($($_.Exception.Message))" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "Error processing path $path : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Empty Recycle Bin if selected
    if ($deleteOption -eq "DeleteAndEmpty" -or $deleteOption -eq "PrivacyCleanup") {
        try {
            Write-Host "Emptying Recycle Bin..." -ForegroundColor Green
            [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
                "C:\`$Recycle.Bin",
                'OnlyErrorDialogs',
                'DeletePermanently'
            )
            Write-Host "Recycle Bin emptied successfully." -ForegroundColor Green
        } catch {
            Write-Host "Error emptying Recycle Bin: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Perform privacy cleanup if selected
    if ($deleteOption -eq "PrivacyCleanup") {
        Write-Host
        Write-Host "==============================================="
        Write-Host "   Performing Advanced Privacy Cleanup"
        Write-Host "==============================================="
        
        # Clear Activity History
        try {
            Write-Host "Clearing Activity History..."
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f 2>&1 | Out-Null
            Write-Host "Activity History cleared." -ForegroundColor Green
        } catch {
            Write-Host "Failed to clear Activity History: $_" -ForegroundColor Yellow
        }

        # Clear Location History
        try {
            Write-Host "Clearing Location History..."
            Get-Process LocationNotificationWindows -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f 2>&1 | Out-Null
            Write-Host "Location History cleared." -ForegroundColor Green
        } catch {
            Write-Host "Failed to clear Location History: $_" -ForegroundColor Yellow
        }

        # Clear Diagnostic Data
        try {
            Write-Host "Clearing Diagnostic Data..."
            wevtutil cl Microsoft-Windows-Diagnostics-Performance/Operational 2>&1 | Out-Null
            Write-Host "Diagnostic Data cleared." -ForegroundColor Green
        } catch {
            Write-Host "Failed to clear Diagnostic Data: $_" -ForegroundColor Yellow
        }

        # Additional privacy cleanup commands
        try {
            Write-Host "Clearing Recent Items..."
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "Recent Items cleared." -ForegroundColor Green
        } catch {
            Write-Host "Failed to clear Recent Items: $_" -ForegroundColor Yellow
        }

        try {
            Write-Host "Clearing Thumbnail Cache..."
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
            Write-Host "Thumbnail Cache cleared." -ForegroundColor Green
        } catch {
            Write-Host "Failed to clear Thumbnail Cache: $_" -ForegroundColor Yellow
        }
    }

    Write-Host
    Write-Host "Cleanup complete. Processed $deletedCount files/directories, skipped $skippedCount files/directories." -ForegroundColor Green
    if ($deleteOption -eq "PrivacyCleanup") {
        Write-Host "Privacy-related data was also cleared."
    } else {
        Write-Host "Files and directories were permanently deleted."
    }

    Pause-Menu
}

function Choice-13 {
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host " Advanced Registry Cleanup & Optimization"
        Write-Host "======================================================"
        Write-Host "[1] List 'safe to delete' registry keys under Uninstall"
        Write-Host "[2] Delete all 'safe to delete' registry keys (with backup)"
        Write-Host "[3] Create Registry Backup"
        Write-Host "[4] Restore Registry Backup"
        Write-Host "[5] Scan for corrupt registry entries"
        Write-Host "[0] Return to main menu"
        Write-Host
        $rchoice = Read-Host "Enter your choice"
        switch ($rchoice) {
            "1" {
                Write-Host
                Write-Host "Listing registry keys matching: IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent"
                Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
                  Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } |
                  ForEach-Object { Write-Host $_.PSChildName }
                Pause-Menu
            }
            "2" {
                Write-Host
                $backupFolder = "$env:SystemRoot\Temp\RegistryBackups"
                if (-not (Test-Path $backupFolder)) { New-Item -Path $backupFolder -ItemType Directory | Out-Null }

                $now = Get-Date
                $existingBackup = Get-ChildItem -Path $backupFolder -Filter "RegistryBackup_*.reg" |
                    Where-Object { ($now - $_.CreationTime).TotalMinutes -lt 10 } |  # backup within last 10 min
                    Sort-Object CreationTime -Descending | Select-Object -First 1

                $backupFile = $null
                if ($existingBackup) {
                    Write-Host "A recent backup already exists: $($existingBackup.Name)"
                    $useOld = Read-Host "Use this backup? (Y/n)"
                    if ($useOld -notin @("n", "N")) {
                        $backupFile = $existingBackup.FullName
                        Write-Host "Using existing backup: $backupFile"
                    } else {
                        $backupName = "RegistryBackup_{0}.reg" -f ($now.ToString("yyyy-MM-dd_HH-mm"))
                        $backupFile = Join-Path $backupFolder $backupName
                        reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $backupFile /y | Out-Null
                        Write-Host "New backup created: $backupFile"
                    }
                } else {
                    $backupName = "RegistryBackup_{0}.reg" -f ($now.ToString("yyyy-MM-dd_HH-mm"))
                    $backupFile = Join-Path $backupFolder $backupName
                    reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $backupFile /y | Out-Null
                    Write-Host "Backup created: $backupFile"
                }

                Write-Host "`nDeleting registry keys matching: IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent"
                $keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
                    Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' }
                
                if ($keys) {
                    foreach ($key in $keys) {
                        try {
                            Remove-Item $key.PSPath -Recurse -Force -ErrorAction Stop
                            Write-Host "Deleted:" $key.PSChildName
                        } catch {
                            Write-Host "Failed to delete:" $key.PSChildName "($_.Exception.Message)"
                        }
                    }
                } else {
                    Write-Host "No matching registry keys found."
                }
                Pause-Menu
            }
            "3" {
                $backupFolder = "$env:SystemRoot\Temp\RegistryBackups"
                if (-not (Test-Path $backupFolder)) { New-Item -Path $backupFolder -ItemType Directory | Out-Null }
                $backupName = "RegistryBackup_{0}.reg" -f (Get-Date -Format "yyyy-MM-dd_HH-mm")
                $backupFile = Join-Path $backupFolder $backupName
                reg export HKLM $backupFile /y
                Write-Host "Full HKLM backup created: $backupFile"
                Pause-Menu
            }
            "4" {
                $backupFolder = "$env:SystemRoot\Temp\RegistryBackups"
                Write-Host "Available backups:"
                Get-ChildItem "$backupFolder\*.reg" | ForEach-Object { Write-Host $_.Name }
                $backupFile = Read-Host "Enter the filename to restore"
                $fullBackup = Join-Path $backupFolder $backupFile
                if (Test-Path $fullBackup) {
                    reg import $fullBackup
                    Write-Host "Backup successfully restored."
                } else {
                    Write-Host "File not found."
                }
                Pause-Menu
            }
            "5" {
                Clear-Host
                Write-Host "Scanning for corrupt registry entries..."
                Start-Process "cmd.exe" "/c sfc /scannow" -Wait
                Start-Process "cmd.exe" "/c dism /online /cleanup-image /checkhealth" -Wait
                Write-Host "Registry scan complete. If errors were found, please restart your PC."
                Pause-Menu
            }
            "0" { return }
            default { Write-Host "Invalid input. Try again."; Pause-Menu }
        }
    }
}

function Choice-14 {
    Clear-Host
    Write-Host "=========================================="
    Write-Host "     Optimize SSDs (ReTrim/TRIM)"
    Write-Host "=========================================="
    Write-Host "This will automatically optimize (TRIM) all detected SSDs."
    Write-Host
    Write-Host "Listing all detected SSD drives..."

    $ssds = Get-PhysicalDisk | Where-Object MediaType -eq 'SSD'
    if (-not $ssds) {
        Write-Host "No SSDs detected."
        Pause-Menu
        return
    }

    $log = "$env:USERPROFILE\Desktop\SSD_OPTIMIZE_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
    $logContent = @()
    $logContent += "SSD Optimize Log - $(Get-Date)"

    foreach ($ssd in $ssds) {
        $disk = Get-Disk | Where-Object { $_.FriendlyName -eq $ssd.FriendlyName }
        if ($disk) {
            $volumes = $disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null
            foreach ($vol in $volumes) {
                Write-Host "Optimizing SSD: $($vol.DriveLetter):"
                $logContent += "Optimizing SSD: $($vol.DriveLetter):"
                $result = Optimize-Volume -DriveLetter $($vol.DriveLetter) -ReTrim -Verbose 4>&1
                $logContent += $result
            }
        } else {
            $logContent += "Could not find Disk for SSD: $($ssd.FriendlyName)"
        }
    }
    Write-Host
    Write-Host "SSD optimization completed. Log file saved on Desktop: $log"
    $logContent | Out-File -FilePath $log -Encoding UTF8
    Pause-Menu
}

function Choice-15 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "     Scheduled Task Management [Admin]"
    Write-Host "==============================================="
    Write-Host "Listing all scheduled tasks..."
    Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
    Write-Host

    # Check for admin privileges
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Error: This function requires administrator privileges." -ForegroundColor Red
        Write-Host "Please run the script as Administrator and try again."
        Pause-Menu
        return
    }

    # Helper function to display task list with dynamic alignment and modified author/taskname
    function Show-TaskList {
        # Retrieve scheduled tasks
        try {
            $tasks = schtasks /query /fo CSV /v | ConvertFrom-Csv | Where-Object {
                $_."TaskName" -ne "" -and                        # Exclude empty TaskName
                $_."TaskName" -ne "TaskName" -and               # Exclude placeholder "TaskName"
                $_."Author" -ne "Author" -and                   # Exclude placeholder "Author"
                $_."Status" -ne "Status" -and                   # Exclude placeholder "Status"
                $_."Author" -notlike "*Scheduling data is not available in this format.*" -and  # Exclude invalid scheduling data
                $_."TaskName" -notlike "*Enabled*" -and         # Exclude rows starting with "Enabled"
                $_."TaskName" -notlike "*Disabled*"             # Exclude rows starting with "Disabled"
            }
            if (-not $tasks) {
                Write-Host "No valid scheduled tasks found." -ForegroundColor Yellow
                return $null
            }
        } catch {
            Write-Host "Error retrieving scheduled tasks: $_" -ForegroundColor Red
            return $null
        }

        # Remove duplicates based on TaskName, Author, and Status
        $uniqueTasks = $tasks | Sort-Object "TaskName", "Author", "Status" -Unique

        # Calculate maximum lengths for dynamic alignment
        $maxIdLength = ($uniqueTasks.Count.ToString()).Length  # Length of largest ID
        $maxTaskNameLength = 50  # Default max length for TaskName, adjustable
        $maxAuthorLength = 30    # Default max length for Author, adjustable
        $maxStatusLength = 10    # Default max length for Status (e.g., "Running", "Ready", "Disabled")

        # Process tasks to adjust Author and TaskName, and calculate max lengths
        $processedTasks = @()
        foreach ($task in $uniqueTasks) {
            $taskName = if ($task."TaskName") { $task."TaskName" } else { "N/A" }
            $author = if ($task."Author") { $task."Author" } else { "N/A" }
            $status = if ($task."Status") { $task."Status" } else { "Unknown" }

            # Fix Author field for Microsoft tasks with resource strings (e.g., $(@%SystemRoot%\...))
            if ($author -like '$(@%SystemRoot%\*' -or $taskName -like '\Microsoft\*') {
                $author = "Microsoft Corporation"
            }

            # Extract first folder from TaskName for Author if still N/A
            if ($author -eq "N/A" -and $taskName -match '^\\([^\\]+)\\') {
                $author = $matches[1]  # Get first folder (e.g., "LGTV Companion")
            }

            # Remove first folder from TaskName
            $displayTaskName = $taskName -replace '^\\[^\\]+\\', ''  # Remove "\Folder\"
            if ($displayTaskName -eq $taskName) { $displayTaskName = $taskName.TrimStart('\') }  # Fallback for tasks without folder

            # Truncate long fields for alignment
            if ($displayTaskName.Length -gt $maxTaskNameLength) { $displayTaskName = $displayTaskName.Substring(0, $maxTaskNameLength - 3) + "..." }
            if ($author.Length -gt $maxAuthorLength) { $author = $author.Substring(0, $maxAuthorLength - 3) + "..." }

            # Update max lengths based on processed data
            $maxTaskNameLength = [Math]::Max($maxTaskNameLength, [Math]::Min($displayTaskName.Length, 50))
            $maxAuthorLength = [Math]::Max($maxAuthorLength, [Math]::Min($author.Length, 30))
            $maxStatusLength = [Math]::Max($maxStatusLength, $status.Length)

            $processedTasks += [PSCustomObject]@{
                OriginalTaskName = $task."TaskName"
                DisplayTaskName  = $displayTaskName
                Author           = $author
                Status           = $status
            }
        }

        # Print header with dynamic widths
        $headerFormat = "{0,-$maxIdLength} | {1,-$maxTaskNameLength} | {2,-$maxAuthorLength} | {3}"
        Write-Host ($headerFormat -f "ID", "Task Name", "Author", "Status")
        Write-Host ("-" * $maxIdLength + "-+-" + "-" * $maxTaskNameLength + "-+-" + "-" * $maxAuthorLength + "-+-" + "-" * $maxStatusLength)

        # Display tasks with index and color coding
        $taskList = @()
        $index = 1
        foreach ($task in $processedTasks) {
            $isMicrosoft = $task.OriginalTaskName -like "\Microsoft\*" -or $task.Author -like "*Microsoft*"
            $taskList += [PSCustomObject]@{
                Index      = $index
                TaskName   = $task.OriginalTaskName  # Store original for schtasks commands
                Author     = $task.Author
                Status     = $task.Status
                IsMicrosoft = $isMicrosoft
            }
            $color = if ($isMicrosoft) { "Green" } else { "Yellow" }
            Write-Host ($headerFormat -f $index, $task.DisplayTaskName, $task.Author, $task.Status) -ForegroundColor $color
            $index++
        }
        Write-Host
        return $taskList
    }

    # Display task list initially
    $taskList = Show-TaskList
    if (-not $taskList) {
        Pause-Menu
        return
    }

    # Main loop for task management options
    while ($true) {
        Write-Host "Options:"
        Write-Host "[1] Enable a task"
        Write-Host "[2] Disable a task"
        Write-Host "[3] Delete a task"
        Write-Host "[4] Refresh task list"
        Write-Host "[0] Return to main menu"
        Write-Host

        $action = Read-Host "Enter option (0-4) or task ID to manage"
        if ($action -eq "0") {
            return
        } elseif ($action -eq "1") {
            $id = Read-Host "Enter task ID to enable"
            if ($id -match '^\d+$' -and $id -ge 1 -and $id -le $taskList.Count) {
                $selectedTask = $taskList[$id - 1]
                Write-Host "Enabling task: $($selectedTask.TaskName)"
                try {
                    schtasks /change /tn "$($selectedTask.TaskName)" /enable | Out-Null
                    Write-Host "Task enabled successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Error enabling task: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "Invalid task ID." -ForegroundColor Red
            }
            Pause-Menu
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } elseif ($action -eq "2") {
            $id = Read-Host "Enter task ID to disable"
            if ($id -match '^\d+$' -and $id -ge 1 -and $id -le $taskList.Count) {
                $selectedTask = $taskList[$id - 1]
                Write-Host "Disabling task: $($selectedTask.TaskName)"
                try {
                    schtasks /change /tn "$($selectedTask.TaskName)" /disable | Out-Null
                    Write-Host "Task disabled successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Error disabling task: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "Invalid task ID." -ForegroundColor Red
            }
            Pause-Menu
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } elseif ($action -eq "3") {
            $id = Read-Host "Enter task ID to delete"
            if ($id -match '^\d+$' -and $id -ge 1 -and $id -le $taskList.Count) {
                $selectedTask = $taskList[$id - 1]
                Write-Host "WARNING: Deleting task: $($selectedTask.TaskName)" -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    try {
                        schtasks /delete /tn "$($selectedTask.TaskName)" /f | Out-Null
                        Write-Host "Task deleted successfully." -ForegroundColor Green
                    } catch {
                        Write-Host "Error deleting task: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Action cancelled." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Invalid task ID." -ForegroundColor Red
            }
            Pause-Menu
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } elseif ($action -eq "4") {
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } else {
            Write-Host "Invalid option. Please enter 0-4 or a valid task ID." -ForegroundColor Red
            Pause-Menu
        }
    }
}

function Choice-30 {
    while ($true) {
        Clear-Host
        $discordUrl = "https://discord.gg/bCQqKHGxja"
        $githubUrl = "https://github.com/ios12checker/Windows-Maintenance-Tool/issues/new/choose"

        Write-Host
        Write-Host "=================================================="
        Write-Host "               CONTACT AND SUPPORT"
        Write-Host "=================================================="
        Write-Host "For direct contact, the owner's Discord username is: Lil_Batti"
        Write-Host "How can we help you?"
        Write-Host
        Write-Host " [1] Open Support Discord Server ($discordUrl)"
        Write-Host " [2] Create a GitHub Issue ($githubUrl)"
        Write-Host
        Write-Host " [0] Return to main menu"
        Write-Host "=================================================="

        $supportChoice = Read-Host "Enter your choice"

        switch ($supportChoice) {
            "1" {
                Write-Host "Opening the support Discord server in your browser..."
                try {
                    Start-Process $discordUrl -ErrorAction Stop
                    Write-Host "The Discord support site has been opened." -ForegroundColor Green
                } catch {
                    Write-Host "Failed to open URL. Please manually visit: $discordUrl" -ForegroundColor Red
                }
                Pause-Menu
                return
            }
            "2" {
                Write-Host "Opening the GitHub issue page in your browser..."
                try {
                    Start-Process $githubUrl -ErrorAction Stop
                    Write-Host "The GitHub issue page has been opened." -ForegroundColor Green
                } catch {
                    Write-Host "Failed to open URL. Please manually visit: $githubUrl" -ForegroundColor Red
                }
                Pause-Menu
                return
            }
            "0" { return }
            default { Write-Host "Invalid choice. Please enter 1, 2, or 0." -ForegroundColor Red; Start-Sleep -Seconds 2 }
        }
    }
}

function Choice-0 { Clear-Host; Write-Host "Exiting script..."; exit }

function Choice-20 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Saving Installed Driver Report to Desktop"
    Write-Host "==============================================="
    $outfile = "$env:USERPROFILE\Desktop\Installed_Drivers.txt"
    driverquery /v > $outfile
    Write-Host
    Write-Host "Driver report has been saved to: $outfile"
    Pause-Menu
}

function Choice-21 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Windows Update Repair Tool [Admin]"
    Write-Host "==============================================="
    Write-Host
    Write-Host "[1/4] Stopping update-related services..."
    $services = @('wuauserv','bits','cryptsvc','msiserver','usosvc','trustedinstaller')
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Host "Stopping $service"
            try { Stop-Service -Name $service -Force -ErrorAction Stop } catch {}
        }
    }
    Start-Sleep -Seconds 2
    Write-Host
    Write-Host "[2/4] Renaming update cache folders..."
    $SUFFIX = ".bak_{0}" -f (Get-Random -Maximum 99999)
    $SD = "$env:windir\SoftwareDistribution"
    $CR = "$env:windir\System32\catroot2"
    $renamedSD = "$env:windir\SoftwareDistribution$SUFFIX"
    $renamedCR = "$env:windir\System32\catroot2$SUFFIX"
    if (Test-Path $SD) {
        try {
            Rename-Item $SD -NewName ("SoftwareDistribution" + $SUFFIX) -ErrorAction Stop
            if (Test-Path $renamedSD) {
                Write-Host "Renamed: $renamedSD"
            } else {
                Write-Host "Warning: Could not rename SoftwareDistribution."
            }
        } catch { Write-Host "Warning: Could not rename SoftwareDistribution." }
    } else { Write-Host "Info: SoftwareDistribution not found." }
    if (Test-Path $CR) {
        try {
            Rename-Item $CR -NewName ("catroot2" + $SUFFIX) -ErrorAction Stop
            if (Test-Path $renamedCR) {
                Write-Host "Renamed: $renamedCR"
            } else {
                Write-Host "Warning: Could not rename catroot2."
            }
        } catch { Write-Host "Warning: Could not rename catroot2." }
    } else { Write-Host "Info: catroot2 not found." }
    Write-Host
    Write-Host "[3/4] Restarting services..."
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-Host "Starting $service"
            try { Start-Service -Name $service -ErrorAction Stop } catch {}
        }
    }
    Write-Host
    Write-Host "[4/4] Windows Update components have been reset."
    Write-Host
    Write-Host "Renamed folders:"
    Write-Host "  - $renamedSD"
    Write-Host "  - $renamedCR"
    Write-Host "You may delete them manually after reboot if all is working."
    Write-Host
    Pause-Menu
}

function Choice-22 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Generating Separated System Reports..."
    Write-Host "==============================================="
    Write-Host
    Write-Host "Choose output location:"
    Write-Host " [1] Desktop (recommended)"
    Write-Host " [2] Enter custom path"
    Write-Host " [3] Show guide for custom path setup"
    $opt = Read-Host ">"
    $outpath = ""
    if ($opt -eq "1") {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $reportdir = "SystemReports_{0}" -f (Get-Date -Format "yyyy-MM-dd_HHmm")
        $outpath = Join-Path $desktop $reportdir
        if (-not (Test-Path $outpath)) { New-Item -Path $outpath -ItemType Directory | Out-Null }
    } elseif ($opt -eq "2") {
        $outpath = Read-Host "Enter full path (e.g. D:\Reports)"
        if (-not (Test-Path $outpath)) {
            Write-Host
            Write-Host "[ERROR] Folder not found: $outpath"
            Pause-Menu
            return
        }
    } elseif ($opt -eq "3") {
        Clear-Host
        Write-Host "==============================================="
        Write-Host "    How to Use a Custom Report Path"
        Write-Host "==============================================="
        Write-Host
        Write-Host "1. Open File Explorer and create a new folder, e.g.:"
        Write-Host "   C:\Users\YourName\Desktop\SystemReports"
        Write-Host "   or"
        Write-Host "   C:\Users\YourName\OneDrive\Documents\SystemReports"
        Write-Host
        Write-Host "2. Copy the folder's full path from the address bar."
        Write-Host "3. Re-run this and choose option [2], then paste it."
        Write-Host
        Pause-Menu
        return
    } else {
        Write-Host
        Write-Host "Invalid selection."
        Start-Sleep -Seconds 2
        return
    }
    $datestr = Get-Date -Format "yyyy-MM-dd"
    $sys   = Join-Path $outpath "System_Info_$datestr.txt"
    $net   = Join-Path $outpath "Network_Info_$datestr.txt"
    $drv   = Join-Path $outpath "Driver_List_$datestr.txt"
    Write-Host
    Write-Host "Writing system info to: $sys"
    systeminfo | Out-File -FilePath $sys -Encoding UTF8
    Write-Host "Writing network info to: $net"
    ipconfig /all | Out-File -FilePath $net -Encoding UTF8
    Write-Host "Writing driver list to: $drv"
    driverquery | Out-File -FilePath $drv -Encoding UTF8
    Write-Host
    Write-Host "Reports saved in:"
    Write-Host $outpath
    Write-Host
    Pause-Menu
}

function Choice-23 {
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host "           Windows Update Utility & Service Reset"
        Write-Host "======================================================"
        Write-Host "This tool will restart core Windows Update services."
        Write-Host "Make sure no Windows Updates are installing right now."
        Pause-Menu
        Write-Host
        Write-Host "[1] Reset Update Services (wuauserv, cryptsvc, appidsvc, bits)"
        Write-Host "[0] Return to Main Menu"
        Write-Host
        $fixchoice = Read-Host "Select an option"
        switch ($fixchoice) {
            "1" {
                Clear-Host
                Write-Host "======================================================"
                Write-Host "    Resetting Windows Update & Related Services"
                Write-Host "======================================================"
                Write-Host "Stopping Windows Update service..."
                try { Stop-Service -Name wuauserv -Force -ErrorAction Stop } catch {}
                Write-Host "Stopping Cryptographic service..."
                try { Stop-Service -Name cryptsvc -Force -ErrorAction Stop } catch {}
                Write-Host "Starting Application Identity service..."
                try { Start-Service -Name appidsvc -ErrorAction Stop } catch {}
                Write-Host "Starting Windows Update service..."
                try { Start-Service -Name wuauserv -ErrorAction Stop } catch {}
                Write-Host "Starting Background Intelligent Transfer Service..."
                try { Start-Service -Name bits -ErrorAction Stop } catch {}
                Write-Host
                Write-Host "[OK] Update-related services have been restarted."
                Pause-Menu
                return
            }
            "2" { return }
            default { Write-Host "Invalid input. Try again."; Pause-Menu }
        }
    }
}

function Choice-24 {
    while ($true) {
        Clear-Host
        Write-Host "==============================================="
        Write-Host "     View Network Routing Table  [Advanced]"
        Write-Host "==============================================="
        Write-Host "This shows how your system handles network traffic."
        Write-Host
        Write-Host "[1] Display routing table in this window"
        Write-Host "[2] Save routing table as a text file on Desktop"
        Write-Host "[0] Return to Main Menu"
        Write-Host
        $routeopt = Read-Host "Choose an option"
        switch ($routeopt) {
            "1" {
                Clear-Host
                route print
                Write-Host
                Pause-Menu
                return
            }
            "2" {
                $desktop = "$env:USERPROFILE\Desktop"
                if (-not (Test-Path $desktop)) {
                    Write-Host "Desktop folder not found."
                    Pause-Menu
                    return
                }
                $dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                if (-not $dt) { $dt = "manual_timestamp" }
                $file = Join-Path $desktop "routing_table_${dt}.txt"
                Clear-Host
                Write-Host "Saving routing table to: `"$file`""
                Write-Host
                route print | Out-File -FilePath $file -Encoding UTF8
                if (Test-Path $file) {
                    Write-Host "[OK] Routing table saved successfully."
                } else {
                    Write-Host "[ERROR] Failed to save routing table to file."
                }
                Write-Host
                Pause-Menu
                return
            }
            "0" { return }
            default {
                Write-Host "Invalid input. Please enter 1, 2 or 0."
                Pause-Menu
            }
        }
    }
}
function Choice-25 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "   .NET RollForward Settings"
    Write-Host "==============================================="
    Write-Host "[1] Enable roll-forward for RUNTIME only  [WARNING] risk: app may run on newer runtime with breaking changes"
    Write-Host "[2] Enable roll-forward for SDK only      [WARNING] risk: builds may differ across machines"
    Write-Host "[3] Enable roll-forward for BOTH          [WARNING] risk: unpredictable runtime/build behavior"
    Write-Host "[4] Disable roll-forward (remove setting)"
    Write-Host "[0] Return to main menu"
    Write-Host

    $choice = Read-Host "Select an option"
    switch ($choice) {
        "1" {
            [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", "LatestMajor", "Machine")
            Write-Host "[OK] Configured .NET Runtime roll-forward to latest major version." -ForegroundColor Green
            Pause-Menu
        }
        "2" {
            $latestSdk = & dotnet --list-sdks | Sort-Object -Descending | Select-Object -First 1
            if ($latestSdk) {
                $version = $latestSdk.Split()[0]
                $globalJsonPath = "$env:USERPROFILE\global.json"
                $globalJsonContent = @{
                    sdk = @{
                        version = $version
                        rollForward = "latestMajor"
                    }
                } | ConvertTo-Json -Depth 3
                $globalJsonContent | Out-File -Encoding UTF8 $globalJsonPath
                Write-Host "[OK] Configured .NET SDK to use version $version with roll-forward to latest major." -ForegroundColor Green
                Write-Host "[INFO] global.json updated at $globalJsonPath"
            } else {
                Write-Host "[WARNING] Could not detect installed .NET SDKs." -ForegroundColor Yellow
            }
            Pause-Menu
        }
        "3" {
            [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", "LatestMajor", "Machine")
            $latestSdk = & dotnet --list-sdks | Sort-Object -Descending | Select-Object -First 1
            if ($latestSdk) {
                $version = $latestSdk.Split()[0]
                $globalJsonPath = "$env:USERPROFILE\global.json"
                $globalJsonContent = @{
                    sdk = @{
                        version = $version
                        rollForward = "latestMajor"
                    }
                } | ConvertTo-Json -Depth 3
                $globalJsonContent | Out-File -Encoding UTF8 $globalJsonPath
                Write-Host "[OK] Configured BOTH Runtime & SDK roll-forward to latest major." -ForegroundColor Green
                Write-Host "[INFO] global.json updated at $globalJsonPath"
            } else {
                Write-Host "[WARNING] Could not detect installed .NET SDKs." -ForegroundColor Yellow
            }
            Pause-Menu
        }
        "4" {
            [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", $null, "Machine")
            $globalJsonPath = "$env:USERPROFILE\global.json"
            if (Test-Path $globalJsonPath) {
                try {
                    $json = Get-Content $globalJsonPath | ConvertFrom-Json
                    if ($json.sdk.rollForward) {
                        $json.sdk.PSObject.Properties.Remove("rollForward")
                        $json | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 $globalJsonPath
                        Write-Host "[REMOVED] rollForward from global.json." -ForegroundColor Green
                    }
                } catch {
                    Write-Host "[WARNING] Could not update global.json: $_" -ForegroundColor Yellow
                }
            }
            Write-Host "[OK] DOTNET_ROLL_FORWARD environment variable removed." -ForegroundColor Green
            Pause-Menu
        }
        default { return }
    }
}


# === MAIN MENU LOOP ===
while ($true) {
    Show-Menu
    $choice = (Read-Host "Enter your choice").ToLower().Trim()
    switch ($choice) {
        "1"  { Choice-1; continue }
        "2"  { Choice-2; continue }
        "3"  { Choice-3; continue }
        "4"  { Choice-4; continue }
        "5"  { Choice-5; continue }
        "6"  { Choice-6; continue }
        "7"  { Choice-7; continue }
        "8"  { Choice-8; continue }
        "9"  { Choice-9; continue }
        "10" { Choice-10; continue }
        "11" { Choice-11; continue }
        "12" { Choice-12; continue }
        "13" { Choice-13; continue }
        "14" { Choice-14; continue }
        "15" { Choice-15; continue }
        "0" { Choice-0 }
        "20" { Choice-20; continue }
        "21" { Choice-21; continue }
        "22" { Choice-22; continue }
        "23" { Choice-23; continue }
        "24" { Choice-24; continue }
        "25" { Choice-25; continue }
        "30" { Choice-30; continue }
        "h"  { Choice-30; continue }
        "help" { Choice-30; continue }
        default { Write-Host "Invalid choice, please try again."; Pause-Menu }
    }
}
