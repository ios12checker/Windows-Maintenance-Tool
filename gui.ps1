<#
    Windows Maintenance Tool v4.4 - GUI Version
    - Fixed Driver Report Export (Force Write)
    - Fixed Color Syntax in Clean Drivers
    - Network Tab Reorganized (3 Columns: General, DNS, Hosts)
#>

# ==========================================
# 1. ADMIN CHECK & PRE-REQUISITES
# ==========================================
$ErrorActionPreference = "SilentlyContinue"

# Check for Admin rights
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = "powershell.exe"
    $processInfo.Arguments = "-File `"$PSCommandPath`""
    $processInfo.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($processInfo)
    } catch {
        Write-Warning "Failed to elevate privileges."
    }
    exit
}

# Load Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Data 

# ==========================================
# 2. VISUAL STYLE
# ==========================================
$Color_Background = [System.Drawing.Color]::FromArgb(30, 30, 30)
$Color_Panel      = [System.Drawing.Color]::FromArgb(45, 45, 48)
$Color_Text       = [System.Drawing.Color]::White
$Color_Input      = [System.Drawing.Color]::FromArgb(60, 60, 60)
$Color_Button     = [System.Drawing.Color]::FromArgb(0, 122, 204)
$Color_Red        = [System.Drawing.Color]::FromArgb(200, 50, 50)
$Color_Green      = [System.Drawing.Color]::FromArgb(50, 200, 50)
$Color_Orange     = [System.Drawing.Color]::Orange
$Color_Purple     = [System.Drawing.Color]::Purple

# ==========================================
# 3. HELPER FUNCTIONS & EDITORS
# ==========================================

function Run-LogCommand {
    param([scriptblock]$ScriptBlock)
    $outputBox.Text += "`r`n> Running command...`r`n"
    $outputBox.SelectionStart = $outputBox.Text.Length
    $outputBox.ScrollToCaret()
    $form.Refresh()

    try {
        $res = & $ScriptBlock | Out-String
        $outputBox.Text += $res
        $outputBox.Text += "`r`n> Done.`r`n"
    } catch {
        $outputBox.Text += "`r`n[ERROR] $($_.Exception.Message)`r`n"
    }
    $outputBox.SelectionStart = $outputBox.Text.Length
    $outputBox.ScrollToCaret()
}

function Show-HostsEditor {
    $hForm = New-Object System.Windows.Forms.Form
    $hForm.Text = "Hosts File Editor (Inline)"
    $hForm.Size = New-Object System.Drawing.Size(800, 600)
    $hForm.StartPosition = "CenterParent"
    $hForm.BackColor = $Color_Background
    $hForm.ForeColor = $Color_Text

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "SAFE AREA: Text highlighted in Cyan is your custom section.`nEverything outside that section may be overwritten by the Adblock updater."
    $lblInfo.Dock = "Top"
    $lblInfo.Height = 70
    $lblInfo.TextAlign = "MiddleLeft"
    $lblInfo.ForeColor = [System.Drawing.Color]::Yellow
    $lblInfo.Padding = New-Object System.Windows.Forms.Padding(10)
    $hForm.Controls.Add($lblInfo)

    $pnlBottom = New-Object System.Windows.Forms.Panel
    $pnlBottom.Dock = "Bottom"
    $pnlBottom.Height = 50
    $hForm.Controls.Add($pnlBottom)

    $txtHosts = New-Object System.Windows.Forms.RichTextBox
    $txtHosts.Dock = "Fill"
    $txtHosts.BackColor = $Color_Input
    $txtHosts.ForeColor = $Color_Text
    $txtHosts.Font = New-Object System.Drawing.Font("Consolas", 10)
    $txtHosts.WordWrap = $false
    $txtHosts.ScrollBars = "Both"
    $hForm.Controls.Add($txtHosts)
    $txtHosts.BringToFront()

    $btnSaveHosts = New-Object System.Windows.Forms.Button
    $btnSaveHosts.Text = "Save Changes"
    $btnSaveHosts.Width = 150
    $btnSaveHosts.Height = 35
    $btnSaveHosts.Top = 5
    $btnSaveHosts.Left = 20
    $btnSaveHosts.BackColor = $Color_Green
    $btnSaveHosts.ForeColor = "Black"
    $btnSaveHosts.FlatStyle = "Flat"
    $pnlBottom.Controls.Add($btnSaveHosts)

    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $startMarker = "# === BEGIN USER CUSTOM ENTRIES ==="
    $endMarker   = "# === END USER CUSTOM ENTRIES ==="

    $content = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
    if ($content -notmatch [regex]::Escape($startMarker)) {
        $defaultEntries = "127.0.0.1       localhost`r`n::1             localhost"
        $safeBlock = "$startMarker`r`n# Add your custom entries below this line`r`n127.0.0.1    local.test`r`n$endMarker"
        $content = "$defaultEntries`r`n`r`n$safeBlock`r`n`r`n$content"
    }

    $txtHosts.Text = $content

    $Highlight = {
        $txtHosts.SelectAll(); $txtHosts.SelectionColor = $Color_Text 
        $sIdx = $txtHosts.Text.IndexOf($startMarker)
        $eIdx = $txtHosts.Text.IndexOf($endMarker)
        if ($sIdx -ge 0 -and $eIdx -gt $sIdx) {
            $len = ($eIdx + $endMarker.Length) - $sIdx
            $txtHosts.Select($sIdx, $len)
            $txtHosts.SelectionColor = [System.Drawing.Color]::Cyan
            $txtHosts.SelectionBackColor = [System.Drawing.Color]::FromArgb(50, 50, 80)
        }
        $txtHosts.Select(0,0)
    }
    & $Highlight

    $btnSaveHosts.Add_Click({
        try {
            Set-Content -Path $hostsPath -Value $txtHosts.Text -NoNewline
            [System.Windows.Forms.MessageBox]::Show("Hosts file saved successfully.", "Success")
            & $Highlight 
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error saving hosts file: $_", "Error")
        }
    })
    $hForm.ShowDialog()
}

function Show-AddRuleForm {
    $addForm = New-Object System.Windows.Forms.Form
    $addForm.Text = "Add New Firewall Rule"
    $addForm.Size = New-Object System.Drawing.Size(400, 450)
    $addForm.StartPosition = "CenterParent"
    $addForm.BackColor = $Color_Background
    $addForm.ForeColor = $Color_Text

    function New-Input {
        param($Label, $Top, $Type="Text", $Options=$null)
        $lbl = New-Object System.Windows.Forms.Label; $lbl.Text = $Label; $lbl.Top = $Top; $lbl.Left = 20; $lbl.AutoSize = $true; $addForm.Controls.Add($lbl)
        if ($Type -eq "Combo") { $ctrl = New-Object System.Windows.Forms.ComboBox; $ctrl.DropDownStyle = "DropDownList"; $Options | ForEach-Object { $ctrl.Items.Add($_) }; $ctrl.SelectedIndex = 0 } else { $ctrl = New-Object System.Windows.Forms.TextBox }
        $ctrl.Top = $Top + 20; $ctrl.Left = 20; $ctrl.Width = 340; $ctrl.BackColor = $Color_Input; $ctrl.ForeColor = $Color_Text; $addForm.Controls.Add($ctrl); return $ctrl
    }

    $txtName = New-Input -Label "Rule Name" -Top 10
    $cmbDir  = New-Input -Label "Direction" -Top 60 -Type "Combo" -Options @("Inbound", "Outbound")
    $cmbAct  = New-Input -Label "Action" -Top 110 -Type "Combo" -Options @("Allow", "Block")
    $cmbProt = New-Input -Label "Protocol" -Top 160 -Type "Combo" -Options @("TCP", "UDP", "Any")
    $txtPort = New-Input -Label "Local Port (e.g. 80, 443 or Leave Empty)" -Top 210

    $btnSave = New-Object System.Windows.Forms.Button
    $btnSave.Text = "Create Rule"; $btnSave.Top = 270; $btnSave.Left = 20; $btnSave.Width = 340; $btnSave.Height = 40; $btnSave.BackColor = $Color_Green; $btnSave.ForeColor = "Black"; $btnSave.DialogResult = "OK"; $addForm.Controls.Add($btnSave)

    if ($addForm.ShowDialog() -eq "OK") {
        try {
            $params = @{ DisplayName = $txtName.Text; Direction = $cmbDir.SelectedItem; Action = $cmbAct.SelectedItem }
            if ($cmbProt.SelectedItem -ne "Any") { $params.Add("Protocol", $cmbProt.SelectedItem) }
            if ($txtPort.Text -match "\d+") { $params.Add("LocalPort", $txtPort.Text) }
            New-NetFirewallRule @params -ErrorAction Stop; return $true
        } catch { [System.Windows.Forms.MessageBox]::Show("Error: $_", "Error"); return $false }
    }
    return $false
}

# ==========================================
# 4. FORM DEFINITION
# ==========================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "Windows Maintenance Tool v4.4 (Complete GUI)"
$form.Size = New-Object System.Drawing.Size(1020, 750) # Slightly wider for 3 columns
$form.StartPosition = "CenterScreen"
$form.BackColor = $Color_Background
$form.ForeColor = $Color_Text

$tabControl = New-Object System.Windows.Forms.TabControl; $tabControl.Dock = "Top"; $tabControl.Height = 450; $tabControl.BackColor = $Color_Panel
function New-TabPage { param($Title); $page = New-Object System.Windows.Forms.TabPage; $page.Text = $Title; $page.BackColor = $Color_Panel; $page.ForeColor = $Color_Text; $page.AutoScroll = $true; return $page }
function New-StyledButton { param($Parent, $Text, $Top, $Left, $Action, $Color=$null); $btn = New-Object System.Windows.Forms.Button; $btn.Text = $Text; $btn.Top = $Top; $btn.Left = $Left; $btn.Width = 300; $btn.Height = 40; $btn.FlatStyle = "Flat"; if ($Color) { $btn.BackColor = $Color } else { $btn.BackColor = $Color_Button }; $btn.ForeColor = "White"; $btn.Font = New-Object System.Drawing.Font("Segoe UI", 10); $btn.Add_Click($Action); $Parent.Controls.Add($btn); return $btn }

$tabUpdates = New-TabPage "Updates"; $tabHealth = New-TabPage "Health"; $tabNetwork = New-TabPage "Network & DNS"; $tabFirewall = New-TabPage "Firewall Manager"; $tabDrivers = New-TabPage "Drivers"; $tabCleanup = New-TabPage "Cleanup"; $tabUtilities = New-TabPage "Utilities"; $tabSupport = New-TabPage "Support"
$tabControl.Controls.AddRange(@($tabUpdates, $tabHealth, $tabNetwork, $tabFirewall, $tabDrivers, $tabCleanup, $tabUtilities, $tabSupport))
$form.Controls.Add($tabControl)

$grpLog = New-Object System.Windows.Forms.GroupBox; $grpLog.Text = "Console Output / Logs"; $grpLog.Dock = "Bottom"; $grpLog.Height = 200; $grpLog.ForeColor = $Color_Text
$outputBox = New-Object System.Windows.Forms.RichTextBox; $outputBox.Dock = "Fill"; $outputBox.BackColor = "Black"; $outputBox.ForeColor = "Lime"; $outputBox.Font = New-Object System.Drawing.Font("Consolas", 10); $outputBox.ReadOnly = $true; $grpLog.Controls.Add($outputBox); $form.Controls.Add($grpLog)

# ==========================================
# 5. TAB CONTENT
# ==========================================

# Updates
New-StyledButton -Parent $tabUpdates -Text "Install Winget (App Installer)" -Top 20 -Left 20 -Action { Start-Process "ms-windows-store://pdp/?productid=9NBLGGH4NNS1" }
New-StyledButton -Parent $tabUpdates -Text "Upgrade All Apps (Winget)" -Top 70 -Left 20 -Action { Start-Process cmd -ArgumentList "/k winget upgrade --all --include-unknown" }

# Health
New-StyledButton -Parent $tabHealth -Text "SFC Scan (Corrupt Files)" -Top 20 -Left 20 -Action { Start-Process cmd -ArgumentList "/k sfc /scannow" }
New-StyledButton -Parent $tabHealth -Text "DISM Check Health" -Top 70 -Left 20 -Action { Run-LogCommand { dism /online /cleanup-image /checkhealth } }
New-StyledButton -Parent $tabHealth -Text "DISM Restore Health" -Top 120 -Left 20 -Action { Start-Process cmd -ArgumentList "/k dism /online /cleanup-image /restorehealth" }
New-StyledButton -Parent $tabHealth -Text "CHKDSK (Check Disk C:)" -Top 170 -Left 20 -Action { Start-Process cmd -ArgumentList "/k chkdsk C: /f /r /x" }

# --- NETWORK TAB (3 COLUMNS) ---
# Column 1: General Network (Left: 20)
New-StyledButton -Parent $tabNetwork -Text "Show Network Info" -Top 20 -Left 20 -Action { Run-LogCommand { ipconfig /all } }
New-StyledButton -Parent $tabNetwork -Text "Flush DNS" -Top 70 -Left 20 -Action { Run-LogCommand { ipconfig /flushdns } }
New-StyledButton -Parent $tabNetwork -Text "Restart Wi-Fi Adapters" -Top 120 -Left 20 -Action { Run-LogCommand { Get-NetAdapter | Where-Object { $_.Name -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*" } | ForEach-Object { Restart-NetAdapter -Name $_.Name -Confirm:$false; Write-Output "Restarted $($_.Name)" } } }
New-StyledButton -Parent $tabNetwork -Text "Show Routing Table" -Top 170 -Left 20 -Action { Run-LogCommand { route print } }

# Column 2: DNS Settings (Middle: 340)
New-StyledButton -Parent $tabNetwork -Text "Set DNS: Google (8.8.8.8)" -Top 20 -Left 340 -Action { Run-LogCommand { Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses ("8.8.8.8","8.8.4.4") -ErrorAction SilentlyContinue; Write-Output "Google DNS set." } }
New-StyledButton -Parent $tabNetwork -Text "Set DNS: Cloudflare (1.1.1.1)" -Top 70 -Left 340 -Action { Run-LogCommand { Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue; Write-Output "Cloudflare DNS set." } }
New-StyledButton -Parent $tabNetwork -Text "Set DNS: Automatic (DHCP)" -Top 120 -Left 340 -Action { Run-LogCommand { Get-NetAdapter | Where-Object Status -eq 'Up' | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction SilentlyContinue; Write-Output "DNS Reset to Automatic (DHCP)." } }
New-StyledButton -Parent $tabNetwork -Text "Enable DNS-over-HTTPS (DoH)" -Top 170 -Left 340 -Action { Run-LogCommand { $dnsList = @("1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4"); $templates = @{ "1.1.1.1"="https://cloudflare-dns.com/dns-query"; "8.8.8.8"="https://dns.google/dns-query" }; foreach ($d in $dnsList) { if ($templates.ContainsKey($d)) { Invoke-Expression "netsh dns add encryption server=$d dohtemplate=$($templates[$d]) autoupgrade=yes udpfallback=no" | Out-Null } }; Write-Output "DoH enabled."; ipconfig /flushdns } }

# Column 3: Hosts File (Right: 660)
New-StyledButton -Parent $tabNetwork -Text "Update Ad-Block Filters (Hosts)" -Top 20 -Left 660 -Action { Run-LogCommand { Write-Output "Downloading Ad-Block Hosts..."; [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $hostsContent = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.win" -UseBasicParsing).Content; $current = Get-Content "$env:windir\System32\drivers\etc\hosts" -Raw -ErrorAction SilentlyContinue; $regex = "(?ms)(# === BEGIN USER CUSTOM ENTRIES ===.*?# === END USER CUSTOM ENTRIES ===)"; if ($current -match $regex) { $custom = $matches[1] } else { $custom = "# === BEGIN USER CUSTOM ENTRIES ===`r`n# Add custom lines here`r`n# === END USER CUSTOM ENTRIES ===" }; Set-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "$custom`r`n`r`n# Ad-Blocking Entries (Updated $(Get-Date))`r`n$hostsContent"; Write-Output "Hosts updated."; ipconfig /flushdns } }
New-StyledButton -Parent $tabNetwork -Text "Edit Hosts File (Inline)" -Top 70 -Left 660 -Action { Show-HostsEditor } -Color $Color_Purple
New-StyledButton -Parent $tabNetwork -Text "Backup Hosts File" -Top 120 -Left 660 -Action { Run-LogCommand { $dst = "$env:windir\System32\drivers\etc\hosts_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').bak"; Copy-Item "$env:windir\System32\drivers\etc\hosts" -Destination $dst -Force; Write-Output "Backed up to: $dst" } }
New-StyledButton -Parent $tabNetwork -Text "Restore Hosts Backup" -Top 170 -Left 660 -Action { $ofd = New-Object System.Windows.Forms.OpenFileDialog; $ofd.InitialDirectory = "$env:windir\System32\drivers\etc"; $ofd.Filter = "Backup Files (*.bak)|*.bak"; if ($ofd.ShowDialog() -eq "OK") { Run-LogCommand { Copy-Item $ofd.FileName -Destination "$env:windir\System32\drivers\etc\hosts" -Force; Write-Output "Restored."; ipconfig /flushdns } } }


# Firewall
$lblSearch = New-Object System.Windows.Forms.Label; $lblSearch.Text = "Search Rules:"; $lblSearch.Top = 25; $lblSearch.Left = 20; $lblSearch.AutoSize = $true; $tabFirewall.Controls.Add($lblSearch)
$txtSearch = New-Object System.Windows.Forms.TextBox; $txtSearch.Top = 20; $txtSearch.Left = 110; $txtSearch.Width = 300; $txtSearch.BackColor = $Color_Input; $txtSearch.ForeColor = $Color_Text; $tabFirewall.Controls.Add($txtSearch)
$fwGrid = New-Object System.Windows.Forms.DataGridView; $fwGrid.Top = 60; $fwGrid.Left = 20; $fwGrid.Width = 630; $fwGrid.Height = 330; $fwGrid.BackgroundColor = $Color_Input; $fwGrid.ForeColor = "Black"; $fwGrid.ReadOnly = $true; $fwGrid.SelectionMode = "FullRowSelect"; $fwGrid.MultiSelect = $false; $fwGrid.AllowUserToAddRows = $false; $fwGrid.RowHeadersVisible = $false; $tabFirewall.Controls.Add($fwGrid)
$btnFwRefresh = New-StyledButton -Parent $tabFirewall -Text "Refresh / Load Rules" -Top 60 -Left 670 -Action { $outputBox.Text += "`r`n> Loading Firewall Rules..."; $form.Refresh(); $rules = Get-NetFirewallRule | Select-Object Name, DisplayName, Enabled, Direction, Action; $dt = New-Object System.Data.DataTable; $dt.Columns.Add("DisplayName"); $dt.Columns.Add("Direction"); $dt.Columns.Add("Action"); $dt.Columns.Add("Enabled"); $dt.Columns.Add("Name"); foreach ($r in $rules) { $row = $dt.NewRow(); $row["DisplayName"] = $r.DisplayName; $row["Direction"] = $r.Direction; $row["Action"] = $r.Action; $row["Enabled"] = $r.Enabled; $row["Name"] = $r.Name; $dt.Rows.Add($row) }; $fwGrid.DataSource = $dt; $fwGrid.Columns["Name"].Visible = $false; $fwGrid.Columns["DisplayName"].Width = 280; $outputBox.Text += " Done.`r`n" }
$tabControl.Add_SelectedIndexChanged({ if ($tabControl.SelectedTab.Text -eq "Firewall Manager" -and $fwGrid.Rows.Count -eq 0) { $btnFwRefresh.PerformClick() } })
$txtSearch.Add_TextChanged({ if ($fwGrid.DataSource) { $fwGrid.DataSource.DefaultView.RowFilter = "DisplayName LIKE '%$($txtSearch.Text)%'" } })
New-StyledButton -Parent $tabFirewall -Text "Add New Rule" -Top 120 -Left 670 -Action { if (Show-AddRuleForm) { $btnFwRefresh.PerformClick() } } -Color $Color_Green
New-StyledButton -Parent $tabFirewall -Text "Enable Selected" -Top 180 -Left 670 -Action { if ($fwGrid.SelectedRows.Count -gt 0) { Set-NetFirewallRule -Name $fwGrid.SelectedRows[0].Cells["Name"].Value -Enabled True; Run-LogCommand { Write-Output "Enabled." }; $btnFwRefresh.PerformClick() } }
New-StyledButton -Parent $tabFirewall -Text "Disable Selected" -Top 230 -Left 670 -Action { if ($fwGrid.SelectedRows.Count -gt 0) { Set-NetFirewallRule -Name $fwGrid.SelectedRows[0].Cells["Name"].Value -Enabled False; Run-LogCommand { Write-Output "Disabled." }; $btnFwRefresh.PerformClick() } } -Color $Color_Orange
New-StyledButton -Parent $tabFirewall -Text "Delete Selected" -Top 280 -Left 670 -Action { if ($fwGrid.SelectedRows.Count -gt 0) { if ([System.Windows.Forms.MessageBox]::Show("Delete?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo) -eq "Yes") { Remove-NetFirewallRule -Name $fwGrid.SelectedRows[0].Cells["Name"].Value; Run-LogCommand { Write-Output "Deleted." }; $btnFwRefresh.PerformClick() } } } -Color $Color_Red

# --- DRIVERS TAB ---
New-StyledButton -Parent $tabDrivers -Text "Generate Installed Driver Report" -Top 20 -Left 20 -Action { 
    Run-LogCommand { 
        $f="$env:USERPROFILE\Desktop\Drivers.txt"; 
        driverquery /v | Out-File -FilePath $f -Force -Encoding UTF8;
        if (Test-Path $f) { Write-Output "Report saved: $f" } else { Write-Output "Error: Failed to save report." } 
    } 
}
New-StyledButton -Parent $tabDrivers -Text "Remove Hidden/Ghost Devices" -Top 70 -Left 20 -Action { Run-LogCommand { $c=0; Get-PnpDevice | Where-Object { $_.Status -eq 'Unknown' } | ForEach-Object { pnputil /remove-device $_.InstanceId; $c++ }; Write-Output "Removed $c hidden devices." } }

New-StyledButton -Parent $tabDrivers -Text "Clean Old Drivers (Interactive)" -Top 120 -Left 20 -Action { 
    $s={
        $ErrorActionPreference="SilentlyContinue";Write-Host "Scanning..." -ForegroundColor Cyan;$raw=pnputil.exe /enum-drivers;$d=@();$c=$null;foreach($l in $raw){if($l-match'^Published Name:\s+(.+)$'){if($c){$d+=[PSCustomObject]$c}$c=[ordered]@{D=$matches[1].Trim();O=$null;V=$null;Da=$null}}elseif($l-match'^Original Name:\s+(.+)$'){$c.O=$matches[1].Trim()}elseif($l-match'^Driver Version:\s+(.+)$'){try{$c.V=[Version]$matches[1].Trim()}catch{$c.V=[Version]"0.0.0.0"}}elseif($l-match'^Date:\s+(.+)$'){try{$c.Da=[DateTime]$matches[1].Trim()}catch{$c.Da=[DateTime]::MinValue}}}if($c){$d+=[PSCustomObject]$c}$grp=$d|Where{$_.O}|Group O;$kill=@();foreach($g in $grp){if($g.Count-gt 1){$srt=$g.Group|Sort Da,V -Desc;$kill+=$srt|Select -Skip 1}};
        if($kill.Count-eq 0){Write-Host "`nScanning Complete and is already clean. You may close this window." -ForegroundColor Green;Read-Host;return}
        Write-Host "Found $($kill.Count) old drivers." -ForegroundColor Yellow;$bk="$env:USERPROFILE\Desktop\DriverBackup_$(Get-Date -F 'yyyyMMdd_HHmmss')";
        Write-Host "Backing up to $bk..." -ForegroundColor Cyan;New-Item -ItemType Directory -Path $bk -Force|Out-Null;
        $p=Start-Process pnputil -Arg "/export-driver * `"$bk`"" -Wait -PassThru -NoNewWindow;
        if($p.ExitCode-eq 0){Write-Host "Backup Done." -ForegroundColor Green}else{Write-Host "Backup Failed." -ForegroundColor Red};
        if((Read-Host "Delete All? (Y/N)")-eq 'Y'){foreach($k in $kill){pnputil /delete-driver $k.D /uninstall}}Read-Host "Done."
    };
    $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($s.ToString()));Start-Process powershell "-NoExit -EncodedCommand $enc" 
} -Color $Color_Orange

# Driver Policies (Right Side)
New-StyledButton -Parent $tabDrivers -Text "Disable Auto Driver Updates" -Top 20 -Left 340 -Action { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0; Run-LogCommand { Write-Output "Auto Updates Disabled" } } -Color $Color_Red
New-StyledButton -Parent $tabDrivers -Text "Enable Auto Driver Updates" -Top 70 -Left 340 -Action { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 1; Run-LogCommand { Write-Output "Auto Updates Enabled" } } -Color $Color_Green
New-StyledButton -Parent $tabDrivers -Text "Disable Device Metadata" -Top 120 -Left 340 -Action { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" "PreventDeviceMetadataFromNetwork" 1 -Type DWord; Run-LogCommand { Write-Output "Metadata Disabled" } } -Color $Color_Red
New-StyledButton -Parent $tabDrivers -Text "Enable Device Metadata" -Top 170 -Left 340 -Action { Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" "PreventDeviceMetadataFromNetwork" 0 -Type DWord; Run-LogCommand { Write-Output "Metadata Enabled" } } -Color $Color_Green
New-StyledButton -Parent $tabDrivers -Text "Restore Drivers from Backup" -Top 220 -Left 340 -Action { $fbd=New-Object System.Windows.Forms.FolderBrowserDialog; if($fbd.ShowDialog()-eq "OK"){ Start-Process powershell "-NoExit -Command & { pnputil /add-driver `"$($fbd.SelectedPath)\*.inf`" /subdirs /install; Read-Host 'Done.' }" } }

# Cleanup
New-StyledButton -Parent $tabCleanup -Text "Disk Cleanup Tool" -Top 20 -Left 20 -Action { Start-Process cleanmgr.exe }
New-StyledButton -Parent $tabCleanup -Text "Quick Temp File Clean" -Top 70 -Left 20 -Action { Run-LogCommand { @($env:TEMP, "C:\Windows\Temp") | ForEach-Object { Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue }; Write-Output "Temp files cleaned." } }
New-StyledButton -Parent $tabCleanup -Text "Broken Shortcut Fixer" -Top 120 -Left 20 -Action { Run-LogCommand { $shell = New-Object -ComObject WScript.Shell; Get-ChildItem "$env:USERPROFILE\Desktop" -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | ForEach-Object { try { if (-not (Test-Path $shell.CreateShortcut($_.FullName).TargetPath)) { Write-Output "Broken: $($_.Name)" } } catch {} }; Write-Output "Scan Complete." } }
New-StyledButton -Parent $tabCleanup -Text "Clean Old Registry Keys" -Top 170 -Left 20 -Action { Run-LogCommand { Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } | ForEach-Object { Remove-Item $_.PSPath -Recurse -Force; Write-Output "Removed: $($_.PSChildName)" } } }
New-StyledButton -Parent $tabCleanup -Text "Clean Xbox Credentials" -Top 220 -Left 20 -Action { Run-LogCommand { cmdkey /list | Select-String "Target:.*(Xbl.*)" | ForEach-Object { cmdkey /delete:$($_.ToString().Split(":")[1].Trim()); Write-Output "Deleted Xbl cred." } } }

# Utilities
New-StyledButton -Parent $tabUtilities -Text "Generate System Report" -Top 20 -Left 20 -Action { Run-LogCommand { systeminfo | Out-File "$env:USERPROFILE\Desktop\System_Report.txt"; Write-Output "Saved to Desktop." } }
New-StyledButton -Parent $tabUtilities -Text "Windows Update Repair" -Top 70 -Left 20 -Action { Start-Process powershell -ArgumentList "-Command & { Stop-Service wuauserv; Stop-Service bits; Start-Service wuauserv; Start-Service bits; Write-Host 'Done.'; Read-Host 'Enter' }" }
New-StyledButton -Parent $tabUtilities -Text "MAS Activation (massgrave.dev)" -Top 120 -Left 20 -Action { if ([System.Windows.Forms.MessageBox]::Show("Run MAS Script?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning) -eq "Yes") { Start-Process powershell -ArgumentList "-NoExit -Command & { iwr -useb https://get.activated.win | iex }" } } -Color $Color_Purple
New-StyledButton -Parent $tabUtilities -Text "Scheduled Tasks Manager" -Top 170 -Left 20 -Action { Start-Process "taskschd.msc" }
New-StyledButton -Parent $tabUtilities -Text "Optimize/Trim SSDs" -Top 220 -Left 20 -Action { Run-LogCommand { Optimize-Volume -DriveLetter C -ReTrim -Verbose } }

# Support
$lblSupport = New-Object System.Windows.Forms.Label; $lblSupport.Text = "Windows Maintenance Tool`nBased on CLI by Lil_Batti & Chaython`nGUI Version 4.0"; $lblSupport.AutoSize = $true; $lblSupport.Top = 20; $lblSupport.Left = 20; $lblSupport.Font = New-Object System.Drawing.Font("Segoe UI", 12); $tabSupport.Controls.Add($lblSupport)
New-StyledButton -Parent $tabSupport -Text "Join Discord Support" -Top 100 -Left 20 -Action { Start-Process "https://discord.gg/bCQqKHGxja" }
New-StyledButton -Parent $tabSupport -Text "Report Issue on GitHub" -Top 150 -Left 20 -Action { Start-Process "https://github.com/ios12checker/Windows-Maintenance-Tool/issues/new/choose" } -Color [System.Drawing.Color]::Gray

$form.Add_Load({ $outputBox.Text = "Welcome to Windows Maintenance Tool GUI v4.0.`r`nSelect a tab above to begin.`r`nRunning as: $env:USERNAME`r`n" })

[void]$form.ShowDialog()

