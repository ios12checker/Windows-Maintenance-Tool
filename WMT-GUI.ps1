<#
    Windows Maintenance Tool - ULTIMATE WPF EDITION = Thanks to https://github.com/Chaython
#>

# ==========================================
# 1. SETUP
# ==========================================
$AppVersion = "4.1"
$ErrorActionPreference = "SilentlyContinue"

# --- DEFINE DATA DIRECTORY (Relative to Script) ---
try {
    # Try to get script path, fallback to current location if running in ISE/Console unsaved
    $ScriptRoot = if ($PSCommandPath) { Split-Path -Parent $PSCommandPath } else { Get-Location }
    $DataDir = Join-Path $ScriptRoot "data"
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
} catch {
    # Fallback to Temp if we can't write to script dir
    $DataDir = Join-Path $env:TEMP "WMT_Data"
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
}

# HIDE CONSOLE
$t = '[DllImport("user32.dll")] public static extern bool ShowWindow(int handle, int state);'
$w = Add-Type -MemberDefinition $t -Name "Win32ShowWindow" -Namespace Win32Functions -PassThru
$w::ShowWindow(([System.Diagnostics.Process]::GetCurrentProcess() | Get-Process).MainWindowHandle, 0)

# ADMIN CHECK
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Add-Type -AssemblyName PresentationFramework, System.Windows.Forms, System.Drawing, Microsoft.VisualBasic

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

function Get-Ctrl { param($Name) return $window.FindName($Name) }

function Log-ToGui {
    param($Msg)
    $lb = Get-Ctrl "LogBox"
    if ($lb) {
        $lb.AppendText("[$((Get-Date).ToString('HH:mm'))] $Msg`n")
        $lb.ScrollToEnd()
        # FORCE UI REFRESH
        [System.Windows.Forms.Application]::DoEvents()
    }
}

function Run-Cmd {
    param([scriptblock]$Sb, $Msg="Processing...")
    [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::WaitCursor
    Log-ToGui $Msg
    try { 
        $res = & $Sb | Out-String
        if ($res){ Log-ToGui $res.Trim() } 
        else { Log-ToGui "Done." }
    } catch { 
        Log-ToGui "ERROR: $($_.Exception.Message)" 
    }
    [System.Windows.Forms.Cursor]::Current = [System.Windows.Forms.Cursors]::Default
}

# --- UPDATE CHECKER ---
function Check-ForUpdate {
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
                # Save backup to DataDir
                $backupName = "$(Split-Path $PSCommandPath -Leaf).bak"
                $backupPath = Join-Path $script:DataDir $backupName
                
                Copy-Item -Path $PSCommandPath -Destination $backupPath -Force
                Set-Content -Path $PSCommandPath -Value $remoteContent -Encoding UTF8
                
                [System.Windows.MessageBox]::Show("Update complete! Backup saved to: $backupName`nRestarting...", "Updated", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
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
    Run-Cmd {
        Stop-Service -Name wuauserv, bits, cryptsvc, msiserver -Force -ErrorAction SilentlyContinue
        $rnd = Get-Random
        if(Test-Path "$env:windir\SoftwareDistribution"){ Rename-Item "$env:windir\SoftwareDistribution" "$env:windir\SoftwareDistribution.bak_$rnd" -ErrorAction SilentlyContinue }
        if(Test-Path "$env:windir\System32\catroot2"){ Rename-Item "$env:windir\System32\catroot2" "$env:windir\System32\catroot2.bak_$rnd" -ErrorAction SilentlyContinue }
        netsh winsock reset | Out-Null
        Start-Service -Name wuauserv, bits, cryptsvc, msiserver -ErrorAction SilentlyContinue
    } "Repairing Windows Update..."
}

function Start-NetRepair {
    Run-Cmd {
        ipconfig /release | Out-Null
        ipconfig /renew | Out-Null
        ipconfig /flushdns | Out-Null
        netsh winsock reset | Out-Null
        netsh int ip reset | Out-Null
    } "Running Full Network Repair..."
}

function Start-RegClean {
    Run-Cmd {
        # Save registry backups to .\data\RegistryBackups
        $bkDir = Join-Path $script:DataDir "RegistryBackups"
        if(!(Test-Path $bkDir)){ New-Item -Path $bkDir -ItemType Directory | Out-Null }
        
        $bkFile = "$bkDir\Backup_$(Get-Date -F 'yyyyMMdd_HHmm').reg"
        reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $bkFile /y | Out-Null
        
        $keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' }
        if ($keys) { foreach ($k in $keys) { Remove-Item $k.PSPath -Recurse -Force; Write-Output "Removed: $($k.PSChildName)" } } else { Write-Output "No obsolete keys found." }
        
        Write-Output "Backup saved to: $bkFile"
    } "Cleaning Registry..."
}

function Start-XboxClean {
    Run-Cmd {
        Write-Output "Stopping Xbox Auth Manager..."
        Stop-Service -Name "XblAuthManager" -Force -ErrorAction SilentlyContinue

        # Get all stored credentials and split into lines
        $allCreds = (cmdkey /list) -split "`r?`n"
        $xblTargets = @()

        # Regex match exactly like the CLI version
        foreach ($line in $allCreds) {
            if ($line -match "(?i)^\s*Target:.*(Xbl.*)$") {
                $xblTargets += $matches[1]
            }
        }

        if ($xblTargets.Count -eq 0) {
            Write-Output "No Xbox Live credentials found."
        } else {
            foreach ($target in $xblTargets) {
                Write-Output "Deleting credential: $target"
                # Redirect stderr to null to hide "Element not found" if it was already deleted
                cmdkey /delete:$target 2>$null
            }
            Write-Output "Successfully deleted $($xblTargets.Count) credential(s)."
        }

        Start-Service -Name "XblAuthManager" -ErrorAction SilentlyContinue
    } "Cleaning Xbox Credentials..."
}

function Start-GpeditInstall {
    # Check for User Confirmation
    $msg = "Install Local Group Policy Editor?`n`nThis enables the Group Policy Editor (gpedit.msc) on Windows Home editions by installing the built-in system packages.`n`nContinue?"
    $res = [System.Windows.Forms.MessageBox]::Show($msg, "Confirm Install", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxImage]::Question)
    if ($res -eq "No") { return }

    Run-Cmd {
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

# --- HOSTS EDITOR ---
function Show-HostsEditor {
    $hForm = New-Object System.Windows.Forms.Form
    $hForm.Text = "Hosts File Editor"; $hForm.Size = "900, 700"; $hForm.StartPosition = "CenterScreen"; $hForm.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
    $txtHosts = New-Object System.Windows.Forms.RichTextBox; $txtHosts.Dock="Fill"; $txtHosts.BackColor=[System.Drawing.Color]::FromArgb(45,45,48); $txtHosts.ForeColor="White"; $txtHosts.Font="Consolas, 11"; $hForm.Controls.Add($txtHosts)
    $pnl = New-Object System.Windows.Forms.Panel; $pnl.Dock="Bottom"; $pnl.Height=50; $hForm.Controls.Add($pnl)
    $btn = New-Object System.Windows.Forms.Button; $btn.Text="Save"; $btn.BackColor="SeaGreen"; $btn.ForeColor="White"; $btn.FlatStyle="Flat"; $btn.Top=10; $btn.Left=20; $btn.Width=100; $pnl.Controls.Add($btn)
    $tip = New-Object System.Windows.Forms.ToolTip; $tip.SetToolTip($btn, "Save changes to the Hosts file immediately")
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $txtHosts.Text = Get-Content $hostsPath -Raw -ErrorAction SilentlyContinue
    $Highlight = {
        $txtHosts.SelectAll(); $txtHosts.SelectionColor = "White"
        $s = $txtHosts.Text.IndexOf("# === BEGIN USER CUSTOM ENTRIES ===")
        $e = $txtHosts.Text.IndexOf("# === END USER CUSTOM ENTRIES ===")
        if ($s -ge 0 -and $e -gt $s) { $txtHosts.Select($s, ($e+33)-$s); $txtHosts.SelectionColor="Cyan" }
        $txtHosts.Select(0,0)
    }; & $Highlight
    $btn.Add_Click({ try { Set-Content $hostsPath $txtHosts.Text -NoNewline; [System.Windows.MessageBox]::Show("Saved!"); & $Highlight } catch { [System.Windows.MessageBox]::Show("Error: $_") } })
    $hForm.ShowDialog()
}

# --- FIREWALL RULE DIALOG ---
function Show-RuleDialog {
    param($Title, $RuleObj=$null) 
    $f = New-Object System.Windows.Forms.Form
    $f.Text = $Title; $f.Size = "450, 450"; $f.StartPosition = "CenterScreen"; $f.BackColor = [System.Drawing.Color]::FromArgb(40,40,40); $f.ForeColor = "White"
    function New-Input { param($L, $Y, $V="", $Opts=$null)
        $lbl=New-Object System.Windows.Forms.Label; $lbl.Text=$L; $lbl.Top=$Y; $lbl.Left=20; $lbl.AutoSize=$true; $f.Controls.Add($lbl)
        if ($Opts) { $c=New-Object System.Windows.Forms.ComboBox; $c.DropDownStyle="DropDownList"; $Opts|%{ [void]$c.Items.Add($_) }; if($V){$c.SelectedItem=$V}else{$c.SelectedIndex=0} } 
        else { $c=New-Object System.Windows.Forms.TextBox; $c.Text=$V }
        $c.Top=$Y+20; $c.Left=20; $c.Width=380; $c.BackColor=[System.Drawing.Color]::FromArgb(60,60,60); $c.ForeColor="White"; $f.Controls.Add($c); return $c
    }
    $vName=""; $vDir="Inbound"; $vAct="Block"; $vProt="TCP"; $vPort=""
    if ($RuleObj) { $vName=$RuleObj.DisplayName; $vDir=$RuleObj.Direction; $vAct=$RuleObj.Action; $vProt=$RuleObj.Protocol; $vPort=$RuleObj.LocalPort }
    $iName = New-Input "Rule Name" 10 $vName
    if ($RuleObj) { $iName.ReadOnly=$true; $iName.BackColor=[System.Drawing.Color]::FromArgb(30,30,30) }
    $iDir = New-Input "Direction" 60 $vDir @("Inbound", "Outbound")
    $iAct = New-Input "Action" 110 $vAct @("Allow", "Block")
    $iProt = New-Input "Protocol" 160 "TCP" @("TCP", "UDP", "Any")
    $iPort = New-Input "Local Port (e.g. 80)" 210 $vPort
    $btn = New-Object System.Windows.Forms.Button; $btn.Text="Save"; $btn.Top=300; $btn.Left=20; $btn.Width=380; $btn.Height=40; $btn.BackColor="SeaGreen"; $btn.ForeColor="White"; $btn.DialogResult="OK"; $f.Controls.Add($btn)
    $tip = New-Object System.Windows.Forms.ToolTip; $tip.SetToolTip($btn, "Confirm and save this firewall rule")
    if ($f.ShowDialog() -eq "OK") { return @{ Name=$iName.Text; Direction=$iDir.SelectedItem; Action=$iAct.SelectedItem; Protocol=$iProt.SelectedItem; Port=$iPort.Text } }
    return $null
}

# --- TASK SCHEDULER MANAGER (Firewall Manager Theme Match) ---
function Show-TaskManager {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Task Scheduler Manager"
    $f.Size = "900, 600"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = [System.Drawing.Color]::White

    # DataGridView styled to match Firewall ListView
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
    
    # --- GRID STYLING ---
    $dg.EnableHeadersVisualStyles = $false
    
    # Header Style (Darker Gray)
    $dg.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#2D2D30")
    $dg.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.ColumnHeadersDefaultCellStyle.Padding = (New-Object System.Windows.Forms.Padding 4)
    $dg.ColumnHeadersBorderStyle = [System.Windows.Forms.DataGridViewHeaderBorderStyle]::Single
    $dg.ColumnHeadersHeight = 30
    
    # Row 1 Style (Base Background)
    $dg.DefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $dg.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
    $dg.DefaultCellStyle.SelectionBackColor = [System.Drawing.ColorTranslator]::FromHtml("#007ACC") # VS Blue
    $dg.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
    $dg.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
    
    # Row 2 Style (Alternating - Slightly Lighter)
    $dg.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#252526")
    $dg.AlternatingRowsDefaultCellStyle.ForeColor = [System.Drawing.Color]::White

    $dg.GridColor = [System.Drawing.ColorTranslator]::FromHtml("#333333")

    $f.Controls.Add($dg)

    # Bottom Panel
    $pnl = New-Object System.Windows.Forms.Panel
    $pnl.Dock = "Bottom"
    $pnl.Height = 80
    $pnl.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.Controls.Add($pnl)

    # Helper to style buttons like XAML "ActionBtn"
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
    $btnEn  = New-StyledBtn "Enable" 130 "#006600" # Green match
    $btnDis = New-StyledBtn "Disable" 240 "#CCAA00" # Yellow/Gold match
    $btnDel = New-StyledBtn "Delete" 350 "#802020" # Red match

    # --- TEXT COLOR LOGIC (RowPrePaint) ---
    $dg.Add_RowPrePaint({
        param($sender, $e)
        $row = $sender.Rows[$e.RowIndex]
        
        if ($row.Cells["State"].Value) {
            $state = $row.Cells["State"].Value.ToString()
            
            # Apply text colors to match Firewall 'Action' column logic
            if ($state -eq "Running") {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#00FF00") # Bright Green
            }
            elseif ($state -eq "Ready") {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FFFF00") # Bright Yellow
            }
            elseif ($state -eq "Disabled") {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#FF3333") # Bright Red
            }
            else {
                $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::LightGray
            }
        }
    })

    $LoadTasks = {
        $tasks = Get-ScheduledTask | Select-Object TaskName, State, Author, TaskPath
        $dt = New-Object System.Data.DataTable
        $dt.Columns.Add("TaskName")
        $dt.Columns.Add("State")
        $dt.Columns.Add("Author")
        $dt.Columns.Add("Path")
        
        foreach ($t in $tasks) { 
            $r=$dt.NewRow()
            $r["TaskName"]=$t.TaskName
            $r["State"]=$t.State
            $r["Author"]=$t.Author
            $r["Path"]=$t.TaskPath
            $dt.Rows.Add($r) 
        }
        $dg.DataSource = $dt
        $dg.ClearSelection()
    }

    $btnRef.Add_Click({ & $LoadTasks })
    
    $btnEn.Add_Click({ 
        if($dg.SelectedRows.Count -gt 0){ 
            $n=$dg.SelectedRows[0].Cells["TaskName"].Value
            Enable-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
            & $LoadTasks 
        } 
    })
    
    $btnDis.Add_Click({ 
        if($dg.SelectedRows.Count -gt 0){ 
            $n=$dg.SelectedRows[0].Cells["TaskName"].Value
            Disable-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
            & $LoadTasks 
        } 
    })
    
    $btnDel.Add_Click({ 
        if($dg.SelectedRows.Count -gt 0){ 
            $n=$dg.SelectedRows[0].Cells["TaskName"].Value
            if([System.Windows.Forms.MessageBox]::Show("Delete $n?","Confirm",[System.Windows.Forms.MessageBoxButtons]::YesNo) -eq "Yes"){ 
                Unregister-ScheduledTask -TaskName $n -Confirm:$false
                & $LoadTasks 
            } 
        } 
    })

    & $LoadTasks
    $f.ShowDialog()
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
                </StackPanel>
                
                <ListBox Name="lstSearchResults" Grid.Row="2" Background="#111" BorderThickness="0" Foreground="Cyan" Visibility="Collapsed" Margin="5"/>

                <StackPanel Grid.Row="3" Margin="10">
                     <TextBlock Text="LOG OUTPUT" FontSize="10" Foreground="#666" FontWeight="Bold"/>
                     <TextBox Name="LogBox" Height="150" IsReadOnly="True" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11" Background="#111" Foreground="#0F0" BorderThickness="0"/>
                </StackPanel>
            </Grid>
        </Border>

        <Border Grid.Column="1" Background="#121212">
            <Grid Margin="20">
            <Grid Name="pnlUpdates">
                    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                    
                    <StackPanel Grid.Row="0">
                        <TextBlock Text="Windows Updates (Winget)" FontSize="24" Margin="0,0,0,10"/>
                        <Grid>
                            <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
                            <StackPanel Orientation="Horizontal">
                                <TextBlock Name="lblWingetTitle" Text="Available Updates" FontSize="14" Foreground="#AAA" VerticalAlignment="Bottom"/>
                                <TextBlock Name="lblWingetStatus" Text="Ready" Foreground="Cyan" Margin="15,0,0,0" VerticalAlignment="Bottom" Visibility="Hidden"/>
                            </StackPanel>
                            <StackPanel Grid.Column="1" Orientation="Horizontal">
                                <TextBox Name="txtWingetSearch" Width="200" Text="Search new packages..." Padding="5" Background="#1E1E1E" Foreground="#AAA" BorderBrush="#444"/>
                                <Button Name="btnWingetFind" Content="Find" Width="60" Style="{StaticResource ActionBtn}" Margin="5,0,0,0"/>
                            </StackPanel>
                        </Grid>
                    </StackPanel>
                    
                    <ListView Name="lstWinget" Grid.Row="1" Margin="0,10" Background="#1E1E1E" Foreground="#DDD" BorderThickness="1" BorderBrush="#333" AlternationCount="2">
                        <ListView.ItemContainerStyle>
                            <Style TargetType="ListViewItem">
                                <Setter Property="BorderThickness" Value="0"/>
                                <Style.Triggers>
                                    <Trigger Property="ItemsControl.AlternationIndex" Value="0"><Setter Property="Background" Value="#1E1E1E"/></Trigger>
                                    <Trigger Property="ItemsControl.AlternationIndex" Value="1"><Setter Property="Background" Value="#252526"/></Trigger>
                                    <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#007ACC"/><Setter Property="Foreground" Value="White"/></Trigger>
                                    <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#3E3E42"/></Trigger>
                                </Style.Triggers>
                            </Style>
                        </ListView.ItemContainerStyle>
                        <ListView.View>
                            <GridView>
                                <GridViewColumn Header="Name" Width="300" DisplayMemberBinding="{Binding Name}"/>
                                <GridViewColumn Header="Id" Width="200" DisplayMemberBinding="{Binding Id}"/>
                                <GridViewColumn Header="Version" Width="100" DisplayMemberBinding="{Binding Version}"/>
                                <GridViewColumn Header="New Ver" Width="100" DisplayMemberBinding="{Binding Available}"/>
                                <GridViewColumn Header="Source" Width="80" DisplayMemberBinding="{Binding Source}"/>
                            </GridView>
                        </ListView.View>
                    </ListView>

                    <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Right">
                        <Button Name="btnWingetScan" Content="Refresh Updates" Width="140" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnWingetUpdateSel" Content="Update Selected" Width="140" Style="{StaticResource ActionBtn}" Background="#006600"/>
                        <Button Name="btnWingetInstall" Content="Install Selected" Width="140" Style="{StaticResource ActionBtn}" Background="#006600" Visibility="Collapsed"/>
                        <Button Name="btnWingetUninstall" Content="Uninstall Selected" Width="140" Style="{StaticResource ActionBtn}" Background="#802020"/>
                    </StackPanel>
                </Grid>
                <StackPanel Name="pnlHealth" Visibility="Collapsed">
                    <TextBlock Text="System Health" FontSize="24" Margin="0,0,0,20"/>
                    
                    <TextBlock Text="File System &amp; Image" Foreground="#888" Margin="5"/>
                    <WrapPanel Margin="0,0,0,15">
                        <Button Name="btnSFC" Content="SFC Scan" Width="220" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDISMCheck" Content="DISM Check" Width="220" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDISMRestore" Content="DISM Restore" Width="220" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnCHKDSK" Content="CHKDSK C:" Width="220" Style="{StaticResource ActionBtn}"/>
                    </WrapPanel>

                    <TextBlock Text="Windows Update Repairs" Foreground="#888" Margin="5"/>
                    <WrapPanel>
                        <Button Name="btnHealthUpdateRepair" Content="Full Update Repair" Width="220" Style="{StaticResource ActionBtn}" Background="#8B0000"/>
                        <Button Name="btnHealthServiceReset" Content="Reset Update Services" Width="220" Style="{StaticResource ActionBtn}" Background="#B8860B"/>
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
                    </WrapPanel>
                    
                    <TextBlock Text="DNS Presets" Foreground="#888" Margin="5"/>
                    <WrapPanel Margin="0,0,0,15">
                        <Button Name="btnDnsGoogle" Content="Google (8.8.8.8)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsCloudflare" Content="Cloudflare (1.1.1.1)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsQuad9" Content="Quad9 (9.9.9.9)" Width="180" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDnsAuto" Content="Auto (DHCP)" Width="180" Style="{StaticResource ActionBtn}"/>
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
                    </StackPanel>
                </Grid>

                <StackPanel Name="pnlDrivers" Visibility="Collapsed">
                    <TextBlock Text="Drivers &amp; Devices" FontSize="24" Margin="0,0,0,20"/>
                    <WrapPanel>
                        <Button Name="btnDrvReport" Content="Generate Driver Report" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvGhost" Content="Remove Ghost Devices" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvClean" Content="Clean Old Drivers" Width="200" Style="{StaticResource ActionBtn}" Background="#B8860B"/>
                    </WrapPanel>
                    
                    <TextBlock Text="Updates &amp; Metadata" Foreground="#888" Margin="5,15,0,5"/>
                    <WrapPanel>
                        <Button Name="btnDrvEnableAuto" Content="Enable Auto Updates" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvDisableAuto" Content="Disable Auto Updates" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvEnableMeta" Content="Enable Device Metadata" Width="200" Style="{StaticResource ActionBtn}"/>
                        <Button Name="btnDrvDisableMeta" Content="Disable Device Metadata" Width="200" Style="{StaticResource ActionBtn}"/>
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
                        <TextBlock Text="- Original CLI: Lil_Batti &amp; " Foreground="#AAA" VerticalAlignment="Center"/>
                        <Button Name="btnCreditChaythonCLI" Content="Chaython" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                    </StackPanel>
                    <StackPanel Orientation="Horizontal" Margin="0,0,0,5">
                        <TextBlock Text="- GUI Design &amp; Implementation: " Foreground="#AAA" VerticalAlignment="Center"/>
                        <Button Name="btnCreditChaythonGUI" Content="Chaython" Foreground="#00BFFF" Background="Transparent" BorderThickness="0" Cursor="Hand" FontSize="12"/>
                    </StackPanel>

                    <TextBlock Text="License: MIT License" Foreground="#666" Margin="0,10,0,0" FontSize="10"/>
                    <TextBlock Text="Copyright (c) 2025" Foreground="#666" FontSize="10"/>
                    
                    <StackPanel Orientation="Horizontal" Margin="0,20,0,0">
                         <Button Name="btnSupportDiscord" Content="Join Discord" Width="180" Style="{StaticResource ActionBtn}" Background="#5865F2"/>
                         <Button Name="btnSupportIssue" Content="Report Issue" Width="180" Style="{StaticResource ActionBtn}"/>
                         <Button Name="btnDonate" Content="Donate" Width="150" Style="{StaticResource ActionBtn}" Background="#2EA043"/>
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
Set-ButtonIcon "btnHealthUpdateRepair" "M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8 M3 3v5h5 M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16 M16 21h5v-5" "Full Update Repair" "Stops services, clears cache, re-registers DLLs, and resets network (Option 21)" 16 "#FF3333"
Set-ButtonIcon "btnHealthServiceReset" "M12,5V1L7,6L12,11V7C15.31,7 18,9.69 18,13C18,16.31 15.31,19 12,19C8.69,19 6,16.31 6,13H4C4,17.42 7.58,21 12,21C16.42,21 20,17.42 20,13C20,8.58 16.42,5 12,5Z" "Reset Update Services" "Quickly restarts update-related services without clearing cache (Option 23)"
Set-ButtonIcon "btnNetRepair" "M20,12H19.5C19.5,14.5 17.5,16.5 15,16.5H9V18.5H15C18.6,18.5 21.5,15.6 21.5,12H21C21,15 19,17.5 16,18V16L13,19L16,22V20C19.9,19.4 23,16 23,12M3,12H3.5C3.5,9.5 5.5,7.5 8,7.5H14V5.5H8C4.4,5.5 1.5,8.4 1.5,12H2C2,9 4,6.5 7,6V8L10,5L7,2V4C3.1,4.6 0,8 0,12H3Z" "Full Net Repair" "Full network stack reset (Winsock, IP, Flush DNS)"
Set-ButtonIcon "btnRouteTable" "M19,15L13,21L11.58,19.58L15.17,16H4V4H6V14H15.17L11.58,10.42L13,9L19,15Z" "Save Route Table" "Exports the current IP routing table to the Desktop"
Set-ButtonIcon "btnCleanReg" "M5,3H19A2,2 0 0,1 21,5V19A2,2 0 0,1 19,21H5A2,2 0 0,1 3,19V5A2,2 0 0,1 5,3M7,7V9H9V7H7M11,7V9H13V7H11M15,7V9H17V7H15M7,11V13H9V11H7M11,11V13H13V11H11M15,11V13H17V11H15M7,15V17H9V15H7M11,15V17H13V15H11M15,15V17H17V15H15Z" "Clean Reg Keys" "Backs up & deletes obsolete Uninstall registry keys"
Set-ButtonIcon "btnCleanXbox" "M6.4,4.8L12,10.4L17.6,4.8L19.2,6.4L13.6,12L19.2,17.6L17.6,19.2L12,13.6L6.4,19.2L4.8,17.6L10.4,12L4.8,6.4L6.4,4.8Z" "Clean Xbox Data" "Removes Xbox Live credentials to fix login loops" 18 "#107C10"
Set-ButtonIcon "btnUpdateRepair" "M21,10.12H14.22L16.96,7.3C14.55,4.61 10.54,4.42 7.85,6.87C5.16,9.32 5.35,13.33 7.8,16.03C10.25,18.72 14.26,18.91 16.95,16.46C17.65,15.82 18.2,15.05 18.56,14.21L20.62,15.05C19.79,16.89 18.3,18.42 16.39,19.34C13.4,20.78 9.77,20.21 7.37,17.96C4.96,15.71 4.54,12.06 6.37,9.32C8.2,6.59 11.83,5.65 14.65,7.09L17.38,4.35H10.63V2.35H21V10.12Z" "Reset Update Svc" "Stops services, clears cache, and resets Windows Update components"
Set-ButtonIcon "btnDotNetEnable" "M14.6,16.6L19.2,12L14.6,7.4L16,6L22,12L16,18L14.6,16.6M9.4,16.6L4.8,12L9.4,7.4L8,6L2,12L8,18L9.4,16.6Z" "Set .NET RollFwd" "Sets DOTNET_ROLL_FORWARD=LatestMajor (Force apps to use newest .NET)"
Set-ButtonIcon "btnDotNetDisable" "M19,6.41L17.59,5L12,10.59L6.41,5L5,6.41L10.59,12L5,17.59L6.41,19L12,13.41L17.59,19L19,17.59L13.41,12L19,6.41Z" "Reset .NET RollFwd" "Removes the DOTNET_ROLL_FORWARD environment variable"
Set-ButtonIcon "btnTaskManager" "M14,10H2V12H14V10M14,6H2V8H14V6M2,16H10V14H2V16M21.5,11.5L23,13L16,20L11.5,15.5L13,14L16,17L21.5,11.5Z" "Task Scheduler" "View, Enable, Disable, or Delete Windows Scheduled Tasks"
Set-ButtonIcon "btnInstallGpedit" "M6,2C4.89,2 4,2.89 4,4V20A2,2 0 0,0 6,22H18A2,2 0 0,0 20,20V8L14,2H6M6,4H13V9H18V20H6V4M8,12V14H16V12H8M8,16V18H13V16H8Z" "Install Gpedit" "Installs the Group Policy Editor on Windows Home editions"
Set-ButtonIcon "btnSFC" "M15.5,14L20.5,19L19,20.5L14,15.5V14.71L13.73,14.43C12.59,15.41 11.11,16 9.5,16A6.5,6.5 0 0,1 3,9.5A6.5,6.5 0 0,1 9.5,3A6.5,6.5 0 0,1 16,9.5C16,11.11 15.41,12.59 14.43,13.73L14.71,14H15.5M9.5,14C12,14 14,12 14,9.5C14,7 12,5 9.5,5C7,5 5,7 5,9.5C5,12 7,14 9.5,14Z" "SFC Scan" "Scans system files for corruption and repairs them"
Set-ButtonIcon "btnDISMCheck" "M22,10V9C22,5.1 18.9,2 15,2C11.1,2 8,5.1 8,9V10H22M19.5,12.5C19.5,11.1 20.6,10 22,10H8V15H19.5V12.5Z" "DISM Check" "Checks the health of the Windows Image (dism /checkhealth)"
Set-ButtonIcon "btnDISMRestore" "M19.5,12.5C19.5,11.1 20.6,10 22,10V9C22,5.1 18.9,2 15,2C11.1,2 8,5.1 8,9V10C9.4,10 10.5,11.1 10.5,12.5C10.5,13.9 9.4,15 8,15V19H12V22H8C6.3,22 5,20.7 5,19V15C3.6,15 2.5,13.9 2.5,12.5C2.5,11.1 3.6,10 5,10V9C5,3.5 9.5,-1 15,-1C20.5,-1 25,3.5 25,9V10C26.4,10 27.5,11.1 27.5,12.5C27.5,13.9 26.4,15 25,15V19C25,20.7 23.7,22 22,22H17V19H22V15C20.6,15 19.5,13.9 19.5,12.5Z" "DISM Restore" "Attempts to repair the Windows Image (dism /restorehealth)"
Set-ButtonIcon "btnCHKDSK" "M18,17L23,12L18,7M1,12H17" "CHKDSK C:" "Scans the C: drive for filesystem errors (requires reboot)"
Set-ButtonIcon "btnFlushDNS" "M2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2A10,10 0 0,0 2,12M4,12A8,8 0 0,1 12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12M10,17L15,12L10,7V17Z" "Flush DNS" "Clears the client DNS resolver cache"
Set-ButtonIcon "btnNetInfo" "M13,9H11V7H13M13,17H11V11H13M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2Z" "Show IP Config" "Displays full IP configuration for all adapters"
Set-ButtonIcon "btnResetWifi" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z" "Restart Wi-Fi" "Disables and Re-Enables Wi-Fi adapters"
Set-ButtonIcon "btnCleanDisk" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Disk Cleanup" "Opens the built-in Windows Disk Cleanup utility"
Set-ButtonIcon "btnCleanTemp" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Delete Temp Files" "Deletes temporary files from User and System Temp folders"
Set-ButtonIcon "btnCleanShortcuts" "M19,3H5C3.89,3 3,3.89 3,5V19A2,2 0 0,0 5,21H19A2,2 0 0,0 21,19V5C21,3.89 20.1,3 19,3M19,19H5V5H19V19M10,17L5,12L6.41,10.59L10,14.17L17.59,6.58L19,8L10,17Z" "Fix Shortcuts" "Scans for and fixes broken .lnk shortcuts on Desktop"
Set-ButtonIcon "btnWingetScan" "M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15V18M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z" "Refresh Updates" "Checks the Winget repository for available application updates"
Set-ButtonIcon "btnWingetUpdateSel" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "Update Selected" "Updates the selected applications"
Set-ButtonIcon "btnWingetInstall" "M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z" "Install Selected" "Installs the selected applications"
Set-ButtonIcon "btnWingetUninstall" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Uninstall Selected" "Uninstalls the selected applications"
Set-ButtonIcon "btnSupportDiscord" "M19.27 5.33C17.94 4.71 16.5 4.26 15 4a.09.09 0 0 0-.07.03c-.18.33-.39.76-.53 1.09a16.09 16.09 0 0 0-4.8 0c-.14-.34-.35-.76-.54-1.09c-.01-.02-.04-.03-.07-.03c-1.5.26-2.93.71-4.27 1.33c-.01 0-.02.01-.03.02c-2.72 4.07-3.47 8.03-3.1 11.95c0 .02.01.04.03.05c1.8 1.32 3.53 2.12 5.2 2.65c.03.01.06 0 .07-.02c.4-.55.76-1.13 1.07-1.74c.02-.04 0-.08-.04-.09c-.57-.22-1.11-.48-1.64-.78c-.04-.02-.04-.08.01-.11c.11-.08.22-.17.33-.25c.02-.02.05-.02.07-.01c3.44 1.57 7.15 1.57 10.55 0c.02-.01.05-.01.07.01c.11.09.22.17.33.26c.04.03.04.09-.01.11c-.52.31-1.07.56-1.64.78c-.04.01-.05.06-.04.09c.32.61.68 1.19 1.07 1.74c.03.01.06.02.09.01c1.67-.53 3.4-1.33 5.2-2.65c.02-.01.03-.03.03-.05c.44-4.53-.73-8.46-3.1-11.95c-.01-.01-.02-.02-.04-.02z" "Join Discord" "Opens the community support Discord server"
Set-ButtonIcon "btnSupportIssue" "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" "Report Issue" "Opens the GitHub Issues page to report bugs"
Set-ButtonIcon "btnDonate" "M7,15H9C9,16.08 10.37,17 12,17C13.63,17 15,16.08 15,15C15,13.9 13.9,13.5 12,13.5C8.36,13.5 6,12.28 6,10C6,7.24 8.7,5 12,5V3H14V5C15.68,5.37 16.86,6.31 17.38,7.5H15.32C14.93,6.85 13.95,6.2 12,6.2C10.37,6.2 9,7.11 9,8.2C9,9.3 10.1,9.7 12,9.7C15.64,9.7 18,10.92 18,13.2C18,15.96 15.3,18.2 12,18.2V20H10V18.2C8.32,17.83 7.14,16.89 6.62,15.7L8.68,15Z" "Donate" "Support the project via GitHub Sponsors" "#00FF00"
Set-ButtonIcon "btnDnsGoogle" "M21.35,11.1H12.18V13.83H18.69C18.36,17.64 15.19,19.27 12.19,19.27C8.36,19.27 5,16.25 5,12C5,7.9 8.2,4.73 12.2,4.73C15.29,4.73 17.1,6.7 17.1,6.7L19,4.72C19,4.72 16.56,2 12.1,2C6.42,2 2.03,6.8 2.03,12C2.03,17.05 6.16,22 12.25,22C17.6,22 21.5,18.33 21.5,12.91C21.5,11.76 21.35,11.1 21.35,11.1V11.1Z" "Google" "Sets DNS to 8.8.8.8 & 8.8.4.4"
Set-ButtonIcon "btnDnsCloudflare" "M19.35,10.04C18.67,6.59 15.64,4 12,4C9.11,4 6.6,5.64 5.35,8.04C2.34,8.36 0,10.91 0,14A6,6 0 0,0 6,20H19A5,5 0 0,0 24,15C24,12.36 21.95,10.22 19.35,10.04Z" "Cloudflare" "Sets DNS to 1.1.1.1 & 1.0.0.1"
Set-ButtonIcon "btnDnsQuad9" "M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" "Quad9" "Sets DNS to 9.9.9.9 (Malware Blocking)"
Set-ButtonIcon "btnDnsAuto" "M12,18A6,6 0 0,1 6,12C6,11 6.25,10.03 6.7,9.2L5.24,7.74C4.46,8.97 4,10.43 4,12A8,8 0 0,0 12,20V23L16,19L12,15V18M12,4V1L8,5L12,9V6A6,6 0 0,1 18,12C18,13 17.75,13.97 17.3,14.8L18.76,16.26C19.54,15.03 20,13.57 20,12A8,8 0 0,0 12,4Z" "Auto (DHCP)" "Resets DNS settings to DHCP (Automatic)"
Set-ButtonIcon "btnHostsUpdate" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "Download AdBlock" "Updates Hosts file with AdBlocking list"
Set-ButtonIcon "btnHostsEdit" "M14.06,9L15,9.94L5.92,19H5V18.08L14.06,9M17.66,3C17.41,3 17.15,3.1 16.96,3.29L15.13,5.12L18.88,8.87L20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18.17,3.09 17.92,3 17.66,3M14.06,6.19L3,17.25V21H6.75L17.81,9.94L14.06,6.19Z" "Edit Hosts" "Opens the Hosts File Editor"
Set-ButtonIcon "btnHostsBackup" "M19,9H15V3H9V9H5L12,16L19,9Z" "Backup Hosts" "Backs up the current hosts file to Desktop"
Set-ButtonIcon "btnHostsRestore" "M13,3A9,9 0 0,0 4,12H1L4.89,15.89L4.96,16.03L9,12H6A7,7 0 0,1 13,5A7,7 0 0,1 20,12A7,7 0 0,1 13,19C11.07,19 9.32,18.21 8.06,16.94L6.64,18.36C8.27,20 10.5,21 13,21A9,9 0 0,0 22,12A9,9 0 0,0 13,3Z" "Restore Hosts" "Restores a previous hosts file backup"
Set-ButtonIcon "btnDohAuto" "M12,1L3,5V11C3,16.55 6.84,21.74 12,23C17.16,21.74 21,16.55 21,11V5L12,1M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" "Enable DoH (All)" "Enables DNS over HTTPS for all supported providers" "#00FFFF"
Set-ButtonIcon "btnDohDisable" "M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z" "Disable DoH" "Disables DNS over HTTPS" "#FF5555"
Set-ButtonIcon "btnFwRefresh" "M17.65,6.35C16.2,4.9 14.21,4 12,4A8,8 0 0,0 4,12A8,8 0 0,0 12,20C15.73,20 18.84,17.45 19.73,14H17.65C16.83,16.33 14.61,18 12,18A6,6 0 0,1 6,12A6,6 0 0,1 12,6C13.66,6 15.14,6.69 16.22,7.78L13,11H20V4L17.65,6.35Z" "Reload" "Refreshes the firewall rule list"
Set-ButtonIcon "btnFwAdd" "M19,13H13V19H11V13H5V11H11V5H13V11H19V13Z" "Add Rule" "Create a new firewall rule"
Set-ButtonIcon "btnFwEdit" "M14.06,9L15,9.94L5.92,19H5V18.08L14.06,9M17.66,3C17.41,3 17.15,3.1 16.96,3.29L15.13,5.12L18.88,8.87L20.71,7.04C21.1,6.65 21.1,6 20.71,5.63L18.37,3.29C18.17,3.09 17.92,3 17.66,3M14.06,6.19L3,17.25V21H6.75L17.81,9.94L14.06,6.19Z" "Modify" "Edit the selected firewall rule"
Set-ButtonIcon "btnFwEnable" "M10,17L6,13L7.41,11.59L10,14.17L16.59,7.58L18,9L10,17Z" "Enable" "Enable selected rule"
Set-ButtonIcon "btnFwDisable" "M12,2C17.53,2 22,6.47 22,12C22,17.53 17.53,22 12,22C6.47,22 2,17.53 2,12C2,6.47 6.47,2 12,2M15.59,7L12,10.59L8.41,7L7,8.41L10.59,12L7,15.59L8.41,17L12,13.41L15.59,17L17,15.59L13.41,12L17,8.41L15.59,7Z" "Disable" "Disable selected rule"
Set-ButtonIcon "btnFwDelete" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Delete" "Delete selected rule"
Set-ButtonIcon "btnUtilSysInfo" "M13,9H18.5L13,3.5V9M6,2H14L20,8V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V4C4,2.89 4.89,2 6,2M15,18V16H6V18H15M18,14V12H6V14H18Z" "System Info Report" "Generates a full system information report"
Set-ButtonIcon "btnUtilTrim" "M6,2H18A2,2 0 0,1 20,4V20A2,2 0 0,1 18,22H6A2,2 0 0,1 4,20V4A2,2 0 0,1 6,2M12,4A6,6 0 0,0 6,10C6,13.31 8.69,16 12,16A6,6 0 0,0 18,10C18,6.69 15.31,4 12,4M12,14A4,4 0 0,1 8,10A4,4 0 0,1 12,6A4,4 0 0,1 16,10A4,4 0 0,1 12,14Z" "Trim SSD" "Optimizes SSD performance via Trim command"
Set-ButtonIcon "btnUtilMas" "M5,20H19V18H5M19,9H15V3H9V9H5L12,16L19,9Z" "MAS Activation" "Downloads and runs Microsoft Activation Scripts"
# --- DRIVER ICONS ---
Set-ButtonIcon "btnDrvReport" "M13,9H18.5L13,3.5V9M6,2H14L20,8V20A2,2 0 0,1 18,22H6C4.89,22 4,21.1 4,20V4C4,2.89 4.89,2 6,2M15,18V16H6V18H15M18,14V12H6V14H18Z" "Generate Driver Report" "Saves a list of all installed drivers to Desktop"
Set-ButtonIcon "btnDrvGhost" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16.5L18,9.5L16.59,8.09L11,13.67L7.91,10.59L6.5,12L11,16.5Z" "Remove Ghost Devices" "Removes disconnected (ghost) PnP devices"
Set-ButtonIcon "btnDrvClean" "M19,4H15.5L14.5,3H9.5L8.5,4H5V6H19M6,19A2,2 0 0,0 8,21H16A2,2 0 0,0 18,19V7H6V19Z" "Clean Old Drivers" "Removes obsolete drivers from the Windows Driver Store"
Set-ButtonIcon "btnDrvEnableAuto" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M17,13H13V17H11V13H7V11H11V7H13V11H17V13Z" "Enable Auto Updates" "Allows Windows Update to automatically install drivers" "#00FF00"
Set-ButtonIcon "btnDrvDisableAuto" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M17,13H7V11H17V13Z" "Disable Auto Updates" "Prevents Windows Update from installing drivers automatically" "#FF3333"
Set-ButtonIcon "btnDrvEnableMeta" "M21,12C21,16.97 16.97,21 12,21C7.03,21 3,16.97 3,12C3,7.03 7.03,3 12,3C16.97,3 21,7.03 21,12M12,14A2,2 0 0,1 10,12A2,2 0 0,1 12,10A2,2 0 0,1 14,12A2,2 0 0,1 12,14Z" "Enable Metadata" "Allows Windows to download high-res icons and info for devices"
Set-ButtonIcon "btnDrvDisableMeta" "M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M15.73,14.5L14.5,15.73L12,13.23L9.5,15.73L8.27,14.5L10.77,12L8.27,9.5L9.5,8.27L12,10.77L14.5,8.27L15.73,9.5L13.23,12L15.73,14.5Z" "Disable Metadata" "Prevents Windows from downloading device metadata (icons/names) from the internet"
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

$btnHealthUpdateRepair = Get-Ctrl "btnHealthUpdateRepair"
$btnHealthServiceReset = Get-Ctrl "btnHealthServiceReset"

$btnSFC = Get-Ctrl "btnSFC"
$btnDISMCheck = Get-Ctrl "btnDISMCheck"
$btnDISMRestore = Get-Ctrl "btnDISMRestore"
$btnCHKDSK = Get-Ctrl "btnCHKDSK"

$btnNetInfo = Get-Ctrl "btnNetInfo"
$btnFlushDNS = Get-Ctrl "btnFlushDNS"
$btnResetWifi = Get-Ctrl "btnResetWifi"
$btnNetRepair = Get-Ctrl "btnNetRepair"
$btnRouteTable = Get-Ctrl "btnRouteTable"
$btnDnsGoogle = Get-Ctrl "btnDnsGoogle"
$btnDnsCloudflare = Get-Ctrl "btnDnsCloudflare"
$btnDnsQuad9 = Get-Ctrl "btnDnsQuad9"
$btnDnsAuto = Get-Ctrl "btnDnsAuto"
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
$lstFw = Get-Ctrl "lstFirewall"
$txtFwSearch = Get-Ctrl "txtFwSearch"
$lblFwStatus = Get-Ctrl "lblFwStatus"

$btnDrvReport = Get-Ctrl "btnDrvReport"
$btnDrvGhost = Get-Ctrl "btnDrvGhost"
$btnDrvClean = Get-Ctrl "btnDrvClean"
$btnDrvEnableAuto = Get-Ctrl "btnDrvEnableAuto"
$btnDrvDisableAuto = Get-Ctrl "btnDrvDisableAuto"
$btnDrvEnableMeta = Get-Ctrl "btnDrvEnableMeta"
$btnDrvDisableMeta = Get-Ctrl "btnDrvDisableMeta"

$btnCleanDisk = Get-Ctrl "btnCleanDisk"
$btnCleanTemp = Get-Ctrl "btnCleanTemp"
$btnCleanShortcuts = Get-Ctrl "btnCleanShortcuts"
$btnCleanReg = Get-Ctrl "btnCleanReg"
$btnCleanXbox = Get-Ctrl "btnCleanXbox"

$btnUtilSysInfo = Get-Ctrl "btnUtilSysInfo"
$btnUtilTrim = Get-Ctrl "btnUtilTrim"
$btnUtilMas = Get-Ctrl "btnUtilMas"
$btnUpdateRepair = Get-Ctrl "btnUpdateRepair"
$btnDotNetEnable = Get-Ctrl "btnDotNetEnable"
$btnDotNetDisable = Get-Ctrl "btnDotNetDisable"
$btnTaskManager = Get-Ctrl "btnTaskManager"
$btnInstallGpedit = Get-Ctrl "btnInstallGpedit"

$btnSupportDiscord = Get-Ctrl "btnSupportDiscord"
$btnSupportIssue = Get-Ctrl "btnSupportIssue"
$btnDonate = Get-Ctrl "btnDonate"
$btnCreditChaythonCLI = Get-Ctrl "btnCreditChaythonCLI"
$btnCreditChaythonGUI = Get-Ctrl "btnCreditChaythonGUI"

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
function Index-Button { param($BtnName, $Desc, $ParentTab) $b=Get-Ctrl $BtnName; if($b){ $SearchIndex[$Desc]=@{Button=$b;Tab=$ParentTab} } }
Index-Button "btnWingetScan" "Winget Updates" "btnTabUpdates"
Index-Button "btnSFC" "SFC Scan" "btnTabHealth"
Index-Button "btnCleanDisk" "Disk Cleanup" "btnTabCleanup"
Index-Button "btnNetRepair" "Network Repair" "btnTabNetwork"
Index-Button "btnUpdateRepair" "Update Repair" "btnTabUtils"
Index-Button "btnTaskManager" "Task Scheduler" "btnTabUtils"
Index-Button "btnInstallGpedit" "Install Group Policy" "btnTabUtils"

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

# --- WINGET (Kept in original location / Temp for performance) ---
$txtWingetSearch.Add_GotFocus({ if ($txtWingetSearch.Text -eq "Search new packages...") { $txtWingetSearch.Text="" } })
$txtWingetSearch.Add_KeyDown({ param($s, $e) if ($e.Key -eq "Return") { $btnWingetFind.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })

$btnWingetScan.Add_Click({
    $lblWingetTitle.Text = "Available Updates"
    $lblWingetStatus.Text = "Scanning..."; $lblWingetStatus.Visibility = "Visible"
    $btnWingetUpdateSel.Visibility = "Visible"; $btnWingetInstall.Visibility = "Collapsed"
    $lstWinget.Items.Clear()
    [System.Windows.Forms.Application]::DoEvents()
    $proc = Start-Process winget -ArgumentList "list --upgrade-available --accept-source-agreements" -NoNewWindow -PassThru -RedirectStandardOutput "$env:TEMP\winget_upd.txt"
    $proc.WaitForExit()
    $lines = Get-Content "$env:TEMP\winget_upd.txt"
    foreach ($line in $lines) {
        if ($line -match '^(\S.{0,30}?)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)') {
            if ($matches[1] -notmatch "Name" -and $matches[1] -notmatch "----") {
               [void]$lstWinget.Items.Add([PSCustomObject]@{ Name=$matches[1].Trim(); Id=$matches[2].Trim(); Version=$matches[3].Trim(); Available=$matches[4].Trim(); Source=$matches[5].Trim() })
            }
        }
    }
    $lblWingetStatus.Visibility = "Hidden"
    Log "Found $($lstWinget.Items.Count) updates."
})

$btnWingetFind.Add_Click({
    if ($txtWingetSearch.Text -eq "" -or $txtWingetSearch.Text -eq "Search new packages...") { return }
    $lblWingetTitle.Text = "Search Results: " + $txtWingetSearch.Text
    $lblWingetStatus.Text = "Searching..."; $lblWingetStatus.Visibility = "Visible"
    $btnWingetUpdateSel.Visibility = "Collapsed"; $btnWingetInstall.Visibility = "Visible"
    $lstWinget.Items.Clear()
    [System.Windows.Forms.Application]::DoEvents()
    $proc = Start-Process winget ... -RedirectStandardOutput $null -NoNewWindow -PassThru
    $proc.WaitForExit()
    $lines = winget search "$($txtWingetSearch.Text)" --accept-source-agreements
    foreach ($line in $lines) {
        if ($line -match '^(\S.{0,35}?)\s{2,}(\S+)\s{2,}(\S+)') {
            if ($matches[1] -notmatch "Name" -and $matches[1] -notmatch "----") {
                 [void]$lstWinget.Items.Add([PSCustomObject]@{ Name=$matches[1].Trim(); Id=$matches[2].Trim(); Version=$matches[3].Trim(); Available="-"; Source="winget" })
            }
        }
    }
    $lblWingetStatus.Visibility = "Hidden"
})

$btnWingetUpdateSel.Add_Click({ foreach ($item in $lstWinget.SelectedItems) { Run-Cmd { winget upgrade --id $item.Id --accept-package-agreements --accept-source-agreements } "Updating $($item.Name)..." }; $btnWingetScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) })
$btnWingetInstall.Add_Click({ foreach ($item in $lstWinget.SelectedItems) { Run-Cmd { winget install --id $item.Id --accept-package-agreements --accept-source-agreements } "Installing $($item.Name)..." } })
$btnWingetUninstall.Add_Click({ if ($lstWinget.SelectedItems.Count -gt 0) { if ([System.Windows.Forms.MessageBox]::Show("Uninstall selected?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo) -eq "Yes") { foreach ($item in $lstWinget.SelectedItems) { Run-Cmd { winget uninstall --id $item.Id } "Uninstalling $($item.Name)..." }; $btnWingetScan.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } } })

# --- NETWORK ---
$btnNetInfo.Add_Click({ Run-Cmd { ipconfig /all } })
$btnFlushDNS.Add_Click({ Run-Cmd { ipconfig /flushdns } })
# Restart Wi-Fi (Ported from CLI Invoke-Choice7)
$btnResetWifi.Add_Click({
    Run-Cmd {
        Write-Output "Searching for Wi-Fi adapters..."
        
        # CLI Logic: Search by InterfaceDescription (covers adapters not named "Wi-Fi")
        $adapters = Get-NetAdapter | Where-Object { 
            $_.InterfaceDescription -match "Wi-Fi|Wireless" -and 
            ($_.Status -eq "Up" -or $_.Status -eq "Disabled") 
        }

        if (-not $adapters) {
            Write-Output "No Wi-Fi adapters found."
            return
        }

        foreach ($adapter in $adapters) {
            Write-Output "Restarting: $($adapter.Name)..."
            
            # Explicit Disable -> Wait -> Enable cycle is more reliable than Restart-NetAdapter
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            
            # Verification
            Start-Sleep -Seconds 4
            $status = Get-NetAdapter -Name $adapter.Name
            if ($status.Status -eq "Up") {
                Write-Output " -> SUCCESS: Back Online"
            } else {
                Write-Output " -> WARNING: Adapter is $($status.Status)"
            }
        }
    } "Restarting Wireless Adapters..."
})
$btnNetRepair.Add_Click({ Start-NetRepair })

$btnRouteTable.Add_Click({ 
    Run-Cmd { 
        $outFile = Join-Path $script:DataDir "RouteTable.txt"
        route print > $outFile
        Write-Output "Route table saved to: $outFile" 
    } 
})

$btnDnsGoogle.Add_Click({ Run-Cmd { Get-NetAdapter | Where Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses ("8.8.8.8","8.8.4.4") } "Google DNS Set" })
$btnDnsCloudflare.Add_Click({ Run-Cmd { Get-NetAdapter | Where Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses ("1.1.1.1","1.0.0.1") } "Cloudflare DNS Set" })
$btnDnsQuad9.Add_Click({ Run-Cmd { Get-NetAdapter | Where Status -eq 'Up' | Set-DnsClientServerAddress -ServerAddresses ("9.9.9.9","149.112.112.112") } "Quad9 DNS Set" })
$btnDnsAuto.Add_Click({ Run-Cmd { Get-NetAdapter | Where Status -eq 'Up' | Set-DnsClientServerAddress -ResetServerAddresses } "DNS Reset to Auto" })

$btnDohAuto.Add_Click({ Run-Cmd { $Providers = @{"8.8.8.8"="https://dns.google/dns-query";"8.8.4.4"="https://dns.google/dns-query";"1.1.1.1"="https://cloudflare-dns.com/dns-query";"1.0.0.1"="https://cloudflare-dns.com/dns-query";"9.9.9.9"="https://dns.quad9.net/dns-query";"149.112.112.112"="https://dns.quad9.net/dns-query"}; foreach ($p in $Providers.Keys) { Invoke-Expression "netsh dns add encryption server=$p dohtemplate=$($Providers[$p]) autoupgrade=yes udpfallback=no" | Out-Null } } "Applied DoH Templates" })
$btnDohDisable.Add_Click({ Run-Cmd { $KnownIPs = @("8.8.8.8","8.8.4.4","1.1.1.1","1.0.0.1","9.9.9.9","149.112.112.112"); foreach ($ip in $KnownIPs) { Invoke-Expression "netsh dns delete encryption server=$ip" | Out-Null } } "DoH Disabled" })

# --- FIREWALL ---
$AllFw = @()
$btnFwRefresh.Add_Click({
    $lblFwStatus.Visibility="Visible"; $lstFw.Items.Clear(); [System.Windows.Forms.Application]::DoEvents()
    $AllFw = Get-NetFirewallRule | Select Name, DisplayName, @{N='Enabled';E={$_.Enabled.ToString()}}, Direction, @{N='Action';E={$_.Action.ToString()}}, @{N='Protocol';E={($_.GetNetworkProtocols().Protocol)}}, @{N='LocalPort';E={($_.GetNetworkProtocols().LocalPort)}}
    $AllFw | % { [void]$lstFw.Items.Add($_) }
    $lblFwStatus.Visibility="Collapsed"
})
$txtFwSearch.Add_TextChanged({ $q=$txtFwSearch.Text; $lstFw.Items.Clear(); if($q -ne "Search Rules..." -and $q){ $AllFw | ?{$_.DisplayName -match $q -or $_.LocalPort -match $q} | %{ [void]$lstFw.Items.Add($_) } }else{ $AllFw | %{ [void]$lstFw.Items.Add($_) } } })
$txtFwSearch.Add_GotFocus({ $t=$txtFwSearch; if($t.Text -eq "Search Rules..."){$t.Text=""} })
$btnFwAdd.Add_Click({ $d=Show-RuleDialog "Add Rule"; if($d){ try{New-NetFirewallRule -DisplayName $d.Name -Direction $d.Direction -Action $d.Action -Protocol $d.Protocol -LocalPort $d.Port -ErrorAction Stop; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))}catch{[System.Windows.MessageBox]::Show("Err: $_")} } })
$btnFwEdit.Add_Click({ if($lstFw.SelectedItem){ $d=Show-RuleDialog "Edit" $lstFw.SelectedItem; if($d){ try{Set-NetFirewallRule -Name $lstFw.SelectedItem.Name -Direction $d.Direction -Action $d.Action -Protocol $d.Protocol -LocalPort $d.Port; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent)))}catch{[System.Windows.MessageBox]::Show("Err: $_")} } } })
$btnFwEnable.Add_Click({ if($lstFw.SelectedItem){ Set-NetFirewallRule -Name $lstFw.SelectedItem.Name -Enabled True; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })
$btnFwDisable.Add_Click({ if($lstFw.SelectedItem){ Set-NetFirewallRule -Name $lstFw.SelectedItem.Name -Enabled False; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })
$btnFwDelete.Add_Click({ if($lstFw.SelectedItem){ Remove-NetFirewallRule -Name $lstFw.SelectedItem.Name; $btnFwRefresh.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) } })

# --- CLEANUP & UTIL ---
$btnHostsEdit.Add_Click({ Show-HostsEditor })
$btnHostsBackup.Add_Click({ 
    Run-Cmd { 
        $bkFile = Join-Path $script:DataDir "hosts_bk.bak"
        Copy-Item "$env:windir\System32\drivers\etc\hosts" $bkFile -Force
        Write-Output "Backup saved to: $bkFile" 
    } 
})

$btnHostsRestore.Add_Click({ 
    $o=New-Object System.Windows.Forms.OpenFileDialog
    $o.Filter="*.bak|*.bak"
    # Set initial directory to our data folder for convenience
    $o.InitialDirectory = $script:DataDir
    
    if($o.ShowDialog()-eq"OK"){
        Run-Cmd{Copy-Item $o.FileName "$env:windir\System32\drivers\etc\hosts" -Force} "Restored."
    } 
})

$btnSupportDiscord.Add_Click({ Start-Process "https://discord.gg/bCQqKHGxja" })
$btnSupportIssue.Add_Click({ Start-Process "https://github.com/ios12checker/Windows-Maintenance-Tool/issues/new/choose" })
$btnCreditChaythonCLI.Add_Click({ Start-Process "https://github.com/Chaython" })
$btnCreditChaythonGUI.Add_Click({ Start-Process "https://github.com/Chaython" })
$btnDonate.Add_Click({ Start-Process "https://github.com/sponsors/Chaython" })

# --- SYSTEM HEALTH TOOLS (Restored & Improved) ---

# 1. SFC (System File Checker)
$btnSFC.Add_Click({
    # Runs in new window to allow interaction and visible progress
    Start-Process cmd.exe -ArgumentList "/k sfc /scannow"
})

# 2. DISM CheckHealth (Restored from CLI Invoke-Choice3)
$btnDISMCheck.Add_Click({
    Run-Cmd {
        Write-Output "Running DISM CheckHealth..."
        dism /online /cleanup-image /checkhealth
    } "Checking Windows Component Store Health..."
})

# 3. DISM RestoreHealth (Restored from CLI Invoke-Choice4)
$btnDISMRestore.Add_Click({
    Run-Cmd {
        Write-Output "Running DISM RestoreHealth (This may take a while)..."
        dism /online /cleanup-image /restorehealth
    } "Restoring Windows Component Store Health..."
})

# 4. CHKDSK with Disk Selection (Restored functionality + Selection)
$btnCHKDSK.Add_Click({
    # Helper to pick a drive
    $f = New-Object System.Windows.Forms.Form
    $f.Text = "Select Drive"
    $f.Size = "300, 150"
    $f.StartPosition = "CenterScreen"
    $f.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#1E1E1E")
    $f.ForeColor = "White"

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = "Select a drive to scan:"
    $lbl.Location = "20, 20"
    $lbl.AutoSize = $true
    $f.Controls.Add($lbl)

    $cb = New-Object System.Windows.Forms.ComboBox
    $cb.Location = "20, 50"
    $cb.Width = 240
    $cb.DropDownStyle = "DropDownList"
    $cb.BackColor = [System.Drawing.ColorTranslator]::FromHtml("#333")
    $cb.ForeColor = "White"
    
    # Populate drives
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $null -ne $_.Free }
    foreach ($d in $drives) { [void]$cb.Items.Add("$($d.Name):") }
    if ($cb.Items.Count -gt 0) { $cb.SelectedIndex = 0 }
    $f.Controls.Add($cb)

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = "Scan"
    $btn.Location = "180, 80"
    $btn.DialogResult = "OK"
    $btn.BackColor = "SeaGreen"
    $btn.ForeColor = "White"
    $btn.FlatStyle = "Flat"
    $f.Controls.Add($btn)
    $f.AcceptButton = $btn

    if ($f.ShowDialog() -eq "OK") {
        $selectedDrive = $cb.SelectedItem
        # We run CHKDSK in a separate CMD window because it often requires 
        # interactive Y/N input for scheduling on reboot (for C: drive).
        Start-Process cmd.exe -ArgumentList "/k chkdsk $selectedDrive /f /r /x"
    }
})
# --- WINDOWS UPDATE REPAIR LOGIC ---

# Option 21: Full Update Repair
# Note: This reuses the robust Start-UpdateRepair function we updated earlier.
$btnHealthUpdateRepair.Add_Click({
    # Call the helper function defined at the top of the script
    Start-UpdateRepair
})

# Option 23: Service Reset Only (Lighter version)
$btnHealthServiceReset.Add_Click({
    Run-Cmd {
        Write-Output "Stopping Windows Update Services..."
        Stop-Service -Name wuauserv, cryptsvc, bits -Force -ErrorAction SilentlyContinue
        
        Write-Output "Starting Services..."
        Start-Service -Name appidsvc, wuauserv, cryptsvc, bits -ErrorAction SilentlyContinue
        
        Write-Output "Update services have been restarted."
    } "Resetting Update Services..."
})
$btnCleanDisk.Add_Click({ Start-Process cleanmgr })
$btnCleanReg.Add_Click({ Start-RegClean })
$btnCleanXbox.Add_Click({ Start-XboxClean })
$btnUpdateRepair.Add_Click({ Start-UpdateRepair })
$btnDotNetEnable.Add_Click({ [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", "LatestMajor", "Machine"); Run-Cmd { "Set DOTNET_ROLL_FORWARD = LatestMajor" } })
$btnDotNetDisable.Add_Click({ [System.Environment]::SetEnvironmentVariable("DOTNET_ROLL_FORWARD", $null, "Machine"); Run-Cmd { "Removed DOTNET_ROLL_FORWARD" } })
$btnTaskManager.Add_Click({ Show-TaskManager })
$btnInstallGpedit.Add_Click({ Start-GpeditInstall })

# ==========================================
# MISSING LOGIC RESTORED
# ==========================================

# 1. System Info Report (Ported from CLI Invoke-Choice22)
$btnUtilSysInfo.Add_Click({
    Run-Cmd {
        # Create timestamped folder on Desktop
        $timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
        $reportDirName = "SystemReports_$timestamp"
        
        # Save to DataDir
        $outpath = Join-Path $script:DataDir $reportDirName
        
        if (-not (Test-Path $outpath)) { 
            New-Item -Path $outpath -ItemType Directory | Out-Null 
        }
        
        $datestr = Get-Date -Format "yyyy-MM-dd"
        $sysFile = Join-Path $outpath "System_Info_$datestr.txt"
        $netFile = Join-Path $outpath "Network_Info_$datestr.txt"
        $drvFile = Join-Path $outpath "Driver_List_$datestr.txt"

        Write-Output "Generating separated reports in:`n$outpath"

        # 1. System Info
        Write-Output " -> Writing System Info (systeminfo)..."
        systeminfo | Out-File -FilePath $sysFile -Encoding UTF8

        # 2. Network Info
        Write-Output " -> Writing Network Info (ipconfig)..."
        ipconfig /all | Out-File -FilePath $netFile -Encoding UTF8

        # 3. Driver List
        Write-Output " -> Writing Driver List (driverquery)..."
        driverquery | Out-File -FilePath $drvFile -Encoding UTF8

        # Open the folder for the user
        Invoke-Item $outpath
        Write-Output "Done. Report folder opened."

    } "Generating Full System Reports..."
})

# 2. Trim SSD (Ported from CLI Invoke-Choice14)
$btnUtilTrim.Add_Click({
    Run-Cmd {
        Write-Output "Identifying SSDs..."
        
        # 1. Detect SSDs
        $ssds = Get-PhysicalDisk | Where-Object MediaType -eq 'SSD'
        if (-not $ssds) {
            Write-Output "No SSDs detected."
            return
        }

        # 2. Setup Log
        $logName = "SSD_OPTIMIZE_$(Get-Date -f 'yyyy-MM-dd_HHmmss').log"
        $logPath = Join-Path $script:DataDir $logName
        
        $logContent = @()
        $logContent += "SSD Optimize Log - $(Get-Date)"
        $logContent += "--------------------------------"

        # 3. Iterate and Optimize
        foreach ($ssd in $ssds) {
            Write-Output "Found SSD: $($ssd.FriendlyName)"
            
            $disk = Get-Disk | Where-Object { $_.FriendlyName -eq $ssd.FriendlyName }
            if ($disk) {
                # Get volumes with drive letters on this specific SSD
                $volumes = $disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null
                
                foreach ($vol in $volumes) {
                    $msg = "Optimizing Volume $($vol.DriveLetter): on $($ssd.FriendlyName)..."
                    Write-Output $msg
                    $logContent += $msg
                    
                    try {
                        # Capture Verbose output (Stream 4) for the log file
                        $result = Optimize-Volume -DriveLetter ($vol.DriveLetter) -ReTrim -Verbose 4>&1 | Out-String
                        $logContent += $result
                        Write-Output " -> Optimization command sent."
                    } catch {
                        $err = " -> Error: $($_.Exception.Message)"
                        Write-Output $err
                        $logContent += $err
                    }
                }
            } else {
                $err = "Could not map PhysicalDisk to Logical Disk for: $($ssd.FriendlyName)"
                Write-Output $err
                $logContent += $err
            }
        }

        # 4. Save Log
        $logContent | Out-File -FilePath $logPath -Encoding UTF8
        Write-Output "Detailed log saved to: $logPath"

    } "Optimizing SSDs (ReTrim)..."
})

# MAS Activation (Ported from CLI Invoke-Choice27)
$btnUtilMas.Add_Click({
    # Safety Prompt
    $msg = "IMPORTANT WARNING!`n`nThis tool will download and execute the Microsoft Activation Script (MAS) from massgrave.dev.`n`nI did NOT create or host this script. You are fully responsible for using MAS.`n`nDo you want to proceed?"
    
    $res = [System.Windows.MessageBox]::Show(
        $msg, 
        "Third-Party Script Warning", 
        [System.Windows.MessageBoxButton]::YesNo, 
        [System.Windows.MessageBoxImage]::Warning
    )
    
    if ($res -eq "Yes") {
        # Log to the GUI text box
        Log-ToGui "User accepted MAS warning. Downloading and running activation script..."
        
        # Runs in a separate window because MAS is an interactive text-based UI
        Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "& {irm https://get.activated.win | iex}"
    } else {
        # Log cancellation to the GUI text box
        Log-ToGui "Cancelled Massgrave activation."
    }
})

# 4. Smart Shortcut Fixer (Ported from CLI Invoke-Choice16)
$btnCleanShortcuts.Add_Click({
    Run-Cmd {
        $sh = New-Object -ComObject WScript.Shell
        # Paths to scan
        $paths = @(
            "C:\ProgramData\Microsoft\Windows\Start Menu",
            "$env:APPDATA\Microsoft\Windows\Start Menu",
            "$env:USERPROFILE\Desktop",
            "C:\Users\Public\Desktop"
        )
        $systemShortcuts = @("File Explorer.lnk", "Run.lnk", "Recycle Bin.lnk", "Control Panel.lnk")
        
        $fixed = 0; $deleted = 0

        foreach ($p in $paths) {
            if (-not (Test-Path $p)) { continue }
            $files = Get-ChildItem $p -Filter "*.lnk" -Recurse -ErrorAction SilentlyContinue
            
            foreach ($file in $files) {
                if ($systemShortcuts -contains $file.Name) { continue }
                
                try {
                    $shortcut = $sh.CreateShortcut($file.FullName)
                    $target = $shortcut.TargetPath
                    
                    # Skip special system targets (CLSID, shell:)
                    if ($target -match '^shell:' -or $target -match '^\s*::{') { continue }

                    # Check if broken
                    if ($target -and -not (Test-Path $target)) {
                        Write-Output "Broken: $($file.Name)"
                        
                        # Smart Fix: Look for the exe in the same parent directory
                        $installFolder = Split-Path $target -Parent
                        $exeName = Split-Path $target -Leaf
                        
                        # Try to find the file elsewhere in the install folder
                        $candidate = $null
                        if (Test-Path $installFolder) {
                            $found = Get-ChildItem -Path $installFolder -Filter $exeName -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                            if ($found) { $candidate = $found.FullName }
                        }

                        if ($candidate) {
                            $shortcut.TargetPath = $candidate
                            $shortcut.Save()
                            Write-Output " -> FIXED: Updated to $candidate"
                            $fixed++
                        } else {
                            Remove-Item $file.FullName -Force
                            Write-Output " -> DELETED: Target not found."
                            $deleted++
                        }
                    }
                } catch {}
            }
        }
        Write-Output "`nScan Complete. Fixed: $fixed, Deleted: $deleted"
    } "Scanning and repairing shortcuts..."
})

# 5. Generate Driver Report
$btnDrvReport.Add_Click({
    Run-Cmd {
        $path = Join-Path $script:DataDir "DriverReport.csv"
        Get-WindowsDriver -Online | Select-Object ProviderName, Date, Version, ClassName, OriginalFileName | Export-Csv $path -NoTypeInformation
        Write-Output "Driver report saved to: $path"
    } "Exporting drivers..."
})

# 6. Download AdBlock (Hosts Update)
$btnHostsUpdate.Add_Click({
    Run-Cmd {
        $hostsPath = "$env:windir\System32\drivers\etc\hosts"
        # Save Backups to DataDir
        $backupDir = Join-Path $script:DataDir "HostsBackups"
        
        $maxRetries = 3
        $retryDelay = 2 

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
                Write-Output "Created backup directory: $backupDir"
            }

            # ===== CREATE BACKUP =====
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $uniqueBackupPath = "$backupDir\hosts_$timestamp.bak"
            
            if (Test-Path $hostsPath) {
                Write-Output "Creating backup..."
                try {
                    Copy-Item $hostsPath $uniqueBackupPath -Force
                    Write-Output "Backup created: $uniqueBackupPath"
                } catch {
                    Write-Output "Warning: Backup failed - $($_.Exception.Message)"
                    $uniqueBackupPath = $null
                }
            } else {
                Write-Output "No existing hosts file found - creating new."
                $uniqueBackupPath = $null
            }

            # ===== DOWNLOAD WITH MIRROR FALLBACK =====
            $adBlockContent = $null
            $successfulMirror = $null

            foreach ($mirror in $mirrors) {
                Write-Output "Attempting download from: $mirror"
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    $webClient = New-Object System.Net.WebClient
                    $adBlockContent = $webClient.DownloadString($mirror)
                    $successfulMirror = $mirror
                    Write-Output "Download successful."
                    break
                } catch {
                    Write-Output "Download failed: $($_.Exception.Message)"
                    continue
                } finally {
                    if ($null -ne $webClient) { $webClient.Dispose() }
                }
            }

            if (-not $adBlockContent) { throw "All mirrors failed!" }

            # ===== PREPARE NEW CONTENT (Preserve Custom Entries) =====
            $userCustomEntries = ""
            $customSectionStart = "# === BEGIN USER CUSTOM ENTRIES ==="
            $customSectionEnd = "# === END USER CUSTOM ENTRIES ==="
            
            if (Test-Path $hostsPath) {
                try {
                    $currentContent = Get-Content $hostsPath -Raw
                    if ($currentContent -match "(?ms)$([regex]::Escape($customSectionStart))\r?\n(.*?)\r?\n$([regex]::Escape($customSectionEnd))") {
                        $userCustomEntries = $matches[1]
                    }
                } catch { Write-Output "Note: Could not read existing custom entries." }
            }

            if ([string]::IsNullOrWhiteSpace($userCustomEntries)) {
                $userCustomEntries = "# Add your custom host entries below this line`n# 192.168.1.100    myserver.local"
            }

            $defaultContent = "# Microsoft Corp Standard Hosts Header`n127.0.0.1       localhost`n::1             localhost"

            $newContent = "$defaultContent`n`n$customSectionStart`n$userCustomEntries`n$customSectionEnd`n`n# Ad-blocking entries - Updated $(Get-Date)`n# Source: $successfulMirror`n`n$adBlockContent"

            # ===== UPDATE HOSTS FILE (CMD Method) =====
            Write-Output "Writing new hosts file..."
            $attempt = 0
            $success = $false
            
            while (-not $success -and $attempt -lt $maxRetries) {
                $attempt++
                try {
                    $tempFile = [System.IO.Path]::GetTempFileName()
                    [System.IO.File]::WriteAllText($tempFile, $newContent, [System.Text.Encoding]::UTF8)
                    
                    $tempDest = "$hostsPath.tmp"
                    $copyCommand = "@echo off`nif exist `"$hostsPath`" move /Y `"$hostsPath`" `"$tempDest`"`nmove /Y `"$tempFile`" `"$hostsPath`"`nif exist `"$tempDest`" del /F /Q `"$tempDest`""
                    
                    $batchFile = [System.IO.Path]::GetTempFileName() + ".cmd"
                    [System.IO.File]::WriteAllText($batchFile, $copyCommand)
                    
                    Start-Process "cmd.exe" -ArgumentList "/c `"$batchFile`"" -Wait -WindowStyle Hidden
                    Remove-Item $batchFile -Force
                    if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                    
                    $success = $true
                    $entryCount = ($adBlockContent -split "`n").Count
                    Write-Output "Success! Added $entryCount ad-blocking entries."
                } catch {
                    Write-Output "Attempt $attempt failed. Retrying..."
                    Start-Sleep -Seconds $retryDelay
                }
            }

            if (-not $success) { throw "Failed to write file after $maxRetries attempts." }

            # ===== FLUSH DNS =====
            ipconfig /flushdns | Out-Null
            Write-Output "DNS Cache Flushed."

            # ===== CLEAN UP OLD BACKUPS (GUI PROMPT) =====
            if ($success) {
                $allBackups = Get-ChildItem -Path $backupDir -Filter "hosts_*.bak"
                if ($allBackups.Count -gt 5) {
                    $msg = "Hosts update successful!`n`nYou have $($allBackups.Count) backups in: $backupDir`n`nDo you want to delete old backups to save space?"
                    $res = [System.Windows.Forms.MessageBox]::Show($msg, "Cleanup Backups", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxImage]::Question)
                    
                    if ($res -eq "Yes") {
                        $allBackups | ForEach-Object { Remove-Item $_.FullName -Force }
                        Write-Output "Old backups deleted."
                    }
                }
            }

        } catch {
            Write-Output "ERROR: $($_.Exception.Message)"
            # Restore logic
            if ($uniqueBackupPath -and (Test-Path $uniqueBackupPath)) {
                Write-Output "Restoring backup..."
                Copy-Item $uniqueBackupPath $hostsPath -Force
                Write-Output "Restored."
            }
        }
    } "Updating Hosts File (AdBlock)..."
})

# 7. Clean Temp & Privacy (Ported from CLI Invoke-Choice12)
$btnCleanTemp.Add_Click({
    Run-Cmd {
        # Standard Temp Files
        $folders = @("$env:TEMP", "$env:windir\Temp")
        foreach ($f in $folders) {
            Get-ChildItem -Path $f -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Output "Standard temporary files deleted."

        # Privacy Cleanup (Registry & Logs)
        Write-Output "Performing Privacy Cleanup..."
        
        # UserAssist (Activity History)
        try { reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f | Out-Null; Write-Output "- Cleared UserAssist (Activity History)" } catch {}
        
        # Recent Docs
        try { 
            [System.Environment]::SetEnvironmentVariable("Process", "LocationNotificationWindows", "Process") # Dummy var
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f | Out-Null
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse -ErrorAction SilentlyContinue
            Write-Output "- Cleared Recent Documents" 
        } catch {}

        # Thumbnail Cache
        try { Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue; Write-Output "- Cleared Thumbnail Cache" } catch {}

        # Diag Data
        try { wevtutil cl Microsoft-Windows-Diagnostics-Performance/Operational; Write-Output "- Cleared Diagnostic Logs" } catch {}

    } "Cleaning Temp Files & Privacy Data..."
})
# 8. Clean Old Drivers (With Backup & Restore Logic)
$btnDrvClean.Add_Click({
    Run-Cmd {
        Write-Output "Scanning Driver Store (Fast Mode)..."
        
        # 1. Capture pnputil output (Instant)
        $rawOutput = pnputil.exe /enum-drivers 2>&1
        
        $drivers = @()
        $current = $null

        # 2. Parse Text - Robust Regex Strategy
        foreach ($line in $rawOutput) {
            $line = $line.ToString().Trim()
            
            # Detect Start of Block: "Published Name: oemXX.inf"
            if ($line -match ':\s*(oem\d+\.inf)$') {
                if ($current) { $drivers += [PSCustomObject]$current }
                $current = [ordered]@{ 
                    PublishedName = $matches[1]; 
                    OriginalName = $null; 
                    Provider = "Unknown"; 
                    Version = [Version]"0.0.0.0"; 
                    Date = [DateTime]::MinValue 
                }
            }
            # Detect Original Name: "Original Name: driver.inf"
            elseif ($current -and $line -match ':\s*([\w\-\.]+\.inf)$') {
                $val = $matches[1]
                if ($val -notmatch '^oem\d+\.inf$') {
                    $current.OriginalName = $val
                }
            }
            # Detect Version
            elseif ($current -and $line -match ':\s*(\d{1,5}(\.\d{1,5}){1,3})$') {
                try { $current.Version = [Version]$matches[1] } catch {}
            }
            # Detect Provider
            elseif ($current -and $line -match 'Provider.*:\s+(.+)$') {
                $current.Provider = $matches[1]
            }
            # Detect Date
            elseif ($current -and $line -match 'Date.*:\s+(\d{1,2}[/\.-]\d{1,2}[/\.-]\d{2,4})') {
                try { $current.Date = [DateTime]$matches[1] } catch {}
            }
        }
        if ($current) { $drivers += [PSCustomObject]$current }

        # 3. Group and Analyze
        $grouped = $drivers | Where-Object { $_.OriginalName } | Group-Object OriginalName
        $toDelete = @()

        foreach ($group in $grouped) {
            if ($group.Count -gt 1) {
                # Sort: Newest Date first, then Highest Version
                $sorted = $group.Group | Sort-Object Date, Version -Descending
                # Keep top 1, delete the rest
                $old = $sorted | Select-Object -Skip 1
                $toDelete += $old
            }
        }

        if ($toDelete.Count -eq 0) {
            Write-Output "Driver store is optimized. No redundant drivers found."
            return
        }

        # 4. User Prompt
        $count = $toDelete.Count
        $msg = "Found $count old driver versions.`n`nThese are old versions of drivers you currently have installed.`n`nBack up drivers to Desktop before cleaning?"
        
        $res = [System.Windows.Forms.MessageBox]::Show($msg, "Driver Cleanup", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Question)

        if ($res -eq "Cancel") { Write-Output "Cancelled."; return }

        # 5. Backup (To DataDir)
        if ($res -eq "Yes") {
            $bkFolderName = "Drivers_Backup_" + (Get-Date -f 'yyyyMMdd_HHmm')
            # Save backup to DataDir
            $bkPath = Join-Path $script:DataDir $bkFolderName

            Write-Output "Backing up to: $bkPath"
            New-Item -Path $bkPath -ItemType Directory -Force | Out-Null
            
            $proc = Start-Process pnputil -ArgumentList "/export-driver * `"$bkPath`"" -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -ne 0) { 
                Write-Output "Backup failed. Aborting."
                [System.Windows.Forms.MessageBox]::Show("Backup failed. Cleanup aborted.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                return 
            }
            Write-Output "Backup Complete."
        }

        # 6. Delete Execution
        Write-Output "`n--- Deleting $count Old Drivers ---"
        $deleted = 0
        $failed = 0

        foreach ($item in $toDelete) {
            $info = "$($item.OriginalName) (v$($item.Version))"
            Write-Output "Removing: $info..."
            
            $proc = Start-Process pnputil -ArgumentList "/delete-driver $($item.PublishedName) /uninstall /force" -NoNewWindow -Wait -PassThru
            
            if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                Write-Output " -> SUCCESS"
                $deleted++
            } else {
                Write-Output " -> FAILED (In Use or Locked)"
                $failed++
            }
        }

        Write-Output "`nDone. Deleted: $deleted | Failed: $failed"
        
    } "Cleaning Driver Store..."
})

# --- NEW DRIVER BUTTONS ---

$btnDrvDisableAuto.Add_Click({
    Run-Cmd {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0
        
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (-not (Test-Path $policyPath)) { New-Item -Path $policyPath -Force | Out-Null }
        Set-ItemProperty -Path $policyPath -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord
        
        Write-Output "Automatic Driver Updates: DISABLED"
    } "Disabling Auto Driver Updates..."
})

$btnDrvEnableAuto.Add_Click({
    Run-Cmd {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 1
        
        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Test-Path $policyPath) {
            Remove-ItemProperty -Path $policyPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
        }
        
        Write-Output "Automatic Driver Updates: ENABLED"
    } "Enabling Auto Driver Updates..."
})

$btnDrvDisableMeta.Add_Click({
    Run-Cmd {
        $metaPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"
        if (-not (Test-Path $metaPath)) { New-Item -Path $metaPath -Force | Out-Null }
        Set-ItemProperty -Path $metaPath -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord
        Write-Output "Device Metadata Downloads: DISABLED"
    } "Disabling Device Metadata..."
})

$btnDrvEnableMeta.Add_Click({
    Run-Cmd {
        $metaPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata"
        if (-not (Test-Path $metaPath)) { New-Item -Path $metaPath -Force | Out-Null }
        Set-ItemProperty -Path $metaPath -Name "PreventDeviceMetadataFromNetwork" -Value 0 -Type DWord
        Write-Output "Device Metadata Downloads: ENABLED"
    } "Enabling Device Metadata..."
})

# 9. Ghost Devices (Ported from CLI Invoke-Choice20 - Option 2)
$btnDrvGhost.Add_Click({
    Run-Cmd {
        Write-Output "Scanning for 'Unknown' (Ghost) devices..."
        $hiddenDevices = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Unknown' }
        
        if ($hiddenDevices) {
            $count = $hiddenDevices.Count
            Write-Output "Found $count ghost device(s). Removing..."
            foreach ($device in $hiddenDevices) {
                Write-Output "Removing: $($device.FriendlyName) ($($device.InstanceId))"
                pnputil /remove-device $device.InstanceId | Out-Null
            }
            Write-Output "All ghost devices removed."
        } else {
            Write-Output "No ghost devices found."
        }
    } "Removing Ghost Devices..."
})


# --- LAUNCH ---
Check-ForUpdate
$window.Add_Loaded({ (Get-Ctrl "btnTabUpdates").RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Button]::ClickEvent))) })
$window.ShowDialog() | Out-Null
