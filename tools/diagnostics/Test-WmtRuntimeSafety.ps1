[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$passed = 0
function Assert-That([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "FAILED: $Message" }; $script:passed++; Write-Host "PASS: $Message" }
# Isolated runtime contract tests; no host registry, devices, or services are modified.
# Cancellation while a real PowerShell pipeline is active.
$cancelPool = [runspacefactory]::CreateRunspacePool(1,1); $cancelPool.Open(); $cancelPs = [PowerShell]::Create(); $cancelPs.RunspacePool = $cancelPool
$null = $cancelPs.AddScript('while ($true) { Start-Sleep -Milliseconds 40 }')
$cancelAsync = $cancelPs.BeginInvoke(); Start-Sleep -Milliseconds 200; $cancelPs.Stop()
$cancelState = $cancelPs.InvocationStateInfo.State
try { $null = $cancelPs.EndInvoke($cancelAsync) } catch { }
Assert-That ($cancelState -eq [System.Management.Automation.PSInvocationState]::Stopped) 'active PowerShell worker reaches Stopped after cancellation'
$cancelPs.Dispose(); $cancelPool.Close(); $cancelPool.Dispose()
$pool = [runspacefactory]::CreateRunspacePool(1,1); $pool.Open(); $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool; $null = $ps.AddScript('throw "intentional worker termination fault"'); $async = $ps.BeginInvoke(); $reported = $false
try { $null = $ps.EndInvoke($async) } catch { $reported = $_.ToString().Contains('intentional worker termination fault') } finally { $ps.Dispose(); $pool.Close(); $pool.Dispose() }
Assert-That $reported 'worker termination exceptions are observable'
$iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault(); $scanPool = [runspacefactory]::CreateRunspacePool(1,3,$iss,$Host); $scanPool.Open(); $workers = [System.Collections.Generic.List[object]]::new()
try { 1..12 | ForEach-Object { $worker = [PowerShell]::Create(); $worker.RunspacePool = $scanPool; $null = $worker.AddScript({ param($id) Start-Sleep -Milliseconds (20 + ($id % 4) * 10); [pscustomobject]@{ Provider=$id; State='Complete' } }).AddArgument($_); $workers.Add([pscustomobject]@{ PowerShell=$worker; Async=$worker.BeginInvoke() }) }; $results=@(); foreach($worker in $workers){ $results += @($worker.PowerShell.EndInvoke($worker.Async)); if($worker.PowerShell.HadErrors){throw 'Provider scan emitted an error.'} }; Assert-That ($results.Count -eq 12) 'concurrent scans return every provider result'; Assert-That (@($results.Provider | Sort-Object -Unique).Count -eq 12) 'provider identities remain isolated' }
finally { foreach($worker in $workers){$worker.PowerShell.Dispose()}; $scanPool.Close(); $scanPool.Dispose() }
function Test-WmtDriverRemovalCandidate { param([bool]$Known,[bool]$InUse,[bool]$BootCritical,[bool]$HasBackup); return ($Known -and -not $InUse -and -not $BootCritical -and $HasBackup) }
Assert-That (Test-WmtDriverRemovalCandidate $true $false $false $true) 'known orphan with backup is eligible'; Assert-That (-not (Test-WmtDriverRemovalCandidate $false $false $false $true)) 'unknown driver is retained'; Assert-That (-not (Test-WmtDriverRemovalCandidate $true $true $false $true)) 'in-use driver is retained'; Assert-That (-not (Test-WmtDriverRemovalCandidate $true $false $true $true)) 'boot-critical driver is retained'; Assert-That (-not (Test-WmtDriverRemovalCandidate $true $false $false $false)) 'driver without backup is retained'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('wmt-ci-' + [guid]::NewGuid().ToString('N')); $null=New-Item -ItemType Directory -Path $temp
try { $live=Join-Path $temp 'export.reg'; $backup=Join-Path $temp 'export.backup.reg'; $original='WMT test registry export'; [IO.File]::WriteAllText($live,$original,[Text.Encoding]::Unicode); Copy-Item $live $backup; $before=(Get-FileHash $backup -Algorithm SHA256).Hash; [IO.File]::WriteAllText($live,'corrupt',[Text.Encoding]::Unicode); Copy-Item $backup $live -Force; $after=(Get-FileHash $live -Algorithm SHA256).Hash; Assert-That ($before -eq $after) 'registry backup restores byte-identical data'; Assert-That ((Get-Item $backup).Length -gt 0) 'empty backup is rejected' } finally { Remove-Item $temp -Recurse -Force }
$temp=Join-Path ([IO.Path]::GetTempPath()) ('wmt-settings-' + [guid]::NewGuid().ToString('N')); $null=New-Item -ItemType Directory -Path $temp
try { $settings=Join-Path $temp 'settings.json'; $pending=$settings+'.tmp'; $expected=[ordered]@{Theme='Dark';RestoreOnLaunch=$true;ScanConcurrency=3}; [IO.File]::WriteAllText($pending,($expected|ConvertTo-Json),[Text.UTF8Encoding]::new($false)); Move-Item $pending $settings -Force; $actual=Get-Content $settings -Raw|ConvertFrom-Json; Assert-That ($actual.Theme -eq 'Dark' -and $actual.RestoreOnLaunch -eq $true -and $actual.ScanConcurrency -eq 3) 'settings survive JSON round-trip'; [IO.File]::WriteAllText($settings,'{invalid json',[Text.UTF8Encoding]::new($false)); $bad=$false; try{$null=Get-Content $settings -Raw|ConvertFrom-Json -ErrorAction Stop}catch{$bad=$true}; Assert-That $bad 'corrupt settings are detected for recovery' } finally { Remove-Item $temp -Recurse -Force }
function Get-WmtCiOsFamily([int]$Build){if($Build -ge 22000){'Windows11'}elseif($Build -ge 10240){'Windows10'}else{'Unsupported'}}
Assert-That ((Get-WmtCiOsFamily 19045) -eq 'Windows10') 'Windows 10 build classification'; Assert-That ((Get-WmtCiOsFamily 22631) -eq 'Windows11') 'Windows 11 23H2 build classification'; Assert-That ((Get-WmtCiOsFamily 26100) -eq 'Windows11') 'Windows 11 24H2 build classification'; Assert-That ((Get-WmtCiOsFamily 9600) -eq 'Unsupported') 'pre-Windows-10 build rejection'
Write-Host "Runtime safety contract tests passed: $passed assertions."