[CmdletBinding()]
param([string]$SourcePath = (Join-Path $PSScriptRoot '..\..\WMT-GUI.ps1'))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$script:passed=0
function Assert-Wmt([bool]$Condition,[string]$Message){if(-not $Condition){throw "FAILED: $Message"};$script:passed++;Write-Host "PASS: $Message"}
if(-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)){throw "WMT source not found: $SourcePath"}
$tokens=$null;$parseErrors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path -LiteralPath $SourcePath).Path,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw "WMT source parse failed: $($parseErrors[0].Message)"}
function Import-WmtFunction([string]$Name){
    $node=$ast.Find({param($n)$n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name},$true)
    if(-not $node){throw "WMT function missing: $Name"}
    Invoke-Expression $node.Extent.Text
}
# Exercise WMT's actual atomic settings writer against isolated temporary files.
Import-WmtFunction 'Write-WmtSettingsFileAtomic'
$script:WmtSettingsWriteMutexName='Local\Wmt-CI-'+[guid]::NewGuid().ToString('N')
$root=Join-Path ([IO.Path]::GetTempPath()) ('wmt-actual-settings-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($root)
try{
    $path=Join-Path $root 'settings.json'
    $first='{"Theme":"dark","ScanConcurrency":2}'
    Write-WmtSettingsFileAtomic -Path $path -Json $first
    Assert-Wmt ((Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).ScanConcurrency -eq 2) 'WMT atomic settings writer creates readable settings'
    $second='{"Theme":"light","ScanConcurrency":4}'
    Write-WmtSettingsFileAtomic -Path $path -Json $second
    Assert-Wmt ((Get-Content -LiteralPath $path -Raw|ConvertFrom-Json).Theme -eq 'light') 'WMT atomic settings writer replaces existing settings'
    $stable=[IO.File]::ReadAllText($path)
    $rejected=$false
    try{Write-WmtSettingsFileAtomic -Path $path -Json '{invalid json'}catch{$rejected=$true}
    Assert-Wmt $rejected 'WMT atomic settings writer rejects malformed JSON'
    Assert-Wmt ([IO.File]::ReadAllText($path) -eq $stable) 'malformed settings never overwrite last known-good file'
    Assert-Wmt (-not (Get-ChildItem -LiteralPath $root -Filter '*.tmp' -File)) 'settings writer cleans temporary files after failure'
    Assert-Wmt ([IO.File]::Exists($path+'.bak')) 'settings writer retains a prior settings backup'
}finally{Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue}
# Exercise WMT's real driver cleanup decision loop; only pnputil and inventory calls are mocked.
Import-WmtFunction 'Invoke-WmtDriverCleanupBatch'
$script:ciUsageMode='Safe'
$script:ciUsageCalls=0
$script:ciProcessCalls=[System.Collections.Generic.List[string]]::new()
function Get-WmtDriverCleanupUsage{
    param([string]$PublishedName='')
    $script:ciUsageCalls++
    if($script:ciUsageMode -eq 'Fail'){throw 'mock inventory unavailable'}
    if($script:ciUsageMode -eq 'InUse' -and $PublishedName){return [pscustomobject]@{InUseInfs=@($PublishedName);RegisteredServices=@()}}
    if($script:ciUsageMode -eq 'Service' -and $PublishedName){return [pscustomobject]@{InUseInfs=@();RegisteredServices=@('MockFilterSvc')}}
    return [pscustomobject]@{InUseInfs=@();RegisteredServices=@()}
}
function Invoke-WmtProcess{
    param([string]$FilePath,[string]$Arguments,[int]$TimeoutMs,[string]$Encoding,[switch]$KillTree)
    [void]$script:ciProcessCalls.Add($Arguments)
    if($Arguments -match '/export-driver'){return [pscustomobject]@{ExitCode=0;TimedOut=$false;TerminationFailed=$false;OutputReadTimedOut=$false;Error='';StdOut='exported';StdErr=''}}
    return [pscustomobject]@{ExitCode=0;TimedOut=$false;TerminationFailed=$false;OutputReadTimedOut=$false;Error='';StdOut='removed';StdErr=''}
}
$backupRoot=Join-Path ([IO.Path]::GetTempPath()) ('wmt-driver-ci-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($backupRoot)
try{
    $script:ciUsageMode='InUse';$script:ciProcessCalls.Clear()
    $r=Invoke-WmtDriverCleanupBatch -Items @([pscustomobject]@{PublishedName='oem10.inf';OriginalName='in-use'}) -Mode NoBackup -BackupRoot $backupRoot
    Assert-Wmt ($r.Failed -eq 1 -and $script:ciProcessCalls.Count -eq 0) 'WMT driver cleanup refuses packages bound to active devices'
    $script:ciUsageMode='Service';$script:ciProcessCalls.Clear()
    $r=Invoke-WmtDriverCleanupBatch -Items @([pscustomobject]@{PublishedName='oem11.inf';OriginalName='filter'}) -Mode NoBackup -BackupRoot $backupRoot
    Assert-Wmt ($r.Failed -eq 1 -and $script:ciProcessCalls.Count -eq 0) 'WMT driver cleanup refuses packages with registered services'
    $script:ciUsageMode='Fail';$script:ciProcessCalls.Clear()
    $r=Invoke-WmtDriverCleanupBatch -Items @([pscustomobject]@{PublishedName='oem12.inf';OriginalName='unknown'}) -Mode NoBackup -BackupRoot $backupRoot
    Assert-Wmt ($r.Failed -eq 1 -and $script:ciProcessCalls.Count -eq 0) 'WMT driver cleanup fails closed when usage inventory fails'
    $script:ciUsageMode='Safe';$script:ciProcessCalls.Clear()
    $r=Invoke-WmtDriverCleanupBatch -Items @([pscustomobject]@{PublishedName='oem13.inf';OriginalName='safe'}) -Mode Backup -BackupRoot $backupRoot
    Assert-Wmt ($r.Failed -eq 0 -and $r.Deleted -contains 'oem13.inf') 'WMT driver cleanup permits verified unused package after successful backup'
    Assert-Wmt ($script:ciProcessCalls.Count -eq 2 -and $script:ciProcessCalls[0] -match '/export-driver' -and $script:ciProcessCalls[1] -match '/delete-driver') 'WMT driver cleanup orders export before deletion'
    $script:ciProcessCalls.Clear()
    $r=Invoke-WmtDriverCleanupBatch -Items @([pscustomobject]@{PublishedName='invalid.inf';OriginalName='invalid'}) -Mode NoBackup -BackupRoot $backupRoot
    Assert-Wmt ($r.Failed -eq 1 -and $script:ciProcessCalls.Count -eq 0) 'WMT driver cleanup rejects malformed published INF identifiers'
}finally{Remove-Item -LiteralPath $backupRoot -Recurse -Force -ErrorAction SilentlyContinue}
# Exercise the real background-operation manager with isolated runspaces and no UI.
foreach($name in @('Write-WmtBackgroundOperationLog','Initialize-WmtBackgroundOperationManager','Start-WmtBackgroundOperation','Request-WmtBackgroundOperationCancellation','Update-WmtBackgroundOperations','Stop-WmtBackgroundOperationManager')){Import-WmtFunction $name}
$script:WmtBackgroundOperationState=[pscustomobject]@{
    SyncRoot=[object]::new()
    Operations=[System.Collections.Generic.Dictionary[string,object]]::new()
    NextId=[long]0
    ShuttingDown=$false
    Log=$null
}
$script:ciOperationLogs=[System.Collections.Generic.List[string]]::new()
Initialize-WmtBackgroundOperationManager -Log {param($line)[void]$script:ciOperationLogs.Add([string]$line)}
$id=Start-WmtBackgroundOperation -Name 'CI-cancel' -ScriptBlock {while($true){Start-Sleep -Milliseconds 25}} -TimeoutSeconds 30 -Quiet
Assert-Wmt ($script:WmtBackgroundOperationState.Operations.ContainsKey($id)) 'WMT manager registers active worker'
Assert-Wmt (Request-WmtBackgroundOperationCancellation -Id $id -Reason 'CI cancellation') 'WMT manager accepts active cancellation'
$deadline=[DateTime]::UtcNow.AddSeconds(8)
while($script:WmtBackgroundOperationState.Operations.ContainsKey($id) -and [DateTime]::UtcNow -lt $deadline){[void](Update-WmtBackgroundOperations);Start-Sleep -Milliseconds 40}
Assert-Wmt (-not $script:WmtBackgroundOperationState.Operations.ContainsKey($id)) 'WMT manager reaps cancelled worker after completion'
Assert-Wmt (@($script:ciOperationLogs | Where-Object {$_ -match 'Cancelled'}).Count -gt 0) 'WMT manager logs cancellation even for quiet operations'
$id=Start-WmtBackgroundOperation -Name 'CI-fault' -ScriptBlock {throw 'CI worker fault'} -TimeoutSeconds 10 -Quiet
$deadline=[DateTime]::UtcNow.AddSeconds(8)
while($script:WmtBackgroundOperationState.Operations.ContainsKey($id) -and [DateTime]::UtcNow -lt $deadline){[void](Update-WmtBackgroundOperations);Start-Sleep -Milliseconds 40}
Assert-Wmt (-not $script:WmtBackgroundOperationState.Operations.ContainsKey($id)) 'WMT manager reaps failed worker'
Assert-Wmt (@($script:ciOperationLogs | Where-Object {$_ -match 'Failed'}).Count -gt 0) 'WMT manager reports worker failures when Quiet is set'
$id=Start-WmtBackgroundOperation -Name 'CI-shutdown' -ScriptBlock {while($true){Start-Sleep -Milliseconds 25}} -TimeoutSeconds 30 -Quiet
Assert-Wmt ((Stop-WmtBackgroundOperationManager) -eq 1) 'WMT manager requests cancellation of outstanding work at shutdown'
$deadline=[DateTime]::UtcNow.AddSeconds(8)
while($script:WmtBackgroundOperationState.Operations.ContainsKey($id) -and [DateTime]::UtcNow -lt $deadline){[void](Update-WmtBackgroundOperations);Start-Sleep -Milliseconds 40}
Assert-Wmt (-not $script:WmtBackgroundOperationState.Operations.ContainsKey($id)) 'WMT manager drains shutdown worker'
$rejected=$false;try{Start-WmtBackgroundOperation -Name 'after-shutdown' -ScriptBlock {1}}catch{$rejected=$true}
Assert-Wmt $rejected 'WMT manager refuses new work after shutdown'
Write-Host "WMT implementation integration tests passed: $script:passed assertions."
