#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InputFile,
    [string]$OutputFile,
    [string]$IconFile,
    [switch]$InstallPS2EXE
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$script:WmtBuildScriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot
}
elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}
else {
    (Get-Location).Path
}

$script:WmtProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $script:WmtBuildScriptRoot ".."))

if ([string]::IsNullOrWhiteSpace($InputFile)) {
    $InputFile = Join-Path $script:WmtProjectRoot "WMT-GUI.ps1"
}

if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $OutputFile = Join-Path $script:WmtProjectRoot "dist\WindowsMaintenanceTool.exe"
}

if ([string]::IsNullOrWhiteSpace($IconFile)) {
    $IconFile = Join-Path $script:WmtBuildScriptRoot "WMT.ico"
}

function Resolve-WmtBuildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return [System.IO.Path]::GetFullPath($Path)
    }

    return [System.IO.Path]::GetFullPath((Join-Path $BasePath $Path))
}

function Get-WmtSourceVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    $content = Get-Content -LiteralPath $Path -Raw

    $assignmentMatch = [regex]::Match(
        $content,
        '(?im)^\s*(?:\$(?:script:|global:|private:)?AppVersion)\s*=\s*(["'']?)(v?\d+(?:\.\d+){0,3})\1\s*(?:$|[;#])'
    )

    if ($assignmentMatch.Success) {
        return $assignmentMatch.Groups[2].Value
    }

    throw "App version not found in source file: $Path"
}

function ConvertTo-WmtVersionText {
    param([Parameter(Mandatory = $true)][string]$Version)

    $match = [regex]::Match(([string]$Version).Trim(), '^\s*v?(\d+(?:\.\d+){0,3})\s*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        throw "Invalid AppVersion format: $Version"
    }

    return $match.Groups[1].Value
}

function ConvertTo-WmtFileVersion {
    param([Parameter(Mandatory = $true)][string]$Version)

    $versionText = ConvertTo-WmtVersionText -Version $Version
    $parts = @($versionText.Split("."))
    while ($parts.Count -lt 4) {
        $parts += "0"
    }

    return ($parts[0..3] -join ".")
}

function Assert-WmtPowerShellSyntax {
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $messages = $parseErrors | ForEach-Object {
            "{0}:{1}: {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message
        }
        throw "PowerShell parse errors were found:`r`n$($messages -join "`r`n")"
    }
}

function Get-WmtPS2EXECommand {
    param([switch]$Install)

    $command = Get-Command Invoke-PS2EXE -ErrorAction SilentlyContinue
    if ($command) {
        return $command
    }

    if (-not $Install) {
        throw "Invoke-PS2EXE was not found. Install PS2EXE first, or rerun this script with -InstallPS2EXE."
    }

    Write-Host "Installing PS2EXE for the current user..."
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }

    Install-Module -Name ps2exe -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -Confirm:$false
    Import-Module ps2exe -Force

    return (Get-Command Invoke-PS2EXE -ErrorAction Stop)
}

function Add-WmtPS2EXEValue {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [Parameter(Mandatory = $true)][string[]]$AvailableParameters,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$Value
    )

    if ($AvailableParameters -contains $Name) {
        $Arguments[$Name] = $Value
    }
}

function Add-WmtPS2EXESwitch {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Arguments,
        [Parameter(Mandatory = $true)][string[]]$AvailableParameters,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($AvailableParameters -contains $Name) {
        $Arguments[$Name] = $true
    }
}

function Remove-WmtCommentsFromScript {
    <#
    .SYNOPSIS
        Strips all comments (line and block) from a PowerShell source file and returns
        the path to a temporary minified copy.
    .DESCRIPTION
        Uses the PowerShell AST parser to identify every comment token, then removes
        those regions from the raw source text. Lines that become empty after comment
        removal are also collapsed, and leading blank lines at the top of the file are
        trimmed. The result is written to a temp file whose path is returned to the
        caller; the caller is responsible for cleaning up the temp file when done.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$parseErrors
    )

    if ($parseErrors -and $parseErrors.Count -gt 0) {
        $messages = $parseErrors | ForEach-Object {
            "{0}:{1}: {2}" -f $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message
        }
        throw "Parse errors during minification:`r`n$($messages -join "`r`n")"
    }

    $commentNodes = $ast.FindAll({
        param($node)
        $node.GetType().FullName -eq 'System.Management.Automation.Language.CommentAst'
    }, $true)

    if ($commentNodes.Count -eq 0) {
        Write-Host "No comments found in source; minification is a no-op."
        return $Path
    }

    $source = Get-Content -LiteralPath $Path -Raw
    $sb = New-Object -TypeName System.Text.StringBuilder($source.Length)

    $position = 0

    foreach ($comment in $commentNodes) {
        $extent = $comment.Extent
        $startOffset = $extent.StartOffset
        $endOffset = $extent.EndOffset

        if ($startOffset -gt $position) {
            [void]$sb.Append($source.Substring($position, $startOffset - $position))
        }

        $position = $endOffset
    }

    if ($position -lt $source.Length) {
        [void]$sb.Append($source.Substring($position))
    }

    $minified = $sb.ToString()

    $minified = $minified -replace '(?m)^\s*\r?\n', ''

    $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) (
        "WMT-minified-{0}.ps1" -f [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    )

    [System.IO.File]::WriteAllText($tempFile, $minified, [System.Text.UTF8Encoding]::new($true))

    $originalSize = (Get-Item -LiteralPath $Path).Length
    $minifiedSize = (Get-Item -LiteralPath $tempFile).Length
    $savedBytes = $originalSize - $minifiedSize
    $savedPct = if ($originalSize -gt 0) { [math]::Round(($savedBytes / $originalSize) * 100, 1) } else { 0 }

    Write-Host ("Minified {0} comment(s): {1:N0} -> {2:N0} bytes ({3:N1}% smaller)") `
        -f $commentNodes.Count, $originalSize, $minifiedSize, $savedPct

    return $tempFile
}

$resolvedInput = Resolve-WmtBuildPath -Path $InputFile -BasePath $script:WmtProjectRoot
$resolvedOutput = Resolve-WmtBuildPath -Path $OutputFile -BasePath $script:WmtProjectRoot
$resolvedIcon = Resolve-WmtBuildPath -Path $IconFile -BasePath $script:WmtBuildScriptRoot

if (-not (Test-Path -LiteralPath $resolvedInput -PathType Leaf)) {
    throw "Input file not found: $resolvedInput"
}

if (-not (Test-Path -LiteralPath $resolvedIcon -PathType Leaf)) {
    throw "Icon file not found: $resolvedIcon"
}

$outputDirectory = Split-Path -Parent $resolvedOutput
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

Assert-WmtPowerShellSyntax -Path $resolvedInput

$appVersion = ConvertTo-WmtVersionText -Version (Get-WmtSourceVersion -Path $resolvedInput)
$fileVersion = ConvertTo-WmtFileVersion -Version $appVersion
$ps2exe = Get-WmtPS2EXECommand -Install:$InstallPS2EXE
$availableParameters = @($ps2exe.Parameters.Keys)

$minifiedInput = Remove-WmtCommentsFromScript -Path $resolvedInput

try {
    $invokeArguments = @{
        InputFile  = $minifiedInput
        OutputFile = $resolvedOutput
    }

    Add-WmtPS2EXESwitch -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "NoConsole"
    Add-WmtPS2EXESwitch -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "STA"
    Add-WmtPS2EXESwitch -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "RequireAdmin"
    Add-WmtPS2EXESwitch -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "DPIAware"
    Add-WmtPS2EXESwitch -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "LongPaths"

    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "IconFile" -Value $resolvedIcon
    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "Title" -Value "Windows Maintenance Tool"
    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "Description" -Value "Windows Maintenance Tool GUI"
    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "Product" -Value "Windows Maintenance Tool"
    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "Company" -Value "Windows Maintenance Tool"
    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "Copyright" -Value "MIT License"
    Add-WmtPS2EXEValue -Arguments $invokeArguments -AvailableParameters $availableParameters -Name "Version" -Value $fileVersion

    Write-Host "Building Windows Maintenance Tool v$appVersion..."
    Write-Host "Source: $resolvedInput"
    Write-Host "Icon:   $resolvedIcon"
    Write-Host "Output: $resolvedOutput"
    Invoke-PS2EXE @invokeArguments

    if (-not (Test-Path -LiteralPath $resolvedOutput -PathType Leaf)) {
        throw "Build finished, but the EXE was not created: $resolvedOutput"
    }

    Write-Host "Built: $resolvedOutput"
}
finally {
    if ($minifiedInput -ne $resolvedInput -and (Test-Path -LiteralPath $minifiedInput -PathType Leaf)) {
        Remove-Item -LiteralPath $minifiedInput -Force
    }
}
