<#
.SYNOPSIS
    Analyzes Patch-WinRE PowerShell scripts.
.DESCRIPTION
    Requires PSScriptAnalyzer. Runs Error and Warning rules with the exclusions documented in PSScriptAnalyzerSettings.psd1.
.PARAMETER Path
    Optional script or folder. Defaults to all PowerShell scripts in the project.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: Invoke-PatchWinREAnalyzer.ps1
    Initial creation date: 2026-11-22
    Last change: 2026-11-22
    Changes: Initial version
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$Path
)

$AnalyzerModule = Get-Module -ListAvailable -Name PSScriptAnalyzer |
    Sort-Object Version -Descending |
    Select-Object -First 1
if (-not $AnalyzerModule) { throw 'PSScriptAnalyzer is required. Install it from the PowerShell Gallery and retry.' }
Import-Module -Name $AnalyzerModule.Path -Force -ErrorAction Stop

if (-not $Path -or $Path.Count -eq 0) {
    $ProjectRoot = Split-Path -Path $PSScriptRoot -Parent
    $Path = @(Get-ChildItem -Path $ProjectRoot -Filter '*.ps1' -File -Recurse | ForEach-Object { $_.FullName })
}
if ($Path.Count -eq 0) { throw 'No PowerShell scripts were found to analyze.' }

$SettingsPath = Join-Path -Path $PSScriptRoot -ChildPath 'PSScriptAnalyzerSettings.psd1'
$Findings = New-Object System.Collections.Generic.List[object]
foreach ($ScriptPath in $Path) {
    foreach ($Finding in (Invoke-ScriptAnalyzer -Path $ScriptPath -Settings $SettingsPath -Severity Error,Warning)) {
        $Findings.Add($Finding)
    }
}
if ($Findings.Count -gt 0) {
    $Findings | Select-Object ScriptName,RuleName,Severity,Line,Message | Format-Table -AutoSize
    exit 1
}
Write-Output 'PSScriptAnalyzer found no errors or warnings.'
