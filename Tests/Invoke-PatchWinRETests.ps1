<#
.SYNOPSIS
    Runs Patch-WinRE and GUI Pester tests.
.DESCRIPTION
    Requires Pester 5 or later. No recovery configuration is changed by the GUI tests.
.PARAMETER Path
    Optional test file or folder. Defaults to all Pester test files under Tests.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: Invoke-PatchWinRETests.ps1
    Initial creation date: 2026-11-22
    Last change: 2026-11-22
    Changes: Initial version
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$Path
)

$PesterModule = Get-Module -ListAvailable -Name Pester |
    Where-Object { $_.Version -ge [version]'5.0' } |
    Sort-Object Version -Descending |
    Select-Object -First 1
if (-not $PesterModule) { throw 'Pester 5 or later is required. Install it from the PowerShell Gallery and retry.' }
Import-Module -Name $PesterModule.Path -Force -ErrorAction Stop

if (-not $Path -or $Path.Count -eq 0) {
    $Path = @(Get-ChildItem -Path $PSScriptRoot -Filter '*.Tests.ps1' -File -Recurse | ForEach-Object { $_.FullName })
}
if ($Path.Count -eq 0) { throw "No Pester test files were found under $PSScriptRoot." }

$Configuration = New-PesterConfiguration
$Configuration.Run.Path = $Path
$Configuration.Output.Verbosity = 'Detailed'
$Result = Invoke-Pester -Configuration $Configuration
if ($Result.FailedCount -gt 0) { exit 1 }
