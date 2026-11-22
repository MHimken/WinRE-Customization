<#
.SYNOPSIS
    Opens the Windows Recovery Environment customization GUI.
.DESCRIPTION
    Provides a graphical interface for Patch-WinRE.ps1. The GUI can generate a command without elevation or run the
    script from an elevated Windows PowerShell 5.1 process.
.PARAMETER GenerateOnly
    Opens the GUI in command-generation mode, even when elevated.
.PARAMETER LogPath
    Folder for this GUI's log file. Defaults to the folder containing this script.
.PARAMETER LogFile
    Optional full path for the GUI log file. If omitted, a timestamped file name is used in LogPath.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: Start-PatchWinREGUI.ps1
    Initial creation date: 2026-11-22
    Last change: 2026-11-22
    Changes: Initial version
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$GenerateOnly,
    [string]$LogPath = $PSScriptRoot,
    [string]$LogFile
)

$Script:ScriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Script:ScriptRoot)) {
    $Script:ScriptRoot = Split-Path -Parent $PSCommandPath
}
if ($PSVersionTable.PSEdition -ne 'Desktop' -or
    $PSVersionTable.PSVersion.Major -ne 5 -or
    [System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
    $PowerShellPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $Arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File "{0}"' -f $PSCommandPath
    if ($GenerateOnly) { $Arguments += ' -GenerateOnly' }
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) { $Arguments += ' -LogPath "{0}"' -f $LogPath }
    if (-not [string]::IsNullOrWhiteSpace($LogFile)) { $Arguments += ' -LogFile "{0}"' -f $LogFile }
    $Process = Start-Process -FilePath $PowerShellPath -ArgumentList $Arguments -PassThru
    $Process.WaitForExit()
    exit $Process.ExitCode
}

$Script:Ui = @{}
$Script:State = $null
$Script:Window = $null
$Script:ActiveRun = $null
$Script:RunTimer = $null
$Script:DebounceTimer = $null
$Script:IsUpdating = $false
$Script:Validation = $null
$Script:Mode = 'Generate'
$Script:IsElevated = $false
$Script:LogFilePath = $null
$Script:LogStatus = ''
$Script:OutputEntries = New-Object System.Collections.Generic.List[object]
$Script:Operations = @()

function Initialize-Script {
    if ([string]::IsNullOrWhiteSpace($LogPath)) { $LogPath = $Script:ScriptRoot }
    if (-not [System.IO.Directory]::Exists($LogPath)) {
        try { [void][System.IO.Directory]::CreateDirectory($LogPath) }
        catch { $Script:LogStatus = 'GUI logging is unavailable: the log folder could not be created.'; return }
    }
    if ([string]::IsNullOrWhiteSpace($LogFile)) {
        $Script:LogFilePath = Join-Path -Path $LogPath -ChildPath ('StartPatchWinREGUI_{0}.log' -f (Get-Date -Format 'yyyy-MM-ddTHH-mm-ss'))
    } else {
        $Script:LogFilePath = $LogFile
    }
    try {
        $Parent = Split-Path -Parent $Script:LogFilePath
        if (-not [string]::IsNullOrWhiteSpace($Parent) -and -not [System.IO.Directory]::Exists($Parent)) {
            [void][System.IO.Directory]::CreateDirectory($Parent)
        }
        [System.IO.File]::AppendAllText($Script:LogFilePath, '')
        $Script:LogStatus = 'GUI log: {0}' -f $Script:LogFilePath
    } catch {
        $Script:LogFilePath = $null
        $Script:LogStatus = 'GUI logging is unavailable: {0}' -f $_.Exception.Message
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Component = 'GUI',
        [ValidateSet(1, 2, 3)]
        [int]$Type = 1
    )
    $Line = '{0:yyyy-MM-dd HH:mm:ss.fff} T:{1} C:{2} M:{3}{4}' -f (Get-Date), $Type, $Component, $Message, [Environment]::NewLine
    if ($Script:LogFilePath) {
        try { [System.IO.File]::AppendAllText($Script:LogFilePath, $Line, (New-Object System.Text.UTF8Encoding -ArgumentList $true)) }
        catch {
            $Script:LogFilePath = $null
            $Script:LogStatus = 'GUI log write failed: {0}' -f $_.Exception.Message
            if ($Script:Ui.ContainsKey('LogStatusText')) { $Script:Ui.LogStatusText.Text = $Script:LogStatus }
            if ($Script:Ui.ContainsKey('LogFileText')) { $Script:Ui.LogFileText.Visibility = 'Collapsed' }
        }
    }
}

function Set-PatchWinRELamp {
    param(
        [Parameter(Mandatory = $true)]
        [System.Windows.Controls.ContentControl]$Control,
        [ValidateSet('Pass', 'Review', 'Blocked', 'Off')]
        [string]$State = 'Off'
    )
    $Canvas = New-Object System.Windows.Controls.Canvas
    $Canvas.Width = 20
    $Canvas.Height = 20
    $Viewbox = New-Object System.Windows.Controls.Viewbox
    $Viewbox.Stretch = [System.Windows.Media.Stretch]::Uniform
    $Viewbox.Child = $Canvas
    switch ($State) {
        'Pass' {
            $Shape = New-Object System.Windows.Shapes.Ellipse
            $Shape.Width = 19
            $Shape.Height = 19
            $Shape.Fill = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(63, 185, 80))
            [void]$Canvas.Children.Add($Shape)
            $Mark = New-Object System.Windows.Shapes.Path
            $Mark.Data = [System.Windows.Media.Geometry]::Parse('M5,10.5 L8.8,14.2 L15.2,6.2')
            $Mark.Stroke = [System.Windows.Media.Brushes]::Black
            $Mark.StrokeThickness = 2.4
            [void]$Canvas.Children.Add($Mark)
        }
        'Review' {
            $Shape = New-Object System.Windows.Shapes.Polygon
            $Shape.Points = '10,1 19.5,18.5 0.5,18.5'
            $Shape.Fill = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(242, 176, 30))
            [void]$Canvas.Children.Add($Shape)
            foreach ($Rect in @(
                (New-Object System.Windows.Shapes.Rectangle),
                (New-Object System.Windows.Shapes.Rectangle)
            )) {
                $Rect.Fill = [System.Windows.Media.Brushes]::Black
                [void]$Canvas.Children.Add($Rect)
            }
            $Canvas.Children[1].Width = 2
            $Canvas.Children[1].Height = 5.5
            [System.Windows.Controls.Canvas]::SetLeft($Canvas.Children[1], 9)
            [System.Windows.Controls.Canvas]::SetTop($Canvas.Children[1], 7.5)
            $Canvas.Children[2].Width = 2
            $Canvas.Children[2].Height = 2
            [System.Windows.Controls.Canvas]::SetLeft($Canvas.Children[2], 9)
            [System.Windows.Controls.Canvas]::SetTop($Canvas.Children[2], 14)
        }
        'Blocked' {
            $Shape = New-Object System.Windows.Shapes.Rectangle
            $Shape.Width = 19
            $Shape.Height = 19
            $Shape.Fill = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(255, 107, 107))
            [void]$Canvas.Children.Add($Shape)
            $Mark = New-Object System.Windows.Shapes.Path
            $Mark.Data = [System.Windows.Media.Geometry]::Parse('M5.5,5.5 L14.5,14.5 M14.5,5.5 L5.5,14.5')
            $Mark.Stroke = [System.Windows.Media.Brushes]::Black
            $Mark.StrokeThickness = 2
            [void]$Canvas.Children.Add($Mark)
        }
        default {
            $Shape = New-Object System.Windows.Shapes.Ellipse
            $Shape.Width = 17
            $Shape.Height = 17
            $Shape.Fill = [System.Windows.Media.Brushes]::Transparent
            $Shape.Stroke = New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(115, 123, 128))
            $Shape.StrokeThickness = 1.4
            [void]$Canvas.Children.Add($Shape)
        }
    }
    $Control.Content = $Viewbox
    $Name = switch ($State) { 'Pass' { 'Valid' } 'Review' { 'Review' } 'Blocked' { 'Blocked' } default { 'Not checked' } }
    [System.Windows.Automation.AutomationProperties]::SetName($Control, $Name)
}

function Set-PatchWinREOutputResult {
    param(
        [ValidateSet('Pass', 'Review', 'Blocked', 'Off')]
        [string]$State,
        [string]$Title,
        [string]$Detail
    )
    Set-PatchWinRELamp -Control $Script:Ui.ResultLamp -State $State
    $Script:Ui.ResultText.Text = $Title
    $Script:Ui.OutputTitle.Text = $Detail
}

function Add-PatchWinREOutputEntry {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Entry
    )
    $Script:OutputEntries.Add($Entry)
    $Paragraph = New-Object System.Windows.Documents.Paragraph
    $Paragraph.Margin = [System.Windows.Thickness]::new(0)
    $Paragraph.LineHeight = 16
    if ($Entry.IsContinuation) {
        $Prefix = '        '
        $Component = ''
    } elseif ($Entry.Type -gt 0) {
        $Prefix = ('{0,-8}' -f $Entry.Level)
        $Component = '[{0}] ' -f $Entry.Component
    } else {
        $Prefix = ('{0,-8}' -f $Entry.Level)
        $Component = ''
    }
    $LevelBrush = switch ($Entry.Level) {
        'WARN' { New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(242, 176, 30)) }
        'ERROR' { New-Object System.Windows.Media.SolidColorBrush ([System.Windows.Media.Color]::FromRgb(255, 107, 107)) }
        default { $Script:Window.FindResource('TextBrush') }
    }
    [void]$Paragraph.Inlines.Add((New-Object System.Windows.Documents.Run -ArgumentList $Prefix -Property @{ Foreground = $LevelBrush }))
    if ($Component) {
        [void]$Paragraph.Inlines.Add((New-Object System.Windows.Documents.Run -ArgumentList $Component -Property @{ Foreground = $Script:Window.FindResource('MutedBrush') }))
    }
    [void]$Paragraph.Inlines.Add((New-Object System.Windows.Documents.Run -ArgumentList ([string]$Entry.Message) -Property @{ Foreground = $LevelBrush }))
    $Script:Ui.OutputBox.Document.Blocks.Add($Paragraph)
    $Script:Ui.OutputBox.ScrollToEnd()
    $Script:Ui.OutputPlaceholder.Visibility = [System.Windows.Visibility]::Collapsed
    $Script:Ui.SaveOutputButton.IsEnabled = $true
}

function Clear-PatchWinREOutput {
    $Script:OutputEntries.Clear()
    $Script:Ui.OutputBox.Document.Blocks.Clear()
    $Script:Ui.OutputPlaceholder.Visibility = [System.Windows.Visibility]::Visible
    $Script:Ui.SaveOutputButton.IsEnabled = $false
    $Script:Ui.OutputTitle.Text = ''
    $Script:Ui.ResultText.Text = 'Nothing has been run yet.'
    Set-PatchWinRELamp -Control $Script:Ui.ResultLamp -State Off
}

function Get-PatchWinRECurrentValidation {
    $Script:Validation = Get-PatchWinREValidation -State $Script:State -Mode $Script:Mode
    return $Script:Validation
}

function Get-PatchWinRECommandFormat {
    if ($Script:Ui.FormatSplat.IsChecked) { return 'Splat' }
    if ($Script:Ui.FormatFile.IsChecked) { return 'File' }
    return 'OneLiner'
}

function Set-PatchWinREFieldDisplay {
    param(
        [string]$Key,
        [object]$Field
    )
    $Lamp = $Script:Ui["${Key}Lamp"]
    $Message = $Script:Ui["${Key}Message"]
    if ($Lamp) {
        Set-PatchWinRELamp -Control $Lamp -State $(if ($Field) { $Field.State } else { 'Off' })
    }
    if ($Message) {
        if ($Field) {
            $Prefix = switch ($Field.State) { 'Review' { 'Review: ' } 'Blocked' { 'Blocked: ' } default { '' } }
            $Message.Text = $Prefix + $Field.Message
            $Message.FontWeight = if ($Field.State -in @('Review', 'Blocked')) { [System.Windows.FontWeights]::SemiBold } else { [System.Windows.FontWeights]::Normal }
        } else {
            $Message.Text = ''
            $Message.FontWeight = [System.Windows.FontWeights]::Normal
        }
    }
}

function Update-PatchWinREView {
    $Operation = Get-PatchWinREOperation -Key $Script:State.Operation
    $ValidationResult = Get-PatchWinRECurrentValidation
    $Script:Ui.OperationTitle.Text = $Operation.DisplayName
    $Script:Ui.OperationDescription.Text = $Operation.Description

    $HasSource = $Operation.Enabled -and [bool]$Operation.SourceParameter
    $HasWim = $Operation.Wim -ne 'None'
    $Script:Ui.SourceSection.Visibility = if ($HasSource -or $HasWim) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.SourceRow.Visibility = if ($HasSource) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.WimRow.Visibility = if ($HasWim) { 'Visible' } else { 'Collapsed' }
    if ($HasSource) {
        $Script:Ui.SourceLabel.Text = switch ($Operation.SourceParameter) {
            'PatchFilesGDRDUorLCU' { 'MSU or CAB file or folder' }
            'PatchFilesDUorSOS' { 'CAB file or folder' }
            'FilesDriver' { 'INF file or driver folder' }
            default { 'Source folder or file' }
        }
        $Script:Ui.SourceParameterText.Text = '-' + $Operation.SourceParameter
        $Script:Ui.SourceBox.Text = [string]$Script:State.($Operation.SourceParameter)
        $Script:Ui.SourceFolderButton.IsEnabled = $true
        $Script:Ui.SourceFileButton.IsEnabled = $Operation.SourceExtensions.Count -gt 0
        $Script:Ui.SourceFileButton.ToolTip = switch ($Operation.SourceParameter) {
            'PatchFilesGDRDUorLCU' { 'Select one .msu or .cab file' }
            'PatchFilesDUorSOS' { 'Select one .cab file' }
            'FilesDriver' { 'Select one .inf file' }
            default { 'Select a source file' }
        }
        Set-PatchWinREFieldDisplay -Key 'Source' -Field $ValidationResult.Fields['Source']
    }
    if ($HasWim) {
        $Script:Ui.WimBox.Text = [string]$Script:State.WIMFilePath
        Set-PatchWinREFieldDisplay -Key 'WIMFilePath' -Field $ValidationResult.Fields['WIMFilePath']
    }

    $Script:Ui.SizeSection.Visibility = if ($Operation.AllowsSize) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.UseSizeCheck.IsChecked = [bool]$Script:State.UseRecoverySize
    $Script:Ui.SizeBox.Text = [string]$Script:State.RecoverySizeGB
    $Script:Ui.SizeBox.IsEnabled = [bool]$Script:State.UseRecoverySize
    $Script:Ui.SizeBox.Visibility = if ($Script:State.UseRecoverySize) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.RecoveryDriveSizeInGBLamp.Visibility = if ($Script:State.UseRecoverySize) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.RecoveryDriveSizeInGBMessage.Visibility = if ($Script:State.UseRecoverySize) { 'Visible' } else { 'Collapsed' }
    Set-PatchWinREFieldDisplay -Key 'RecoveryDriveSizeInGB' -Field $ValidationResult.Fields['RecoveryDriveSizeInGB']

    $Script:Ui.OptionsSection.Visibility = if ($Operation.Options.Count -gt 0 -or $Operation.AllowsDeleteBackups -or $Operation.Key -eq 'ReportOnly' -or $Operation.Key -eq 'Backup') { 'Visible' } else { 'Collapsed' }
    $ShowCreate = $Operation.Options -contains 'CreateWinREDrive'
    $Script:Ui.CreateWinREDriveCheck.Visibility = if ($ShowCreate) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.CreateWinREDriveCheck.IsChecked = [bool]$Script:State.CreateWinREDrive
    $ShowDoNotExpand = $Operation.Options -contains 'DoNotExpandRecoveryPartition'
    $Script:Ui.DoNotExpandCheck.Visibility = if ($ShowDoNotExpand) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.DoNotExpandCheck.IsChecked = [bool]$Script:State.DoNotExpandRecoveryPartition
    $ShowAbort = $Operation.Options -contains 'AbortIfFailed'
    $Script:Ui.AbortIfFailedCheck.Visibility = if ($ShowAbort) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.AbortIfFailedCheck.IsChecked = [bool]$Script:State.AbortIfFailed
    $ShowDelete = $Operation.AllowsDeleteBackups
    $Script:Ui.DeleteBackupsRow.Visibility = if ($ShowDelete) { 'Visible' } else { 'Collapsed' }
    $Script:Ui.DeleteBackupsCheck.IsChecked = [bool]$Script:State.DeleteBackups
    Set-PatchWinREFieldDisplay -Key 'DeleteBackups' -Field $ValidationResult.Fields['DeleteBackups']
    $Script:Ui.ToConsoleCheck.IsChecked = if ($Script:Mode -eq 'Run') { $true } else { [bool]$Script:State.ToConsole }
    $Script:Ui.ToConsoleCheck.IsEnabled = $Script:Mode -ne 'Run'
    $Script:Ui.ToConsoleMessage.Text = if ($Script:Mode -eq 'Run') { 'Locked on while the GUI runs the script so output can be shown here.' } else { 'The generated command includes -ToConsole only when this is checked.' }
    $Script:Ui.WhatIfCheck.IsChecked = [bool]$Script:State.WhatIf
    $Script:Ui.WhatIfMessage.Text = 'Previews supported changes; the script asks before each change and does not apply it.'

    $Script:Ui.RootBox.Text = [string]$Script:State.Root
    $Script:Ui.RootChipText.Text = 'ROOT'
    $Script:Ui.RootChip.BorderBrush = $Script:Window.FindResource('LineBrush')
    $Script:Ui.RootResetButton.Visibility = if (Test-PatchWinRESamePath -Path $Script:State.Root -OtherPath (Get-PatchWinREScriptDefault).Root) { 'Collapsed' } else { 'Visible' }
    Set-PatchWinREFieldDisplay -Key 'Root' -Field $ValidationResult.Fields['Root']
    foreach ($FolderName in (Get-PatchWinREFolderName)) {
        $Script:Ui["${FolderName}Box"].Text = [string]$Script:State.$FolderName
        $Script:Ui["${FolderName}ChipText"].Text = if ($FolderName -eq 'Root') { 'ROOT' } elseif ($Script:State.FollowsRoot[$FolderName]) { 'FOLLOWS ROOT' } else { 'CUSTOM' }
        $Script:Ui["${FolderName}ResetButton"].Visibility = if ($FolderName -ne 'Root' -and -not $Script:State.FollowsRoot[$FolderName]) { 'Visible' } else { 'Collapsed' }
        $Script:Ui["${FolderName}Chip"].BorderBrush = if ($FolderName -ne 'Root' -and -not $Script:State.FollowsRoot[$FolderName]) { $Script:Window.FindResource('AccentBrush') } else { $Script:Window.FindResource('LineBrush') }
        Set-PatchWinREFieldDisplay -Key $FolderName -Field $ValidationResult.Fields[$FolderName]
    }

    foreach ($Readiness in @('Pass', 'Review', 'Blocked')) {
        $LampName = switch ($Readiness) { 'Pass' { 'ReadyLampPass' } 'Review' { 'ReadyLampReview' } default { 'ReadyLampBlocked' } }
        $Script:Ui[$LampName].Visibility = if ($ValidationResult.Readiness -eq $Readiness) { 'Visible' } else { 'Collapsed' }
        Set-PatchWinRELamp -Control $Script:Ui[$LampName] -State $Readiness
    }
    $Script:Ui.ReadyTitle.Text = $ValidationResult.Title
    $Script:Ui.ReadyDetail.Text = $ValidationResult.Detail
    $Params = Get-PatchWinREParameter -State $Script:State -ForceToConsole:($Script:Mode -eq 'Run')
    $Script:Ui.CommandBox.Text = ConvertTo-PatchWinRECommand -Parameter $Params -Format (Get-PatchWinRECommandFormat) -ScriptPath '.\Patch-WinRE.ps1'
    $Script:Ui.CommandNote.Text = 'Run this command from the Patch-WinRE folder in elevated Windows PowerShell 5.1.'
    $Script:Ui.CopyButton.IsEnabled = $ValidationResult.Readiness -ne 'Blocked' -and -not $Script:ActiveRun
    $Script:Ui.RunButton.IsEnabled = $Script:Mode -eq 'Run' -and $Operation.Enabled -and $ValidationResult.Readiness -ne 'Blocked' -and -not $Script:ActiveRun
    $Script:Ui.CheckSystemButton.IsEnabled = $Script:Mode -eq 'Run' -and -not $Script:ActiveRun
    $Script:Ui.SettingsPanel.IsEnabled = -not $Script:ActiveRun
    $Script:Ui.OperationList.IsEnabled = -not $Script:ActiveRun
}

function Sync-PatchWinREStateFromControls {
    if ($Script:IsUpdating -or $Script:ActiveRun) { return }
    $Operation = Get-PatchWinREOperation -Key $Script:State.Operation
    if ($Operation.SourceParameter) { $Script:State.($Operation.SourceParameter) = $Script:Ui.SourceBox.Text }
    $Script:State.WIMFilePath = $Script:Ui.WimBox.Text
    if ($Script:Ui.WimBox.Text) { $Script:State.WimBrowseFolder = Split-Path -Parent $Script:Ui.WimBox.Text }
    $Script:State.UseRecoverySize = [bool]$Script:Ui.UseSizeCheck.IsChecked
    $Script:State.RecoverySizeGB = $Script:Ui.SizeBox.Text
    $Script:State.CreateWinREDrive = [bool]$Script:Ui.CreateWinREDriveCheck.IsChecked
    $Script:State.DoNotExpandRecoveryPartition = [bool]$Script:Ui.DoNotExpandCheck.IsChecked
    $Script:State.AbortIfFailed = [bool]$Script:Ui.AbortIfFailedCheck.IsChecked
    $Script:State.DeleteBackups = [bool]$Script:Ui.DeleteBackupsCheck.IsChecked
    if ($Script:Mode -ne 'Run') { $Script:State.ToConsole = [bool]$Script:Ui.ToConsoleCheck.IsChecked }
    $Script:State.WhatIf = [bool]$Script:Ui.WhatIfCheck.IsChecked
    $Script:State.ShowAll = [bool]$Script:Ui.ShowAllCheck.IsChecked
    $UpdatedRoot = $Script:Ui.RootBox.Text
    $RootChanged = -not (Test-PatchWinRESamePath -Path $Script:State.Root -OtherPath $UpdatedRoot)
    if ($RootChanged) {
        $FollowingFolders = @{}
        foreach ($FolderName in (Get-PatchWinREFolderName)) { $FollowingFolders[$FolderName] = [bool]$Script:State.FollowsRoot[$FolderName] }
        Set-PatchWinRERoot -State $Script:State -Root $UpdatedRoot
        $Script:IsUpdating = $true
        foreach ($FolderName in (Get-PatchWinREFolderName)) {
            if ($FollowingFolders[$FolderName]) { $Script:Ui["${FolderName}Box"].Text = $Script:State.$FolderName }
        }
        $Script:IsUpdating = $false
    }
    foreach ($FolderName in (Get-PatchWinREFolderName)) {
        if ($FolderName -eq 'Root') { continue }
        $Value = $Script:Ui["${FolderName}Box"].Text
        if (-not (Test-PatchWinRESamePath -Path $Script:State.$FolderName -OtherPath $Value)) {
            Set-PatchWinREFolder -State $Script:State -Name $FolderName -Path $Value
        }
    }
    Update-PatchWinREView
}

function Set-PatchWinREOutputHeader {
    param([string]$Title)
    Clear-PatchWinREOutput
    $Script:Ui.OutputTitle.Text = $Title
    $Script:Ui.ResultText.Text = 'Running...'
    Set-PatchWinRELamp -Control $Script:Ui.ResultLamp -State Off
}

function Start-PatchWinREOperation {
    param(
        [ValidateSet('Run', 'Check')]
        [string]$Kind
    )
    if ($Script:ActiveRun) { return }
    if ($Kind -eq 'Check' -and ($Script:Mode -ne 'Run' -or -not $Script:IsElevated)) { return }
    if ($Script:DebounceTimer -and $Script:DebounceTimer.IsEnabled) {
        $Script:DebounceTimer.Stop()
        Sync-PatchWinREStateFromControls
    }
    if ($Kind -eq 'Run') {
        $ValidationResult = Get-PatchWinRECurrentValidation
        if ($ValidationResult.Readiness -eq 'Blocked') { return }
        $ScriptPath = Join-Path -Path $Script:ScriptRoot -ChildPath 'Patch-WinRE.ps1'
        $Parameter = Get-PatchWinREParameter -State $Script:State -ForceToConsole
        $FullCommand = ConvertTo-PatchWinRECommand -Parameter $Parameter -Format OneLiner -ScriptPath $ScriptPath
        $ConfirmText = "The following command will run in an elevated Windows PowerShell 5.1 process:`r`n`r`n$FullCommand"
        if ($ValidationResult.Readiness -eq 'Review') { $ConfirmText += "`r`n`r`nREVIEW: Check the highlighted findings before continuing." }
        if ($Script:State.WhatIf) { $ConfirmText += "`r`n`r`nThis is a -WhatIf preview; supported changes will not be applied." }
        $Choice = [System.Windows.MessageBox]::Show($Script:Window, $ConfirmText, 'Confirm Patch-WinRE run', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning, [System.Windows.MessageBoxResult]::No)
        if ($Choice -ne [System.Windows.MessageBoxResult]::Yes) { return }
        $Content = New-PatchWinREWrapperContent -Parameter $Parameter -ScriptPath $ScriptPath
        Set-PatchWinREOutputHeader -Title ('Run started {0}' -f (Get-Date -Format 'G'))
        Write-Log -Message ('Starting Patch-WinRE: {0}' -f $FullCommand) -Component 'Runner'
        $Preview = [bool]$Script:State.WhatIf
    } else {
        $Content = New-PatchWinRESystemCheckScript
        Set-PatchWinREOutputHeader -Title ('System check started {0}' -f (Get-Date -Format 'G'))
        Write-Log -Message 'Starting read-only system check.' -Component 'SystemCheck'
        $Preview = $false
    }
    try {
        $Script:ActiveRun = Start-PatchWinREChildScript -Content $Content -Kind $Kind -WorkingDirectory $Script:ScriptRoot -Preview:$Preview
        $Script:Ui.CancelButton.IsEnabled = $true
        $Script:Ui.CancelButton.Visibility = 'Visible'
        $Script:Ui.RunButton.Visibility = 'Collapsed'
        $Script:RunTimer.Start()
        Update-PatchWinREView
    } catch {
        $Script:ActiveRun = $null
        Write-Log -Message ('Could not start child process: {0}' -f $_.Exception.Message) -Component 'Runner' -Type 3
        $Entry = ConvertFrom-PatchWinREOutputLine -Line ('Could not start child process: {0}' -f $_.Exception.Message) -Stream Error
        Add-PatchWinREOutputEntry -Entry $Entry
        Set-PatchWinREOutputResult -State Blocked -Title 'Failed to start' -Detail $_.Exception.Message
        $Script:Ui.CancelButton.Visibility = 'Collapsed'
        $Script:Ui.RunButton.Visibility = 'Visible'
        Update-PatchWinREView
    }
}

function Complete-PatchWinREOperation {
    param([object]$Run)
    $Script:RunTimer.Stop()
    try {
        if ($Run.Kind -eq 'Check' -and -not $Run.Cancelled) {
            $Discovery = ConvertFrom-PatchWinRESystemCheckOutput -Lines $Run.Output.ToArray()
            $Finding = Get-PatchWinRESystemFinding -Discovery $Discovery -State $Script:State
            foreach ($Entry in $Finding.Entries) { Add-PatchWinREOutputEntry -Entry $Entry }
            $State = if ($Run.Runner.ExitCode -ne 0) { 'Blocked' } else { $Finding.Readiness }
            $Detail = $Finding.Detail
            $Title = $Finding.Title
            if ($Run.Runner.ExitCode -ne 0) {
                $Title = 'System check failed'
                $Detail += (' Child process exit code: {0}.' -f $Run.Runner.ExitCode)
            }
            Set-PatchWinREOutputResult -State $State -Title $Title -Detail $Detail
            Write-Log -Message ('System check finished with {0}.' -f $Finding.Title) -Component 'SystemCheck'
        } else {
            $RunResult = Get-PatchWinRERunResult -Entry $Run.Entries.ToArray() -ExitCode $Run.Runner.ExitCode -Cancelled:$Run.Cancelled -Preview:$Run.Preview
            Set-PatchWinREOutputResult -State $RunResult.State -Title $RunResult.Title -Detail $RunResult.Detail
            Write-Log -Message ('Patch-WinRE finished: {0}' -f $RunResult.Title) -Component 'Runner' -Type $(if ($RunResult.State -eq 'Blocked') { 3 } elseif ($RunResult.State -eq 'Review') { 2 } else { 1 })
        }
    } catch {
        $Message = 'Could not process child output: {0}' -f $_.Exception.Message
        Write-Log -Message $Message -Component $Run.Kind -Type 3
        $Entry = ConvertFrom-PatchWinREOutputLine -Line $Message -Stream Error
        Add-PatchWinREOutputEntry -Entry $Entry
        Set-PatchWinREOutputResult -State Blocked -Title 'Output processing failed' -Detail $_.Exception.Message
    } finally {
        $Run.Runner.Dispose()
        if (-not (Remove-PatchWinRERunDirectory -Path $Run.Directory)) {
            Write-Log -Message ('Could not remove temporary run folder {0}.' -f $Run.Directory) -Component 'Runner' -Type 2
            $Script:Ui.LogStatusText.Text = 'Temporary folder cleanup failed: {0}' -f $Run.Directory
        }
        $Script:ActiveRun = $null
        $Script:Ui.CancelButton.Visibility = 'Collapsed'
        $Script:Ui.RunButton.Visibility = 'Visible'
        Update-PatchWinREView
    }
}

function Receive-PatchWinREProcessOutput {
    if (-not $Script:ActiveRun) { return }
    $Run = $Script:ActiveRun
    foreach ($Line in $Run.Runner.Drain()) {
        $Run.Output.Add($Line)
        $Stream = if ($Line.StartsWith('E')) { 'Error' } else { 'Output' }
        $Text = $Line.Substring(1)
        if ($Run.Kind -eq 'Check') {
            if (-not $Text.StartsWith('PATCHWINRE-JSON:', [System.StringComparison]::Ordinal) -and
                -not $Text.StartsWith('{', [System.StringComparison]::Ordinal)) {
                $Entry = ConvertFrom-PatchWinREOutputLine -Line $Text -Stream $Stream -PreviousEntry $Run.LastEntry
                $Run.Entries.Add($Entry)
                $Run.LastEntry = $Entry
                Add-PatchWinREOutputEntry -Entry $Entry
            }
        } else {
            $Entry = ConvertFrom-PatchWinREOutputLine -Line $Text -Stream $Stream -PreviousEntry $Run.LastEntry
            $Run.Entries.Add($Entry)
            $Run.LastEntry = $Entry
            Add-PatchWinREOutputEntry -Entry $Entry
        }
    }
    if ($Run.Runner.IsFinished) {
        foreach ($Line in $Run.Runner.Drain()) {
            $Run.Output.Add($Line)
            $Stream = if ($Line.StartsWith('E')) { 'Error' } else { 'Output' }
            $Text = $Line.Substring(1)
            if ($Run.Kind -ne 'Check' -or
                (-not $Text.StartsWith('PATCHWINRE-JSON:', [System.StringComparison]::Ordinal) -and
                 -not $Text.StartsWith('{', [System.StringComparison]::Ordinal))) {
                $Entry = ConvertFrom-PatchWinREOutputLine -Line $Text -Stream $Stream -PreviousEntry $Run.LastEntry
                $Run.Entries.Add($Entry)
                $Run.LastEntry = $Entry
                Add-PatchWinREOutputEntry -Entry $Entry
            }
        }
        Complete-PatchWinREOperation -Run $Run
    }
}

function Stop-PatchWinREActiveOperation {
    if (-not $Script:ActiveRun) { return }
    try {
        $Message = Stop-PatchWinREProcessTree -ProcessId $Script:ActiveRun.Id
        $Script:ActiveRun.Cancelled = $true
        $Script:Ui.CancelButton.IsEnabled = $false
        Write-Log -Message ('Cancellation requested. {0}' -f $Message) -Component 'Runner' -Type 2
    } catch {
        Write-Log -Message ('Could not cancel child process: {0}' -f $_.Exception.Message) -Component 'Runner' -Type 3
        $Script:Ui.LogStatusText.Text = 'Cancel failed: {0}' -f $_.Exception.Message
    }
}

function Copy-PatchWinRECommand {
    if ($Script:DebounceTimer -and $Script:DebounceTimer.IsEnabled) {
        $Script:DebounceTimer.Stop()
        Sync-PatchWinREStateFromControls
    }
    $Text = $Script:Ui.CommandBox.Text
    $LastError = $null
    for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
        try {
            [System.Windows.Clipboard]::SetText($Text)
            $Script:Ui.LogStatusText.Text = 'Command copied to the clipboard.'
            return
        } catch {
            $LastError = $_
            Start-Sleep -Milliseconds 100
        }
    }
    Write-Log -Message ('Clipboard copy failed: {0}' -f $LastError.Exception.Message) -Component 'Clipboard' -Type 3
    $Script:Ui.LogStatusText.Text = 'Clipboard copy failed: {0}' -f $LastError.Exception.Message
}

function Open-PatchWinRELogFile {
    if (-not $Script:LogFilePath -or -not [System.IO.File]::Exists($Script:LogFilePath)) {
        $Script:Ui.LogStatusText.Text = 'The GUI log file is not available.'
        return
    }
    try { Start-Process -FilePath $Script:LogFilePath -ErrorAction Stop }
    catch {
        # No file association for .log: fall back to Notepad
        try { Start-Process -FilePath 'notepad.exe' -ArgumentList ('"{0}"' -f $Script:LogFilePath) -ErrorAction Stop }
        catch { $Script:Ui.LogStatusText.Text = 'Opening the log file failed: {0}' -f $_.Exception.Message }
    }
}

function Save-PatchWinREOutputFile {
    if ($Script:OutputEntries.Count -eq 0) { return }
    $Dialog = New-Object Microsoft.Win32.SaveFileDialog
    $Dialog.Title = 'Save Patch-WinRE output'
    $Dialog.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
    $Dialog.DefaultExt = '.txt'
    $Dialog.AddExtension = $true
    $Dialog.FileName = 'PatchWinRE-output.txt'
    if ($Dialog.ShowDialog($Script:Window) -eq $true) {
        try {
            $Header = @(
                'Patch-WinRE GUI output'
                ('Saved: {0}' -f (Get-Date -Format 'G'))
                ('Operation: {0}' -f $Script:State.Operation)
                ('Result: {0}' -f $Script:Ui.ResultText.Text)
            )
            Save-PatchWinREOutput -Path $Dialog.FileName -Header $Header -Entry $Script:OutputEntries.ToArray()
            $Script:Ui.LogStatusText.Text = 'Output saved to {0}' -f $Dialog.FileName
            Write-Log -Message ('Output saved to {0}' -f $Dialog.FileName) -Component 'Output'
        } catch {
            Write-Log -Message ('Saving output failed: {0}' -f $_.Exception.Message) -Component 'Output' -Type 3
            $Script:Ui.LogStatusText.Text = 'Saving output failed: {0}' -f $_.Exception.Message
        }
    }
}

function Restart-PatchWinREGUIAsAdministrator {
    $PowerShellPath = Get-PatchWinREPowerShellPath
    $Arguments = '-NoProfile -STA -ExecutionPolicy Bypass -File {0}' -f (ConvertTo-PatchWinRENativeArgument -Value $PSCommandPath)
    if ($GenerateOnly) { $Arguments += ' -GenerateOnly' }
    if ($LogPath) { $Arguments += ' -LogPath {0}' -f (ConvertTo-PatchWinRENativeArgument -Value $LogPath) }
    if ($LogFile) { $Arguments += ' -LogFile {0}' -f (ConvertTo-PatchWinRENativeArgument -Value $LogFile) }
    try {
        Start-Process -FilePath $PowerShellPath -ArgumentList $Arguments -Verb RunAs | Out-Null
        $Script:Window.Close()
    } catch {
        Write-Log -Message ('Administrator restart failed: {0}' -f $_.Exception.Message) -Component 'Mode' -Type 3
        $Script:Ui.LogStatusText.Text = 'Administrator restart failed: {0}' -f $_.Exception.Message
    }
}

function Add-PatchWinREOperationItems {
    foreach ($Operation in $Script:Operations) {
        $Item = New-Object System.Windows.Controls.ListBoxItem
        $Item.IsEnabled = [bool]$Operation.Enabled
        $Item.Tag = $Operation.Key
        if (-not $Operation.Enabled) {
            $Item.ToolTip = $Operation.DisabledReason
            [System.Windows.Automation.AutomationProperties]::SetHelpText($Item, $Operation.DisabledReason)
        }
        $Stack = New-Object System.Windows.Controls.StackPanel
        $Name = New-Object System.Windows.Controls.TextBlock
        $Name.Text = $Operation.DisplayName
        $Name.FontSize = 14
        $Name.FontWeight = [System.Windows.FontWeights]::SemiBold
        $Summary = New-Object System.Windows.Controls.TextBlock
        $Summary.Text = $Operation.Summary
        $Summary.FontSize = 12
        $Summary.TextWrapping = [System.Windows.TextWrapping]::Wrap
        [void]$Stack.Children.Add($Name)
        [void]$Stack.Children.Add($Summary)
        $Item.Content = $Stack
        [void]$Script:Ui.OperationList.Items.Add($Item)
    }
}

function Initialize-PatchWinREWindow {
    $XamlPath = Join-Path -Path $Script:ScriptRoot -ChildPath 'GUI\MainWindow.xaml'
    [xml]$Xaml = [System.IO.File]::ReadAllText($XamlPath)
    $Reader = New-Object System.Xml.XmlNodeReader -ArgumentList $Xaml
    try { $Script:Window = [System.Windows.Markup.XamlReader]::Load($Reader) }
    finally { $Reader.Close() }
    foreach ($Match in [regex]::Matches([System.IO.File]::ReadAllText($XamlPath), 'x:Name="([^"]+)"')) {
        $Name = $Match.Groups[1].Value
        if (-not $Script:Ui.ContainsKey($Name)) {
            $Control = $Script:Window.FindName($Name)
            if ($null -ne $Control) { $Script:Ui[$Name] = $Control }
        }
    }
    $RequiredNames = @('OperationList', 'SettingsPanel', 'SourceBox', 'WimBox', 'RootBox', 'ReadyTitle', 'CommandBox', 'OutputBox', 'RunButton')
    foreach ($Name in $RequiredNames) {
        if (-not $Script:Ui.ContainsKey($Name)) { throw "Required XAML control '$Name' could not be found." }
    }
    if ([System.Windows.SystemParameters]::HighContrast) {
        foreach ($Key in @('SurfaceBrush', 'PanelBrush', 'FieldBrush')) { $Script:Window.Resources[$Key] = [System.Windows.SystemColors]::WindowBrush }
        foreach ($Key in @('TextBrush', 'LineBrush', 'MutedBrush')) { $Script:Window.Resources[$Key] = [System.Windows.SystemColors]::WindowTextBrush }
        $Script:Window.Resources['AccentBrush'] = [System.Windows.SystemColors]::HighlightBrush
        $Script:Window.Resources['PrimaryBrush'] = [System.Windows.SystemColors]::HighlightBrush
        $Script:Window.Resources['PrimaryTextBrush'] = [System.Windows.SystemColors]::HighlightTextBrush
    }

    $Script:IsElevated = Test-PatchWinREElevated
    $Script:Mode = if ($Script:IsElevated -and -not $GenerateOnly) { 'Run' } else { 'Generate' }
    $DefaultRoot = (Get-PatchWinREScriptDefault).Root
    $Script:State = New-PatchWinREGuiState -Root $DefaultRoot -SourceBase $Script:ScriptRoot
    $Script:State.ToConsole = $Script:Mode -eq 'Run'
    $Script:Operations = @(Get-PatchWinREOperation)
    $Script:Ui.VersionText.Text = 'GUI 1.0.0'
    if ($Script:Mode -eq 'Run') {
        $Script:Ui.ModeText.Text = 'Administrator mode. Run and Check System are available.'
    } elseif ($GenerateOnly) {
        $Script:Ui.ModeText.Text = 'Generate-only mode. This window can only generate the command.'
    } else {
        $Script:Ui.ModeText.Text = 'Not elevated. This window can only generate the command.'
    }
    Set-PatchWinRELamp -Control $Script:Ui.ModeLamp -State $(if ($Script:Mode -eq 'Run') { 'Pass' } else { 'Review' })
    $Script:Ui.RestartButton.Visibility = if (-not $Script:IsElevated -and -not $GenerateOnly) { 'Visible' } else { 'Collapsed' }
    $CheckTooltip = Get-PatchWinRESystemCheckTooltip -IsElevated $Script:IsElevated -GenerateOnly ([bool]$GenerateOnly)
    $Script:Ui.CheckSystemButton.ToolTip = $CheckTooltip
    [System.Windows.Automation.AutomationProperties]::SetHelpText($Script:Ui.CheckSystemButton, $CheckTooltip)
    if ($Script:LogFilePath) {
        $Script:Ui.LogStatusText.Text = ''
        $Script:Ui.LogFileRun.Text = $Script:LogStatus
        $Script:Ui.LogFileText.ToolTip = 'Open {0}' -f $Script:LogFilePath
        $Script:Ui.LogFileText.Visibility = 'Visible'
        Write-Log -Message 'GUI initialized.' -Component 'Startup'
    } else {
        $Script:Ui.LogStatusText.Text = $Script:LogStatus
    }

    foreach ($Name in @('ModeLamp', 'SourceLamp', 'WIMFilePathLamp', 'RecoveryDriveSizeInGBLamp', 'DeleteBackupsLamp', 'RootLamp', 'WorkingDirectoryLamp', 'BackupDirectoryLamp', 'MountDirectoryLamp', 'LogDirectoryLamp', 'ResultLamp', 'LegendLampPass', 'LegendLampReview', 'LegendLampBlocked')) {
        if ($Script:Ui.ContainsKey($Name)) { Set-PatchWinRELamp -Control $Script:Ui[$Name] -State Off }
    }
    Set-PatchWinRELamp -Control $Script:Ui.LegendLampPass -State Pass
    Set-PatchWinRELamp -Control $Script:Ui.LegendLampReview -State Review
    Set-PatchWinRELamp -Control $Script:Ui.LegendLampBlocked -State Blocked
    Add-PatchWinREOperationItems

    $Script:DebounceTimer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:DebounceTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $Script:DebounceTimer.Add_Tick({
        param($EventSource, $EventData)
        $Script:DebounceTimer.Stop()
        Sync-PatchWinREStateFromControls
    })
    $Script:RunTimer = New-Object System.Windows.Threading.DispatcherTimer
    $Script:RunTimer.Interval = [TimeSpan]::FromMilliseconds(100)
    $Script:RunTimer.Add_Tick({
        param($EventSource, $EventData)
        Receive-PatchWinREProcessOutput
    })

    foreach ($Name in @('SourceBox', 'WimBox', 'SizeBox', 'RootBox', 'WorkingDirectoryBox', 'BackupDirectoryBox', 'MountDirectoryBox', 'LogDirectoryBox')) {
        $Script:Ui[$Name].Add_TextChanged({
            param($EventSource, $EventData)
            if (-not $Script:IsUpdating -and -not $Script:ActiveRun) {
                $Script:DebounceTimer.Stop()
                $Script:DebounceTimer.Start()
            }
        })
        $Script:Ui.RootResetButton.Add_Click({
            param($EventSource, $EventData)
            $DefaultRoot = (Get-PatchWinREScriptDefault).Root
            Set-PatchWinRERoot -State $Script:State -Root $DefaultRoot
            $Script:IsUpdating = $true
            $Script:Ui.RootBox.Text = $Script:State.Root
            foreach ($FolderName in (Get-PatchWinREFolderName)) {
                if ($Script:State.FollowsRoot[$FolderName]) { $Script:Ui["${FolderName}Box"].Text = $Script:State.$FolderName }
            }
            $Script:IsUpdating = $false
            Update-PatchWinREView
        })
    }
    foreach ($Name in @('UseSizeCheck', 'CreateWinREDriveCheck', 'DoNotExpandCheck', 'AbortIfFailedCheck', 'DeleteBackupsCheck', 'ToConsoleCheck', 'WhatIfCheck', 'ShowAllCheck')) {
        $Script:Ui[$Name].Add_Click({
            param($EventSource, $EventData)
            Sync-PatchWinREStateFromControls
        })
    }
    foreach ($Name in @('FormatOneLiner', 'FormatSplat', 'FormatFile')) {
        $Script:Ui[$Name].Add_Checked({
            param($EventSource, $EventData)
            Update-PatchWinREView
        })
    }
    $Script:Ui.OperationList.Add_SelectionChanged({
        param($EventSource, $EventData)
        if ($Script:Ui.OperationList.SelectedItem -and -not $Script:ActiveRun) {
            if ($Script:DebounceTimer -and $Script:DebounceTimer.IsEnabled) {
                $Script:DebounceTimer.Stop()
                Sync-PatchWinREStateFromControls
            }
            $Script:State.Operation = $Script:Ui.OperationList.SelectedItem.Tag
            Update-PatchWinREView
        }
    })
    $Script:Ui.RootBox.Add_LostFocus({
        param($EventSource, $EventData)
        if (-not $Script:IsUpdating -and -not $Script:ActiveRun) {
            $Script:DebounceTimer.Stop()
            Sync-PatchWinREStateFromControls
        }
    })

    foreach ($FolderName in (Get-PatchWinREFolderName)) {
        if ($FolderName -eq 'Root') { continue }
        $Script:Ui["${FolderName}ResetButton"].Add_Click({
            param($EventSource, $EventData)
            $Name = $EventSource.Tag
            Reset-PatchWinREFolder -State $Script:State -Name $Name
            $Script:IsUpdating = $true
            $Script:Ui["${Name}Box"].Text = $Script:State.$Name
            $Script:IsUpdating = $false
            Update-PatchWinREView
        }.GetNewClosure())
        $Script:Ui["${FolderName}BrowseButton"].Add_Click({
            param($EventSource, $EventData)
            $Name = $EventSource.Tag
            $InitialFolder = $Script:State.$Name
            $Selected = Select-PatchWinREFolder -Window $Script:Window -Title ('Select {0}' -f $Name) -InitialFolder $InitialFolder
            if ($Selected) {
                Set-PatchWinREFolder -State $Script:State -Name $Name -Path $Selected
                $Script:IsUpdating = $true
                $Script:Ui["${Name}Box"].Text = $Selected
                $Script:IsUpdating = $false
                Update-PatchWinREView
            }
        }.GetNewClosure())
        $Script:Ui["${FolderName}ResetButton"].Tag = $FolderName
        $Script:Ui["${FolderName}BrowseButton"].Tag = $FolderName
    }
    $Script:Ui.RootBrowseButton.Add_Click({
        param($EventSource, $EventData)
        $Selected = Select-PatchWinREFolder -Window $Script:Window -Title 'Select root folder' -InitialFolder $Script:State.Root
        if ($Selected) {
            Set-PatchWinRERoot -State $Script:State -Root $Selected
            $Script:IsUpdating = $true
            $Script:Ui.RootBox.Text = $Selected
            foreach ($FolderName in (Get-PatchWinREFolderName)) { $Script:Ui["${FolderName}Box"].Text = $Script:State.$FolderName }
            $Script:IsUpdating = $false
            Update-PatchWinREView
        }
    })
    $Script:Ui.SourceFolderButton.Add_Click({
        param($EventSource, $EventData)
        $Operation = Get-PatchWinREOperation -Key $Script:State.Operation
        $SourcePath = $Script:State.($Operation.SourceParameter)
        $Selected = Select-PatchWinREFolder -Window $Script:Window -Title 'Select source folder' -InitialFolder $SourcePath
        if ($Selected) { $Script:Ui.SourceBox.Text = $Selected }
    })
    $Script:Ui.SourceFileButton.Add_Click({
        param($EventSource, $EventData)
        $Operation = Get-PatchWinREOperation -Key $Script:State.Operation
        $Extensions = @($Operation.SourceExtensions | ForEach-Object { '*' + $_ }) -join ';'
        $Filter = ('Supported source files|{0}|All files|*.*' -f $Extensions)
        $SourcePath = $Script:State.($Operation.SourceParameter)
        $Selected = Select-PatchWinREFile -Window $Script:Window -Title 'Select source file' -Filter $Filter -InitialPath $SourcePath
        if ($Selected) { $Script:Ui.SourceBox.Text = $Selected }
    })
    $Script:Ui.WimFileButton.Add_Click({
        param($EventSource, $EventData)
        $Selected = Select-PatchWinREFile -Window $Script:Window -Title 'Select WinRE image' -Filter 'Windows image (*.wim)|*.wim|All files (*.*)|*.*' -InitialPath $Script:State.WimBrowseFolder
        if ($Selected) { $Script:Ui.WimBox.Text = $Selected }
    })
    $Script:Ui.CopyButton.Add_Click({ param($EventSource, $EventData) Copy-PatchWinRECommand })
    $Script:Ui.RunButton.Add_Click({ param($EventSource, $EventData) Start-PatchWinREOperation -Kind Run })
    $Script:Ui.CancelButton.Add_Click({ param($EventSource, $EventData) Stop-PatchWinREActiveOperation })
    $Script:Ui.CheckSystemButton.Add_Click({ param($EventSource, $EventData) Start-PatchWinREOperation -Kind Check })
    $Script:Ui.SaveOutputButton.Add_Click({ param($EventSource, $EventData) Save-PatchWinREOutputFile })
    $Script:Ui.RestartButton.Add_Click({ param($EventSource, $EventData) Restart-PatchWinREGUIAsAdministrator })
    $Script:Ui.LogFileLink.Add_Click({ param($EventSource, $EventData) Open-PatchWinRELogFile })
    $Script:Window.Add_Closing({
        param($EventSource, $EventData)
        if ($Script:ActiveRun) {
            $Choice = [System.Windows.MessageBox]::Show($Script:Window, 'A child process is still running. Stop it and close the window?', 'Close Patch-WinRE GUI', [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning, [System.Windows.MessageBoxResult]::No)
            if ($Choice -ne [System.Windows.MessageBoxResult]::Yes) {
                $EventData.Cancel = $true
                return
            }
            try {
                [void](Stop-PatchWinREProcessTree -ProcessId $Script:ActiveRun.Id)
                $Script:ActiveRun.Runner.Dispose()
                [void](Remove-PatchWinRERunDirectory -Path $Script:ActiveRun.Directory)
                $Script:ActiveRun = $null
            } catch {
                $EventData.Cancel = $true
                Write-Log -Message ('Could not stop the child process; window remains open: {0}' -f $_.Exception.Message) -Component 'Runner' -Type 3
            }
        }
        if (-not $EventData.Cancel) {
            $Script:RunTimer.Stop()
            $Script:DebounceTimer.Stop()
            Write-Log -Message 'GUI closed.' -Component 'Shutdown'
        }
    })

    $Script:Ui.OperationList.SelectedItem = @($Script:Ui.OperationList.Items | Where-Object { $_.Tag -eq 'Backup' })[0]
    $Script:IsUpdating = $true
    foreach ($FolderName in (Get-PatchWinREFolderName)) { $Script:Ui["${FolderName}Box"].Text = $Script:State.$FolderName }
    $Script:Ui.SourceBox.Text = ''
    $Script:Ui.WimBox.Text = ''
    $Script:Ui.SizeBox.Text = [string]$Script:State.RecoverySizeGB
    $Script:IsUpdating = $false
    Update-PatchWinREView
}

Initialize-Script
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
. (Join-Path -Path $Script:ScriptRoot -ChildPath 'GUI\PatchWinREGUI.Core.ps1')
. (Join-Path -Path $Script:ScriptRoot -ChildPath 'GUI\PatchWinREGUI.Validation.ps1')
. (Join-Path -Path $Script:ScriptRoot -ChildPath 'GUI\PatchWinREGUI.FolderPicker.ps1')
. (Join-Path -Path $Script:ScriptRoot -ChildPath 'GUI\PatchWinREGUI.Runner.ps1')
. (Join-Path -Path $Script:ScriptRoot -ChildPath 'GUI\PatchWinREGUI.SystemCheck.ps1')
Initialize-PatchWinREWindow
Write-Log -Message ('Starting in {0} mode.' -f $Script:Mode) -Component 'Startup'
[void]$Script:Window.ShowDialog()
