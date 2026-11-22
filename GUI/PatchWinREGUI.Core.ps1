<#
.SYNOPSIS
    Rules engine, command builder and output parser for the Patch-WinRE GUI.
.DESCRIPTION
    Dot-sourced by Start-PatchWinREGUI.ps1 and by the Pester tests. Contains no WPF code.
    - Operation table that maps the GUI operations to the parameter sets of Patch-WinRE.ps1.
    - Structural parameter set model, compared with the PowerShell binder by the parity tests.
    - GUI state, root folder logic and sibling source defaults (patch, drivers, wim).
    - Parameter emission and the three command formats (one-liner, splat, powershell.exe -File).
    - Content of the temporary wrapper script that runs Patch-WinRE.ps1 in a child process.
    - Output parser for the -ToConsole format and the run result classification.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: PatchWinREGUI.Core.ps1
    Initial creation date: 2026-11-19
    Last change: 2026-11-19
    Changes: Initial version
#>

function Get-PatchWinREScriptDefault {
    # Defaults of the directory parameters in Patch-WinRE.ps1. The parity tests compare them with the script.
    [PSCustomObject]@{
        Root             = 'C:\WinRE-Customization\'
        WorkingDirectory = 'C:\WinRE-Customization\'
        BackupDirectory  = 'C:\WinRE-Customization\WinREBackups\'
        MountDirectory   = 'C:\WinRE-Customization\WinREMount\'
        LogDirectory     = 'C:\WinRE-Customization\Logs\'
        RecoverySizeGB   = 1
    }
}

function Get-PatchWinREFolderName {
    @('WorkingDirectory', 'BackupDirectory', 'MountDirectory', 'LogDirectory')
}

function Get-PatchWinRESetDefiningParameter {
    # The ten parameters that decide the parameter set. All other parameters are common to every set.
    @('FoDDirectory', 'PatchFilesGDRDUorLCU', 'PatchFilesDUorSOS', 'FilesDriver', 'ReplaceWIM', 'WIMFilePath', 'CreateWinREDrive', 'DoNotExpandRecoveryPartition', 'AbortIfFailed', 'ReportOnly')
}

function Get-PatchWinREParameterSetModel {
    # Structural model of the parameter sets in Patch-WinRE.ps1 (Mandatory and Optional among the set-defining parameters).
    @(
        [PSCustomObject]@{ Name = 'ReportOnly'; Mandatory = @(); Optional = @('ReportOnly') }
        [PSCustomObject]@{ Name = 'CreateWinREDrive'; Mandatory = @('CreateWinREDrive'); Optional = @('WIMFilePath') }
        [PSCustomObject]@{ Name = 'FoD'; Mandatory = @('FoDDirectory'); Optional = @('CreateWinREDrive') }
        [PSCustomObject]@{ Name = 'Driver'; Mandatory = @('FilesDriver'); Optional = @('CreateWinREDrive', 'DoNotExpandRecoveryPartition') }
        [PSCustomObject]@{ Name = 'PatchDUorSOS'; Mandatory = @('PatchFilesDUorSOS'); Optional = @('CreateWinREDrive', 'DoNotExpandRecoveryPartition', 'AbortIfFailed') }
        [PSCustomObject]@{ Name = 'PatchGDRDUorLCU'; Mandatory = @('PatchFilesGDRDUorLCU'); Optional = @('CreateWinREDrive', 'DoNotExpandRecoveryPartition', 'AbortIfFailed') }
        [PSCustomObject]@{ Name = 'ReplaceWIM'; Mandatory = @('ReplaceWIM', 'WIMFilePath'); Optional = @('CreateWinREDrive') }
    )
}

function Resolve-PatchWinREParameterSet {
    <#
    .SYNOPSIS
        Returns the parameter set that a combination of present parameters resolves to, or $null if it is invalid.
    .PARAMETER Name
        Names of the parameters that are present. Parameters that do not define the set are ignored.
    #>
    param(
        [AllowEmptyCollection()]
        [string[]]$Name = @()
    )
    $SetDefining = Get-PatchWinRESetDefiningParameter
    $Present = @($Name | Where-Object { $SetDefining -contains $_ })
    $Candidates = @(
        foreach ($Set in (Get-PatchWinREParameterSetModel)) {
            $Allowed = @($Set.Mandatory) + @($Set.Optional)
            $MissingMandatory = @($Set.Mandatory | Where-Object { $Present -notcontains $_ })
            $NotAllowed = @($Present | Where-Object { $Allowed -notcontains $_ })
            if ($MissingMandatory.Count -eq 0 -and $NotAllowed.Count -eq 0) { $Set.Name }
        }
    )
    if ($Candidates.Count -eq 1) { return $Candidates[0] }
    return $null
}

function Get-PatchWinREOperation {
    <#
    .SYNOPSIS
        Returns the operation table of the GUI, or a single operation if -Key is used.
    #>
    param(
        [string]$Key
    )
    $Operations = @(
        [PSCustomObject]@{
            Key                 = 'Backup'
            DisplayName         = 'Backup and verify'
            Summary             = 'Default run: back up WinRE and check the setup'
            ParameterSet        = 'ReportOnly'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = ''
            SourceParameter     = ''
            SourceExtensions    = @()
            Wim                 = 'None'
            Options             = @()
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Creates a backup of WinRE.wim and ReAgent.xml and checks the recovery configuration. Patch-WinRE.ps1 runs this when it is started without parameters. With a recovery size, the recovery partition is resized if it is smaller.'
        }
        [PSCustomObject]@{
            Key                 = 'ReportOnly'
            DisplayName         = 'Report only'
            Summary             = 'Show the WinRE and recovery partition state'
            ParameterSet        = 'ReportOnly'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = 'ReportOnly'
            SourceParameter     = ''
            SourceExtensions    = @()
            Wim                 = 'None'
            Options             = @()
            AllowsSize          = $false
            AllowsDeleteBackups = $false
            Description         = 'Reports the state of WinRE and the recovery partition. The script creates the working and log folders and always exits with code 0.'
        }
        [PSCustomObject]@{
            Key                 = 'PatchGDRDUorLCU'
            DisplayName         = 'Patch: GDR-DU / LCU'
            Summary             = 'Apply cumulative or GDR-DU updates'
            ParameterSet        = 'PatchGDRDUorLCU'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = ''
            SourceParameter     = 'PatchFilesGDRDUorLCU'
            SourceExtensions    = @('.msu', '.cab')
            Wim                 = 'None'
            Options             = @('CreateWinREDrive', 'DoNotExpandRecoveryPartition', 'AbortIfFailed')
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Applies a latest cumulative update (LCU) or GDR dynamic update to WinRE. Accepts a folder with .msu or .cab files or a single file. Files starting with "ssu" are applied first. The recovery partition is checked for at least 1 GB.'
        }
        [PSCustomObject]@{
            Key                 = 'PatchDUorSOS'
            DisplayName         = 'Patch: DU / SafeOS'
            Summary             = 'Apply Dynamic Update or SafeOS packages'
            ParameterSet        = 'PatchDUorSOS'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = ''
            SourceParameter     = 'PatchFilesDUorSOS'
            SourceExtensions    = @('.cab')
            Wim                 = 'None'
            Options             = @('CreateWinREDrive', 'DoNotExpandRecoveryPartition', 'AbortIfFailed')
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Applies Safe OS dynamic updates (DU / SafeOS) to WinRE. Accepts a folder with .cab files or a single .cab file.'
        }
        [PSCustomObject]@{
            Key                 = 'Driver'
            DisplayName         = 'Add drivers'
            Summary             = 'Inject drivers from a folder or .inf file'
            ParameterSet        = 'Driver'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = ''
            SourceParameter     = 'FilesDriver'
            SourceExtensions    = @('.inf')
            Wim                 = 'None'
            Options             = @('CreateWinREDrive', 'DoNotExpandRecoveryPartition')
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Adds drivers to WinRE, for example network or storage drivers. Accepts a folder with at least one .inf file or a single .inf file.'
        }
        [PSCustomObject]@{
            Key                 = 'ReplaceWIM'
            DisplayName         = 'Replace WinRE image'
            Summary             = 'Use your own WinRE.wim'
            ParameterSet        = 'ReplaceWIM'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = 'ReplaceWIM'
            SourceParameter     = ''
            SourceExtensions    = @()
            Wim                 = 'Required'
            Options             = @('CreateWinREDrive')
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Replaces WinRE.wim with the selected image or installs it if none exists. Use an unmodified WinRE.wim of the same OS version.'
        }
        [PSCustomObject]@{
            Key                 = 'CreateWinREDrive'
            DisplayName         = 'Create recovery partition'
            Summary             = 'Create a new recovery partition only'
            ParameterSet        = 'CreateWinREDrive'
            Enabled             = $true
            DisabledReason      = ''
            SwitchParameter     = 'CreateWinREDrive'
            SourceParameter     = ''
            SourceExtensions    = @()
            Wim                 = 'Optional'
            Options             = @()
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Creates a recovery partition by shrinking the OS partition (1 GB unless a size is set). Optionally installs the selected WinRE.wim first.'
        }
        [PSCustomObject]@{
            Key                 = 'FoD'
            DisplayName         = 'Features on Demand'
            Summary             = 'Not implemented in the script yet'
            ParameterSet        = 'FoD'
            Enabled             = $false
            DisabledReason      = 'Patch-WinRE.ps1 does not implement Features on Demand yet.'
            SwitchParameter     = ''
            SourceParameter     = 'FoDDirectory'
            SourceExtensions    = @()
            Wim                 = 'None'
            Options             = @('CreateWinREDrive')
            AllowsSize          = $true
            AllowsDeleteBackups = $true
            Description         = 'Features on Demand and language packs. Patch-WinRE.ps1 does not implement this operation yet.'
        }
    )
    if ($Key) {
        return ($Operations | Where-Object { $_.Key -eq $Key } | Select-Object -First 1)
    }
    return $Operations
}

function ConvertTo-PatchWinRENormalPath {
    # Normalises a path for comparisons: trimmed, backslashes, no trailing backslash except for drive roots.
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $Value = $Path.Trim().Replace('/', '\')
    if ($Value -match '^[A-Za-z]:\\*$') { return $Value.Substring(0, 2).ToUpperInvariant() + '\' }
    return $Value.TrimEnd('\')
}

function Test-PatchWinRESamePath {
    param(
        [AllowEmptyString()][AllowNull()][string]$Path,
        [AllowEmptyString()][AllowNull()][string]$OtherPath
    )
    $Left = ConvertTo-PatchWinRENormalPath -Path $Path
    $Right = ConvertTo-PatchWinRENormalPath -Path $OtherPath
    if (-not $Left -or -not $Right) { return $false }
    return [string]::Equals($Left, $Right, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PatchWinREPathInside {
    # True if $Path equals $Container or is located below it.
    param(
        [AllowEmptyString()][AllowNull()][string]$Path,
        [AllowEmptyString()][AllowNull()][string]$Container
    )
    $Child = ConvertTo-PatchWinRENormalPath -Path $Path
    $Parent = ConvertTo-PatchWinRENormalPath -Path $Container
    if (-not $Child -or -not $Parent) { return $false }
    if ([string]::Equals($Child, $Parent, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    $Prefix = $Parent.TrimEnd('\') + '\'
    return $Child.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-PatchWinREFolderDefault {
    <#
    .SYNOPSIS
        Returns the four folders derived from a root folder, matching the layout of the script defaults.
    #>
    param(
        [AllowEmptyString()]
        [string]$Root
    )
    if ([string]::IsNullOrWhiteSpace($Root)) {
        return [PSCustomObject]@{ WorkingDirectory = ''; BackupDirectory = ''; MountDirectory = ''; LogDirectory = '' }
    }
    $Base = $Root.Trim().TrimEnd('\')
    [PSCustomObject]@{
        WorkingDirectory = $Base + '\'
        BackupDirectory  = $Base + '\WinREBackups\'
        MountDirectory   = $Base + '\WinREMount\'
        LogDirectory     = $Base + '\Logs\'
    }
}

function Get-PatchWinRESourceDefault {
    <#
    .SYNOPSIS
        Detects the sibling folders patch, drivers and wim next to the entry script. Nothing is created or searched recursively.
    #>
    param(
        [AllowEmptyString()]
        [string]$BaseFolder
    )
    $SourceDefault = [ordered]@{ Patch = ''; Drivers = ''; Wim = '' }
    if (-not [string]::IsNullOrWhiteSpace($BaseFolder)) {
        foreach ($FolderName in @('Patch', 'Drivers', 'Wim')) {
            $Candidate = Join-Path -Path $BaseFolder -ChildPath $FolderName.ToLowerInvariant()
            if (Test-Path -LiteralPath $Candidate -PathType Container) {
                $SourceDefault[$FolderName] = (Get-Item -LiteralPath $Candidate -Force).FullName
            }
        }
    }
    [PSCustomObject]$SourceDefault
}

function New-PatchWinREGuiState {
    <#
    .SYNOPSIS
        Creates the GUI state with the script defaults, the root folder and the sibling source defaults.
    .PARAMETER Root
        GUI root folder. Working, Backup, Mount and Log follow it until they are changed.
    .PARAMETER SourceBase
        Folder of the entry script. Existing patch, drivers and wim subfolders are used as source defaults.
    #>
    param(
        [string]$Root = (Get-PatchWinREScriptDefault).Root,
        [AllowEmptyString()]
        [string]$SourceBase = ''
    )
    $FolderDefault = Get-PatchWinREFolderDefault -Root $Root
    $SourceDefault = Get-PatchWinRESourceDefault -BaseFolder $SourceBase
    [PSCustomObject]@{
        Operation                    = 'Backup'
        PatchFilesGDRDUorLCU         = $SourceDefault.Patch
        PatchFilesDUorSOS            = $SourceDefault.Patch
        FilesDriver                  = $SourceDefault.Drivers
        FoDDirectory                 = ''
        WIMFilePath                  = ''
        WimBrowseFolder              = $SourceDefault.Wim
        CreateWinREDrive             = $false
        UseRecoverySize              = $false
        RecoverySizeGB               = [string](Get-PatchWinREScriptDefault).RecoverySizeGB
        DoNotExpandRecoveryPartition = $false
        AbortIfFailed                = $false
        DeleteBackups                = $false
        ToConsole                    = $false
        WhatIf                       = $false
        ShowAll                      = $false
        Root                         = $Root
        WorkingDirectory             = $FolderDefault.WorkingDirectory
        BackupDirectory              = $FolderDefault.BackupDirectory
        MountDirectory               = $FolderDefault.MountDirectory
        LogDirectory                 = $FolderDefault.LogDirectory
        FollowsRoot                  = @{ WorkingDirectory = $true; BackupDirectory = $true; MountDirectory = $true; LogDirectory = $true }
    }
}

function Set-PatchWinRERoot {
    # Changes the root folder and rewrites only the folders that still follow it.
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [AllowEmptyString()]
        [string]$Root
    )
    $State.Root = $Root
    $FolderDefault = Get-PatchWinREFolderDefault -Root $Root
    foreach ($FolderName in (Get-PatchWinREFolderName)) {
        if ($State.FollowsRoot[$FolderName]) {
            $State.$FolderName = $FolderDefault.$FolderName
        }
    }
}

function Set-PatchWinREFolder {
    # Typing or browsing a folder marks it as custom.
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [ValidateSet('WorkingDirectory', 'BackupDirectory', 'MountDirectory', 'LogDirectory')]
        [string]$Name,
        [AllowEmptyString()]
        [string]$Path
    )
    $State.$Name = $Path
    $State.FollowsRoot[$Name] = $false
}

function Reset-PatchWinREFolder {
    # Returns a folder to "follows root".
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [Parameter(Mandatory = $true)]
        [ValidateSet('WorkingDirectory', 'BackupDirectory', 'MountDirectory', 'LogDirectory')]
        [string]$Name
    )
    $State.FollowsRoot[$Name] = $true
    $State.$Name = (Get-PatchWinREFolderDefault -Root $State.Root).$Name
}

function ConvertTo-PatchWinRESizeGB {
    # Returns the recovery size as a whole number of GB, or $null if the text is no whole number.
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Text
    )
    $SizeGB = 0
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    if ([int]::TryParse($Text.Trim(), [System.Globalization.NumberStyles]::None, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$SizeGB)) {
        return $SizeGB
    }
    return $null
}

function Get-PatchWinREParameter {
    <#
    .SYNOPSIS
        Returns the parameters to emit for the GUI state, in display order.
    .DESCRIPTION
        Only parameters of the selected operation are emitted, values of hidden options never are.
        Directories are emitted if they differ from the script default or if ShowAll is set.
        Each item has Name, Kind (Switch, Path, Size or Boolean) and Value.
    .PARAMETER ForceToConsole
        Emits -ToConsole regardless of the state (Run mode).
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [switch]$ForceToConsole
    )
    $Operation = Get-PatchWinREOperation -Key $State.Operation
    if (-not $Operation) { throw "Unknown operation '$($State.Operation)'" }
    $Emitted = New-Object System.Collections.Generic.List[object]
    if ($Operation.SwitchParameter) {
        $Emitted.Add([PSCustomObject]@{ Name = $Operation.SwitchParameter; Kind = 'Switch'; Value = $true })
    }
    if ($Operation.SourceParameter -and -not [string]::IsNullOrWhiteSpace($State.($Operation.SourceParameter))) {
        $Emitted.Add([PSCustomObject]@{ Name = $Operation.SourceParameter; Kind = 'Path'; Value = $State.($Operation.SourceParameter).Trim() })
    }
    if ($Operation.Wim -ne 'None' -and -not [string]::IsNullOrWhiteSpace($State.WIMFilePath)) {
        $Emitted.Add([PSCustomObject]@{ Name = 'WIMFilePath'; Kind = 'Path'; Value = $State.WIMFilePath.Trim() })
    }
    if ($Operation.Options -contains 'CreateWinREDrive' -and $State.CreateWinREDrive) {
        $Emitted.Add([PSCustomObject]@{ Name = 'CreateWinREDrive'; Kind = 'Switch'; Value = $true })
    }
    if ($Operation.AllowsSize -and $State.UseRecoverySize) {
        $SizeGB = ConvertTo-PatchWinRESizeGB -Text $State.RecoverySizeGB
        if ($null -ne $SizeGB) {
            $Emitted.Add([PSCustomObject]@{ Name = 'RecoveryDriveSizeInGB'; Kind = 'Size'; Value = $SizeGB })
        }
    }
    if ($Operation.Options -contains 'DoNotExpandRecoveryPartition' -and $State.DoNotExpandRecoveryPartition) {
        $Emitted.Add([PSCustomObject]@{ Name = 'DoNotExpandRecoveryPartition'; Kind = 'Boolean'; Value = $true })
    }
    if ($Operation.Options -contains 'AbortIfFailed' -and $State.AbortIfFailed) {
        $Emitted.Add([PSCustomObject]@{ Name = 'AbortIfFailed'; Kind = 'Switch'; Value = $true })
    }
    if ($Operation.AllowsDeleteBackups -and $State.DeleteBackups) {
        $Emitted.Add([PSCustomObject]@{ Name = 'DeleteBackups'; Kind = 'Boolean'; Value = $true })
    }
    $ScriptDefault = Get-PatchWinREScriptDefault
    foreach ($FolderName in (Get-PatchWinREFolderName)) {
        $FolderValue = $State.$FolderName
        if ([string]::IsNullOrWhiteSpace($FolderValue)) { continue }
        if ($State.ShowAll -or -not (Test-PatchWinRESamePath -Path $FolderValue -OtherPath $ScriptDefault.$FolderName)) {
            $Emitted.Add([PSCustomObject]@{ Name = $FolderName; Kind = 'Path'; Value = $FolderValue.Trim() })
        }
    }
    if ($State.ToConsole -or $ForceToConsole) {
        $Emitted.Add([PSCustomObject]@{ Name = 'ToConsole'; Kind = 'Switch'; Value = $true })
    }
    if ($State.WhatIf) {
        $Emitted.Add([PSCustomObject]@{ Name = 'WhatIf'; Kind = 'Switch'; Value = $true })
    }
    return , $Emitted.ToArray()
}

function ConvertTo-PatchWinRELiteral {
    # Single-quoted PowerShell string. Every kind of single quote is doubled, including typographic ones.
    param(
        [AllowEmptyString()]
        [string]$Value
    )
    return "'" + [System.Management.Automation.Language.CodeGeneration]::EscapeSingleQuotedStringContent($Value) + "'"
}

function ConvertTo-PatchWinRENativeArgument {
    # Argument for a powershell.exe -File command line (cmd.exe, Intune, ConfigMgr).
    param(
        [AllowEmptyString()]
        [string]$Value
    )
    if ($Value -match '^[A-Za-z0-9_\.\-\\:]+$') { return $Value }
    $Quoted = $Value
    # A backslash before the closing quote would escape it, so trailing backslashes are removed.
    if ($Quoted -notmatch '^[A-Za-z]:\\$') { $Quoted = $Quoted.TrimEnd('\') }
    return '"' + $Quoted + '"'
}

function ConvertTo-PatchWinRECommand {
    <#
    .SYNOPSIS
        Formats emitted parameters as a command.
    .PARAMETER Format
        OneLiner: PowerShell one-liner. Splat: $Params hashtable plus call. File: powershell.exe -File command line with the size in bytes.
    .PARAMETER ScriptPath
        Path of Patch-WinRE.ps1. The default .\Patch-WinRE.ps1 is emitted as is, other paths are called with the call operator.
    #>
    param(
        [AllowEmptyCollection()]
        [object[]]$Parameter = @(),
        [ValidateSet('OneLiner', 'Splat', 'File')]
        [string]$Format = 'OneLiner',
        [string]$ScriptPath = '.\Patch-WinRE.ps1'
    )
    if ($ScriptPath -match '^\.\\[A-Za-z0-9_\.\-]+$') {
        $Invocation = $ScriptPath
    } else {
        $Invocation = '& ' + (ConvertTo-PatchWinRELiteral -Value $ScriptPath)
    }
    $Parts = New-Object System.Collections.Generic.List[string]
    switch ($Format) {
        'OneLiner' {
            $Parts.Add($Invocation)
            foreach ($Item in $Parameter) {
                switch ($Item.Kind) {
                    'Switch' { $Parts.Add('-' + $Item.Name) }
                    'Path' { $Parts.Add('-' + $Item.Name + ' ' + (ConvertTo-PatchWinRELiteral -Value $Item.Value)) }
                    'Size' { $Parts.Add('-' + $Item.Name + ' ' + $Item.Value + 'GB') }
                    'Boolean' { $Parts.Add('-' + $Item.Name + ' $true') }
                }
            }
            return ($Parts -join ' ')
        }
        'Splat' {
            if (@($Parameter).Count -eq 0) {
                return ('$Params = @{}' + "`r`n" + $Invocation + ' @Params')
            }
            $NameWidth = (@($Parameter | ForEach-Object { $_.Name.Length }) | Measure-Object -Maximum).Maximum
            $Parts.Add('$Params = @{')
            foreach ($Item in $Parameter) {
                $PaddedName = $Item.Name.PadRight($NameWidth)
                switch ($Item.Kind) {
                    'Path' { $Parts.Add('    ' + $PaddedName + ' = ' + (ConvertTo-PatchWinRELiteral -Value $Item.Value)) }
                    'Size' { $Parts.Add('    ' + $PaddedName + ' = ' + $Item.Value + 'GB') }
                    default { $Parts.Add('    ' + $PaddedName + ' = $true') }
                }
            }
            $Parts.Add('}')
            $Parts.Add($Invocation + ' @Params')
            return ($Parts -join "`r`n")
        }
        'File' {
            $Parts.Add('powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' + (ConvertTo-PatchWinRENativeArgument -Value $ScriptPath))
            foreach ($Item in $Parameter) {
                switch ($Item.Kind) {
                    'Switch' { $Parts.Add('-' + $Item.Name) }
                    'Path' { $Parts.Add('-' + $Item.Name + ' ' + (ConvertTo-PatchWinRENativeArgument -Value $Item.Value)) }
                    'Size' { $Parts.Add('-' + $Item.Name + ' ' + ([int64]$Item.Value * 1GB).ToString([System.Globalization.CultureInfo]::InvariantCulture)) }
                    'Boolean' { $Parts.Add('-' + $Item.Name + ' $true') }
                }
            }
            return ($Parts -join ' ')
        }
    }
}

function New-PatchWinREWrapperContent {
    <#
    .SYNOPSIS
        Returns the content of the temporary wrapper script that runs Patch-WinRE.ps1 in a child powershell.exe.
    .DESCRIPTION
        The wrapper is started with powershell.exe -File and has no arguments of its own, so every argument keeps its type
        ($true stays a boolean, 2GB stays a number). -ToConsole is always added because the GUI reads the console output.
    #>
    param(
        [AllowEmptyCollection()]
        [object[]]$Parameter = @(),
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )
    $RunParameter = @($Parameter | Where-Object { $_.Name -ne 'ToConsole' -and $_.Name -ne 'WhatIf' })
    $RunParameter += [PSCustomObject]@{ Name = 'ToConsole'; Kind = 'Switch'; Value = $true }
    $RunParameter += @($Parameter | Where-Object { $_.Name -eq 'WhatIf' })
    $Invocation = ConvertTo-PatchWinRECommand -Parameter $RunParameter -Format OneLiner -ScriptPath $ScriptPath
    if (-not $Invocation.StartsWith('& ')) { $Invocation = '& ' + $Invocation }
    $WrapperLines = @(
        '# Temporary wrapper written by Start-PatchWinREGUI.ps1. The GUI deletes it after the run.'
        '[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding -ArgumentList $false'
        '$OriginalProgressPreference = $ProgressPreference'
        '$PatchWinREExitCode = 1'
        'try {'
        '    $ProgressPreference = ''SilentlyContinue'''
        ('    ' + $Invocation)
        '    if ($null -eq $LASTEXITCODE) { $PatchWinREExitCode = 0 } else { $PatchWinREExitCode = $LASTEXITCODE }'
        '} catch {'
        '    [Console]::Error.WriteLine(''Patch-WinRE.ps1 stopped with a terminating error: '' + $_.Exception.Message)'
        '    $PatchWinREExitCode = 1'
        '} finally {'
        '    $ProgressPreference = $OriginalProgressPreference'
        '}'
        'exit $PatchWinREExitCode'
    )
    return ($WrapperLines -join "`r`n") + "`r`n"
}

function Get-PatchWinRERoutineWarning {
    # Type 2 messages that occur in normal runs. They are shown as NOTE and do not turn the result amber.
    @(
        'Disabling WinRE, otherwise BitLocker will complain'
        'No recovery drive size specified, using default of 1GB'
        'No recovery drive size specified, using defaults to verify'
        'No patch directory/file specified to apply GDR or LCU updates'
        'No patch directory/file specified to apply SafeOS or Dynamic Updates'
        'Preparing patches to WinRE'
        'WinRE is not enabled currently - trying to enable WinRE'
        'Removing recovery partition'
        'Switching to repartition mode will leave an empty partition'
    )
}

function Test-PatchWinRERoutineWarning {
    param(
        [AllowEmptyString()]
        [string]$Message
    )
    $Trimmed = $Message.TrimStart()
    foreach ($Prefix in (Get-PatchWinRERoutineWarning)) {
        if ($Trimmed.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function ConvertFrom-PatchWinREOutputLine {
    <#
    .SYNOPSIS
        Classifies one line of -ToConsole output.
    .DESCRIPTION
        Levels: INFO (type 1), NOTE (routine type 2), WARN (type 2), ERROR (type 3 or error stream), PREVIEW (What if),
        TEXT (other output). Lines that follow a T: line and do not start a new entry are continuation lines of that entry.
    .PARAMETER PreviousEntry
        The entry returned for the previous line of the same run.
    #>
    param(
        [AllowEmptyString()]
        [string]$Line,
        [ValidateSet('Output', 'Error')]
        [string]$Stream = 'Output',
        [object]$PreviousEntry
    )
    $Entry = [PSCustomObject]@{
        Level          = 'TEXT'
        Type           = 0
        Component      = ''
        Message        = $Line
        IsContinuation = $false
        Stream         = $Stream
        Display        = ''
    }
    if ($Stream -eq 'Error') {
        $Entry.Level = 'ERROR'
    } else {
        $LogMatch = [regex]::Match($Line, '^T:(?<Type>[0-9]) C:(?<Component>.*?) M:(?<Message>.*)$')
        if ($LogMatch.Success) {
            $Entry.Type = [int]$LogMatch.Groups['Type'].Value
            $Entry.Component = $LogMatch.Groups['Component'].Value
            $Entry.Message = $LogMatch.Groups['Message'].Value
            switch ($Entry.Type) {
                2 {
                    if (Test-PatchWinRERoutineWarning -Message $Entry.Message) { $Entry.Level = 'NOTE' } else { $Entry.Level = 'WARN' }
                }
                3 { $Entry.Level = 'ERROR' }
                default { $Entry.Level = 'INFO' }
            }
        } elseif ($Line.StartsWith('What if: ', [System.StringComparison]::OrdinalIgnoreCase)) {
            $Entry.Level = 'PREVIEW'
        } elseif ($PreviousEntry -and $PreviousEntry.Stream -eq 'Output' -and $PreviousEntry.Type -gt 0) {
            $Entry.Level = $PreviousEntry.Level
            $Entry.Type = $PreviousEntry.Type
            $Entry.Component = $PreviousEntry.Component
            $Entry.IsContinuation = $true
        }
    }
    if ($Entry.IsContinuation) {
        $Entry.Display = ('{0,-8}    {1}' -f '', $Line)
    } elseif ($Entry.Type -gt 0) {
        $Entry.Display = ('{0,-8}[{1}] {2}' -f $Entry.Level, $Entry.Component, $Entry.Message)
    } else {
        $Entry.Display = ('{0,-8}{1}' -f $Entry.Level, $Line)
    }
    return $Entry
}

function Get-PatchWinRERunResult {
    <#
    .SYNOPSIS
        Classifies a finished run for the result lamp.
    .DESCRIPTION
        Blocked (red): exit code other than 0 or any type 3 message. Review (amber): non-routine type 2 messages,
        error stream output or a cancelled run. Pass (green): otherwise. A preview is never reported as an applied run.
    #>
    param(
        [AllowEmptyCollection()]
        [object[]]$Entry = @(),
        [AllowNull()]
        [object]$ExitCode,
        [switch]$Cancelled,
        [switch]$Preview
    )
    $Entries = @($Entry | Where-Object { $_ -and -not $_.IsContinuation })
    $ErrorCount = @($Entries | Where-Object { $_.Type -eq 3 }).Count
    $ErrorStreamCount = @($Entries | Where-Object { $_.Stream -eq 'Error' }).Count
    $WarningCount = @($Entries | Where-Object { $_.Level -eq 'WARN' }).Count
    $NoteCount = @($Entries | Where-Object { $_.Level -eq 'NOTE' }).Count
    $PreviewCount = @($Entries | Where-Object { $_.Level -eq 'PREVIEW' }).Count
    $Result = [PSCustomObject]@{
        State            = 'Pass'
        Title            = ''
        Detail           = ''
        ExitCode         = $ExitCode
        ErrorCount       = $ErrorCount
        ErrorStreamCount = $ErrorStreamCount
        WarningCount     = $WarningCount
        NoteCount        = $NoteCount
        PreviewCount     = $PreviewCount
        Preview          = [bool]$Preview
        Cancelled        = [bool]$Cancelled
    }
    $Counts = '{0} error(s), {1} warning(s), {2} note(s), {3} error stream line(s).' -f $ErrorCount, $WarningCount, $NoteCount, $ErrorStreamCount
    if ($Cancelled) {
        $Result.State = 'Review'
        if ($Preview) {
            $Result.Title = 'Preview cancelled - no changes applied'
            $Result.Detail = 'The preview was stopped before it finished.'
        } else {
            $Result.Title = 'Cancelled'
            $Result.Detail = 'The run was stopped. WinRE may still be disabled or an image may still be mounted. Run "Report only" to check the system.'
        }
    } elseif (($null -eq $ExitCode) -or ([int]$ExitCode -ne 0) -or $ErrorCount -gt 0) {
        $Result.State = 'Blocked'
        if ($Preview) { $Result.Title = 'Preview failed - no changes applied' } else { $Result.Title = 'Failed' }
        $Result.Detail = 'Exit code {0}. {1}' -f $(if ($null -eq $ExitCode) { 'unknown' } else { $ExitCode }), $Counts
    } elseif ($WarningCount -gt 0 -or $ErrorStreamCount -gt 0) {
        $Result.State = 'Review'
        if ($Preview) { $Result.Title = 'Preview completed with warnings - no changes applied' } else { $Result.Title = 'Completed with warnings' }
        $Result.Detail = 'Exit code 0. {0} Review the WARN and ERROR lines.' -f $Counts
    } else {
        if ($Preview) {
            $Result.Title = 'Preview completed - no changes applied'
            $Result.Detail = 'Exit code 0. {0} planned change(s). Steps that need a mounted image or a resized partition are not verified by a preview.' -f $PreviewCount
        } else {
            $Result.Title = 'Completed'
            $Result.Detail = 'Exit code 0. {0}' -f $Counts
        }
    }
    return $Result
}
