<#
.SYNOPSIS
    Field validation and readiness rules for the Patch-WinRE GUI.
.DESCRIPTION
    Dot-sourced by Start-PatchWinREGUI.ps1 and by the Pester tests. Contains no WPF code and changes nothing on disk.
    Every field gets a state (Pass, Review, Blocked or Off) and a message. Any Blocked field makes the readiness BLOCKED,
    any Review field makes it REVIEW, otherwise it is READY. Requires PatchWinREGUI.Core.ps1.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: PatchWinREGUI.Validation.ps1
    Initial creation date: 2026-11-19
    Last change: 2026-11-19
    Changes: Initial version
#>

function New-PatchWinREFieldResult {
    param(
        [string]$Key,
        [string]$Label,
        [ValidateSet('Pass', 'Review', 'Blocked', 'Off')]
        [string]$State = 'Pass',
        [string]$Message = '',
        [bool]$CountsForReadiness = $true
    )
    [PSCustomObject]@{
        Key                = $Key
        Label              = $Label
        State              = $State
        Message            = $Message
        CountsForReadiness = $CountsForReadiness
    }
}

function Get-PatchWinREPathProblem {
    # Returns a message if the path is empty, relative or invalid, otherwise an empty string.
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Path,
        [string]$Example = 'C:\WinRE-Customization\'
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Required.' }
    $Value = $Path.Trim()
    if ($Value -notmatch '^[A-Za-z]:\\' -and $Value -notmatch '^\\\\[^\\]+\\[^\\]+') {
        return "Use a full path, for example $Example"
    }
    $Remainder = $Value.Substring(2)
    if ($Remainder.IndexOfAny([char[]]'*?"<>|') -ge 0 -or $Remainder.Contains(':') -or $Value.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0) {
        return 'Contains characters that are not allowed in a path.'
    }
    try {
        [void][System.IO.Path]::GetFullPath($Value)
    } catch {
        return 'Is not a valid path.'
    }
    return ''
}

function Get-PatchWinREDriveProblem {
    # Returns a message if the drive of a local path is missing on this PC.
    param(
        [string]$Path
    )
    if ($Path -match '^(?<Drive>[A-Za-z]):') {
        $DriveRoot = $Path.Substring(0, 2).ToUpperInvariant() + '\'
        if (-not [System.IO.Directory]::Exists($DriveRoot)) {
            return ('Drive {0} is not present on this PC.' -f $DriveRoot.Substring(0, 2))
        }
    }
    return ''
}

function Get-PatchWinREProtectedFolderReason {
    # Returns why a folder is unsuitable for deletions or mounting (drive root, system or recovery folder), otherwise ''.
    param(
        [string]$Path
    )
    $Normal = ConvertTo-PatchWinRENormalPath -Path $Path
    if (-not $Normal) { return '' }
    if ($Normal -match '^[A-Za-z]:\\$') { return 'is a drive root' }
    if ($Normal -match '^[A-Za-z]:\\Recovery(\\|$)') { return 'is the Windows recovery folder' }
    $InsideRules = @(
        @{ Path = $env:SystemRoot; Reason = 'is inside the Windows folder (live WinRE.wim and ReAgent.xml)' }
        @{ Path = $env:ProgramFiles; Reason = 'is inside Program Files' }
        @{ Path = ${env:ProgramFiles(x86)}; Reason = 'is inside Program Files (x86)' }
        @{ Path = $env:ProgramW6432; Reason = 'is inside Program Files' }
    )
    foreach ($Rule in $InsideRules) {
        if ($Rule.Path -and (Test-PatchWinREPathInside -Path $Normal -Container $Rule.Path)) { return $Rule.Reason }
    }
    $ExactRules = @(
        @{ Path = $env:ProgramData; Reason = 'is the ProgramData folder' }
        @{ Path = (Join-Path -Path ([System.IO.Path]::GetPathRoot($env:SystemRoot)) -ChildPath 'Users'); Reason = 'is the Users folder' }
    )
    foreach ($Rule in $ExactRules) {
        if ($Rule.Path -and (Test-PatchWinRESamePath -Path $Normal -OtherPath $Rule.Path)) { return $Rule.Reason }
    }
    return ''
}

function Format-PatchWinREFileList {
    # Short, readable list of file names.
    param(
        [AllowEmptyCollection()]
        [string[]]$Name = @(),
        [int]$Maximum = 4
    )
    $Names = @($Name)
    if ($Names.Count -le $Maximum) { return ($Names -join ', ') }
    return (($Names | Select-Object -First $Maximum) -join ', ') + (' and {0} more' -f ($Names.Count - $Maximum))
}

function Test-PatchWinREFolderField {
    <#
    .SYNOPSIS
        Generic folder checks: empty, relative or invalid path, missing drive, existing file.
    #>
    param(
        [string]$Key,
        [string]$Label,
        [AllowEmptyString()]
        [string]$Path,
        [ValidateSet('Run', 'Generate')]
        [string]$Mode,
        [bool]$CountsForReadiness = $true,
        [switch]$ShowFreeSpace
    )
    $Problem = Get-PatchWinREPathProblem -Path $Path
    if ($Problem) { return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message $Problem -CountsForReadiness $CountsForReadiness }
    $Value = $Path.Trim()
    $DriveProblem = Get-PatchWinREDriveProblem -Path $Value
    if ($DriveProblem) {
        if ($Mode -eq 'Run') {
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message $DriveProblem -CountsForReadiness $CountsForReadiness
        }
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Review -Message ($DriveProblem + ' Fine if the command runs on another device.') -CountsForReadiness $CountsForReadiness
    }
    if ($Value -match '^\\\\') {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message 'Network path. It is not checked from this window.' -CountsForReadiness $CountsForReadiness
    }
    if ([System.IO.File]::Exists($Value)) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Points to a file. Select a folder.' -CountsForReadiness $CountsForReadiness
    }
    if ([System.IO.Directory]::Exists($Value)) {
        $Message = 'Folder exists.'
    } else {
        $Message = 'Does not exist yet. The script creates it.'
    }
    if ($ShowFreeSpace) {
        try {
            $Drive = New-Object System.IO.DriveInfo -ArgumentList $Value.Substring(0, 1)
            $Message += (' Drive {0}: has {1:N0} GB free.' -f $Value.Substring(0, 1).ToUpperInvariant(), ($Drive.AvailableFreeSpace / 1GB))
        } catch {
            $Message += ' The free space could not be read.'
        }
    }
    return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message $Message -CountsForReadiness $CountsForReadiness
}

function Test-PatchWinREMountField {
    # Mount folder: must be local, empty or missing, separate from the other folders and outside system folders.
    param(
        [object]$State,
        [ValidateSet('Run', 'Generate')]
        [string]$Mode
    )
    $Label = 'Mount folder'
    $Result = Test-PatchWinREFolderField -Key 'MountDirectory' -Label $Label -Path $State.MountDirectory -Mode $Mode
    if ($Result.State -eq 'Blocked') { return $Result }
    $Value = $State.MountDirectory.Trim()
    if ($Value -match '^\\\\') {
        return New-PatchWinREFieldResult -Key 'MountDirectory' -Label $Label -State Blocked -Message 'Must be on a local drive. DISM mounts the WinRE image there.'
    }
    $ProtectedReason = Get-PatchWinREProtectedFolderReason -Path $Value
    if ($ProtectedReason) {
        return New-PatchWinREFieldResult -Key 'MountDirectory' -Label $Label -State Blocked -Message ("This folder $ProtectedReason. The mount folder is deleted after a successful run.")
    }
    foreach ($Other in @(
            @{ Name = 'working folder'; Path = $State.WorkingDirectory }
            @{ Name = 'backup folder'; Path = $State.BackupDirectory }
            @{ Name = 'log folder'; Path = $State.LogDirectory })) {
        if (Test-PatchWinREPathInside -Path $Other.Path -Container $Value) {
            return New-PatchWinREFieldResult -Key 'MountDirectory' -Label $Label -State Blocked -Message ("Equals or contains the {0}. The mount folder is deleted after a successful run, so it must be separate from the other folders." -f $Other.Name)
        }
    }
    if ([System.IO.Directory]::Exists($Value)) {
        $FirstEntry = $null
        try {
            $FirstEntry = [System.IO.Directory]::EnumerateFileSystemEntries($Value) | Select-Object -First 1
        } catch {
            return New-PatchWinREFieldResult -Key 'MountDirectory' -Label $Label -State Blocked -Message ('The folder could not be read: {0}' -f $_.Exception.Message)
        }
        if ($FirstEntry) {
            return New-PatchWinREFieldResult -Key 'MountDirectory' -Label $Label -State Blocked -Message 'Is not empty. The script stops if the mount folder contains files.'
        }
    }
    if ($Result.State -eq 'Review') { return $Result }
    return New-PatchWinREFieldResult -Key 'MountDirectory' -Label $Label -State Pass -Message 'Empty or missing. It is deleted after a successful run.'
}

function Get-PatchWinREBackupFile {
    # The files -DeleteBackups removes: *.wim and *.xml directly in the backup folder.
    param(
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Directory]::Exists($Path.Trim())) { return @() }
    try {
        return @(Get-ChildItem -LiteralPath $Path.Trim() -File -Force -ErrorAction Stop | Where-Object { $_.Extension -eq '.wim' -or $_.Extension -eq '.xml' } | Sort-Object Name)
    } catch {
        return @()
    }
}

function Get-PatchWinRESourceFile {
    <#
    .SYNOPSIS
        Lists the files the script would apply from a source folder, in the order it applies them.
    .DESCRIPTION
        Patches: .msu and .cab directly in the folder, files starting with "ssu" first. Drivers: .inf files including subfolders.
    #>
    param(
        [string]$Path,
        [string[]]$Extension,
        [switch]$Recurse,
        [int]$Maximum = 1000
    )
    $Found = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $SearchOption = [System.IO.SearchOption]::TopDirectoryOnly
    if ($Recurse) { $SearchOption = [System.IO.SearchOption]::AllDirectories }
    $Directory = New-Object System.IO.DirectoryInfo -ArgumentList $Path
    foreach ($Item in $Extension) {
        foreach ($File in $Directory.EnumerateFiles('*' + $Item, $SearchOption)) {
            if ($File.Extension -eq $Item) { $Found.Add($File) }
            if ($Found.Count -ge $Maximum) { break }
        }
    }
    $SsuFiles = @($Found | Where-Object { $_.Name -like 'ssu*' } | Sort-Object Name)
    $OtherFiles = @($Found | Where-Object { $_.Name -notlike 'ssu*' } | Sort-Object Name)
    return @($SsuFiles + $OtherFiles)
}

function Test-PatchWinRESourceField {
    # Patch or driver source: folder with matching files or a single file of the right type.
    param(
        [object]$Operation,
        [AllowEmptyString()]
        [string]$Path,
        [ValidateSet('Run', 'Generate')]
        [string]$Mode
    )
    $Key = 'Source'
    $Label = $Operation.SourceParameter
    $ExtensionText = ($Operation.SourceExtensions -join ' or ')
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message ('Required. Select a folder or a single {0} file.' -f $ExtensionText)
    }
    $Problem = Get-PatchWinREPathProblem -Path $Path -Example 'C:\Temp\LCU'
    if ($Problem) { return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message $Problem }
    $Value = $Path.Trim()
    if ([System.IO.File]::Exists($Value)) {
        $FileExtension = [System.IO.Path]::GetExtension($Value).ToLowerInvariant()
        if ($Operation.SourceExtensions -notcontains $FileExtension) {
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message ('Single files must be {0}.' -f $ExtensionText)
        }
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message ('Single file found: {0}.' -f [System.IO.Path]::GetFileName($Value))
    }
    if (-not [System.IO.Directory]::Exists($Value)) {
        if ($Mode -eq 'Run') {
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Not found on this PC.'
        }
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Review -Message 'Not found on this PC. Fine if the command runs on another device.'
    }
    try {
        if ($Operation.Key -eq 'Driver') {
            $Files = @(Get-PatchWinRESourceFile -Path $Value -Extension '.inf' -Recurse)
            if ($Files.Count -eq 0) {
                return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Contains no .inf files (subfolders included).'
            }
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message ('Folder found with {0} .inf file(s), subfolders included: {1}.' -f $Files.Count, (Format-PatchWinREFileList -Name ($Files | ForEach-Object { $_.Name })))
        }
        if ($Operation.Key -eq 'PatchGDRDUorLCU') {
            $MsuFiles = @(Get-PatchWinRESourceFile -Path $Value -Extension '.msu')
            $CabFiles = @(Get-PatchWinRESourceFile -Path $Value -Extension '.cab')
            if ($MsuFiles.Count -gt 0 -and $CabFiles.Count -gt 0) {
                return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Contains .msu and .cab files. The script applies nothing in that case. Use a folder with either the LCU (.msu) or the GDR-DU (.cab) files.'
            }
            $Files = @($MsuFiles + $CabFiles)
        } else {
            $Files = @(Get-PatchWinRESourceFile -Path $Value -Extension $Operation.SourceExtensions)
        }
    } catch {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message ('The folder could not be read: {0}' -f $_.Exception.Message)
    }
    if ($Files.Count -eq 0) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message ('Contains no {0} files. Subfolders are not searched.' -f $ExtensionText)
    }
    return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message ('Folder found with {0} file(s), applied in this order: {1}.' -f $Files.Count, (Format-PatchWinREFileList -Name ($Files | ForEach-Object { $_.Name })))
}

function Test-PatchWinREWimField {
    param(
        [AllowEmptyString()]
        [string]$Path,
        [bool]$Required,
        [ValidateSet('Run', 'Generate')]
        [string]$Mode
    )
    $Key = 'WIMFilePath'
    $Label = 'WIMFilePath'
    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ($Required) {
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Required. Select a WinRE.wim file.'
        }
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Off -Message 'Optional. Without an image, the WinRE.wim already on the system is used.'
    }
    $Problem = Get-PatchWinREPathProblem -Path $Path -Example 'C:\Temp\WinRE.wim'
    if ($Problem) { return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message $Problem }
    $Value = $Path.Trim()
    if ([System.IO.Path]::GetExtension($Value) -ne '.wim') {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Must be a .wim file.'
    }
    if ([System.IO.Directory]::Exists($Value)) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Points to a folder. Select a .wim file.'
    }
    if (-not [System.IO.File]::Exists($Value)) {
        if ($Mode -eq 'Run') {
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Not found on this PC.'
        }
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Review -Message 'Not found on this PC. Fine if the command runs on another device.'
    }
    $SizeMB = (New-Object System.IO.FileInfo -ArgumentList $Value).Length / 1MB
    return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message ('File found ({0:N0} MB).' -f $SizeMB)
}

function Test-PatchWinRESizeField {
    param(
        [object]$State,
        [object]$Operation
    )
    $Key = 'RecoveryDriveSizeInGB'
    $Label = 'RecoveryDriveSizeInGB'
    if (-not $State.UseRecoverySize) {
        if ($Operation.Options -contains 'CreateWinREDrive' -and
            $State.CreateWinREDrive -and
            $Operation.Options -contains 'DoNotExpandRecoveryPartition' -and
            $State.DoNotExpandRecoveryPartition) {
            return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'The script cannot create a recovery partition with -DoNotExpandRecoveryPartition when no size is set. Set a size of at least 1 GB or clear this option.'
        }
        if ($Operation.Key -eq 'CreateWinREDrive' -or
            ($Operation.Options -contains 'CreateWinREDrive' -and $State.CreateWinREDrive)) { $Message = 'Not set. The new recovery partition gets 1 GB.' }
        elseif ($Operation.Key -eq 'PatchGDRDUorLCU') { $Message = 'Not set. The script checks for at least 1 GB and expands the partition if needed.' }
        else { $Message = 'Not set. The recovery partition size is not changed.' }
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Off -Message $Message
    }
    $SizeGB = ConvertTo-PatchWinRESizeGB -Text $State.RecoverySizeGB
    if ($null -eq $SizeGB) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'Enter a whole number of GB, for example 2.'
    }
    if ($SizeGB -lt 1) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Blocked -Message 'The minimum is 1 GB.'
    }
    if ($Operation.Options -contains 'DoNotExpandRecoveryPartition' -and $State.DoNotExpandRecoveryPartition) {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Review -Message ('Contradiction: -DoNotExpandRecoveryPartition is set, but the script still resizes the partition to {0} GB because a size is set.' -f $SizeGB)
    }
    if ($Operation.Key -eq 'CreateWinREDrive') {
        return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message ('The new recovery partition gets {0} GB.' -f $SizeGB)
    }
    return New-PatchWinREFieldResult -Key $Key -Label $Label -State Pass -Message ('The partition is resized only if it is smaller than {0} GB.' -f $SizeGB)
}

function Get-PatchWinREValidation {
    <#
    .SYNOPSIS
        Validates the GUI state and returns the field results and the readiness.
    .PARAMETER Mode
        Run: elevated and able to run on this PC, missing paths are blocked.
        Generate: the command may run on another device, missing paths are only flagged for review.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [ValidateSet('Run', 'Generate')]
        [string]$Mode = 'Generate'
    )
    $Operation = Get-PatchWinREOperation -Key $State.Operation
    $Fields = [ordered]@{}
    if (-not $Operation.Enabled) {
        $Fields['Operation'] = New-PatchWinREFieldResult -Key 'Operation' -Label $Operation.DisplayName -State Blocked -Message $Operation.DisabledReason
    }
    if ($Operation.SourceParameter -and $Operation.Enabled) {
        $Fields['Source'] = Test-PatchWinRESourceField -Operation $Operation -Path $State.($Operation.SourceParameter) -Mode $Mode
    }
    if ($Operation.Wim -ne 'None') {
        $Fields['WIMFilePath'] = Test-PatchWinREWimField -Path $State.WIMFilePath -Required ($Operation.Wim -eq 'Required') -Mode $Mode
    }
    if ($Operation.AllowsSize) {
        $Fields['RecoveryDriveSizeInGB'] = Test-PatchWinRESizeField -State $State -Operation $Operation
    }
    $Fields['Root'] = Test-PatchWinREFolderField -Key 'Root' -Label 'Root folder' -Path $State.Root -Mode $Mode -CountsForReadiness $false -ShowFreeSpace
    $Fields['WorkingDirectory'] = Test-PatchWinREFolderField -Key 'WorkingDirectory' -Label 'Working folder' -Path $State.WorkingDirectory -Mode $Mode
    $Fields['BackupDirectory'] = Test-PatchWinREFolderField -Key 'BackupDirectory' -Label 'Backup folder' -Path $State.BackupDirectory -Mode $Mode
    $Fields['MountDirectory'] = Test-PatchWinREMountField -State $State -Mode $Mode
    $Fields['LogDirectory'] = Test-PatchWinREFolderField -Key 'LogDirectory' -Label 'Log folder' -Path $State.LogDirectory -Mode $Mode
    if ($Fields['LogDirectory'].State -ne 'Blocked' -and ($State.ToConsole -or $Mode -eq 'Run')) {
        $Fields['LogDirectory'].Message = $Fields['LogDirectory'].Message + ' No log file is written while the output goes to the console (-ToConsole).'
    }
    if ($Operation.AllowsDeleteBackups -and $State.DeleteBackups) {
        $BackupValue = $State.BackupDirectory
        $ProtectedReason = ''
        if (-not (Get-PatchWinREPathProblem -Path $BackupValue)) {
            $ProtectedReason = Get-PatchWinREProtectedFolderReason -Path $BackupValue.Trim()
        }
        if ($ProtectedReason -and $Fields['BackupDirectory'].State -ne 'Blocked') {
            $Fields['BackupDirectory'] = New-PatchWinREFieldResult -Key 'BackupDirectory' -Label 'Backup folder' -State Blocked -Message ("This folder $ProtectedReason. -DeleteBackups would delete every .wim and .xml file in it.")
        }
        $BackupFiles = @(Get-PatchWinREBackupFile -Path $BackupValue)
        if ($BackupFiles.Count -gt 0) {
            $DeleteMessage = ('Deletes all .wim and .xml files in the backup folder after a successful run: {0}, plus the backup this run creates.' -f (Format-PatchWinREFileList -Name ($BackupFiles | ForEach-Object { $_.Name })))
        } else {
            $DeleteMessage = 'Deletes all .wim and .xml files in the backup folder after a successful run, including the backup this run creates.'
        }
        $Fields['DeleteBackups'] = New-PatchWinREFieldResult -Key 'DeleteBackups' -Label 'DeleteBackups' -State Review -Message $DeleteMessage
    }
    $Counted = @($Fields.Values | Where-Object { $_.CountsForReadiness })
    $BlockedItems = @($Counted | Where-Object { $_.State -eq 'Blocked' })
    $ReviewItems = @($Counted | Where-Object { $_.State -eq 'Review' })
    if ($BlockedItems.Count -gt 0) {
        $Readiness = 'Blocked'
        $Title = 'BLOCKED'
        $Detail = '{0} item(s) must be fixed before the command can be copied or run.' -f $BlockedItems.Count
    } elseif ($ReviewItems.Count -gt 0) {
        $Readiness = 'Review'
        $Title = 'REVIEW'
        if ($Mode -eq 'Run') {
            $Detail = '{0} item(s) need a look. Run asks for confirmation.' -f $ReviewItems.Count
        } else {
            $Detail = '{0} item(s) need a look. The command can still be copied.' -f $ReviewItems.Count
        }
    } else {
        $Readiness = 'Pass'
        $Title = 'READY'
        if ($Mode -eq 'Run') {
            $Detail = 'All values are valid. Run executes the command shown here.'
        } else {
            $Detail = 'All values are valid. Run the copied command as administrator.'
        }
    }
    [PSCustomObject]@{
        Fields    = $Fields
        Readiness = $Readiness
        Title     = $Title
        Detail    = $Detail
        Findings  = @($BlockedItems + $ReviewItems)
    }
}
