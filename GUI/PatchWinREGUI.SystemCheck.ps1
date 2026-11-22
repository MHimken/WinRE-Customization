<#
.SYNOPSIS
    Read-only WinRE and partition discovery and evaluation for the GUI.
.DESCRIPTION
    The discovery script runs in an elevated child process. The evaluator is pure PowerShell and accepts fixture objects,
    which keeps the system checks testable without changing recovery configuration.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: PatchWinREGUI.SystemCheck.ps1
    Initial creation date: 2026-11-22
    Last change: 2026-11-22
    Changes: Initial version
#>

function New-PatchWinRESystemCheckScript {
    <#
    .SYNOPSIS
        Returns the self-contained, read-only discovery script for the child process.
    #>
    @'
$ErrorActionPreference = 'Stop'
$CheckErrors = New-Object System.Collections.Generic.List[string]
function Add-CheckError {
    param([string]$Name, [object]$Exception)
    $CheckErrors.Add(('{0}: {1}' -f $Name, $Exception.Exception.Message))
}
function ConvertTo-CheckPartition {
    param([object]$Partition)
    $Remaining = $null
    try { $Remaining = (Get-Volume -Partition $Partition -ErrorAction Stop).SizeRemaining }
    catch { Add-CheckError -Name ('Volume for disk {0}, partition {1}' -f $Partition.DiskNumber, $Partition.PartitionNumber) -Exception $_ }
    [ordered]@{
        DiskNumber = [int]$Partition.DiskNumber
        PartitionNumber = [int]$Partition.PartitionNumber
        Size = [uint64]$Partition.Size
        Offset = [uint64]$Partition.Offset
        GptType = [string]$Partition.GptType
        SizeRemaining = if ($null -eq $Remaining) { $null } else { [uint64]$Remaining }
    }
}
$Data = [ordered]@{
    Reagent = $null
    ReagentStatusToken = $null
    ReagentLocationLine = $null
    ScriptRecoveryDiskNumber = $null
    ScriptRecoveryPartitionNumber = $null
    ActualRecoveryDiskNumber = $null
    ActualRecoveryPartitionNumber = $null
    ReAgentXmlExists = $false
    ImageLocation = $null
    WinreLocation = $null
    OSDrive = $env:SystemDrive.TrimEnd(':')
    OSPartition = $null
    OSDisk = $null
    OSVolume = $null
    SupportedSize = $null
    Partitions = $null
    RecoveryPartitions = $null
    SelectedRecoveryPartition = $null
    MountedImages = $null
    WinREImagePath = $null
    WinREImageChecked = $false
    WinREImageExists = $false
    WinREImageSize = $null
    WinREImageVersion = $null
    DriveFreeBytes = @{}
    Errors = @()
}
try {
    $ReagentLines = @(& reagentc.exe /info 2>&1 | ForEach-Object { "$_" })
    $ReagentExitCode = $LASTEXITCODE
    $StatusToken = $null
    if ($ReagentLines.Count -gt 3) {
        $StatusParts = @($ReagentLines[3].TrimEnd().Split(' ') | Where-Object { $_ })
        if ($StatusParts.Count -gt 0) { $StatusToken = $StatusParts[-1] }
    }
    $LocationLine = $null
    $LocationPath = $null
    $ScriptDisk = $null
    $ScriptPartition = $null
    $ActualDisk = $null
    $ActualPartition = $null
    if ($ReagentLines.Count -gt 4) {
        $LocationLine = $ReagentLines[4]
        if ($LocationLine.Length -gt 31) {
            $LocationPath = $LocationLine.Substring(31).Trim()
            $Prefix = '\\?\GLOBALROOT\device\harddisk'
            if ($LocationPath.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $Remainder = $LocationPath.Substring($Prefix.Length)
                if ($Remainder.Length -gt 0) { $ScriptDisk = $Remainder.Substring(0, 1) }
                $PartitionMarker = $Remainder.IndexOf('\partition', [System.StringComparison]::OrdinalIgnoreCase)
                if ($PartitionMarker -ge 0 -and $Remainder.Length -gt ($PartitionMarker + 10)) {
                    $ScriptPartition = $Remainder.Substring($PartitionMarker + 10, 1)
                }
            }
            $Match = [regex]::Match($LocationPath, 'harddisk(?<Disk>\d+)\\partition(?<Partition>\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($Match.Success) {
                $ActualDisk = [int]$Match.Groups['Disk'].Value
                $ActualPartition = [int]$Match.Groups['Partition'].Value
            }
        }
    }
    $Data.Reagent = [ordered]@{ ExitCode = $ReagentExitCode; Lines = $ReagentLines; LocationPath = $LocationPath }
    $Data.ReagentStatusToken = $StatusToken
    $Data.ReagentLocationLine = $LocationLine
    $Data.ScriptRecoveryDiskNumber = $ScriptDisk
    $Data.ScriptRecoveryPartitionNumber = $ScriptPartition
    $Data.ActualRecoveryDiskNumber = $ActualDisk
    $Data.ActualRecoveryPartitionNumber = $ActualPartition
} catch { Add-CheckError -Name 'reagentc /info' -Exception $_ }

try {
    $XmlPath = Join-Path $env:SystemRoot 'System32\Recovery\ReAgent.xml'
    if (Test-Path -LiteralPath $XmlPath -PathType Leaf) {
        [xml]$ReAgent = [System.IO.File]::ReadAllText($XmlPath)
        $Data.ReAgentXmlExists = $true
        $Data.ImageLocation = [ordered]@{
            Guid = [string]$ReAgent.WindowsRE.ImageLocation.Guid
            Offset = [string]$ReAgent.WindowsRE.ImageLocation.Offset
            Path = [string]$ReAgent.WindowsRE.ImageLocation.Path
        }
        $Data.WinreLocation = [ordered]@{
            Guid = [string]$ReAgent.WindowsRE.WinreLocation.Guid
            Offset = [string]$ReAgent.WindowsRE.WinreLocation.Offset
            Path = [string]$ReAgent.WindowsRE.WinreLocation.Path
        }
    }
} catch { Add-CheckError -Name 'ReAgent.xml' -Exception $_ }

$RecoveryType = '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
try {
    $OSPartition = Get-Partition -DriveLetter $Data.OSDrive -ErrorAction Stop
    $OSDisk = Get-Disk -Number $OSPartition.DiskNumber -ErrorAction Stop
    $OSVolume = Get-Volume -DriveLetter $Data.OSDrive -ErrorAction Stop
    $Supported = Get-PartitionSupportedSize -DriveLetter $Data.OSDrive -ErrorAction Stop
    $Data.OSPartition = ConvertTo-CheckPartition -Partition $OSPartition
    $Data.OSDisk = [ordered]@{ Number = [int]$OSDisk.Number; PartitionStyle = [string]$OSDisk.PartitionStyle; Guid = [string]$OSDisk.Guid }
    $Data.OSVolume = [ordered]@{ Size = [uint64]$OSVolume.Size; SizeRemaining = [uint64]$OSVolume.SizeRemaining }
    $Data.SupportedSize = [ordered]@{ SizeMin = [uint64]$Supported.SizeMin; SizeMax = [uint64]$Supported.SizeMax }
} catch { Add-CheckError -Name 'OS disk and volume' -Exception $_ }

try {
    $AllPartitions = @(Get-Partition -ErrorAction Stop)
    $Recovery = @($AllPartitions | Where-Object { $_.GptType -eq $RecoveryType })
    $DiskNumbers = @($AllPartitions | ForEach-Object { [int]$_.DiskNumber } | Sort-Object -Unique)
    $PartitionRecords = New-Object System.Collections.Generic.List[object]
    foreach ($DiskNumber in $DiskNumbers) {
        foreach ($Partition in @($AllPartitions | Where-Object { $_.DiskNumber -eq $DiskNumber } | Sort-Object PartitionNumber)) {
            $PartitionRecords.Add((ConvertTo-CheckPartition -Partition $Partition))
        }
    }
    $RecoveryRecords = @($PartitionRecords | Where-Object { $_.GptType -eq $RecoveryType })
    $Data.Partitions = @($PartitionRecords.ToArray())
    $Data.RecoveryPartitions = $RecoveryRecords
    if ($Data.ReagentStatusToken -eq 'Enabled' -and $null -ne $Data.ActualRecoveryDiskNumber) {
        $Selected = @($PartitionRecords | Where-Object {
                $_.DiskNumber -eq $Data.ActualRecoveryDiskNumber -and $_.PartitionNumber -eq $Data.ActualRecoveryPartitionNumber
            } | Select-Object -First 1)
        if ($Selected.Count -gt 0) { $Data.SelectedRecoveryPartition = $Selected[0] }
    } elseif ($RecoveryRecords.Count -gt 0) {
        $Selected = @($RecoveryRecords | Sort-Object @{ Expression = { if ($null -eq $_.SizeRemaining) { [uint64]0 } else { [uint64]$_.SizeRemaining } }; Descending = $true } | Select-Object -First 1)
        if ($Selected.Count -gt 0) { $Data.SelectedRecoveryPartition = $Selected[0] }
    }
    if ($Data.SelectedRecoveryPartition) {
        $Data.ActualRecoveryDiskNumber = $Data.SelectedRecoveryPartition.DiskNumber
        $Data.ActualRecoveryPartitionNumber = $Data.SelectedRecoveryPartition.PartitionNumber
    }
} catch { Add-CheckError -Name 'Partition layout' -Exception $_ }

try {
    $Mounted = @(Get-WindowsImage -Mounted -ErrorAction Stop)
    $Data.MountedImages = @($Mounted | ForEach-Object {
        [ordered]@{ MountPath = [string]$_.Path; ImagePath = [string]$_.ImagePath; MountStatus = [string]$_.MountStatus }
    })
} catch { Add-CheckError -Name 'Mounted images' -Exception $_ }

try {
    $Location = if ($Data.ReagentStatusToken -eq 'Enabled') { $Data.WinreLocation } else { $Data.ImageLocation }
    if ($Data.ReagentStatusToken -ne 'Enabled' -and
        $Location -and
        $Location.Guid -eq '{00000000-0000-0000-0000-000000000000}') {
        $ImagePath = Join-Path $env:SystemRoot 'System32\Recovery\WinRE.wim'
    } elseif ($Location -and $Location.Guid) {
        $Disk = Get-Disk -ErrorAction Stop | Where-Object { $_.Guid -eq $Location.Guid } | Select-Object -First 1
        if ($Disk) {
            $Partition = Get-Partition -DiskNumber $Disk.Number -ErrorAction Stop | Where-Object { [string]$_.Offset -eq [string]$Location.Offset } | Select-Object -First 1
            if ($Partition -and $Partition.AccessPaths.Count -gt 0) {
                $ImagePath = Join-Path -Path $Partition.AccessPaths[0] -ChildPath (([string]$Location.Path).Trim('\') + '\WinRE.wim')
            }
        }
    }
    $Data.WinREImagePath = $ImagePath
    if ($ImagePath) {
        $ImageExists = Test-Path -LiteralPath $ImagePath -PathType Leaf -ErrorAction Stop
        $Data.WinREImageChecked = $true
        if ($ImageExists) {
            $Data.WinREImageExists = $true
            # WinRE.wim is hidden and system; Get-Item needs -Force for it
            $ImageFile = Get-Item -LiteralPath $ImagePath -Force -ErrorAction Stop
            $Data.WinREImageSize = [uint64]$ImageFile.Length
            try { $Data.WinREImageVersion = [string](Get-WindowsImage -ImagePath $ImagePath -Index 1 -ErrorAction Stop).SPBuild } catch { Add-CheckError -Name 'WinRE image version' -Exception $_ }
        }
    }
} catch { Add-CheckError -Name 'WinRE image location' -Exception $_ }

try {
    $LogicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction Stop)
    foreach ($LogicalDisk in $LogicalDisks) {
        $Data.DriveFreeBytes[[string]$LogicalDisk.DeviceID] = [uint64]$LogicalDisk.FreeSpace
    }
} catch { Add-CheckError -Name 'Local drive free space' -Exception $_ }

$Data.Errors = @($CheckErrors.ToArray())
Write-Output 'PATCHWINRE-JSON:'
$Data | ConvertTo-Json -Compress -Depth 6 | Write-Output
'@
}

function ConvertFrom-PatchWinRESystemCheckOutput {
    <#
    .SYNOPSIS
        Extracts discovery JSON from the child process output.
    .PARAMETER Lines
        Output lines, optionally prefixed with O/E by ProcessRunner.
    #>
    param(
        [AllowEmptyCollection()]
        [string[]]$Lines = @()
    )
    $Marker = 'PATCHWINRE-JSON:'
    $JsonLine = $null
    for ($Index = 0; $Index -lt $Lines.Count; $Index++) {
        $Line = $Lines[$Index]
        if ($Line.Length -gt 0 -and ($Line[0] -eq 'O' -or $Line[0] -eq 'E')) {
            $Line = $Line.Substring(1)
        }
        if ($Line -eq $Marker -and $Index + 1 -lt $Lines.Count) {
            $NextLine = $Lines[$Index + 1]
            if ($NextLine.Length -gt 0 -and ($NextLine[0] -eq 'O' -or $NextLine[0] -eq 'E')) {
                $NextLine = $NextLine.Substring(1)
            }
            $JsonLine = $NextLine
            break
        }
        if ($Line.StartsWith($Marker, [System.StringComparison]::Ordinal)) {
            $JsonLine = $Line.Substring($Marker.Length).Trim()
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($JsonLine)) { throw 'The system check did not return its JSON result marker.' }
    try { return (ConvertFrom-Json -InputObject $JsonLine -ErrorAction Stop) }
    catch { throw ('The system check returned invalid JSON: {0}' -f $_.Exception.Message) }
}

function New-PatchWinRESystemFinding {
    param(
        [ValidateSet('Pass', 'Review', 'Blocked')]
        [string]$State,
        [string]$Topic,
        [string]$Message
    )
    [PSCustomObject]@{ State = $State; Topic = $Topic; Message = $Message }
}

function Get-PatchWinRESystemDriveFreeBytes {
    param(
        [object]$Discovery,
        [AllowEmptyString()]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\')) { return $null }
    $DriveMatch = [regex]::Match($Path, '^(?<Drive>[A-Za-z]):\\')
    if (-not $DriveMatch.Success) { return $null }
    $Key = $DriveMatch.Groups['Drive'].Value.ToUpperInvariant() + ':'
    if ($Discovery.DriveFreeBytes -is [System.Collections.IDictionary]) {
        if ($Discovery.DriveFreeBytes.Contains($Key)) { return [decimal]$Discovery.DriveFreeBytes[$Key] }
    } elseif ($Discovery.DriveFreeBytes.PSObject.Properties[$Key]) {
        return [decimal]$Discovery.DriveFreeBytes.PSObject.Properties[$Key].Value
    }
    return $null
}

function Get-PatchWinRESystemFinding {
    <#
    .SYNOPSIS
        Evaluates a discovery object against the selected GUI operation and its form validation.
    .DESCRIPTION
        Unknown data is Review. This function performs no system discovery and makes no changes.
    .OUTPUTS
        Readiness, Title, Detail, Findings, and Entries for the Output panel.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Discovery,
        [Parameter(Mandatory = $true)]
        [object]$State
    )
    $Operation = Get-PatchWinREOperation -Key $State.Operation
    if (-not $Operation) { throw "Unknown operation '$($State.Operation)'." }
    $Findings = New-Object System.Collections.Generic.List[object]
    $IsReportOnly = $Operation.Key -eq 'ReportOnly'
    $EffectiveCreate = $Operation.Key -eq 'CreateWinREDrive' -or
        ($Operation.Options -contains 'CreateWinREDrive' -and $State.CreateWinREDrive)
    $EffectiveReplace = $Operation.Key -eq 'ReplaceWIM'
    $EffectiveDoNotExpand = $Operation.Options -contains 'DoNotExpandRecoveryPartition' -and $State.DoNotExpandRecoveryPartition
    $SizeGB = $null
    if ($Operation.AllowsSize -and $State.UseRecoverySize) {
        $SizeGB = ConvertTo-PatchWinRESizeGB -Text $State.RecoverySizeGB
    }
    $NewSize = $null
    if ($null -ne $SizeGB) { $NewSize = [decimal]$SizeGB * 1GB }
    elseif ($EffectiveCreate -and -not $EffectiveDoNotExpand) { $NewSize = 1GB }
    elseif ($Operation.Key -eq 'PatchGDRDUorLCU') { $NewSize = 1GB }
    $OperationNeedsMount = $Operation.Key -in @('PatchGDRDUorLCU', 'PatchDUorSOS', 'Driver', 'ReplaceWIM')

    $Form = Get-PatchWinREValidation -State $State -Mode Run
    foreach ($Field in $Form.Fields.Values) {
        if ($Field.State -eq 'Off' -or -not $Field.CountsForReadiness) { continue }
        if ($Field.State -eq 'Pass') {
            $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic $Field.Label -Message $Field.Message))
        } else {
            $Findings.Add((New-PatchWinRESystemFinding -State $Field.State -Topic $Field.Label -Message $Field.Message))
        }
    }

    if ($Discovery.ReagentStatusToken -eq 'Enabled') {
        $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'WinRE status' -Message 'reagentc reports WinRE enabled.'))
    } elseif ($Discovery.ReagentStatusToken -eq 'Disabled') {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'WinRE status' -Message 'reagentc reports WinRE disabled. The script may enable it during patching.'))
    } else {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'WinRE status' -Message 'WinRE status is unknown; reagentc output may be localized or unavailable.'))
    }

    $FatalState = if ($IsReportOnly) { 'Review' } else { 'Blocked' }
    if ($Discovery.OSDisk -and $Discovery.OSDisk.PartitionStyle -eq 'GPT') {
        $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Partition style' -Message 'The OS disk uses GPT.'))
    } elseif ($Discovery.OSDisk -and $Discovery.OSDisk.PartitionStyle) {
        $Findings.Add((New-PatchWinRESystemFinding -State $FatalState -Topic 'Partition style' -Message ('The OS disk uses {0}; the script requires GPT.' -f $Discovery.OSDisk.PartitionStyle)))
    } else {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Partition style' -Message 'The OS disk partition style could not be determined.'))
    }

    $Recovery = $Discovery.SelectedRecoveryPartition
    $PartitionInventoryKnown = $null -ne $Discovery.Partitions -and $null -ne $Discovery.RecoveryPartitions
    $RecoveryPartitions = @($Discovery.RecoveryPartitions)
    if (-not $PartitionInventoryKnown) {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Recovery partition' -Message 'The partition inventory could not be completed.'))
    } elseif (-not $Recovery -and $RecoveryPartitions.Count -gt 0) {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Recovery partition' -Message 'Recovery partitions were found, but the active WinRE location could not be matched to one.'))
    } elseif (-not $Recovery) {
        if ($EffectiveCreate -or $EffectiveReplace) {
            $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Recovery partition' -Message 'No recovery partition was found; this operation can create one.'))
        } elseif ($IsReportOnly) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Recovery partition' -Message 'No recovery partition was found. Report only will report this condition.'))
        } else {
            $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'Recovery partition' -Message 'No recovery partition was found. Use an operation that creates or replaces WinRE.'))
        }
    } else {
        if ($EffectiveCreate) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Recovery partition' -Message 'A recovery partition already exists; the script switches from create to resize mode.'))
        } elseif ($RecoveryPartitions.Count -gt 1) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Recovery partition' -Message ('Found {0} recovery partitions. The script selects the one with the most free space when WinRE is disabled.' -f $RecoveryPartitions.Count)))
        } else {
            $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Recovery partition' -Message ('Selected disk {0}, partition {1}.' -f $Recovery.DiskNumber, $Recovery.PartitionNumber)))
        }
        if ($Discovery.OSPartition -and
            $Recovery.DiskNumber -eq $Discovery.OSPartition.DiskNumber -and
            $Recovery.PartitionNumber -eq $Discovery.OSPartition.PartitionNumber -and
            -not $EffectiveCreate) {
            $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'Recovery partition' -Message 'The selected recovery partition is the OS partition; the script cannot handle this layout.'))
        }
        if ($Discovery.OSPartition -and $Recovery.DiskNumber -ne $Discovery.OSPartition.DiskNumber) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Recovery partition' -Message 'The selected recovery partition is on a different disk from the OS.'))
        }
        if ($Discovery.ReagentStatusToken -eq 'Enabled' -and
            $null -ne $Discovery.ActualRecoveryDiskNumber -and
            ($Discovery.ScriptRecoveryDiskNumber -ne [string]$Discovery.ActualRecoveryDiskNumber -or
             $Discovery.ScriptRecoveryPartitionNumber -ne [string]$Discovery.ActualRecoveryPartitionNumber)) {
            $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'reagentc location' -Message ('The script reads one digit from the reagentc location and may target disk {0}, partition {1}; the full location is disk {2}, partition {3}.' -f $Discovery.ScriptRecoveryDiskNumber, $Discovery.ScriptRecoveryPartitionNumber, $Discovery.ActualRecoveryDiskNumber, $Discovery.ActualRecoveryPartitionNumber)))
        }
    }

    if (-not $EffectiveCreate -and $Recovery -and $Discovery.OSPartition) {
        $DiskPartitions = @($Discovery.Partitions | Where-Object { $_.DiskNumber -eq $Recovery.DiskNumber } | Sort-Object PartitionNumber)
        if ($DiskPartitions.Count -gt 0) {
            $LastPartition = $DiskPartitions[-1]
            $RecoveryIsLast = $Recovery.PartitionNumber -eq $LastPartition.PartitionNumber
            $OSPartitions = @($Discovery.Partitions | Where-Object {
                $_.DiskNumber -eq $Discovery.OSPartition.DiskNumber -and
                $_.PartitionNumber -eq $Discovery.OSPartition.PartitionNumber
            })
            $OSIsLast = $false
            if ($OSPartitions.Count -gt 0) {
                $OSDiskPartitions = @($Discovery.Partitions | Where-Object { $_.DiskNumber -eq $Discovery.OSPartition.DiskNumber } | Sort-Object PartitionNumber)
                $OSIsLast = $OSDiskPartitions.Count -gt 0 -and $Discovery.OSPartition.PartitionNumber -eq $OSDiskPartitions[-1].PartitionNumber
            }
            $SizeToVerify = if ($EffectiveDoNotExpand) { [decimal](100MB) } elseif ($null -ne $NewSize) { [decimal]$NewSize } else { [decimal](1GB) }
            if ($null -eq $Recovery.Size) {
                $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Partition size' -Message 'The selected recovery partition size could not be determined.'))
            } elseif ([decimal]$Recovery.Size -lt $SizeToVerify) {
                if (-not $OSIsLast -and -not $RecoveryIsLast) {
                    $Findings.Add((New-PatchWinRESystemFinding -State $FatalState -Topic 'Partition order' -Message 'The recovery partition is undersized, and neither it nor the OS partition is last on its disk. The script cannot shrink the OS partition safely.'))
                } elseif ($RecoveryIsLast -and ($Recovery.DiskNumber -ne $Discovery.OSPartition.DiskNumber -or $Recovery.PartitionNumber -ne ($Discovery.OSPartition.PartitionNumber + 1))) {
                    $Findings.Add((New-PatchWinRESystemFinding -State $FatalState -Topic 'Partition order' -Message 'The recovery partition is undersized and is not immediately after the OS partition. The script cannot shrink the OS partition safely.'))
                } else {
                    $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Partition order' -Message 'The undersized recovery partition is positioned so the script can attempt a resize.'))
                }
            } else {
                $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Partition size' -Message 'The recovery partition meets the size prerequisite.'))
            }
        } else {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Partition order' -Message 'Partition order could not be determined.'))
        }
    }

    if ($NewSize -gt 0 -and $Operation.Key -ne 'ReportOnly') {
        if ($Recovery -and $null -eq $Recovery.Size) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Resize' -Message 'The selected recovery partition size could not be determined.'))
        } elseif ($Recovery -and [decimal]$Recovery.Size -ge $NewSize) {
            $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Resize' -Message 'The recovery partition already meets the requested size; no resize is needed.'))
        } elseif ($Recovery -and -not $PartitionInventoryKnown) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Resize' -Message 'The partition inventory is incomplete, so the resize mode cannot be determined.'))
        } elseif ($Discovery.OSVolume -and $Discovery.SupportedSize) {
            $RecoveryDiskPartitions = @($Discovery.Partitions | Where-Object { $_.DiskNumber -eq $Recovery.DiskNumber } | Sort-Object PartitionNumber)
            $RepartitionMode = $Recovery -and $RecoveryDiskPartitions.Count -gt 0 -and
                ($RecoveryDiskPartitions[-1].PartitionNumber -ne $Recovery.PartitionNumber)
            $RequiredShrink = if ($EffectiveCreate -or $RepartitionMode) { [decimal]$NewSize } elseif ($Recovery) { [decimal]$NewSize - [decimal]$Recovery.Size } else { [decimal]$NewSize }
            $FreeEnough = [decimal]$Discovery.OSVolume.SizeRemaining -ge [decimal]$NewSize
            $Shrinkable = [decimal]$Discovery.SupportedSize.SizeMax - [decimal]$Discovery.SupportedSize.SizeMin
            if ($RepartitionMode) {
                $ScriptCheck = [decimal]$Shrinkable -ge ([decimal]$NewSize - [decimal]$Recovery.Size)
                if ($ScriptCheck -and $Shrinkable -lt $RequiredShrink) {
                    $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'Resize' -Message 'Repartition mode needs the full new size of shrinkable space, but the script checks only the size minus the existing recovery partition. It may delete the recovery partition and then fail, leaving WinRE disabled.'))
                } elseif (-not $ScriptCheck -or -not $FreeEnough) {
                    $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'Resize' -Message 'There is not enough free or shrinkable space for the requested size. The script may leave WinRE disabled if shrinking fails.'))
                } else {
                    $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Resize' -Message 'The recovery partition is not last. Resizing uses repartition mode and leaves an empty partition where the old recovery partition was.'))
                }
            } elseif (-not $FreeEnough -or $Shrinkable -lt $RequiredShrink) {
                $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'Resize' -Message ('The OS volume needs {0:N2} GB free and {1:N2} GB of shrinkable space; available: {2:N2} GB free and {3:N2} GB shrinkable. A failed shrink can leave WinRE disabled.' -f ($NewSize / 1GB), ($RequiredShrink / 1GB), ([decimal]$Discovery.OSVolume.SizeRemaining / 1GB), ($Shrinkable / 1GB))))
            } else {
                $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Resize' -Message 'The OS volume has enough free and shrinkable space for the requested size.'))
            }
        } else {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Resize' -Message 'Free space or supported shrink size could not be determined.'))
        }
    }

    if ($Discovery.MountedImages -and @($Discovery.MountedImages).Count -gt 0) {
        $MountedState = if ($OperationNeedsMount) { 'Blocked' } else { 'Review' }
        $Findings.Add((New-PatchWinRESystemFinding -State $MountedState -Topic 'Mounted images' -Message ('Found {0} mounted Windows image(s). The selected operation {1}.' -f @($Discovery.MountedImages).Count, $(if ($OperationNeedsMount) { 'cannot start while an image is mounted' } else { 'does not mount an image' }))))
    } elseif ($null -ne $Discovery.MountedImages) {
        $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Mounted images' -Message 'No mounted Windows images were found.'))
    } else {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Mounted images' -Message 'Mounted images could not be checked.'))
    }

    if ($Discovery.WinREImageExists) {
        $ImageMessage = 'WinRE.wim was found'
        if ($Discovery.WinREImageSize) { $ImageMessage += (' ({0:N2} GB).' -f ([decimal]$Discovery.WinREImageSize / 1GB)) } else { $ImageMessage += '.' }
        if ($Discovery.WinREImageVersion) { $ImageMessage += (' Image build: {0}.' -f $Discovery.WinREImageVersion) }
        $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'WinRE image' -Message $ImageMessage))
    } elseif ($EffectiveReplace -or ($EffectiveCreate -and -not [string]::IsNullOrWhiteSpace($State.WIMFilePath))) {
        $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'WinRE image' -Message 'No current WinRE image was found; the selected WIM file will be used.'))
    } elseif (-not $Discovery.WinREImageChecked) {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'WinRE image' -Message 'The WinRE image location could not be checked.'))
    } elseif ($EffectiveCreate) {
        $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'WinRE image' -Message 'No current WinRE image was found. Select a WIM file to create the recovery partition.'))
    } elseif ($IsReportOnly) {
        $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'WinRE image' -Message 'No WinRE image was found. Report only will report this condition.'))
    } else {
        $Findings.Add((New-PatchWinRESystemFinding -State Blocked -Topic 'WinRE image' -Message 'No online or offline WinRE image was found.'))
    }

    foreach ($ErrorMessage in @($Discovery.Errors)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$ErrorMessage)) {
            $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Discovery' -Message ([string]$ErrorMessage)))
        }
    }

    if ($Discovery.WinREImageExists -and $Discovery.WinREImageSize) {
        if ($Operation.Key -ne 'ReportOnly') {
            $BackupFree = Get-PatchWinRESystemDriveFreeBytes -Discovery $Discovery -Path $State.BackupDirectory
            if ($null -ne $BackupFree -and $BackupFree -lt [decimal]$Discovery.WinREImageSize) {
                $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Backup space' -Message 'The backup drive has less free space than the current WinRE image. Confirm that enough space is available.'))
            } elseif ($null -eq $BackupFree) {
                $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic 'Backup space' -Message 'Free space for the WinRE backup could not be checked (network or non-local path).'))
            } else {
                $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic 'Backup space' -Message 'The backup drive has enough space for one copy of the current WinRE image.'))
            }
        }
        if ($OperationNeedsMount) {
            $RequiredWork = [decimal]$Discovery.WinREImageSize * 3
            foreach ($Folder in @(
                [PSCustomObject]@{ Topic = 'Working space'; Path = $State.WorkingDirectory },
                [PSCustomObject]@{ Topic = 'Mount space'; Path = $State.MountDirectory }
            )) {
                $FreeBytes = Get-PatchWinRESystemDriveFreeBytes -Discovery $Discovery -Path $Folder.Path
                if ($null -eq $FreeBytes) {
                    $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic $Folder.Topic -Message 'Free space could not be checked (network or non-local path).'))
                } elseif ($FreeBytes -lt $RequiredWork) {
                    $Findings.Add((New-PatchWinRESystemFinding -State Review -Topic $Folder.Topic -Message ('About {0:N2} GB may be needed; {1:N2} GB is free.' -f ($RequiredWork / 1GB), ($FreeBytes / 1GB))))
                } else {
                    $Findings.Add((New-PatchWinRESystemFinding -State Pass -Topic $Folder.Topic -Message ('About {0:N2} GB is needed; {1:N2} GB is free.' -f ($RequiredWork / 1GB), ($FreeBytes / 1GB))))
                }
            }
        }
    }

    $Blocked = @($Findings | Where-Object { $_.State -eq 'Blocked' })
    $Review = @($Findings | Where-Object { $_.State -eq 'Review' })
    if ($Blocked.Count -gt 0) {
        $Readiness = 'Blocked'; $Title = 'BLOCKED'
        $Detail = '{0} finding(s) block this operation.' -f $Blocked.Count
    } elseif ($Review.Count -gt 0) {
        $Readiness = 'Review'; $Title = 'REVIEW'
        $Detail = '{0} finding(s) need review before you proceed.' -f $Review.Count
    } else {
        $Readiness = 'Pass'; $Title = 'READY'
        $Detail = 'No blocking system findings were detected.'
    }
    $Entries = @($Findings | ForEach-Object {
        $Level = switch ($_.State) { 'Blocked' { 'ERROR' } 'Review' { 'WARN' } default { 'INFO' } }
        [PSCustomObject]@{
            Level = $Level
            Type = if ($_.State -eq 'Blocked') { 3 } elseif ($_.State -eq 'Review') { 2 } else { 1 }
            Component = $_.Topic
            Message = $_.Message
            Display = ('{0,-8}[{1}] {2}' -f $Level, $_.Topic, $_.Message)
        }
    })
    [PSCustomObject]@{
        Readiness = $Readiness
        Title = $Title
        Detail = $Detail
        Findings = @($Findings.ToArray())
        Entries = $Entries
    }
}

function Get-PatchWinRESystemCheckTooltip {
    <#
    .SYNOPSIS
        Returns the Check System tooltip for the current mode.
    #>
    param(
        [bool]$IsElevated,
        [bool]$GenerateOnly
    )
    if (-not $IsElevated) {
        return 'Requires administrator mode. Checks WinRE status, partition layout, free space and prerequisites without changing recovery configuration.'
    }
    if ($GenerateOnly) {
        return 'Unavailable in generate-only mode. Checks WinRE status, partition layout, free space and prerequisites without changing recovery configuration.'
    }
    return 'Checks WinRE status, partition layout, free space and prerequisites without changing recovery configuration.'
}
