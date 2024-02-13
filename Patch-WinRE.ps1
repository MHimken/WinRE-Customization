<#
.SYNOPSIS
    Customizes WinRE. This script will apply patches and drivers. Will resize recovery partition if needed.
.DESCRIPTION
    This script was created to automate the remediation of CVE-2022-41099, but can also be used to automate the patching and customization of WinRE. 
    If specified, the script will check the size of your recovery partition and resize it if necessary.
    
    !!There is an order that has be followed when adding things to _any_ type of Windows Image see https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/servicing-the-image-with-windows-updates-sxs !!
    
    #####ATTENTION#####
    This can only be done automatically if the sysdrive has enough space and no blocking files to shrink it to the required size. This is verified.
    This script will attempt to use the default sequence recommended for OS GPT partitions. Meaning the recovery drive will always be created by shrinking the OS drive.
.PARAMETER WorkingDirectory
    Adds a working directory as we need to create some logs and files. Default C:\WinRE-Customization\
.PARAMETER BackupDirectory
    Specify a folder to backup WinRE to. Careful, WinRE backups will not be deleted even if successful (use -DeleteBackups if desired). Default is C:\WinRE-Customization\WinREBackups\
.PARAMETER MountDirectory
    Specify the folder to mount your WinRE to. Default is C:\WinRE-Customization\WinREMount\
.PARAMETER LogDirectory
    Specify a folder to output logs to. Default is C:\WinRE-Customization\Logs
.PARAMETER FoDDirectory
    #ToDo Features and Language Packs go here
.PARAMETER PatchFilesGDRDUorLCU
    Use to apply the latest cumulative update (LCU) or general distribution release dynamic update (GDRDU).
    Accepts the path to a folder containing CABs/MSUs or a single CAB/MSU file. Please make sure that you provide this script with the appropriate OS version file.
    Attention: SSUs _must_ start with "ssu" to be applied first.
    Attention: To ensure that you have enough space left on your recovery partition after patching with a GDRDU/LCU, it will check if the minimum of 1GB is configured and otherwise extend the partition (aka recreate).
.PARAMETER PatchFilesDUorSOS
    Use this to apply the Dynamic Update (DU) and Safe OS (SOS) updates.
    Accepts the path to a folder containing CABs or a single CAB file. Please make sure you provide this script with the appropriate OS version file(s).
.PARAMETER RecoveryDriveSizeInGB
    Specify the size of the recovery disk. The default is 1GB. If not specified, the size is assumed to be appropriate.
    Caution: It is recommended to set this, it will be checked before changing it.
.PARAMETER FilesDriver
    Specify the path to a folder containing the drivers - must have at least one *.inf file. You can also specify a single path to an *.inf file.
.PARAMETER DeleteBackups
    Removes all .wim files in the folder specified through -BackupDirectory.
.PARAMETER CreateWinREDrive
    This parameter allows you to create a recovery drive only. It assumes that you don't need a backup of WinRE at this point. However, the activation will fail if WinRE.wim is missing from %systemroot%/system32/recovery.
.PARAMETER AbortIfFailed
    If applying content fails, this switch will automatically discard all changes when the image is unmounted.
    This will cause the script to exit successfully if the content couldn't be applied(!)
.PARAMETER ReportOnly
    This switch returns only some general information about the current state of the recovery drive and recovery agent.
    This parameter causes the script to always run successfully, as it is intended for information gathering purposes.
.PARAMETER ToConsole
    This parameter does NOT CREATE A LOG. Instead, it returns to the current output (console or similar).
.INPUTS
    None, script only accepts parameterised input.
.OUTPUTS
    None, this script doesn't output anything unless -ToConsole is used.
.EXAMPLE
    This will create a backup of WinRE, then exit.
    Patch-WinRE.ps1
.EXAMPLE
    This example will use a subfolder named "LCU" in the current script location as a resource for MSUs. It will resize the recovery partition to 2GB if necessary.
    Backups will be written to C:\WinREBackup\. Temporarily, C:\WinREMounted\ is used as the mounting directory.
    Patch-WinRE.ps1 -PatchFilesGDRDUorLCU C:\temp\LCU -RecoveryDriveSizeInGB 2GB -MountDirectory C:\WinREMounted\ -BackupDirectory C:\WinREBackup\
.EXAMPLE
    This will delete all backups created by Patch-WinRE in a custom folder.
    Patch-WinRE.ps1 -BackupDirectory C:\Temp\ -DeleteBackups
.EXAMPLE
    Will perform all three main functions of this script. Create a backup of the WinRE, resize the partition to 1GB, apply patches and add drivers from a folder
    Patch-WinRE.ps1 -PatchFilesGDRDUorLCU C:\temp\LCU -RecoveryDriveSizeInGB 1GB -FilesDriver C:\Temp\Drivers\x64\
.EXAMPLE
    This example will apply all CAB/MSUs from the specified directory and discard changes if any of the patches fail.
    Patch-WinRE.ps1 -PatchFilesGDRDUorLCU C:\temp\LCU -AbortIfFailed
.EXAMPLE
    This example will create a recovery partition only - nothing else.
    Patch-WinRE.ps1 -CreateWinREDrive
.EXAMPLE
    This example will expand the recovery partition to 1GB and pipe all log messages to the current output instead of the log file. 
    See the second link in the LINKS section to learn more about what partitioning is covered.
    Patch-WinRE.ps1 -RecoveryDriveSizeInGB 1GB -ToConsole
.NOTES
    Version: 3.2
    Versionname: REcovered Mystery
    Intial creation date: 11.01.2023
    Last change date: 06.02.2024
    Latest changes: https://github.com/MHimken/WinRE-Customization/blob/main/changelog.md
.LINK
    https://manima.de/2023/01/modify-winre-patches-drivers-and-cve-2022-41099/
    https://manima.de/2024/01/winre-patching-round-2/
#>

param(
    [System.IO.DirectoryInfo]$WorkingDirectory = 'C:\WinRE-Customization\',
    [System.IO.DirectoryInfo]$BackupDirectory = 'C:\WinRE-Customization\WinREBackups\',
    [System.IO.DirectoryInfo]$MountDirectory = 'C:\WinRE-Customization\WinREMount\',
    [System.IO.DirectoryInfo]$LogDirectory = 'C:\WinRE-Customization\Logs\',
    # Can't use [System.IO.DirectoryInfo] here, as it will not accept a single file.
    $FoDDirectory,
    $PatchFilesGDRDUorLCU,
    $PatchFilesDUorSOS,
    $RecoveryDriveSizeInGB,
    $FilesDriver,
    $DeleteBackups = $false, #Make really sure you want to do this, hence not a switch
    [switch]$CreateWinREDrive,
    [switch]$AbortIfFailed,
    [switch]$ReportOnly,
    [switch]$ToConsole
)
$Script:TimeStampStart = Get-Date
if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null }
$Script:RecoveryPartition = $false
$CurrentLocation = Get-Location
Set-Location $WorkingDirectory
# Setting some variables - you can change these if you know what you're doing
$Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
$LogPrefix = 'Patch'
$LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $DateTime)

# Functions
function Get-ScriptPath {
    if ($psISE) {
        if ([object].Assembly.GetType('System.AppContextSwitches').GetField('_useLegacyPathHandling', 'Static, NonPublic').GetValue($null) -eq 1) {
            Write-Output 'Running in ISE you need to disable legacy path handling - use the following command to disable temporarily and try again'
            Write-Output "[object].Assembly.GetType('System.AppContextSwitches').GetField('_useLegacyPathHandling', 'Static, NonPublic').SetValue(`$null, -1)"
            exit 6
        }
    }
    if ($PSScriptRoot) { 
        # Console or VS Code debug/run button/F5 temp console
        $ScriptRoot = $PSScriptRoot 
    } else {
        if ($psISE) { 
            Split-Path -Path $psISE.CurrentFile.FullPath
        } else {
            if ($profile -match 'VScode') { 
                # VS Code "Run Code Selection" button/F8 in integrated console
                $ScriptRoot = Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
            } else { 
                Write-Output 'unknown directory to set path variable. exiting script.'
                exit
            } 
        } 
    }
    $Script:PathToScript = $ScriptRoot
}
function Write-Log {
    <#
    .DESCRIPTION
        This is a modified version of Ryan Ephgrave's script
    .LINK
        https://www.ephingadmin.com/powershell-cmtrace-log-function/
    #>
    Param (
        [Parameter(Mandatory = $false)]
        $Message,
        $Component,
        # Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
        [ValidateSet('1', '2', '3')][int]$Type
    )
    $Time = Get-Date -Format 'HH:mm:ss.ffffff'
    $Date = Get-Date -Format 'MM-dd-yyyy'
    if (-not($Component)) { $Component = 'Runner' }
    if (-not($Type)) { $Type = 1 }
    if (-not($ToConsole)) {
        $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
        $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
    } elseif ($ToConsole) {
        Write-Output "T:$Type C:$Component M:$Message"
    }
}
function Get-Stats {
    param(
        [switch]$InitialRun,
        [switch]$ReportOnly,
        [switch]$Report
    )
    if ($InitialRun) {
        $TimeStampStop = Get-Date
        $RuntimeRaw = $TimeStampStop - $Script:TimeStampStart
        $Script:Runtime = $RuntimeRaw.ToString("hh':'mm':'ss")
        if ($Script:RecoveryPartition) {
            $RecoveryVolume = Get-Volume -Partition $Script:RecoveryPartition
            $Script:CurrentRecoveryPartitionSize = [math]::round($RecoveryVolume.Size / 1GB, 2)
            $Script:CurrentRecoveryPartitionFree = [math]::round($RecoveryVolume.SizeRemaining / 1GB, 2)
            $Script:InitialRecoveryPartitionSize = $Script:CurrentRecoveryPartitionSize
            $Script:InitialRecoveryPartitionSizeFree = $Script:CurrentRecoveryPartitionFree
        }
    }
    if ($ReportOnly) {
        if ($Script:RecoveryPartition) {
            $LastPartitionNumber = $((Get-Partition -DiskNumber $Script:RecoveryDiskNumber | Select-Object -Last 1).PartitionNumber)
        } else {
            Write-Log -Message 'No recovery partition found - report will be empty' -Component 'StatsGathering' -Type 2
        }
        Write-Log -Message "Recovery Partition Stats
        Recovery partition size: $Script:CurrentRecoveryPartitionSize GB
        Recovery partition free space: $Script:CurrentRecoveryPartitionFree GB
        Current location: Hardisk $Script:RecoveryDiskNumber Partition $Script:RecoveryPartitionNumber
        RecoveryIsLastPartition: $($Script:RecoveryPartitionNumber -eq $LastPartitionNumber)
        OSIsLastPartition: $((Get-Partition -DriveLetter ($ENV:SystemDrive).Replace(':','')).PartitionNumber -eq $LastPartitionNumber)
        If the estimated WinRE size is <300MB or >2GB the recovery 'partition' is likely the OS-Drive.
        Estimated WinRE.wim size: $($Script:CurrentRecoveryPartitionSize - $Script:CurrentRecoveryPartitionFree) GB
        Script runtime: $Script:Runtime`n
        More information can be found at 
        C:\Windows\Logs\ReAgent\ReAgent.log" -Component 'StatsGathering'
        return
    }
    if ($Report) {
        Write-Log -Message 'Refreshing partition information' -Component 'StatsGathering'
        Update-RecoveryPartitionInformation
        if (Test-Path $BackupDirectory) {
            Get-ChildItem -Path (Join-Path -Path $BackupDirectory -ChildPath '*') -Filter *.wim -Force | Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object { $Script:BackupWinRESize = [math]::round($_.Length / 1GB, 2) }
        }
        $RecoveryVolume = Get-Volume -Partition $Script:RecoveryPartition
        $Script:CurrentRecoveryPartitionSize = [math]::round($RecoveryVolume.Size / 1GB, 2)
        $Script:CurrentRecoveryPartitionFree = [math]::round($RecoveryVolume.SizeRemaining / 1GB, 2)
        $Script:EstimatedCurrentWinRESize = $Script:CurrentRecoveryPartitionSize - $Script:CurrentRecoveryPartitionFree
        $DifferenceWinREEstimate = $Script:BackupWinRESize - $Script:EstimatedCurrentWinRESize
        Write-Log -Message "Recovery partition size before running: $Script:InitialRecoveryPartitionSize GB
        Recovery partition free space before running: $Script:InitialRecoveryPartitionSizeFree GB
        Recovery partition size after running: $Script:CurrentRecoveryPartitionSize GB
        Recovery partition free space after running: $Script:CurrentRecoveryPartitionFree GB
        Estimated Current WinRE size: $Script:EstimatedCurrentWinRESize GB
        Backup WinRE size: $Script:BackupWinRESize
        Backup WinRE difference: $DifferenceWinREEstimate
        Script runtime: $Script:Runtime`n 
        More information can be found at 
        C:\Windows\Logs\ReAgent\ReAgent.log
        C:\Windows\Logs\Dism\Dism.log" -Component 'StatsGathering'
        return
    }
}

function Get-WinREImageLocation {
    <#
    .NOTES
    Thanks Christopher Moore https://github.com/dreary-ennui
    #>
    param(
        [switch]$OnlineLocation
    )
    [xml]$ReAgentXML = [System.IO.File]::ReadAllText("$env:SYSTEMROOT\System32\Recovery\ReAgent.xml")
    if (-not($OnlineLocation)) {
        if ($ReAgentXML.WindowsRE.ImageLocation.Guid -eq "{00000000-0000-0000-0000-000000000000}") {
            $WinREImagepath = "$env:SYSTEMROOT\System32\Recovery\WinRE.wim"
            $WinREImageLocationPartition = (Get-Partition -DriveLetter ($ENV:SystemDrive).Substring(0, 1)).PartitionNumber
            $WinREImageLocationDisk = (Get-Partition -DriveLetter ($ENV:SystemDrive).Substring(0, 1)).DiskNumber
        } else {
            $WinREImageLocationDisk = Get-Disk | Where-Object { $_.Guid -eq $ReAgentXML.WindowsRE.ImageLocation.Guid }
            $WinREImageLocationPartition = Get-Partition -DiskNumber $WinREImageLocationDisk.DiskNumber | Where-Object { $_.Offset -eq $ReAgentXML.WindowsRE.ImageLocation.offset }
            $WinREImagePath = Join-Path -Path $WinREImageLocationPartition.AccessPaths[0] -ChildPath "$($ReAgentXML.WindowsRE.ImageLocation.path)\WinRE.wim"
            if (-not(Test-Path -LiteralPath $WinREImagePath)) {
                Write-Log -Message "Image expected at $WinREImagePath but not found" -Component GetWinREImageLocation -Type 2
                $WinREImagePath = $false
            }
        }

    } else {
        $WinREImageLocationDisk = Get-Disk | Where-Object { $_.Guid -eq $ReAgentXML.WindowsRE.WinreLocation.Guid }
        $WinREImageLocationPartition = Get-Partition -DiskNumber $WinREImageLocationDisk.DiskNumber | Where-Object { $_.Offset -eq $ReAgentXML.WindowsRE.WinreLocation.offset }
        $WinREImagePath = Join-Path -Path $WinREImageLocationPartition.AccessPaths[0] -ChildPath "$($ReAgentXML.WindowsRE.WinreLocation.path)\WinRE.wim"
        if (-not(Test-Path -LiteralPath $WinREImagePath)) {
            Write-Log -Message "Image expected at $WinREImagePath but not found" -Component GetWinREImageLocation -Type 2
            $WinREImagePath = $false
        }
    }
    $Script:RecoveryImagePath = $WinREImagepath
    $Script:RecoveryImagePathPartition = $WinREImageLocationPartition
    $Script:RecoveryImagePathDisk = $WinREImageLocationDisk
    return 
}
function Get-WinREStatus {
    Write-Log -Message 'Retrieving current WinRE status' -Component 'WinREStatus'
    $WinreStatus = reagentc /info
    $RecoveryPartitionStatus = $WinreStatus.split("`n")[3].split(' ')[-1]
    if ($LASTEXITCODE -eq 5) {
        Write-Log -Message 'You did not run the script as admin' -Component 'WinREStatus' -Type 3
        $Status = $false
    }
    switch ($RecoveryPartitionStatus) {
        'Enabled' { Write-Log -Message 'Recovery Agent is enabled' -Component 'WinREStatus'; $Status = $true }
        'Disabled' { Write-Log -Message 'Recovery Agent is disabled' -Component 'WinREStatus'; $Status = $false }
        default { Write-Log -Message 'Recovery Agent status could not be determined. Are you running as admin?' -Component 'WinREStatus' -Type 3; $Status = $null }
    }
    return $Status
}
function Disable-WinRE {
    $DisableRE = ReAgentc.exe /disable
    #Regex will check if the message contains an error number. Errors will cause reagentc to throw and not return anything
    #Exitcode 2 = Already disabled
    if ($LASTEXITCODE -eq 2 -or ($LASTEXITCODE -eq 0 -and ($DisableRE) -and ($DisableRE[0] -notmatch ".*\d+.*"))) {
        Write-Log -Message 'Disabled WinRE' -Component 'DisableWinRE'
        Get-WinREImageLocation
        return $true
    } else {
        Write-Log -Message 'Disabling failed' -Component 'DisableWinRE' -Type 3
        return $false
    }
}
function Enable-WinRE {
    $EnableRE = ReAgentc.exe /enable
    if (($EnableRE[0] -notmatch ".*\d+.*") -and $LASTEXITCODE -eq 0) {
        Write-Log -Message 'Enabled WinRE' -Component 'EnableWinRE'
        Get-WinREImageLocation -OnlineLocation
        return $true
    } else {
        Write-Log -Message 'Enabling failed' -Component 'EnableWinRE' -Type 3
        return $false
    }
}
function Mount-WinRE {
    if (-not(Test-Path $MountDirectory)) {
        New-Item $MountDirectory -ItemType Directory
    } else {
        Write-Log -Message 'Directory already exists - verifying its empty' -Component 'MountWinRE'
        $MountDirectoryEmpty = Get-ChildItem $MountDirectory 
        if ($MountDirectoryEmpty) {
            Write-Log -Message "Mount directory isn't empty - exiting" -Component 'MountWinRE' -Type 3
            return $false
        }
    }
    Write-Log -Message 'Mounting WinRE' -Component 'MountWinRE'    
    if ((Get-WindowsImage -Mounted).count -ge 1) {
        Write-Log -Message 'There is at least one other image mounted already' -Component 'MountWinRE' -Type 2
        return $false
    }
    if (-not(Get-WinREStatus)) {
        if (-not(Enable-WinRE)) {
            Write-Log -Message 'WinRE could not be enabled - due to a recent change it needs to be enabled to mount the image' -Component 'MountWinRE' -Type 3
            return $false
        } else {
            Write-Log -Message 'Recovery Agent enabled to mount the image' -Component 'MountWinRE'
        }
    }
    $Mount = ReAgentC.exe /mountre /path $MountDirectory
    if ($Mount) {
        if ($Mount[0] -notmatch ".*\d+.*" -and (Get-WindowsImage -Mounted).count -ge 1 -and $LASTEXITCODE -eq 0) {
            Write-Log -Message 'WinRE successfully mounted using ReAgentC' -Component 'MountWinRE'
            return $true
        }
    } else {
        Write-Log -Message 'Could not mount WinRE image - please consult the log' -Component 'MountWinRE' -Type 3
        Write-Log -Message "$Mount" -Component 'MountWinRE'
        Write-Log -Message "Trying to copy the reagentc.log to the log folder" -Component 'MountWinRE'
        $ReagentCLog = Join-Path -Path $LogDirectory -ChildPath ("ReAgentC_$DateTime.log")
        Copy-Item -Path "$env:SystemDrive\Windows\Logs\ReAgent\ReAgent.log" -Destination $ReagentCLog
        return $false
    }
}
function Dismount-WinRE {
    param(
        [switch]$Discard
    )
    $DismountImageLogFile = Join-Path -Path $LogDirectory -ChildPath ('Dismount-WindowsImage_{0}.log' -f $DateTime)
    $DismountWinRECommonParameters = @{
        Path     = $MountDirectory
        LogLevel = 'WarningsInfo'
    }
    $ResetBaseLogFile = Join-Path -Path $LogDirectory -ChildPath ('ResetBase_{0}.log' -f $DateTime)
    Write-Log -Message 'Cleanup before dismount (shrink image to only required size)' -Component 'DismountWinRE'
    dism /image:$MountDirectory /cleanup-image /StartComponentCleanup /ResetBase /LogPath:$ResetBaseLogFile /loglevel:3
    Write-Log -Message 'Cleanup done, verifying image status' -Component 'DismountWinRE'
    $REMountedStatus = $((Get-WindowsImage -Mounted).MountStatus -eq "Ok")
    if ($REMountedStatus -and -not($Discard)) {
        Write-Log -Message "Mounted WinRE status is $REMountedStatus" -Component 'DismountWinRE'
        $UnmountCommit = ReAgentC.exe /unmountre /path $($MountDirectory) /commit
    } else {
        $UnmountCommit = $false
    }
    #ReAgentC responds with an error in case of a failure, not a string. Verify that the var is set
    <#Error collection so far
        -1052638948 or c142011c = Image isn't mounted anymore
    #>
    if (-not($UnmountCommit) -or $LASTEXITCODE -ne 0) {
        Write-Log -Message 'Commiting failed - discarding changes' -Component 'DismountWinRE' -Type 3
        Write-Log -Message "Status of the WinRE during this operation according to Get-WindowsImage was: $((Get-WindowsImage -Mounted).MountStatus)" -Component 'DismountWinRE'
        $UnmountDiscard = ReAgentC.exe /unmountre /path $($MountDirectory) /discard
        if (($UnmountDiscard[0] -match ".*\d+.*") -or $LASTEXITCODE -ne 0) {
            Write-Log 'Attempting to unmount and discard failed - trying alternative method' -Component 'DismountWinRE' -Type 2
            Dismount-WindowsImage @DismountWinRECommonParameters -LogPath $DismountImageLogFile -Discard
            if ($(Get-WindowsImage -Mounted).count -ge 1) {
                Write-Log -Message 'Unmounting finally failed, please consult the logs' -Component 'DismountWinRE' -Type 3
                return $false
            } else {
                Write-Log 'Alternative unmounting successful, but discarded changes, please consult the logs for more information' -Component 'DismountWinRE' -Type 3
                return $false
            }
        } else {
            Write-Log -Message 'Unmounting done, but discarded changes, please consult the logs' -Component 'DismountWinRE' -Type 3
            return $false
        }   
    } elseif ($UnmountCommit[0] -notmatch ".*\d+.*") {
        Write-Log -Message 'WinRE commited changes successfully - cleaning up temporary folder' -Component 'DismountWinRE'
        Remove-Item $MountDirectory -Force -Recurse
        Write-Log -Message 'Disabling WinRE, otherwise BitLocker will complain. Will re-enable at the end' -Component 'DismountWinRE' -Type 2
        if (-not(Disable-WinRE)) {
            Write-Log -Message 'Disabling WinRE failed - this means BitLocker will require the recovery key next reboot' -Component 'DismountWinRE' -Type 3
            Write-Log -Message 'After next reboot try reagentc /disable and reagentc /enable and troubleshoot if required' -Component 'DismountWinRE' -Type 2
        }
        return $true
    }
}
function Update-ReAgentXML {
    <#
    .NOTES
    If a recovery partition re-format is required, the recovery image will be placed next to the OS drive. This function ensures, 
    that the ImageLocation and WinreLocation are set to "default".
    ImageLocation = Location of WinRE while recovery agent is disabled
    WinreLocation = Location of WinRE while recovery agent is enabled
    #>
    Write-Log -Message 'Ensure that the WinRE.wim ImageLocation is set to default' -Component 'UpdateReAgentXML'
    if (-not(Get-WinREStatus)) {
        if (-not(Enable-WinRE)) {
            Write-Log -Message 'WinRE was disabled and could not be enabled, which is a requirement for this function' -Component 'UpdateReAgentXML'
            return $false
        }
    }
    $ReAgentXMLLocation = "$env:SYSTEMROOT\System32\Recovery\ReAgent.xml"
    $ToBackupHash = Get-FileHash -LiteralPath $ReAgentXMLLocation -Algorithm MD5
    $XMLBackups = Get-ChildItem (Join-Path -Path $BackupDirectory -ChildPath '*') -Include *.xml -Force
    if ($XMLBackups.count -ge 1) {
        foreach ($Backup in $XMLBackups) {
            $BackedFile = Get-FileHash $Backup.FullName -Algorithm MD5
            if ($BackedFile.Hash -eq $ToBackupHash.Hash) {
                Write-Log -Message "Full ReAgentXML backup found $($Backup.Name)" -Component 'UpdateReAgentXML'
                $XMLBackupFound = $true
            }
        }
    }
    if (-not($XMLBackupFound)) {
        $XMLBackupFileName = ('ReAgent{0}.xml' -f $Script:DateTime)
        $XMLBackupFilePath = Join-Path $BackupDirectory -ChildPath $XMLBackupFileName
        Copy-Item $ReAgentXMLLocation $XMLBackupFilePath -Force
        $XMLBackupSuccessful = (Get-FileHash $XMLBackupFilePath -Algorithm MD5).Hash -eq $ToBackupHash.Hash
    } 
    if (-not($XMLBackupSuccessful)) {
        Write-Log -Message 'Could not create a backup copy of ReAgent.xml - please ensure that third party Antivirus is disabled' -Component 'UpdateReAgentXML'
        return $false
    }
    [xml]$RecoveryAgentXML = [System.IO.File]::ReadAllText($ReAgentXMLLocation)
    $RecoveryAgentXML.WindowsRE.ImageLocation.path = ''
    $RecoveryAgentXML.WindowsRE.ImageLocation.id = '0'
    $RecoveryAgentXML.WindowsRE.ImageLocation.offset = '0'
    $RecoveryAgentXML.WindowsRE.ImageLocation.guid = '{00000000-0000-0000-0000-000000000000}'
    $RecoveryAgentXML.Save($ReAgentXMLLocation)
    return $true
}
function Add-WinREPackage {
    <#
    .SYNOPSIS
    Adds content to WinRE using Add-WindowsPackage. Each content is checked, applied and verified.
    .PARAMETER PackagePath
    Required. Filepath to the content to be applied
    .NOTES
    Each switch may have a unique detection method, overlapping methods are merged
    #>
    param(
        $PackagePath,
        [switch]$SSU,
        [switch]$GDRDUorLCU,
        [switch]$DynamicUpdateOrSOS,
        [switch]$FoD #ToDo
    )
    $AddWindowsPackageLogFile = Join-Path -Path $LogDirectory -ChildPath ('Add-WindowsPackage_{0}.log' -f $DateTime)
    # Setup hashtable for common parameters for *-WindowsImage
    $AddPatchCommonParams = @{
        PackagePath = $PackagePath
        Path        = $MountDirectory
        LogPath     = $AddWindowsPackageLogFile
        LogLevel    = 'WarningsInfo'
    }
    Write-Log -Message "Analysing Package $PackagePath" -Component 'AddWinREPackage'
    if ($SSU) {
        $PackagePathBuildNumber = $PackagePath.Fullname.split("-")[1]
        $AddWindowsPackageLogFile = Join-Path -Path $LogDirectory -ChildPath ('Analyseusing-Get-WindowsPackage_{0}.log' -f $DateTime)
        $ApplySSU = (Get-WindowsPackage -Path $MountDirectory -LogPath $AddWindowsPackageLogFile -LogLevel 'WarningsInfo' | Where-Object { $_.PackageName -like "*ServicingStack*" -and $_.PackageName -like "*$PackagePathBuildNumber*" }).packagestate -eq "Installed"
        if (-not($ApplySSU)) {
            Write-Log -Message 'SSU not found, applying...' -Component 'AddWinREPackage'
            Add-WindowsPackage @AddPatchCommonParams | Out-Null
        } else {
            Write-Log 'This SSU is already applied - skipping'
            return $true
        }
        Write-Log -Message 'SSU applied, verifying' -Component 'AddWinREPackage'
        $SSUApplied = (Get-WindowsPackage -Path $MountDirectory | Where-Object { $_.PackageName -like "*$PackagePathKB*" }).packagestate -eq "Installed"
        if ($SSUApplied) {
            Write-Log -Message 'SSU was successfully installed' -Component 'AddWinREPackage'
            return $true
        } else {
            Write-Log -Message 'SSU was not successfully installed' -Component 'AddWinREPackage' -Type 3
            return $false
        }
    }
    if ($GDRDUorLCU) {
        $CurrentBuildNumber = ((Get-WindowsPackage -Path $MountDirectory | Where-Object { $_.releasetype -eq "Foundation" }).packagename.split("~") | Select-String -SimpleMatch "10.0").ToString().trim().split(".")[3]
        Write-Log -Message "Applying dynamic update or latest cumulative update. Current build number: $CurrentBuildNumber" -Component 'AddWinREPackage'
        Add-WindowsPackage @AddPatchCommonParams | Out-Null
        $NewBuildNumber = ((Get-WindowsPackage -Path $MountDirectory | Where-Object { $_.releasetype -eq "Foundation" }).packagename.split("~") | Select-String -SimpleMatch "10.0").ToString().trim().split(".")[3]
        if (-not($CurrentBuildNumber -lt $NewBuildNumber)) {
            Write-Log -Message 'Build number did not change, not applied' -Component 'AddWinREPackage' -Type 3
            return $false
        } else {
            Write-Log -Message "Build number was raised to: $NewBuildNumber" -Component 'AddWinREPackage'
            return $true
        }
    }

    #ToDo This will probably apply to language packs as well. Adjust once verified
    if ($DynamicUpdateOrSOS) {
        $PackagePathKB = $PackagePath.Fullname.split("-")[1]
        $ApplyPackage = (Get-WindowsPackage -Path $MountDirectory | Where-Object { $_.PackageName -like "*$PackagePathKB*" }).packagestate -eq "Installed"
        if (-not($ApplyPackage)) {
            Write-Log -Message 'Package not found, applying...' -Component 'AddWinREPackage'
            Add-WindowsPackage @AddPatchCommonParams | Out-Null
        } else {
            Write-Log 'This package is already applied - skipping'
            return $true
        }
        Write-Log -Message 'Package applied, verifying' -Component 'AddWinREPackage'
        $PackageApplied = (Get-WindowsPackage -Path $MountDirectory | Where-Object { $_.PackageName -like "*$PackagePathKB*" }).packagestate -eq "Installed"
        if ($PackageApplied) {
            Write-Log -Message 'Package was successfully installed' -Component 'AddWinREPackage'
            return $true
        } else {
            Write-Log -Message 'Package was not successfully installed' -Component 'AddWinREPackage' -Type 3
            return $false
        }
    }
}
function Backup-WinRE {
    Write-Log -Message 'Creating WinRE Backup - will not be automatically deleted(!)' -Component 'BackupWinRE'
    $WinRELocationFromReAgentXML = $Script:RecoveryImagePath
    $ToBackupHash = Get-FileHash -LiteralPath $WinRELocationFromReAgentXML -Algorithm MD5
    $BackupFileName = ('WinRE{0}.wim' -f $Script:DateTime)
    if (-not(Test-Path $BackupDirectory)) {
        New-Item $BackupDirectory -ItemType Directory -Force
    } else {
        Write-Log -Message 'Backup folder already exists' -Component 'BackupWinRE'
        Write-Log -Message 'Checking if the current WinRE is already backed' -Component 'BackupWinRE'
        $Backups = Get-ChildItem (Join-Path -Path $BackupDirectory -ChildPath '*') -Include *.wim -Force
        if ($Backups.count -ge 1) {
            foreach ($Backup in $Backups) {
                $BackedFile = Get-FileHash $Backup.FullName -Algorithm MD5
                if ($BackedFile.Hash -eq $ToBackupHash.Hash) {
                    Write-Log -Message 'Full backup found' -Component 'BackupWinRE'
                    return $true
                }
            }
        }
        Write-Log -Message 'No Backup of the current available WinRE found - creating backup...' -Component 'BackupWinRE'
    }
    $TargetFile = Join-Path $BackupDirectory -ChildPath $BackupFileName
    Write-Log -Message "Moving $WinRELocationFromReAgentXML to $BackupDirectory and name $BackupFileName" -Component 'BackupWinRE'
    Copy-Item -LiteralPath $WinRELocationFromReAgentXML -Destination $TargetFile -Force
    if (Test-Path -LiteralPath $TargetFile) {
        Write-Log -Message 'Verify backup hash matches actual' -Component 'BackupWinRE'
        $BackupSuccessful = (Get-FileHash -LiteralPath $TargetFile -Algorithm MD5).Hash -eq $ToBackupHash.Hash
        if (-not($BackupSuccessful)) {
            Write-Log -Message 'Hashes do not match! Make sure third party Antivirus-Software is disabled' -Component 'BackupWinRE' -Type 3
            return $false
        }
        return $true
    } else {
        return $false
    }
}
function Update-RecoveryPartitionInformation {
    <#
    .NOTES 
        Detecting the recovery partition can be difficult depening on how the machine was set up. 
        This function will try multiple methods to discover the correct partition.
    #>
    $WinREStatus = Get-WinREStatus
    if ($WinREStatus) {
        $Script:ReAgentCCurrentInfo = ReAgentc.exe /info
        $Script:ReAgentCCurrentDrive = $Script:ReAgentCCurrentInfo.split("`n")[4].Substring(31, $Script:ReAgentCCurrentInfo.split("`n")[4].length - 31).trim()
        $Script:RecoveryDiskNumber = $Script:ReAgentCCurrentDrive.substring("\\?\GLOBALROOT\device\".length + "harddisk".length, 1)
        $Script:RecoveryPartitionNumber = $Script:ReAgentCCurrentDrive.substring("\\?\GLOBALROOT\device\harddisk".length + "0\partition".length, 1)
        $Script:RecoveryPartition = Get-Partition -PartitionNumber $Script:RecoveryPartitionNumber -DiskNumber $Script:RecoveryDiskNumber
    } else {
        Write-Log -Message 'Recovery Agent not enabled trying different method' -Component 'UpdateRecoveryPartition'
        $Partitions = Get-Partition | where-Object { $_.GptType -eq "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}" }
        if (-not($Partitions)) {
            $Script:RecoveryPartition = $false
            Write-Log -Message 'No partition of type "Recovery" detected. The GPT type might be missing' -Component 'WinREPrerequisites' -Type 2
            return
        }
        if ($Partitions.count -gt 1) {
            Write-Log -Message 'Multiple recovery partitions detected - selecting the one with the most free space' -Component 'UpdateRecoveryPartition'
            $Volumes = $Partitions | Get-Volume
            $Script:RecoveryPartition = $Volumes | Sort-Object -Property SizeRemaining -Descending | Select-Object -First 1 | Get-Partition
        } else {
            $Script:RecoveryPartition = $Partitions
        }
        $Script:RecoveryDiskNumber = $Partitions.DiskNumber
        $Script:RecoveryPartitionNumber = $Partitions.PartitionNumber
    }
}
function Confirm-WinREPrerequisites {
    param(
        [switch]$InitialRun,
        [switch]$CheckGPT,
        [switch]$CheckPartition,
        [switch]$CheckWinRE,
        [switch]$CheckRecoveryPartitionPreStage
    )
    if ($InitialRun) {
        if (-not($RecoveryDriveSizeInGB)) {
            $SizeToVerify = 1GB
        } else {
            $SizeToVerify = $RecoveryDriveSizeInGB
        }
        Write-Log -Message 'Verifying general prerequisites' -Component 'WinREPrerequisites'
        Write-Log -Message '1. Disk must use GPT formatting style' -Component 'WinREPrerequisites'
        Write-Log -Message '2. Recovery Partition must exist, unless -CreateWinREDrive is used' -Component 'WinREPrerequisites'
        Write-Log -Message '3. There must be a WinRE available online or offline' -Component 'WinREPrerequisites'
        Write-Log -Message '4. Multiple writeable partitions on the same disk are not supported' -Component 'WinREPrerequisites'
        Write-Log -Message '5. (-CreateWinREDrive) WinRE must exist in in the default location' -Component 'WinREPrerequisites'
        $CheckGPT = $true
        $CheckPartition = $true
        $CheckWinRE = $true
        if(-not($CreateWinREDrive)){
            $CheckRecoveryPartitionEligibility = $true
        }
        else{
            $CheckDiskEligibility = $true
        }
    }
    if ($CheckGPT) {
        Write-Log -Message 'Verifying the disk is a GPT formatted disk. BIOS disks are not supported' -Component 'WinREPrerequisites'
        if ((Get-Partition -DriveLetter ($ENV:SystemDrive).Substring(0, 1) | Get-Disk).partitionstyle -ne "GPT") {
            Write-Log -Message 'This disk is not formatted in GPT - aborting' -Component 'FormatRecoveryDrive' -Type 3
            return $false
        }
    }
    if ($CheckPartition) {
        Write-Log -Message 'Start detection of recovery partition(s)' -Component 'WinREPrerequisites'
        if (-not($Script:RecoveryPartition)) {
            Update-RecoveryPartitionInformation
        }
    }
    
    if ($CheckWinRE) {
        Write-Log -Message 'Verify WinRE.wim is available (online or offline)' -Component 'WinREPrerequisites'
        $WinREFileMissing = $false
        if (-not(Get-WinREStatus)) {
            Get-WinREImageLocation
        } else {
            Get-WinREImageLocation -OnlineLocation
        }
        if (-not(Test-Path -LiteralPath $Script:RecoveryImagePath)) {
            $WinREFileMissing = $true
        }
    }
    if($CheckDiskEligibility){
        if($Script:RecoveryPartition){
            Write-Log -Message 'Found different recovery partition - mode will be switched later' -Component 'WinREPrerequisites' -Type 3
        }
        if ($WinREFileMissing) {
            Write-Log -Message 'No WinRE location found, can not create WinRE drive' -Component 'WinREPrerequisites' -Type 3
            return $false
        }
        else {
            $OSDriveDiskNumber = (Get-Partition -DriveLetter ($ENV:SystemDrive).Replace(':', '')).DiskNumber
            $RecoveryImageIsOnSameDiskAsOS = $OSDriveDiskNumber -eq $Script:RecoveryImagePathDisk
            if (-not($RecoveryImageIsOnSameDiskAsOS)) {
                Write-Log -Message 'The recovery image is on a different disk than the OS' -Component 'WinREPrerequisites' -Type 3
                Write-Log -Message 'This will cause the recovery partition becoming a different disk. If you need help with this please contact me' -Component 'WinREPrerequisites'
                return $false
            }
        }
    }
    if ($CheckRecoveryPartitionEligibility) {
        if (-not($Script:RecoveryPartition) -and -not($CreateWinREDrive)) {
            Write-Log 'There is no recovery partition. To create a recovery drive use -CreateWinREDrive or verify that its called "Recovery" using diskpart' -Component 'WinREPrerequisites' -Type 3
            return $false
        }
        Write-Log -Message 'Verifying the potenially discovered partition for eligibility' -Component 'WinREPrerequisites'
        $LastPartitionNumber = $((Get-Partition -DiskNumber $Script:RecoveryDiskNumber | Select-Object -Last 1).PartitionNumber)
        $OSDrivePartitionNumber = (Get-Partition -DriveLetter ($ENV:SystemDrive).Replace(':', '')).PartitionNumber
        $RecoveryIsLastPartition = $Script:RecoveryPartition.PartitionNumber -eq $LastPartitionNumber
        $OSIsLastPartition = $($OSDrivePartitionNumber -eq $LastPartitionNumber)
        $RecoveryPartitionIsOnRightOfOSPartition = ($Script:RecoveryPartition.PartitionNumber - $OSDrivePartitionNumber) -eq 1
        $RecoveryPartitionIsOSPartition = $OSDrivePartitionNumber -eq $Script:RecoveryPartition.PartitionNumber
        if (($Script:RecoveryPartition.size -lt $SizeToVerify)) {
            if (-not($OSIsLastPartition) -and -not($RecoveryIsLastPartition)) {
                Write-Log -Message 'Recovery partition found, but OS-drive is not shrinkable because it is not the last partition.' -Component 'WinREPrerequisites' -Type 3
                Write-Log -Message 'If you have multiple partitions on the disk and need help please contact me.' -Component 'WinREPrerequisites'
                return $false
            }
            if ($RecoveryIsLastPartition -and -not($RecoveryPartitionIsOnRightOfOSPartition)) {
                Write-Log -Message 'Recovery partition found, but can not use OS-drive to shrink.' -Component 'WinREPrerequisites' -Type 3
                Write-Log -Message 'If you have multiple partitions on the disk and need help please contact me.' -Component 'WinREPrerequisites'
                return $false
            }
        }
        if ($RecoveryPartitionIsOSPartition) {
            Write-Log -Message 'The OS partition harbors the recovery partition.' -Component 'WinREPrerequisites' -Type 3
            Write-Log -Message 'Something went wrong during imaging, but the script can not currently handle this situation, please contact me.' -Component 'WinREPrerequisites'
            return $false
        }
    }

    if ($InitialRun) {
        if ($CreateWinREDrive) { 
            if (-not($Script:RecoveryPartition) -and $WinREFileMissing) {
                Write-Log -Message "There is no recovery partition, but WinRE.wim is missing from $WinRELocation" -Component 'WinREPrerequisites' -Type 3
                Write-Log -Message 'You need a fresh WinRE from inside a Windows ISO (inside the Install.wim) and copy it to this location - aborting' -Component 'WinREPrerequisites'
                return $false
            } else {
                Write-Log -Message 'Recovery drive can be created' -Component 'WinREPrerequisites'
                return $true
            }
        }
        return $true
    }
    if ($CheckRecoveryPartitionPreStage) {
        #Required during the creation phase of the recovery partition - the partition isn't yet marked as 'Recovery' which is why we need to check like this
        $Volume = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'Recovery' -and $_.OperationalStatus -eq 'OK' }
        if ($Volume) {
            #We can safely fail here as the value will be checked later. 
            $Script:RecoveryPartition = Get-Partition -Volume $Volume -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message 'No volume is currently a pre-phase recovery partition' -Component 'WinREPrerequisites' -Type 3
        }
    }
}
function Format-WinREPartition {    
    param(
        $RecoveryDriveNewSize = 1GB
    )
    if ($RecoveryDriveNewSize -lt 1GB) {
        Write-Log -Message 'You can not shrink the recovery below the recommended minimum of 1GB' -Component 'FormatWinREPartition' -Type 3
        return $false
    }
    #Harcoded to OS drive for now - this should cover almost all cases
    $DriveToShrink = ($env:SystemDrive).Substring(0, 1)
    Write-Log -Message 'Recommended minimum partition size is 1GB for WinRE - this depends on the level of customization. If anything fails, please adjust the script' -Component 'FormatWinREPartition'
    Update-RecoveryPartitionInformation
    if (-not($Script:RecoveryPartition)) {
        Write-Log -Message 'No recovery partition detected' -Component 'FormatWinREPartition' -Type 2
        if (-not($CreateWinREDrive)) {
            return $false
        }
    }
    if ($Script:RecoveryPartition.Size -ge $RecoveryDriveNewSize) {
        Write-Log -Message 'The recovery partition is already of adequate size' -Component 'FormatWinREPartition'
        return $true
    }
    if ($Script:RecoveryPartition -and $CreateWinREDrive) {
        Write-Log -Message 'Recovery partition detected but -CreateWinREDrive was used - switching to resize mode' -Component 'FormatWinREPartition' -Type 2
        $CreateWinREDrive = $false
    }
    if (-not($CreateWinREDrive) ) {
        if(($Script:RecoveryPartitionNumber -ne $((Get-Partition -DiskNumber $Script:RecoveryDiskNumber | Select-Object -Last 1).PartitionNumber))){
            Write-Log -Message 'Recovery partition is not the last partition on the disk - switching mode to repartition' -Component 'FormatWinREPartition' -Type 1
            Write-Log -Message 'Switching to repartition mode will leave an empty partition where the old recovery partition was' -Component 'FormatWinREPartition' -Type 2
            $RepartitionMode = $true
        }
        if (-not(Update-ReAgentXML)) {
            Write-Log -Message 'Could not enforce ImageLocation - please consult the log' -Component 'FormatWinREPartition'
            return $false
        }
    }
    $WinREStatus = Get-WinREStatus
    if ($WinREStatus) {
        if (Disable-WinRE) {
            Write-Log -Message 'ReagentC successfully disabled for resizing' -Component 'FormatWinREPartition'
        } else {
            Write-Log -Message 'ReagentC could not be disabled - please make sure you are running this script as admin' -Component 'FormatWinREPartition' -Type 3
            return $false
        }
    } elseif ($WinREStatus -eq $false) {
        Write-Log -Message 'WinRE is already disabled' -Component 'FormatWinREPartition'
    }
    Write-Log -Message "Verify that the $DriveToShrink`: has adequate size left to shrink" -Component 'FormatWinREPartition'
    $WindowsPartitionCurrentSize = Get-Volume -DriveLetter $DriveToShrink
    if ($WindowsPartitionCurrentSize.SizeRemaining -ge $RecoveryDriveNewSize) {
        $WindowsPartitionSize = Get-PartitionSupportedSize -DriveLetter $DriveToShrink
        # Shrink source disk size
        if ($CreateWinREDrive) {
            $ShrinkSizeCheck = ($WindowsPartitionSize.SizeMax - $WindowsPartitionSize.SizeMin) -ge $RecoveryDriveNewSize
        } else {
            $ShrinkSizeCheck = ($WindowsPartitionSize.SizeMax - $WindowsPartitionSize.SizeMin) -ge ($RecoveryDriveNewSize - $Script:RecoveryPartition.Size)
        }
        if ($ShrinkSizeCheck) {
            $WinREStatus = Get-WinREStatus
            if ($WinREStatus -eq $false) {
                if ($CreateWinREDrive -or $RepartitionMode) {
                    $NewSystemDriveSize = $WindowsPartitionSize.SizeMax - $RecoveryDriveNewSize
                } else {
                    $NewSystemDriveSize = $WindowsPartitionSize.SizeMax - $RecoveryDriveNewSize + $Script:RecoveryPartition.Size
                }
                if (-not($CreateWinREDrive)) {
                    #The following additional check is to make very sure, that the the recovery agent is disabled before we REMOVE the recovery partition
                    $DisableReAgentC = (Get-Volume -Partition $Script:RecoveryPartition).SizeRemaining
                    if ($DisableReAgentC -le 100MB) {
                        Write-Log -Message 'Verification of disabled ReAgentC failed - cannot continue. No changes where performed' -Component 'FormatWinREPartition' -Type 3
                        return $false              
                    }
                    Write-Log -Message 'Removing recovery partition' -Type 2
                    Remove-Partition $Script:RecoveryPartition.DiskNumber $Script:RecoveryPartition.PartitionNumber -Confirm:$false
                }
                if ($RepartitionMode) {
                    $Script:OldRecoveryPartition = New-Partition -DiskNumber $Script:RecoveryPartition.DiskNumber -UseMaximumSize -IsHidden:$true
                }
                $Script:RecoveryPartition = $false
                Write-Log -Message 'Shrinking C: and re-creating recovery partition' -Component 'FormatWinREPartition'
                try {
                    Resize-Partition -DriveLetter $DriveToShrink -Size $NewSystemDriveSize -ErrorAction Stop
                } catch {
                    Write-Log -Message "$($error[0].Exception.Message)" -Component 'FormatWinREPartition' -Type 3
                    Write-Log -Message "Unrecoverable error occured - this could mean there is a partition in the way to shrink the system partition" -Component 'FormatWinREPartition' 
                    return $false
                }
                # Unfortunately Set-Partition has no -Attributes parameter, so we need to use diskpart.
                $Diskpart = @"
select disk $((Get-Partition -DriveLetter $DriveToShrink).DiskNumber)
create partition primary`
format quick fs=ntfs label='Recovery'`
gpt attributes=0x8000000000000001
"@
                if (Test-Path -Path '.\diskpart.txt') { Get-Item -Path '.\diskpart.txt' | Remove-Item -Force }
                if (Test-Path -Path '.\diskpart.log') { Get-Item -Path '.\diskpart.log' | Remove-Item -Force }
                Add-Content -Path '.\diskpart.txt' -Value $Diskpart
                diskpart /s '.\diskpart.txt' > '.\diskpart.log'
                Move-Item -Path '.\diskpart.log' -Destination $LogDirectory -Force
                Confirm-WinREPrerequisites -CheckRecoveryPartitionPreStage
                if ($Script:RecoveryPartition) {
                    Write-Log -Message 'Successfully created the recovery partition' -Component 'FormatWinREPartition'
                } else {
                    Write-Log -Message 'Failed to create the recovery partition, waiting 10 seconds, then retry once' -Component 'FormatWinREPartition' -Type 3
                    Start-Sleep -Seconds 10
                    diskpart /s '.\diskpart.txt' > '.\diskpart2.log'
                    Move-Item -Path '.\diskpart2.log' -Destination $LogDirectory -Force
                    Confirm-WinREPrerequisites -CheckRecoveryPartitionPreStage
                    if (-not($Script:RecoveryPartition)) {
                        Write-Log 'Finally failed to create recovery partition - giving up' -Component 'FormatWinREPartition' -Type 3
                        return $false
                    } else {
                        Write-Log -Message 'Successfully created the recovery partition in 2nd try' -Component 'FormatWinREPartition'
                    }
                }
                $DiskpartStatus = (Get-Volume -Partition (Get-Partition -DiskNumber $Script:RecoveryPartition.DiskNumber -PartitionNumber $Script:RecoveryPartition.PartitionNumber)).OperationalStatus -eq "OK"
                Get-Item '.\diskpart.txt' | Remove-Item -Force
                if ($DiskpartStatus) {
                    Write-Log -Message 'Recovery partition recreated. Define recovery partition using GPTType' -Component 'FormatWinREPartition'
                    Set-Partition -DiskNumber $Script:RecoveryPartition.DiskNumber -PartitionNumber $Script:RecoveryPartition.PartitionNumber -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
                    Write-Log -Message 'Recovery partition defined. Enabling ReAgentC' -Component 'FormatWinREPartition'
                    if (-not(Enable-WinRE)) {
                        Write-Log -Message 'WinRE could not be enabled please consult the logs. Its likely you need to recreate the partition manually' -Component 'FormatWinREPartition' -Type 3
                        return $false
                    } else {
                        Write-Log -Message 'Successfully re-enabled ReAgentC' -Component 'FormatWinREPartition'
                        return $true
                    }
                } else {
                    $LogMessage = "The recovery drive could not be created/shrunk to the requested size of $($RecoveryDriveNewSize/1024/1024/1024) GB - please consult the application event log" 
                    Write-Log -Message "$LogMessage `n  $((Get-EventLog -LogName Application -Newest 1 -Source Microsoft-Windows-Defrag -EntryType Information).Message)" -Component 'FormatWinREPartition' -Type 3
                    Write-Log -Message 'The (re-)format could not be performed.' -Component 'FormatWinREPartition' -Type 2
                    return $false
                }
            } elseif ($WinREStatus -eq $true) {
                Write-Log -Message 'Somehow ReAgentC was still enabled at this stage. Aborting (re-)formatting' -Component 'FormatWinREPartition' -Type 3
                return $false
            } elseif ($null -eq $WinreStatus) {
                Write-Log -Message 'Failed to get the WinRE Status. No changes performed to partition, trying to re-enable WinRE.' -Component 'FormatWinREPartition'                    
                if (-not(Enable-WinRE)) {
                    Write-Log -Message 'Could not re-enable WinRE' -Component 'FormatWinREPartition' -Type 3
                }
                return $false
            }
        } else {
            Write-Log -Message "Drive can not be shrunk by $($WindowsPartitionSize.SizeMax - $WindowsPartitionSize.SizeMin)" -Component 'FormatWinREPartition' -Type 3
            return $false
        }
    } else {
        Write-Log -Message "Free space left is $($WindowsPartitionCurrentSize.SizeRemaining), please make some room first" -Component 'FormatWinREPartition' -Type 3
        return $false
    }
}
function Add-DriverToWinRE {
    param(
        $Drivers,
        $SingleDriver
    )
    Write-Log -Message 'Adding driver(s) to WinRE image' -Component 'AddDriversToWinRE'
    $AddDriverLogFile = Join-Path -Path $LogDirectory -ChildPath ('Add-WindowsDriver_{0}.log' -f $DateTime)
    $AddDriverCommonParams = @{
        Path     = $MountDirectory
        LogPath  = $AddDriverLogFile
        LogLevel = 'WarningsInfo'
    }
    if (Get-WinREStatus -eq $false) {
        Write-Log -Message 'WinRE is not enabled currently - trying to enable WinRE' -Component 'AddDriversToWinRE' -Type 2
        if (-not(Enable-WinRE)) {
            Write-Log -Message "WinRE couldn't be enabled" -Component 'AddDriversToWinRE' -Type 3
            return $false
        }
    }
    Write-Log -Message 'Mounting WinRE to add drivers' -Component 'PatchWinRE'
    if (-not(Mount-WinRE)) {
        Write-Log -Message 'WinRE could not be mounted to apply drivers ' -Component 'PatchWinRE' -Type 3
        return $false
    }
    if ($Drivers) {
        Write-Log -Message "Adding drivers from folder $Drivers" -Component 'PatchWinRE'
        Add-WindowsDriver -Driver $Drivers -Recurse @AddDriverCommonParams
    } elseif ($SingleDriver) {
        Write-Log -Message "Adding driver $SingleDriver" -Component 'PatchWinRE'
        Add-WindowsDriver -Driver $SingleDriver @AddDriverCommonParams
    }
    Write-Log -Message 'Added drivers, trying to unmount and apply' -Component 'PatchWinRE'
    if (-not(Dismount-WinRE)) {
        Write-Log -Message 'Commiting drivers failed, please consult the logs' -Component 'PatchWinRE' -Type 3
        return $false
    }
    Write-Log -Message 'Successfully applied drivers' -Component 'PatchWinRE'
    return $true
}
function Add-PatchesToWinRE {
    param(
        $Files,
        $SingleFile,
        [switch]$GDRDUorLCU,
        [switch]$DUorSOS
    )
    Write-Log -Message 'Preparing patches to WinRE' -Component 'AddPatchesToWinRE' -Type 2
    if (Get-WinREStatus -eq $false) {
        Write-Log -Message 'WinRE is not enabled currently - trying to enable WinRE' -Component 'AddPatchesToWinRE' -Type 2
        if (-not(Enable-WinRE)) {
            Write-Log -Message "WinRE couldn't be enabled" -Component 'AddPatchesToWinRE' -Type 3
            return $false
        }
    }
    if ($GDRDUorLCU) {
        $CurrentWinREPath = "\\?" + (ReAgentc.exe /info | Select-String -SimpleMatch "\\?\GLOBALROOT\device").ToString().split("?")[1] + "\WinRE.wim"
        $CurrenWinREBuild = (Get-WindowsImage -ImagePath $CurrentWinREPath -Index 1).SPBuild
        Write-Log -Message "Current Patchversion of mounted WinRE: $CurrenWinREBuild"
        $Windows10 = ([System.Environment]::OSVersion.Version.Build -ge 19042 -and [System.Environment]::OSVersion.Version.Build -lt 22000) 
        if ($Windows10 -and -not($SSU)) {
            Write-Log -Message "Windows 10 machine detected: Please be aware, that this script doesn't check if the SSU has been applied to the WinRE before patching. Rename the SSU to start with '1_'. You will want to check for KB5014032" -Component 'PatchWinRE' -Type 2
        }
        $SSU = $Files | Where-Object { $_.Name -like 'ssu*' }
    }
    if ($SingleFile) {
        $Files = Get-Item $SingleFile
    }
    Write-Log -Message 'Preparing WinRE' -Component 'AddPatchesToWinRE'
    if (-not(Mount-WinRE)) {
        Write-Log -Message "WinRE couldn't be mounted - please verify the logs" -Component 'AddPatchesToWinRE' -Type 3
        return $false
    }
    Write-Log -Message 'WinRE mounted successful' -Component 'AddPatchesToWinRE'
    [System.Collections.ArrayList]$PatchError = @()
    if ($SSU) {
        Write-Log -Message 'SSU detected in folder/file - applying SSU to WinRE' -Component 'AddPatchesToWinRE'
        $PatchError.add((Add-WinREPackage -PackagePath $($SSU.FullName) -SSU))
    }
    Write-Log -Message 'Applying Patches to WinRE' -Component 'AddPatchesToWinRE'
    if ($GDRDUorLCU) {
        foreach ($Patch in $Files) {
            if ($Patch.name -notlike "ssu*") {
                $PatchError.add((Add-WinREPackage -PackagePath $([System.IO.FileInfo]$Patch.FullName) -GDRDUorLCU))
            }
        }
    }
    if ($DUorSOS) {
        foreach ($Patch in $Files) {
            $PatchError.add((Add-WinREPackage -PackagePath $([System.IO.FileInfo]$Patch.FullName) -DynamicUpdateOrSOS))
        }
    }
    if (($PatchError | Where-Object { $_ -ne $true }).count -ge 1) {
        Write-Log -Message 'Some patches could not be applied - please check the log!' -Component 'AddPatchesToWinRE' -Type 3
        if ($AbortIfFailed) {
            Write-Log -Message 'Discard changes, because AbortIfFailed is set' -Component 'AddPatchesToWinRE' -Type 3
            Dismount-WinRE -Discard
            return $false
        }
    }
    Write-Log -Message 'Finished applying patches, attempting to cleanup, dismount and commit' -Component 'AddPatchesToWinRE'
    if (-not(Dismount-WinRE)) {
        Write-Log 'WinRE could not be dismounted, changes have been discarded' -Component 'AddPatchesToWinRE' -Type 3
        return $false
    }
    if ($GDRDUorLCU) {
        $NewWinREPath = "\\?" + (ReAgentc.exe /info | Select-String -SimpleMatch "\\?\GLOBALROOT\device").ToString().split("?")[1] + "\WinRE.wim"
        $NewWinREBuild = (Get-WindowsImage -ImagePath $NewWinREPath -Index 1).SPBuild
        Write-Log -Message "Current Patchversion of mounted WinRE: $NewWinREBuild"
    }
    Write-Log -Message 'Applying finished' -Component 'AddPatchesToWinRE'
    return $true
}

# Start Coding!
Get-ScriptPath
Write-Log -Message "Patch-WinRE started at $(Get-Date)" -Component 'WinREPatchCore'
# Only run the prereques if and only if a recovery partition needs to be touched aka resized
if (-not(Confirm-WinREPrerequisites -InitialRun) -and -not($ReportOnly)) {
    Write-Log -Message 'Prerequisites could not be confirmed, please consult the log' -Type 3 -Component 'WinREPatchCore'
    Exit 1
} else {
    Get-Stats -InitialRun
}
if ($ReportOnly) {
    Get-Stats -ReportOnly
    Set-Location $CurrentLocation
    exit 0
}
Write-Log -Message 'Creating backup first' -Component 'WinREPatchCore'
if ($CreateWinREDrive) {
    Write-Log -Message 'Using CreateWinREDrive will disable the creation of backups, because it assumes that there is no recovery drive yet.' -Component 'CreateWinREDrive' -Type 2
    if (-not(Format-WinREPartition)) {
        Write-Log -Message 'Creation of the recovery partition failed - please consult the logs' -Component 'CreateWinREDrive' -Type 3
        Exit 1
    }
} elseif (-not(Backup-WinRE)) {
    Write-Log -Message 'Could not create WinRE Backup - the file might be missing. Please extract it from install media (via install.wim)' -Component 'WinREPatchCore' -Type 3
    Exit 1
}
#Resizing recovery partition
if ($RecoveryDriveSizeInGB) {
    Write-Log -Message "Verify that the recovery partition has the appropiate size of $($RecoveryDriveSizeInGB/1GB) GB" -Component 'WinREPatchCore'
    if (-not(Format-WinREPartition -RecoveryDriveNewSize $RecoveryDriveSizeInGB)) {
        Write-Log -Message "Something went wrong with the recovery partition - please check the log $LogFile" -Component 'WinREPatchCore' -Type 3
        Exit 1
    }
}
if ($FoDDirectory) {
    Write-Log -Message 'Not yet implemented' -Component 'WinREPatchCore' -Type 2
    return $false
}
if ($FilesDriver) {
    if (Test-Path -Path $FilesDriver) {
        if ((Get-ItemProperty $FilesDriver).Attributes -eq 'Directory') {
            if (-not(Add-DriverToWinRE -Drivers $FilesDriver)) {
                Write-Log -Message 'Something went wrong while applying drivers, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } elseif ($FilesDriver -like '*.inf') {
            if (-not(Add-DriverToWinRE -SingleDriver $FilesDriver)) {
                Write-Log -Message 'Something went wrong while applying the driver, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }        
        } else {
            Write-Log -Message 'No directory or path does not end in *.inf' -Component 'WinREPatchCore' -Type 3
            Exit 1
        }
    } else {
        Write-Log -Message 'Directory/file does not exist' -Component 'WinREPatchCore' -Type 3
        Exit 1
    }
}

if ($PatchFilesGDRDUorLCU) {
    Write-Log -Message 'Applying Generel Release Distribution Dynamic Updates or Latest Cumulative Updates' -Component 'WinREPatchCore'
    if (-not($RecoveryDriveSizeInGB)) {
        Write-Log -Message 'No recovery drive size specified, using defaults to verify and if required change size' -Component 'WinREPatchCore' -Type 2
        Write-Log -Message "Verifying recovery partition size is at least set to the default: $(Format-WinREPartition)" -Component 'WinREPatchCore'
    }
    if (Test-Path -Path $PatchFilesGDRDUorLCU) {
        if ((Get-ItemProperty $PatchFilesGDRDUorLCU).Attributes -eq 'Directory') {
            $MSUFiles = (Get-ChildItem $PatchFilesGDRDUorLCU -Filter *.msu -Force)
            $CABFiles = (Get-ChildItem $PatchFilesGDRDUorLCU -Filter *.cab -Force)
            if ($CABFiles -and $MSUFiles) {
                Write-Log -Message 'MSU and CAB files detected - make sure they do not interfere (GDRDU _or_ LCU, not both)' -Type 2
            } elseif ($CABFiles) {
                $AddPatches = $CABFiles
            } else {
                $AddPatches = $MSUFiles
            }
            if (-not(Add-PatchesToWinRE -Files $AddPatches -GDRDUorLCU)) {
                Write-Log -Message 'Something went wrong while applying patches, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } elseif ($PatchFilesGDRDUorLCU -like '*.cab' -or $PatchFilesGDRDUorLCU -like '*.msu') {
            if (-not(Add-PatchesToWinRE -SingleFile $PatchFilesGDRDUorLCU -GDRDUorLCU)) {
                Write-Log -Message 'Something went wrong while applying patches, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } else {
            Write-Log -Message 'Directory/file not found or no files ending in *.cab in directory.' -Component 'WinREPatchCore' -Type 3
            Exit 1
        }
    } else {
        Write-Log -Message 'Patch directory/file does not exist at provided path' -Component 'WinREPatchCore' -Type 2
    }
} else {
    Write-Log -Message 'No patch directory/file specified' -Component 'WinREPatchCore' -Type 2
}
if ($PatchFilesDUorSOS) {
    Write-Log -Message 'Applying SafeOS or Dynamic Updates' -Component 'WinREPatchCore'
    if (Test-Path -Path $PatchFilesDUorSOS) {
        if ((Get-ItemProperty $PatchFilesDUorSOS).Attributes -eq 'Directory') {
            $CABFiles = (Get-ChildItem $PatchFilesDUorSOS -Filter *.cab -Force)
            if (-not(Add-PatchesToWinRE -Files $CABFiles -DUorSOS)) {
                Write-Log -Message 'Something went wrong while applying patches, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } elseif ($PatchFilesDUorSOS -like '*.cab') {
            if (-not(Add-PatchesToWinRE -SingleFile $PatchFilesDUorSOS -DUorSOS)) {
                Write-Log -Message 'Something went wrong while applying patches, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } else {
            Write-Log -Message 'Directory/file not found or no files ending in *.cab in directory.' -Component 'WinREPatchCore' -Type 3
            Exit 1
        }
    } else {
        Write-Log -Message 'Patch directory/file does not exist at provided path' -Component 'WinREPatchCore' -Type 2
    }
} else {
    Write-Log -Message 'No patch directory/file specified' -Component 'WinREPatchCore' -Type 2
}    

if ($DeleteBackups) {
    if ($BackupDirectory) {
        Write-Log -Message "Deleting all backups of WinRE wims in $BackupDirectory"
        Get-ChildItem $(Join-Path -Path $BackupDirectory -ChildPath '*') -Include *.wim -Force | ForEach-Object { if ($_) { Remove-Item -Path $_.FullName -Force } }
    } else {
        Write-Log -Message "Can't delete backups if no folder is specified" -Component 'WinREPatchCore' -Type 2
    }
}
if (-not(Get-WinREStatus)) {
    Write-Log -Message 'Found that WinRE was still disabled - trying to enable it' -Component 'WinREPatchCore'
    if (-not(Enable-WinRE)) {
        Write-Log -Message 'Something went wrong while enabling WinRE, please consult the ReAgent.log' -Component 'WinREPatchCore' -Type 3
        Write-Log -Message 'Do not be confused by the errormessage that says "Can not be enabled on a disk with BitLocker enabled".`
        This means that the recovery partition could not be used. There are multiple reasons for that. `
        This might happen if the new WinRE partition is too small. As mentioned, make sure to read the ReAgent.log' -Component 'WinREPatchCore'  -Type 2
        Exit 1
    }
}
if (-not($CreateWinREDrive)) {
    Write-Log -Message 'Customization finished, creating statistics' -Component 'WinREPatchCore'
    Get-Stats -Report
}
Write-Log -Message 'Nothing left to process' -Component 'WinREPatchCore'
Write-Log -Message 'Thanks for using Patch-WinRE' -Component 'WinREPatchCore'
Set-Location $CurrentLocation
Exit 0