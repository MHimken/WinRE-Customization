<#
.SYNOPSIS
    Customizes WinRE. This script applies patches and drivers. Will resize recovery partition if required.
.DESCRIPTION
    This script was created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 
    #####ATTENTION#####
    This can only be done in an automated fashion, if the disk:
    a) the disk is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk)
    b) the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified
.PARAMETER WorkingDirectory
    Adds a working directory, as we have to create some logs and files. Default C:\WinRE-Customization\
.PARAMETER BackupDirectory
    Specify a folder to backup WinRE to. Careful, WinRE backups are not deleted, even after successful (use -DeleteBackups). Default: C:\WinRE-Customization\WinREBackups\
.PARAMETER MountDirectory
    Specify the folder to mount your WinRE to. Default: C:\WinRE-Customization\WinREMount\
.PARAMETER LogDirectory
    Specify a folder to output logs to. Default: C:\WinRE-Customization\Logs
.PARAMETER PatchDirectory
    Accepts the path to a folder containing MSUs or a single file. Please make sure you provide this script with the matching OS-Version file.
    Attention: Add a trailing slash if its a foldername!
    Attention: SSUs _must_ start with "1_" to be applied first.    
.PARAMETER RecoveryDriveSizeInGB
    Specify the recovery drive size. The recommendation is 1GB. If not specified, will assume that the size is appropiate.
    Attention: It is recommended to set this, it will verify beforce changing.
.PARAMETER DriverDirectory
    Specify the path to a folder containing the drivers - needs to have at least one *.inf. You can also specify a single path to an *.inf file
.PARAMETER DeleteBackups
    Removes all .wim files in -BackupDirectory
.INPUTS
    None, script only accepts parameterised input.
.OUTPUTS
    None, this script doesn't output anything.
.EXAMPLE
    This will create a backup of WinRE, then exit.
    Patch-WinRE.ps1
.EXAMPLE
    This example will use the current script folders subfolder called "Patches" as resource for MSUs. It will resize the recovery partition to 2GB if necessary.
    Backups are written to C:\WinREBackup\. Temporarily C:\WinREMounted\ will be used as mounting directory.
    Patch-WinRE.ps1 -PatchDirectory .\Patches\ -RecoveryDriveSizeInGB 2GB -MountDirectory C:\WinREMounted\ -BackupDirectory C:\WinREBackup\
.EXAMPLE
    This will delete all backups created by Patch-WinRE in a custom folder.
    Patch-WinRE.ps1 -BackupDirectory C:\Temp\ -DeleteBackups
.EXAMPLE
    Will perform all three main functions of this script. Create a backup of the WinRE, resize the partition to 1GB, apply patches and add drivers from a folder
    .\Patch-WinRE.ps1 -Patchfolder .\Patches\ -RecoveryDriveSizeInGB 1GB -DriverDirectory C:\Temp\Drivers\x64\
.NOTES
    Version: 1.5
    Intial creation date: 11.01.2023
    Last change date: 17.01.2023
.LINK
    https://manima.de/2023/01/modify-winre-patches-drivers-and-cve-2022-41099/
#>

param(
    [System.IO.DirectoryInfo]$WorkingDirectory = 'C:\WinRE-Customization\',
    [System.IO.DirectoryInfo]$BackupDirectory = 'C:\WinRE-Customization\WinREBackups\',
    [System.IO.DirectoryInfo]$MountDirectory = 'C:\WinRE-Customization\WinREMount\',
    [System.IO.DirectoryInfo]$LogDirectory = 'C:\WinRE-Customization\Logs\',
    # Can't use [System.IO.DirectoryInfo] here, as it will not accept a single file.
    $PatchDirectory,
    $RecoveryDriveSizeInGB,
    $DriverDirectory,
    $DeleteBackups = $false
)
$Script:TimeStampStart = Get-Date
$Script:PathToScript = if ( $PSScriptRoot ) { 
    # Console or VS Code debug/run button/F5 temp console
    $PSScriptRoot 
} else {
    if ( $psISE ) { Split-Path -Path $psISE.CurrentFile.FullPath }
    else {
        if ($profile -match 'VScode') { 
            # VS Code "Run Code Selection" button/F8 in integrated console
            Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
        } else { 
            Write-Output 'unknown directory to set path variable. exiting script.'
            exit
        } 
    } 
}
if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null }
$CurrentLocation = Get-Location
Set-Location $WorkingDirectory
# Setting some variables - you can change these if you know what you're doing
$Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
if (-not(Test-Path $LogDirectory)) { New-Item $LogDirectory -ItemType Directory -Force | Out-Null }
$LogPrefix = 'Patch'
$LogFile = Join-Path -Path $LogDirectory -ChildPath ('{0}_{1}.log' -f $LogPrefix, $DateTime)

# Functions
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
    $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}
function Get-Stats {
    $Script:ReAgentCCurrentInfo = ReAgentc.exe /info
    $Script:ReAgentCCurrent = $Script:ReAgentCCurrentInfo.split("`n")[4].Substring(31, $Script:ReAgentCCurrentInfo.split("`n")[4].length - 31)
    $Script:BackupWinRESize = 0
    if (Test-Path $BackupDirectory) {
        Get-ChildItem -Path (Join-Path -Path $BackupDirectory -ChildPath '*') -Include *.wim | ForEach-Object { $Script:BackupWinRESize += [math]::round($_.Length / 1GB, 2) }
    }
    $Script:CurrentRecoveryPartitionSize = [math]::round((Get-Partition -DiskNumber $($Script:ReAgentCCurrent.split('k'))[1].Substring(0, 1) -PartitionNumber $($Script:ReAgentCCurrent.split('n'))[1].Substring(0, 1)).size / 1GB, 2)
    $Script:CurrentRecoveryPartitionFree = [math]::round((Get-Volume -Partition $((Get-Partition -DiskNumber $($Script:ReAgentCCurrent.split('k'))[1].Substring(0, 1) -PartitionNumber $($Script:ReAgentCCurrent.split('n'))[1].Substring(0, 1)))).SizeRemaining / 1GB, 2)
    $Script:EstimatedWinRESize = $Script:CurrentRecoveryPartitionSize - $Script:CurrentRecoveryPartitionFree
    $TimeStampStop = Get-Date
    $RuntimeRaw = $TimeStampStop - $Script:TimeStampStart
    $Script:Runtime = $RuntimeRaw.ToString("hh':'mm':'ss")
}
function Get-WinREStatus {
    Write-Log -Message 'Retrieving current WinRE status' -Component 'WinREStatus'
    $WinreStatus = reagentc /info
    $RecoveryPartitionStatus = $WinreStatus.split("`n")[3].split(' ')[-1]
    switch ($RecoveryPartitionStatus) {
        'Enabled' { Write-Log -Message 'Recovery Agent is enabled' -Component 'WinREStatus'; return $true }
        'Disabled' { Write-Log -Message 'Recovery Agent is disabled' -Component 'WinREStatus'; return $false }
        default { Write-Log -Message 'Recovery Agent status could not be determined' -Component 'WinREStatus'; return }
    }
}
function Disable-WinRE {
    $DisableRE = ReAgentc.exe /disable
    if ($DisableRE[0] -like '*Success*') {
        Write-Log -Message 'Disabled WinRE' -Component 'DisableWinRE'
        return $true
    } else {
        Write-Log -Message 'Disabling failed' -Component 'DisableWinRE' -Type 3
        return $false
    }
}
function Enable-WinRE {
    $EnableRE = ReAgentc.exe /enable
    if ($EnableRE[0] -like '*Success*') {
        Write-Log -Message 'Enabled WinRE' -Component 'EnableWinRE'
        return $true
    } else {
        Write-Log -Message 'Enabling failed' -Component 'EnableWinRE' -Type 3
        return $false
    }
}
function Mount-WinRE {
    if ((Get-WindowsImage -Mounted).count -ge 1) {
        Write-Log -Message 'There is at least one other image mounted already' -Component 'MountWinRE' -Type 2
        return $false
    }
    $Mount = ReAgentC.exe /mountre /path $MountDirectory
    if ($Mount[0] -like "*Success*" -and (Get-WindowsImage -Mounted).count -ge 1) {
        Write-Log -Message 'WinRE successfully mounted using ReAgentC' -Component 'MountWinRE'
        return $true
    } else {
        Write-Log -Message 'Could not mount WinRE image - please consult the log' -Component 'MountWinRE' -Type 3
        Write-Log -Message "$Mount" -Component 'MountWinRE'
        return $false
    }
}
function Dismount-WinRE {
    $DismountImageLogFile = Join-Path -Path $LogDirectory -ChildPath ('Dismount-WindowsImage_{0}.log' -f $DateTime)
    $DismountWinRECommonParameters = @{
        Path     = $MountDirectory
        LogLevel = 'WarningsInfo'
    }
    $UnmountCommit = ReAgentC.exe /unmountre /path $($MountDirectory) /commit
    if (-not($UnmountCommit) -or (-not($UnmountCommit[0] -like '*Success*') -and $(Get-WindowsImage -Mounted).count -ge 1)) {
        Write-Log -Message 'Commiting failed - discarding changes' -Component 'DismountWinRE' -Type 3
        Write-Log -Message "Status of the WinRE during this operation according to Get-WindowsImage was: $((Get-WindowsImage -Mounted).MountStatus)" -Component 'DismountWinRE'
        $UnmountDiscard = ReAgentC.exe /unmountre /path $($MountDirectory) /discard
        if (-not($UnmountDiscard[0] -like "*Successful*")) {
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
    } else {
        Write-Log -Message 'WinRE commited changes successfully' -Component 'DismountWinRE'
        return $true
    }
}
function Backup-WinRE {
    Write-Log -Message 'Creating WinRE Backup - will not be automatically deleted(!)' -Component 'BackupWinRE'
    Write-Log -Message 'This will temporarily disable WinRE' -Component 'BackupWinRE' -Type 2
    if (Get-WinREStatus) {
        if (-not(Disable-WinRE)) {
            Write-Log -Message 'Could not disable WinRE, so we cannot create a backup' -Component 'BackupWinRE' -Type 3
            return $false
        }
    }
    $WinREDefaultLocation = Join-Path -Path $ENV:SystemDrive -ChildPath '\Windows\System32\Recovery\WinRE.wim'
    $BackupFileName = ('WinRE{0}.wim' -f $Script:DateTime)
    if (-not(Test-Path $BackupDirectory)) {
        New-Item $BackupDirectory -ItemType Directory -Force
    } else {
        Write-Log -Message 'Backup folder already exists' -Component 'BackupWinRE'
        Write-Log -Message 'Checking if the current WinRE is already backed' -Component 'BackupWinRE'
        $Backups = Get-ChildItem (Join-Path -Path $BackupDirectory -ChildPath '*') -Include *.wim -Force
        $ToBackupHash = Get-FileHash $WinREDefaultLocation -Algorithm MD5
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
    Write-Log -Message "Moving $WinREDefaultLocation to $BackupDirectory and name $BackupFileName" -Component 'BackupWinRE'
    Copy-Item -Path $WinREDefaultLocation -Destination $BackupDirectory -Force -PassThru  | Rename-Item -NewName $BackupFileName
    if (Test-Path (Join-Path -Path $BackupDirectory -ChildPath $BackupFileName)) {
        return $true
    } else {
        return $false
    }
}
function Resize-RecoveryPartition {    
    param(
        $RecoveryDriveNewSize = 1GB
    )
    $DriveToShrink = ($env:SystemDrive).Substring(0, 1)
    Write-Log -Message 'Recommended minimum partition size is 1GB for WinRE - this depends on the level of customization. If anything fails, please adjust the script' -Component 'ResizeRecoveryPartition'
    $Partitions = Get-Partition
    Write-Log -Message 'Finding the "Recovery" partition. If this is named differently than this default value, you need to adjust the script' -Component 'ResizeRecoveryPartition'
    foreach ($Partition in $Partitions) {
        if ($Partition.Type -eq 'Recovery') {
            $RecoveryPartition = $Partition
            break
        }
    }
    if (-not($RecoveryPartition)) {
        Write-Log -Message 'No recovery partition detected' -Component 'ResizeRecoveryPartition' -Type 3
        return $false
    }
    if ($RecoveryPartition.Size -ge $RecoveryDriveNewSize) {
        Write-Log -Message 'The recovery partition is already of adequate size' -Component 'ResizeRecoveryPartition'
        return $true
    } else {
        $WinREStatus = Get-WinREStatus
        if ($WinREStatus) {
            if (Disable-WinRE) {
                Write-Log -Message 'ReagentC successfully disabled for resizing' -Component 'ResizeRecoveryPartition'
            } else {
                Write-Log -Message 'ReagentC could not be disabled - please make sure you are running this script as admin' -Component 'ResizeRecoveryPartition' -Type 3
                return $false
            }
        } elseif (-not($WinREStatus)) {
            Write-Log -Message 'WinRE is already disabled' -Component 'ResizeRecoveryPartition'
        } else {
            Write-Log -Message 'WinRE status could not be determined - are you running as admin?' -Component 'ResizeRecoveryPartition' -Type 3
            return $false
        }        
        Write-Log -Message "Verify that the $DriveToShrink has adequate size left to shrink" -Component 'ResizeRecoveryPartition'
        $WindowsPartitionCurrentSize = Get-Volume -DriveLetter $DriveToShrink
        if ($WindowsPartitionCurrentSize.SizeRemaining -ge $RecoveryDriveNewSize) {
            $WindowsPartitionSize = Get-PartitionSupportedSize -DriveLetter $DriveToShrink
            # Shrink source disk size
            $ShrinkSizeCheck = ($WindowsPartitionSize.SizeMax - $WindowsPartitionSize.SizeMin) -ge ($RecoveryDriveNewSize - $RecoveryPartition.Size)
            if ($ShrinkSizeCheck) {
                if (-not(Get-WinREStatus)) {
                    $DisableReAgentC = (Get-Volume -Partition $RecoveryPartition).SizeRemaining
                    if ($DisableReAgentC -le 100MB) {
                        Write-Log -Message 'Disabling ReAgentC failed' -Component 'ResizeRecoveryPartition' -Type 3
                        return $false
                    }
                    Write-Log -Message 'Shrinking C: and re-creating recovery partition' -Component 'ResizeRecoveryPartition'
                    Remove-Partition $RecoveryPartition.DiskNumber $RecoveryPartition.PartitionNumber -Confirm:$false
                    $NewSystemDriveSize = $WindowsPartitionSize.SizeMax - $RecoveryDriveNewSize + $RecoveryPartition.Size
                    Resize-Partition -DriveLetter $DriveToShrink -Size $NewSystemDriveSize
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
                    $DiskpartStatus = (Get-Content -Path $(Join-Path -Path $LogDirectory -ChildPath 'diskpart.log') -Raw) -like '*DiskPart successfully assigned the attributes to the selected GPT partition.*'
                    Get-Item '.\diskpart.txt' | Remove-Item -Force
                    Write-Log -Message 'Created Recovery Partition' -Component 'ResizeRecoveryPartition'
                    if ($DiskpartStatus) {
                        Write-Log -Message 'Recovery partition recreated. Define recovery partition using GPTType' -Component 'ResizeRecoveryPartition'
                        Set-Partition -DiskNumber $RecoveryPartition.DiskNumber -PartitionNumber $RecoveryPartition.PartitionNumber -GptType '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'
                        Write-Log -Message 'Recovery partition defined. Enabling ReAgentC' -Component 'ResizeRecoveryPartition'
                        if (-not(Enable-WinRE)) {
                            Write-Log -Message 'WinRE could not be enabled please consult the logs. Its likely you need to recreate the partition manually' -Component 'ResizeRecoveryPartition' -Type 3
                            return $false
                        } else {
                            Write-Log -Message 'Successfully re-enabled ReAgentC' -Component 'ResizeRecoveryPartition'
                            return $true
                        }
                    } else {
                        $LogMessage = "The system drive could not be shrunk to the requested size of $($RecoveryDriveNewSize/1024/1024/1024) GB - Please consult the application event log"
                        Write-Log -Message "$LogMessage `n  $((Get-EventLog -LogName Application -Newest 1 -Source Microsoft-Windows-Defrag -EntryType Information).Message)" -Component 'ResizeRecoveryPartition' -Type 3
                        Write-Log -Message 'The re-sizing could not be performed' -Component 'ResizeRecoveryPartition' -Type 2
                        return $false
                    }
                } else {
                    Write-Log -Message 'The WinRE.wim seems to be missing. Please make sure C:\Windows\System32\Recovery\Winre.wim exists and is accessible. You can get this file from a matching Windows install.wim' -Component 'ResizeRecoveryPartition' -Type 3
                    Write-Log -Message 'No changes performed to partition, re-enable WinRE' -Component 'ResizeRecoveryPartition'                    
                    if (-not(Enable-WinRE)) {
                        Write-Log -Message 'Could not re-enable WinRE' -Component 'ResizeRecoveryPartition' -Type 3
                    }
                    return $false
                }
            }
        } else {
            Write-Log -Message "Free space left is $($WindowsPartitionCurrentSize.SizeRemaining), please make some room first" -Component 'ResizeRecoveryPartition' -Type 3
            return $false
        }
    }
}
function Add-DriverToWinRE {
    param(
        $Drivers,
        $SingleDriver
    )
    Write-Log -Message 'Adding driver(s) to WinRE image' -Component 'AddDriversToWinRE'
    Write-Log -Message 'Mounting Winre' -Component 'AddDriversToWinRE'
    $AddDriverLogFile = Join-Path -Path $LogDirectory -ChildPath ('Add-WindowsDriver_{0}.log' -f $DateTime)
    $AddDriverCommonParams = @{
        Path     = $MountDirectory
        LogPath  = $AddDriverLogFile
        LogLevel = 'WarningsInfo'
    }
    if (-not(Test-Path $MountDirectory)) {
        New-Item $MountDirectory -ItemType Directory
    } else {
        Write-Log -Message 'Directory already exists - verifying its empty' -Component 'PatchWinRE'
        $MountDirectoryEmpty = Get-ChildItem $MountDirectory 
        if ($MountDirectoryEmpty) {
            Write-Log -Message "Mount directory isn't empty - exiting" -Component 'PatchWinRE' -Type 3
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

function Add-PatchToWinRE {
    param(
        $MSUFiles,
        $SingleFile
    )
    if (-not(Get-WinREStatus)) {
        Write-Log -Message 'WinRE is not enabled currently - trying to enable WinRE' -Component 'PatchWinRE' -Type 2
        if (-not(Enable-WinRE)) {
            Write-Log -Message "WinRE couldn't be enabled" -Component 'PatchWinRE' -Type 3
            return $false
        }
    }
    $CurrentWinREPath = (ReAgentc.exe /info | Select-String -SimpleMatch "\\?\GLOBALROOT\device").ToString().replace("Windows RE location:", "").Trim() + "\WinRE.wim"
    $CurrentWinREBuild = (Get-WindowsImage -ImagePath $CurrentWinREPath -Index 1).SPBuild
    Write-Log "Current Patchversion of mounted WinRE: $CurrentWinREBuild"
    if ($MSUFiles) {
        $Patches = $MSUFiles
        $SSU = $Patches | Where-Object { $_.Name -like '1_*' }
    } elseif ($SingleFile) {
        $Patches = $SingleFile
    }
    $Windows10 = ([System.Environment]::OSVersion.Version.Build -ge 19042 -and [System.Environment]::OSVersion.Version.Build -lt 22000) 
    if ($Windows10 -and -not($SSU)) {
        Write-Log -Message "Windows 10 machine detected: Please be aware, that this script doesn't check if the SSU has been applied to the WinRE before patching. Rename the SSU to start with '1_'. You will want to check for KB5014032" -Component 'PatchWinRE' -Type 2
    }
    if (-not(Test-Path $MountDirectory)) {
        New-Item $MountDirectory -ItemType Directory
    } else {
        Write-Log -Message 'Directory already exists - verifying its empty' -Component 'PatchWinRE'
        $MountDirectoryEmpty = Get-ChildItem $MountDirectory 
        if ($MountDirectoryEmpty) {
            Write-Log -Message "Mount directory isn't empty - exiting" -Component 'PatchWinRE' -Type 3
            return $false
        }
    }
    Write-Log -Message 'Mounting WinRE' -Component 'PatchWinRE'
    if (-not(Mount-WinRE)) {
        Write-Log -Message "WinRE couldn't be mounted - please verify the logs" -Component 'PatchWinRE' -Type 3
        return $false
    }
    Write-Log -Message 'WinRE mounted successful' -Component 'PatchWinRE'
    $AddWindowsPackageLogFile = Join-Path -Path $LogDirectory -ChildPath ('Add-WindowsPackage_{0}.log' -f $DateTime)
    $ResetBaseLogFile = Join-Path -Path $LogDirectory -ChildPath ('ResetBase_{0}.log' -f $DateTime)
    # Setup hashtable for common parameters for *-WindowsImage
    $AddPatchCommonParams = @{
        Path     = $MountDirectory
        LogLevel = 'WarningsInfo'
    }
    if ($SSU) {
        Write-Log -Message 'Applying SSU to WinRE' -Component 'PatchWinRE'
        Add-WindowsPackage -PackagePath $($SSU.FullName) @AddPatchCommonParams -LogPath $AddWindowsPackageLogFile
    }
    Write-Log -Message 'Applying MSU file(s) to WinRE' -Component 'PatchWinRE'
    foreach ($Patch in $Patches) {
        Add-WindowsPackage -PackagePath $($Patch.FullName) @AddPatchCommonParams -LogPath $AddWindowsPackageLogFile
    }
    Write-Log -Message 'Done applying patches - attempting' -Component 'PatchWinRE'
    dism /image:$MountDirectory /cleanup-image /StartComponentCleanup /ResetBase /LogPath:$ResetBaseLogFile /loglevel:3
    Write-Log -Message 'Cleanup done, attempting to commit patches' -Component 'PatchWinRE'
    if (-not(Dismount-WinRE)) {
        Write-Log 'WinRE could not be dismounted, changes have not been applied' -Component 'PatchWinRE' -Type 3
        return $false
    }
    $NewWinREPath = (ReAgentc.exe /info | Select-String -SimpleMatch '\\?\GLOBALROOT\device').ToString().Replace('Windows RE location:', '').Trim() + '\WinRE.wim'
    $NewWinREBuild = (Get-WindowsImage -ImagePath $NewWinREPath -Index 1).SPBuild
    Write-Log -Message "Current Patchversion of mounted WinRE: $NewWinREBuild"
    Write-Log -Message 'Applying patches finished' -Component 'PatchWinRE'
    return $true
}

# Start Coding!
Write-Log -Message "Patch-WinRE started at $(Get-Date)" -Component 'WinREPatchCore'
Write-Log -Message 'Creating backup first' -Component 'WinREPatchCore'
if (-not(Backup-WinRE)) {
    Write-Log -Message 'Could not create WinRE Backup - the file might be missing. Please extract it from install media (via install.wim)' -Component 'WinREPatchCore' -Type 3
    return $false
}
if ($RecoveryDriveSizeInGB) {
    Write-Log -Message "Verify that the recovery partition has the appropiate size of $($RecoveryDriveSizeInGB/1GB) GB" -Component 'WinREPatchCore'
    if (-not(Resize-RecoveryPartition -RecoveryDriveNewSize $RecoveryDriveSizeInGB)) {
        Write-Log -Message "Something went wrong with the recovery partition - please check the log $LogFile" -Component 'WinREPatchCore' -Type 3
        Exit 1
    }
} else {
    Write-Log -Message 'No recovery drive size specified, using defaults for verification' -Component 'WinREPatchCore' -Type 2
    Write-Log -Message "Verifying recovery partition size is at least set to the default: $(Resize-RecoveryPartition)" -Component 'WinREPatchCore'
}

if ($DriverDirectory) {
    if (Test-Path -Path $DriverDirectory) {
        if ((Get-ItemProperty $DriverDirectory).Attributes -eq 'Directory') {
            if (-not(Add-DriverToWinRE -Drivers $DriverDirectory)) {
                Write-Log -Message 'Something went wrong while applying drivers, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } elseif ($DriverDirectory -like '*.inf') {
            if (-not(Add-DriverToWinRE -SingleDriver $DriverDirectory)) {
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
if ($PatchDirectory) {
    if (Test-Path -Path $PatchDirectory) {
        if ((Get-ItemProperty $PatchDirectory).Attributes -eq 'Directory') {
            if (-not(Add-PatchToWinRE -MSUFiles (Get-ChildItem $PatchDirectory -Filter *.msu))) {
                Write-Log -Message 'Something went wrong while applying patches, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } elseif ($PatchDirectory -like '*.msu') {
            if (-not(Add-PatchToWinRE -SingleFile $PatchDirectory)) {
                Write-Log -Message 'Something went wrong while applying patches, please consult the logs' -Component 'WinREPatchCore' -Type 3
                Exit 1
            }
        } else {
            Write-Log -Message 'Directory/file not found or no files ending in *.msu in directory.' -Component 'WinREPatchCore' -Type 3
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
if(-not(Get-WinREStatus)){
    Write-Log -Message 'Found that WinRE was still disabled - trying to enable it' -Component 'WinREPatchCore'
    if(-not(Enable-WinRE)){
        Write-Log -Message 'Something went wrong while enabling WinRE, please consult the logs' -Component 'WinREPatchCore' -Type 3
    }
}
Write-Log -Message 'Customization finished, creating statistics' -Component 'WinREPatchCore'
Get-Stats
Write-Log -Message "Original WinRE size before patching: $Script:BackupWinRESize
RecoveryPartitionSize: $Script:CurrentRecoveryPartitionSize GB
RecoveryPartitionFree: $Script:CurrentRecoveryPartitionFree GB
EstimatedWinRESize: $Script:EstimatedWinRESize GB
Script runtime: $Script:Runtime`n 
More information can be found at 
C:\Windows\Logs\ReAgent\ReAgent.log
C:\Windows\Logs\Dism\Dism.log" -Component 'WinREPatchCore'
Write-Log -Message 'Nothing left to process' -Component 'WinREPatchCore'
Write-Log -Message 'Thanks for using Patch-WinRE' -Component 'WinREPatchCore'
Set-Location $CurrentLocation
Exit 0