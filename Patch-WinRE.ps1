<#
.SYNOPSIS
Customizes WinRE. This script applies patches and drivers. Will resize recovery partition if required.
.DESCRIPTION
This script was created to automate CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 
#####ATTENTION#####
This can only be done in an automated fashion, if the disk:
a) the disk is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk)
b) the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified
.PARAMETER WorkingDirectory
Adds a working directory, as we have to create some logs and files. Default C:\WinRE-Customization\
.PARAMETER PatchFolder
Accepts the path to a folder containing MSUs or a single file. Please make sure you provide this script with the matching OS-Version file.
Attention: Add a trailing slash if its a foldername!
Attention: SSUs _must_ start with "1_" to be applied first.
.PARAMETER RecoveryDriveSize
Specify the recovery drive size. The recommendation is 1GB. If not specified, will assume that the size is appropiate.
Attention: It is recommended to set this, it will verify beforce changing.
.PARAMETER MountFolder
Specify the folder to mount your WinRE to. Default: C:\WinRE-Customization\WinREMount\
Add a trailing slash to the foldername!
.PARAMETER LogDir
Specify a folder to output logs to. Default: C:\WinRE-Customization\Logs
.PARAMETER BackupFolder
Specify a folder to backup WinRE to. Careful, WinRE backups are not deleted, even after successful (use -DeleteBackups). Default: C:\WinRE-Customization\WinREBackups\
.PARAMETER DeleteBackups
Removes all .wim files in -BackupFolder
.INPUTS
None, script only accepts switches.
.OUTPUTS
None, this script doesn't output anything.
.EXAMPLE
This example will use the current script folders subfolder called "Patches" as resource for MSUs. It will resize the recovery partition to 2GB if necessary.
Backups are written to C:\WinREBackup\. Temporarily C:\WinREMounted\ will be used as mounting directory.
Patch-WinRE.ps1 -PatchFolder .\Patches\ -RecoveryDriveSize 2GB -MountFolder C:\WinREMounted\ -BackupFolder C:\WinREBackup\
.EXAMPLE
This will delete all backups created by Patch-WinRE.
Patch-WinRE.ps1 -BackupFolder C:\Temp\ -DeleteBackups
.EXAMPLE
.\Patch-WinRE.ps1 -Patchfolder .\Patches\ -RecoveryDriveSize 1GB -Driver C:\Temp\Drivers\x64\
.NOTES
Version: 1.4
Intial creation date: 11.01.2023
Last change date: 16.01.2023
.LINK
https://manima.de/
https://manima.de/ARTICLEHERE
#>

param(
    $WorkingDirectory = "C:\WinRE-Customization\",
    $BackupFolder = "C:\WinRE-Customization\WinREBackups\",
    $MountFolder = "C:\WinRE-Customization\WinREMount\",
    $LogDir = "C:\WinRE-Customization\Logs\",
    $PatchFolder,
    $RecoveryDriveSize,
    #$Driver,#NotDoneYet!
    $DeleteBackups = $false
)
$Script:TimeStampStart = Get-Date
$Script:PathToScript = if ( $PSScriptRoot ) { 
    # Console or vscode debug/run button/F5 temp console
    $PSScriptRoot 
}
Else {
    if ( $psISE ) { Split-Path -Path $psISE.CurrentFile.FullPath }
    else {
        if ($profile -match "VScode") { 
            # vscode "Run Code Selection" button/F8 in integrated console
            Split-Path $psEditor.GetEditorContext().CurrentFile.Path 
        }
        else { 
            Write-Output "unknown directory to set path variable. exiting script."
            exit
        } 
    } 
}
if (-not(Test-Path $WorkingDirectory )) { New-Item $WorkingDirectory -ItemType Directory -Force | Out-Null }
Set-Location $WorkingDirectory
#Setting some variables - you can change these if you know what you're doing
$Script:DateTime = Get-Date -Format ddMMyyyy_hhmmss
if (-not(Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
$LogPrefix = "Patch"
$LogFile = $LogDir + $LogPrefix + "_" + $DateTime + ".log"

#Functions
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
        [ValidateSet("1", "2", "3")][int]$Type
    )
    #Type: 1 = Normal, 2 = Warning (yellow), 3 = Error (red)
    $Time = Get-Date -Format "HH:mm:ss.ffffff"
    $Date = Get-Date -Format "MM-dd-yyyy"
    if (-not($Component)) { $Component = "Runner" }
    if (-not($Type)) { $Type = 1 }
    $LogMessage = "<![LOG[$Message" + "]LOG]!><time=`"$Time`" date=`"$Date`" component=`"$Component`" context=`"`" type=`"$Type`" thread=`"`" file=`"`">"
    $LogMessage | Out-File -Append -Encoding UTF8 -FilePath $LogFile
}
function Get-Stats {
    $Script:ReAgentCCurrentInfo = ReAgentc.exe /info
    $Script:ReAgentCCurrent = $Script:ReAgentCCurrentInfo.split("`n")[4].Substring(31, $Script:ReAgentCCurrentInfo.split("`n")[4].length - 31)
    $Script:BackupWinRESize = 0
    if (Test-Path $BackupFolder) {
        Get-Childitem -Path $($BackupFolder + "*") -Include *.wim | ForEach-Object { $Script:BackupWinRESize += [math]::round($_.Length / 1GB, 2) }
    }
    $Script:CurrentRecoveryPartitionSize = [math]::round((Get-Partition -DiskNumber  $($Script:ReAgentCCurrent.split("k"))[1].Substring(0, 1) -PartitionNumber  $($Script:ReAgentCCurrent.split("n"))[1].Substring(0, 1)).size / 1GB, 2)
    $Script:CurrentRecoveryPartitionFree = [math]::round((Get-Volume -Partition $((Get-Partition -DiskNumber  $($Script:ReAgentCCurrent.split("k"))[1].Substring(0, 1) -PartitionNumber  $($Script:ReAgentCCurrent.split("n"))[1].Substring(0, 1)))).SizeRemaining / 1GB, 2)
    $Script:EstimatedWinRESize = $Script:CurrentRecoveryPartitionSize - $Script:CurrentRecoveryPartitionFree
    $TimeStampStop = Get-Date
    $RuntimeRaw = $TimeStampStop - $Script:TimeStampStart
    $Script:Runtime = $RuntimeRaw.ToString("hh':'mm':'ss")
}
function Get-WinREStatus {
    Write-Log "Retrieving current WinRE status" -Component "WinREStatus"
    $WinreStatus = reagentc /info
    $RecoveryPartitionStatus = $WinreStatus.split("`n")[3].split(" ")[-1]
    switch ($RecoveryPartitionStatus) {
        "Enabled" { Write-Log "Recovery Agent is enabled" -Component "WinREStatus"; return $true }
        "Disabled" { Write-Log "Recovery Agent is disabled" -Component "WinREStatus"; return $false }
        default { Write-Log "Status couldn't be determined" -Component "WinREStatus"; return }
    }
}
function Disable-WinRE {
    $DisableRE = ReAgentc.exe /disable
    if ($DisableRE[0] -like "*Success*") {
        Write-Log "Disabled WinRE" -Component "DisableWinRE"
        return $true
    }
    else {
        Write-Log "Disabling failed" -Component "DisableWinRE" -Type 3
        return $false
    }
}
function Enable-WinRE {
    $EnableRE = ReAgentc.exe /enable
    if ($EnableRE[0] -like "*Success*") {
        Write-Log "Enabled WinRE" -Component "EnableWinRE"
        return $true
    }
    else {
        Write-Log "Enabling failed" -Component "EnableWinRE" -Type 3
        return $false
    }
}
function Backup-WinRE {
    Write-Log "Creating intial Backup - will not be automatically deleted(!)" -Component "BackupWinRE"
    Write-Log "This will temporarily disable WinRE" -Component "BackupWinRE" -Type 2
    if (Get-WinREStatus) {
        if (-not(Disable-WinRE)) {
            Write-Log "Couldn't disable WinRE, so we can't create a backup" -Component "BackupWinRE" -Type 3
            return $false
        }
    }
    $WinREDefaultLocation = $env:SystemDrive + "\Windows\System32\Recovery\WinRE.wim"
    if (-not(Test-Path $BackupFolder)) {
        New-Item $BackupFolder -ItemType Directory -Force
    }
    else {
        Write-Log "Backup folder already exists" -Component "BackupWinRE"
        Write-Log "Checking if the current WinRE is already backed" -Component "BackupWinRE"
        $Backups = Get-ChildItem $($BackupFolder + "*") -Include *.wim -Force
        if ($Backups.count -ge 1) {
            $ToBackupHash = Get-FileHash $WinREDefaultLocation -Algorithm MD5
            foreach ($Backup in $Backups) {
                $BackedFile = Get-FileHash $Backup.FullName -Algorithm MD5
                if ($BackedFile.Hash -eq $ToBackupHash.Hash) {
                    Write-Log "Full backup found" -Component "BackupWinRE"
                    return $true
                }
            }
        }
        Write-Log "No Backup of the current available WinRE found - creating backup..." -Component "BackupWinRE"
    }
    Write-Log "Moving $WinREDefaultLocation to $Backupfolder" -Component "BackupWinRE"
    Copy-Item -Path $WinREDefaultLocation -Destination $BackupFolder -PassThru | Rename-Item -NewName $("WinRE" + $Script:DateTime + ".wim")
    if (Test-Path $($BackupFolder + "WinRE" + $Script:DateTime + ".wim")) {
        return $true
    }
    else {
        return $false
    }
}
function Resize-RecoveryPartition {    
    param(
        $RecoveryDriveNewSize = 1GB
    )
    if (-not(Backup-WinRE)) {
        Write-Log "Couldn't create WinRE Backup - the file might be missing. Please extract it from and install media (via install.wim)" -Component "ResizeRecoveryPartition" -Type 3
        return $false
    }
    $DriveToShrink = ($env:SystemDrive).Substring(0, 1)
    Write-Log "Currently recommended minimum is 1GB for WinRE - this depends on the level is customization. If anything fails, please adjust the script" -Component "ResizeRecoveryPartition"

    $Partitions = Get-Partition
    Write-Log "Finding the 'Recovery' partition. If this is named differently than this default value, you need to adjust the script." -Component "ResizeRecoveryPartition"
    foreach ($Partition in $Partitions) {
        if ($Partition.Type -eq "Recovery") {
            $RecoveryPartition = $Partition
            break
        }
    }
    if (-not($RecoveryPartition)) {
        Write-Log "No recovery partition detected" "ResizeRecoveryPartition" -Type 3
        return $false
    }
    if ($RecoveryPartition.Size -ge $RecoveryDriveNewSize) {
        Write-Log "The recovery partition is already of adequate size" -Component "ResizeRecoveryPartition"
        return $true
    }
    else {
        $WinREStatus = Get-WinREStatus
        if ($WinREStatus) {
            if (Disable-WinRE) {
                Write-Log "ReagentC successfully disabled for resizing" -Component "ResizeRecoveryPartition"
            }
            else {
                Write-Log "ReagentC couldn't be disabled - please make sure you are running this script as admin" -Component "ResizeRecoveryPartition" -Type 3
                return $false
            }
        }
        elseif (-not($WinREStatus)) {
            Write-Log "WinRE is already disabled" -Component "ResizeRecoveryPartition"
        }
        else {
            Write-Log "WinRE status couldn't be determined - are you running as admin?" -Component "ResizeRecoveryPartition" -Type 3
            return $false
        }        
        Write-Log "Verify that the $DriveToShrink has adequate size left to shrink" -Component "ResizeRecoveryPartition"
        $WindowsPartitionCurrentSize = Get-Volume -DriveLetter $DriveToShrink
        if ($WindowsPartitionCurrentSize.SizeRemaining -ge $RecoveryDriveNewSize) {
            $WindowsPartitionSize = Get-PartitionSupportedSize -DriveLetter $DriveToShrink
            # Shrink source disk size
            $ShrinkSizeCheck = ($WindowsPartitionSize.SizeMax - $WindowsPartitionSize.SizeMin) -ge ($RecoveryDriveNewSize - $RecoveryPartition.Size)
            if ($ShrinkSizeCheck) {
                if (-not(Get-WinREStatus)) {
                    $DisableReAgentC = (Get-Volume -Partition $RecoveryPartition).SizeRemaining
                    if ($DisableReAgentC -le 100MB) {
                        Write-Log "Disabling ReAgentC failed" -Component "ResizeRecoveryPartition" -Type 3
                        return $false
                    }
                    Write-Log "Shrinking C: and re-creating recovery partition" -Component "ResizeRecoveryPartition"
                    Remove-Partition $RecoveryPartition.DiskNumber $RecoveryPartition.PartitionNumber -Confirm:$false
                    $NewSystemDriveSize = $WindowsPartitionSize.SizeMax - $RecoveryDriveNewSize + $RecoveryPartition.Size
                    Resize-Partition -DriveLetter $DriveToShrink -Size $NewSystemDriveSize
                    #Unfortunately Set-Partition has no -Attributes switch, so we need to resort to violence
                    $Diskpart = @"
select disk $((Get-Partition -DriveLetter $DriveToShrink).DiskNumber)
create partition primary`
format quick fs=ntfs label='Recovery'`
gpt attributes=0x8000000000000001
"@
                    if (Test-Path .\diskpart.txt) { Get-Item .\diskpart.txt | Remove-Item -Force }
                    if (Test-Path .\diskpart.log) { Get-Item .\diskpart.log | Remove-Item -Force }
                    Add-Content .\diskpart.txt -Value $Diskpart
                    diskpart /s .\diskpart.txt > diskpart.log
                    Move-Item -Path .\diskpart.log -Destination .\Logs\
                    $DiskpartStatus = (Get-Content .\diskpart.log -Raw) -like "*DiskPart successfully assigned the attributes to the selected GPT partition.*"
                    Get-Item .\diskpart.txt | Remove-Item -Force
                    Write-Log "Created Recovery Partition" -Component "ResizeRecoveryPartition"
                    #$NewRecoveryPartition = Get-Volume
                    if ($DiskpartStatus) {
                        Write-Log "Recovery partition recreated. Define recovery partition using GPTType" -Component "ResizeRecoveryPartition"
                        Set-Partition -DiskNumber $RecoveryPartition.DiskNumber -PartitionNumber $RecoveryPartition.PartitionNumber -GptType "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
                        Write-Log "Recovery partition defined. Enabling ReagentC" -Component "ResizeRecoveryPartition"
                        if (-not(Enable-WinRE)) {
                            Write-Log "WinRE couldn't be enabled please consult the logs. Its likely you need to recreate the partition manually." -Component "ResizeRecoveryPartition" -Type 3
                            return $false
                        }
                        Write-Log "Enabled, hide the partition" -Component "ResizeRecoveryPartition" 
                        Set-Partition -DiskNumber $RecoveryPartition.DiskNumber -PartitionNumber $RecoveryPartition.PartitionNumber -GptType "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
                        return $true
                    }
                    else {
                        $LogMessage = "The system drive couldn't be shrinked to the requested size of $($RecoveryDriveNewSize/1024/1024/1024) GB - Please consult the application event log"
                        Write-Log "$LogMessage `n  $((Get-Eventlog -LogName Application -Newest 1 -Source Microsoft-Windows-Defrag -EntryType Information).Message)" -Component "ResizeRecoveryPartition" -Type 3
                        Write-Log "The re-sizing couldn't be performed. If the first blocking file " -Component "ResizeRecoveryPartition" -Type 2
                        return $false
                    }
                }
                else {
                    Write-Log "The WinRE.wim seems to be missing. Please make sure C:\Windows\System32\Recovery\Winre.wim exists and is accessible. You can get this file from a matching Windows 10 install.wim" -Component "ResizeRecoveryPartition" -Type 3
                    Write-Log "No changes performed to partition, reenable WinRE" -Component "ResizeRecoveryPartition"                    
                    if (-not(Enable-WinRE)) {
                        Write-Log "Couldn't enable WinRE" -Component "ResizeRecoveryPartition" -Type 3
                    }

                    return $false
                }
            }
        }
        else {
            Write-Log "Free space left is $($WindowsPartitionCurrentSize.SizeRemaining), please make some room first" -Component "ResizeRecoveryPartition" -Type 3
            return $false
        }
    }
}
function Add-DriverToWinRE {
    param(
        $Drivers,
        $SingleDriver
    )
    Write-Log "Adding driver(s) to " -Component "AddDriversToWinRE"
    if ($Drivers) {
        Add-WindowsDriver -Path $MountFolder -Driver $Drivers -Recurse -LogPath $($LogDir + "Add-WindowsDriver_" + $DateTime + ".log") -LogLevel WarningsInfo 
    }
    elseif ($SingleDriver) {
        Add-WindowsDriver -Path $MountFolder -Driver $SingleDriver -LogPath $($LogDir + "Add-WindowsDriver_" + $DateTime + ".log") -LogLevel WarningsInfo 
    }
}

function Add-PatchToWinRE {
    param(
        $MSUFiles,
        $SingleFile
    )
    if (-not(Get-WinREStatus)) {
        Write-Log "WinRE is not enabled currently - trying to enable WinRE" -Component "PatchWinRE" -Type 2
        if (-not(Enable-WinRE)) {
            Write-Log "WinRE couldn't be mounted" -Component "PatchWinRE" -Type 3
            return $false
        }
    }
    $CurrentWinREPath = (ReAgentc.exe /info | Select-String -SimpleMatch "\\?\GLOBALROOT\device").ToString().replace("Windows RE location:", "").Trim() + "\WinRE.wim"
    $CurrentWinREBuild = (Get-WindowsImage -ImagePath $CurrentWinREPath -Index 1).SPBuild
    Write-Log "Current Patchversion of mounted WinRE: $CurrentWinREBuild"
    if ($MSUFiles) {
        $Patches = Get-ChildItem $FullPatchFolder
        $SSU = $Patches | Where-Object { $_.Name -like "1_*" }
    }
    elseif ($SingleFile) {
        $Patches = $SingleFile
    }
    $WindowsDisplayName = (Get-CimInstance -ClassName Win32_OperatingSystem).Name
    if ($WindowsDisplayName -like "*10*" -and -not($SSU)) {
        Write-Log "Windows 10 machine detected: Please be aware, that this script doesn't check if the SSU has been applied to the WinRE before patching. Rename the SSU to start with '1_'. You will want to check for KB5014032" -Component "PatchWinRE" -Type 2
    }
    if (-not(Test-Path $MountFolder)) {
        New-Item $MountFolder -ItemType Directory
    }
    else {
        Write-Log "Folder already exists - verifying its empty" -Component "PatchWinRE"
        $MountFolderEmpty = Get-ChildItem $MountFolder 
        if ($MountFolderEmpty) {
            Write-Log "Mount directory isn't empty - exiting" -Component "PatchWinRE" -Type 3
            return $false
        }
    }
    Write-Log "Mounting WinRE" -Component "PatchWinRE"
    $Mount = ReAgentC.exe /mountre /path $MountFolder
    if ($Mount[0] -like "*Successful*" -and $(Get-WindowsImage -Mounted).count -ge 1) {
        Write-Log "WinRE mounted successful" -Component "PatchWinRE"
    }
    else {
        Write-Log "ReAgentC gave the following as the last exitcode: $LASTEXITCODE" -Component "PatchWinRE" -Type 3
        Write-Log "WinRE couldn't be mounted - please verify the logs" -Component "PatchWinRE" -Type 3
        return $false
    }
    #Dism /Add-Package /Image:C:\mount\ /PackagePath:$($SSU.FullName)
    if ($SSU) {
        Write-Log "Applying SSU to WinRE" -Component "PatchWinRE"
        Add-WindowsPackage -Path $MountFolder -PackagePath $($SSU.FullName) -LogPath $($LogDir + "Add-WindowsPackage_" + $DateTime + ".log") -LogLevel WarningsInfo 
    }
    Write-Log "Applying MSU file(s) to WinRE" -Component "PatchWinRE"
    foreach ($Patch in $Patches) {
        Add-WindowsPackage -Path $MountFolder -PackagePath $($Patch.FullName) -LogPath $($LogDir + "Add-WindowsPackage_" + $DateTime + ".log") -LogLevel WarningsInfo 
    }
    Write-Log "Done applying patches - attempting" -Component "PatchWinRE"
    dism /image:$MountFolder /cleanup-image /StartComponentCleanup /ResetBase /LogPath:$($LogDir+"Cleanup-WindowsImage_"+$DateTime+".log") /loglevel:3
    Write-Log "Cleanup done, attempting to commit patches" -Component "PatchWinRE"
    $UnmountCommit = ReAgentC.exe /unmountre /path $($MountFolder) /commit
    if (-not($UnmountCommit[0] -like "*Success*") -and $(Get-WindowsImage -Mounted).count -ge 1) {
        Write-Log "Commiting failed - discarding changes" -Component "PatchWinRE" -Type 3
        Write-Log "Status of the WinRE during this operation according to Get-WindowsImage was: $((Get-WindowsImage -Mounted).MountStatus)" -Component "PatchWinRE"
        $UnmountDiscard = ReAgentC.exe /unmountre /path $($MountFolder) /discard
        if (-not($UnmountDiscard[0] -like "*Successful*")) {
            Write-Log "Unmounting first attempt failed - trying alternative method" -Component "PatchWinRE"
            Dismount-WindowsImage -Path $MountFolder -Discard -LogPath $($WorkingDirectory + "Dismount-WindowsImage_" + $DateTime + ".log")
            if ($(Get-WindowsImage -Mounted).count -ge 1) {
                Write-Log "Unmounting finally failed, please consult the logs" -Component "PatchWinRE" -Type 3
                return $false
            }
            else {
                Write-Log "Alternative unmounting successful, please consult the logs for more information" -Component "PatchWinRE" -Type 3
                return $true
            }
        }
        else {
            Write-Log "Unmounting done, please consult the logs" -Component "PatchWinRE"
            return $false
        }

    }
    else {
        $NewWinREPath = (ReAgentc.exe /info | Select-String -SimpleMatch "\\?\GLOBALROOT\device").ToString().replace("Windows RE location:", "").Trim() + "\WinRE.wim"
        $NewWinREBuild = (Get-WindowsImage -ImagePath $NewWinREPath -Index 1).SPBuild
        Write-Log "Current Patchversion of mounted WinRE: $NewWinREBuild"
        Write-Log "Applying patches finished" -Component "PatchWinRE"
        return $true
    }
}

#Start Coding!
Write-Log "Patch-WinRE started at $(Get-Date)" -Component "WinREPatchCore"
Write-Log "Verify that the recovery partition has the appropiate size of $($RecoveryDriveSize/1GB) GB" -Component "WinREPatchCore"

if ($RecoveryDriveSize) {
    if (-not(Resize-RecoveryPartition -RecoveryDriveNewSize $RecoveryDriveSize)) {
        Write-Log "Something went wrong with the recovery partition - please check the log $LogFile " -Component "WinREPatchCore" -Type 3
        Exit 1
    }
}
else {
    Write-Log "No recovery drive size specified" -Component "WinREPatchCore" -Type 2
}

if ($Driver) {
    if ((Get-ItemProperty $Driver).Attributes -eq "Directory") {
        if (-not(Add-DriverToWinRE -Drivers $DriverFolder)) {
            Write-Log "Something went wrong while applying drivers, please consult the logs" -Component "WinREPatchCore" -Type 3
            Exit 1
        }
    }
    elseif ($Driver -like "*.inf") {
        if (-not(Add-DriverToWinRE -SingleDriver $DriverFolder)) {
            Write-Log "Something went wrong while applying the driver, please consult the logs" -Component "WinREPatchCore" -Type 3
            Exit 1
        }        
    }
    else {
        Write-Log "No directory or path isn't ending in *.inf" -Component "WinREPatchCore" -Type 3
        Exit 1
    }    
}
if ($PatchFolder) {
    if ((Get-ItemProperty $PatchFolder).Attributes -eq "Directory") {
        if (-not(Add-PatchToWinRE -MSUFiles $Patches)) {
            Write-Log "Something went wrong while applying patches, please consult the logs" -Component "WinREPatchCore" -Type 3
            Exit 1
        }
    }
    elseif ($Patches -like "*.msu") {
        if (-not(Add-PatchToWinRE -SingleFile $Patches)) {
            Write-Log "Something went wrong while applying patches, please consult the logs" -Component "WinREPatchCore" -Type 3
            Exit 1
        }
    }
    else {
        Write-Log "No directory or path isn't ending in *.msu" -Component "WinREPatchCore" -Type 3
        Exit 1
    }
}
else {
    Write-Log "No patchfolder specified" -Component "WinREPatchCore" -Type 2
}
if ($DeleteBackups) {
    if ($BackupFolder) {
        Write-Log "Deleting all backups of WinRE wims in $BackupFolder" -Component "DeleteBackups"
        Get-ChildItem $($BackupFolder + "*") -Include *.wim -Force | Foreach-Object { if ($_) { Remove-Item -Path $_.FullName -Force } }
    }
    else {
        Write-Log "Can't delete backups if no folder is specified" -Component "DeleteBackups" -Type 2
    }
}

Write-Log "Customization finished, creating statistics" -Component "WinREPatchCore"
Get-Stats
Write-Log "Original WinRE size before patching: $Script:BackupWinRESize
RecoveryPartitionSize: $Script:CurrentRecoveryPartitionSize GB
RecoveryPartitionFree: $Script:CurrentRecoveryPartitionFree GB
EstimatedWinRESize: $Script:EstimatedWinRESize GB
Script runtime: $Script:Runtime`n 
More information can be found at 
C:\Windows\Logs\ReAgent\ReAgent.log
C:\Windows\Logs\Dism\Dism.log" -Component "WinREPatchCore"
Write-Log "Nothing left to process" -Component "WinREPatchCore"
Write-Log "Thanks for using Patch-WinRE" -Component "WinREPatchCore"
Exit 0