<#
.SYNOPSIS
Patches WinRE on the current system given a suitable MSU file to apply.
.DESCRIPTION
This script was created to automate CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 
#####ATTENTION#####
This can only be done in an autmated fashion, if the disk:
a) the disk is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk)
b) the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified
.PARAMETER PatchFile
Accepts the path to the msu to be used while patching. Please make sure you provide this script with the matching OS-Version file. 
.INPUTS
Path as string to use to patch WinRE. If none is given it will look for the most recent .msu in the same folder as the script. 
.OUTPUTS
None, this script doesn't output anything.
.EXAMPLE
Patch-WinRE.ps1 "C:\Temp\windows11.0-kb5022303-x64_87d49704f3f7312cddfe27e45ba493048fdd1517.msu"
.EXAMPLE
Patch-WinRE.ps1 -PatchFile "C:\Temp\windows11.0-kb5022303-x64_87d49704f3f7312cddfe27e45ba493048fdd1517.msu"
.NOTES
Version: 1.0
Intial creation date: 11.01.2023
Last change date: 12.01.2023
.LINK
#>
$PathToScript = if ( $PSScriptRoot ) { 
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
#Setting some variables - you can change these
$LogDir = $PathToScript
$LogPrefix = "Patch"
$LogFile = $LogDir + $LogPrefix + "_" + $PackageName + ".log"

#Functions
function Log {
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

# Variable specifying the drive you want to extend
#Get current WinRE .wim location
$WinreLocation = reagentc /info
$RecoveryPartitionLocation = ($WinreLocation.split("`n")[4].Substring(31, $WinreLocation.split("`n")[4].Length - 31))
$WinREWim = $RecoveryPartitionLocation + "\WinRE.wim" #I _hate_ string manipulation...
function Resize-RecoveryPartition {
    $DriveToShrink = ($env:SystemDrive).Substring(0, 1)
    Log "Currently recommended minimum is 1GB for WinRE - this depends on the level is customization. If anything fails, please adjust the script" -Component "RecoveryPartition"
    $RecoveryDriveNewSize = 1GB

    $Partitions = Get-Partition
    Log "Finding the 'Recovery' partition. If this is named differently than this default value, you need to adjust the script." -Component "RecoveryPartition"
    foreach ($Partition in $Partitions) {
        if ($Partition.Type -eq "Recovery") {
            $RecoveryPartition = $Partition
            break
        }
    }
    if ($RecoveryPartition.Size -ge $RecoveryDriveNewSize) {
        Log "The recovery partition is already of adequate size" -Component "RecoveryPartition"
        return $true
    }
    else {
        Log "Verify that the $DriveToShrink has adequate size left to shrink" -Component "RecoveryPartition"
        $WindowsPartitionCurrentSize = Get-Volume -DriveLetter $DriveToShrink
        if ($WindowsPartitionCurrentSize.SizeRemaining -ge $RecoveryDriveNewSize) {
            $WindowsPartitionSize = Get-PartitionSupportedSize -DriveLetter $DriveToShrink
            # Shrink source disk size
            $ShrinkSizeCheck = ($WindowsPartitionSize.SizeMax - $WindowsPartitionSize.SizeMin) -ge ($RecoveryDriveNewSize - $RecoveryPartition.Size)
            if ($ShrinkSizeCheck) {
                #Putting it all together
                #Disable ReagentC first, this will put the .wim back into the default folder
                Log "Disabling ReagentC" -Component "RecoveryPartition"
                ReAgentc.exe /disable
                $WinREImageExists = Get-Item "C:\Windows\System32\Recovery\Winre.wim" -Force
                if ($WinREImageExists) {
                    $DisableReAgentC = (Get-Volume -Partition $RecoveryPartition).SizeRemaining
                    if ($DisableReAgentC -le 100MB) {
                        Log "Disabling ReAgentC failed" -Component "RecoveryPartition" -Type 3
                        return $false
                    }
                    Log "Shrinking C: and re-creating recovery partition" -Component "RecoveryPartition"
                    Remove-Partition $RecoveryPartition.DiskNumber $RecoveryPartition.PartitionNumber -Confirm:$false
                    $NewSystemDriveSize = $WindowsPartitionSize.SizeMax - $RecoveryDriveNewSize + $RecoveryPartition.Size
                    Resize-Partition -DriveLetter $DriveToShrink -Size $NewSystemDriveSize
                    $Diskpart = @"
select disk $((Get-Partition -DriveLetter $DriveToShrink).DiskNumber)
create partition primary`
format quick fs=ntfs label='Recovery'`
gpt attributes=0x8000000000000001
"@
                    Get-Item .\diskpart.txt | Remove-Item -Force
                    Add-Content .\diskpart.txt -Value $Diskpart
                    diskpart /s .\diskpart.txt
                    Get-Item .\diskpart.txt | Remove-Item -Force
                    Log "Created Recovery Partition"
                    if ($NewRecoveryPartition) {
                        Log "Recovery Partition recreated. Enabling ReagentC" -Component "RecoveryPartition"
                        ReAgentc.exe /enable
                        Log "Enabled, hide the partition"
                        Set-Partition -DiskNumber $RecoveryPartition.DiskNumber -PartitionNumber $RecoveryPartition.PartitionNumber -GptType "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}"
                        return $true
                    }
                    else {
                        $LogMessage = "The system drive couldn't be shrinked to the requested size of $($RecoveryDriveNewSize/1024/1024/1024) GB - Please consult the application event log"
                        Log -Message "$LogMessage `n  $((Get-Eventlog -LogName Application -Newest 1 -Source Microsoft-Windows-Defrag -EntryType Information).Message)" -Component "RecoveryPartition" -Type 3
                        Log -Message "The re-sizing couldn't be performed. If the first blocking file " -Component "RecoveryPartition" -Type 2
                        return $false
                    }
                }
                else {
                    ReAgentc.exe /enable
                    Log -Message "The WinRE.wim seems to be missing. Please make sure C:\Windows\System32\Recovery\Winre.wim exists and is accessible. You can get this file from a matching Windows 10 install.wim" -Component "RecoveryPartition" -Type 3
                    Log -Message "No changes performed to partition" -Component "RecoveryPartition"
                    return $false
                }
            }
        }
        else {
            Log "Free space left is $($WindowsPartitionCurrentSize.SizeRemaining), please make some room first" -Component "RecoveryPartition" -Type 3
            return $false
        }
    }
}

