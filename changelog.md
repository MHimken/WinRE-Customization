# Changes

## 27th of January 2024 - Version 3.1

Thanks to Christopher Moore <https://github.com/dreary-ennui> input the detection for the WinRE is now more dynamic.

- Add: New function Get-WinREImageLocation
- Change: Adjusted occurences that use the WinRE image location like Backup-WinRE and Confirm-WinREPrerequisites
- Change: Updated logic for Confirm-WinREPrerequisites. Several new error scenarios added, that the script can not handle

## 23th of January 2024 - Version 3.0

New major Version 3.0 aka 'REcovered Mystery'.

- Add: New Switch ReportOnly
- Add: New Switch ToConsole
- Add: New function Update-RecoveryPartitionInformation
- Change: Format-WinREPartition has been adjusted to work with recovery partitions that can't be expanded.
- Change: Confirm-WinREPrerequisites has been overhauled to reflect new scenarios
- Change: Adjusted in script documentation to reflect new functions
- Change: Adjusted Write-Log function to output to console
- Change: Expanded Get-Stats function for the 'ReportOnly' switch
- Known-Issue: Recovery drive on OS-disk isn't handled currently. Contact me if you require this.
- Known-Issue: Multiple partition on the same disk as the OS partition isn't handled currently. Contact me if you require this.

## 13th of January 2024

- This script can help to extend a recovery partition which might be required for CVE-2024-20666 (see KB5034440, KB5034441 or KB5034439)

## October 2023

- Change: WinRE needs to be ENABLED as of recent(?) to be able to mount the WinRE. This has been implemented now
- Fix: Added multiple new log messages
- Fix: A log message was missing a component
- Note: I took good care to make sure that the recovery agent is disabled and enabled as required via MS docs to make certain (see <https://github.com/MHimken/WinRE-Customization#adressing-the-recent-script-offered-by-microsoft>)
    that its recognized as valid by BitLocker. The Safe-OS update from October windows11.0-kb5031476-x64_d93ef6c86b4010a7f00c8a56037af0cc16190f48.cab
    can now be applied successfully to Windows 11 22H2.
- Fix: Fixed missing Exit 1 for failing to enable WinRE

## July 2023

- Change: Renamed Resize-RecoveryPartition to Format-WinRERecoveryPartition
- Change: Get-WinREStatus will now return $true, $false or $null instead of just $true or $false
- Add: Several functions like Format-WinRERecoveryPartition and Get-WinREStatus have been adjusted for -CreateWinREDrive
- Add: Prerequisite check added with Confirm-WinREPrerequisites
