# Changes

## January 2024

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
