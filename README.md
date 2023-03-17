# WinRE-Customization
Customizes WinRE. This script applies patches and drivers. Will resize recovery partition if required.

This script was created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 

Please read https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre to learn which patches you should apply! GDR-DU and LCU should only be applied to fix major issues, they take about 8-10 minutes. SOS and DUs are extremly small and take seconds to apply (less than a minute).

## Wrongly named patch released!
Please be aware of this special update that was released **for Windows 11** https://support.microsoft.com/en-us/topic/kb5022370-setup-dynamic-update-for-windows-11-version-21h2-january-19-2023-e8b86249-d1c6-4cee-8969-1cadb07a45e3

The file offered is named "windows10.0-kb5022370-x64_216ed6897b0f0194f9d48d2142b9f806b69e07f8.cab", but should be named windows1_**1**_.0

## Prerequisites
**Attention**
This can only be done in an automated fashion, if the disk:
* is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk) and
* if the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified.

A description of each parameter comes with the script. 

## Adressing the recent script offered by Microsoft
Microsoft release their own script officially on https://support.microsoft.com/en-us/topic/kb5025175-updating-the-winre-partition-on-deployed-devices-to-address-security-vulnerabilities-in-cve-2022-41099-ba6621fa-5a9f-48f1-9ca3-e13eb56fb589.

In it the following information is given:
>If the BitLocker TPM protector is present, reconfigures WinRE for BitLocker service.
>**Important** This step is not present in most third-party scripts for applying updates to the WinRE image.

Which most likely refers to this snippet from their code
```ps
                if (IsTPMBasedProtector)
                {

                    # Disable WinRE and re-enable it to let new WinRE be trusted by BitLocker

                    LogMessage("Disable WinRE")

                    reagentc /disable

                    LogMessage("Re-enable WinRE")

                    reagentc /enable

                    reagentc /info

                }
```
This script does that, although it may not be obvious. The order for this script is (because it made the most sense to me)
1. Backup WinRE - the script does this, even if you specify to delete said backup later
    * This **disables** the Recovery Agent so the .wim file can be backed up somewhere else.
    * This also verifies that the Recovery Agent can be safely disabled and that the .wim is accessible.
2. Mount the WinRE using the new method that was provided here https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre?view=windows-11#apply-the-update-to-a-running-pc
3. Apply whatever you provided to the script (as of writing drivers or patches)
4. Dismount the image trying to commit the changes
5. Enable the recovery agent

All in all the script does the exact same steps. Although by accident, because apparently this re-signs the partition 
or the .wim to allow secure boot/BitLocker to trust the recovery partition still. If you think about it that makes 
sense, because otherwise an attacker could just replace the .wim in the unprotected partition. 

So far I didn't get issue reports about secure boot or BitLocker itself acting up (unless the script never fully ran!). 
If you used this script to apply your patches, you should be good. Here's the obvious remindder though, that I'm not an MS
employee and cannot vouche for the accuracy of the provided information of what I just described. You're still using this
script at your own risk!

# Latest changes

- MUI support added (Major change)
    * Removed all text based verifications and replaced them 
- Now accepts GDRDU, LCU, SOS and DU as patch inputs (Major change)
    * Merged several functions that did almost the same - added detection methods accordingly
    * Renamed several parameters to reflect function merges
- Verbose removed for now, needs to be switch to cmdletbind
- Added "AbortIfFailed"

Thanks to everyone that helped build this, especially https://homotechsual.dev/