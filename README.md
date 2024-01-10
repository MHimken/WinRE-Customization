# WinRE-Customization

Customizes WinRE - recent updates can be found in the changelog. This script applies patches and drivers. Will resize recovery partition if required.

This script was initially created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required.

Please read <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre> to learn which patches you should apply! GDR-DU and LCU should only be applied to fix major issues, they take about 8-10 minutes. SOS and DUs are extremly small and take seconds to apply (less than a minute).

## Wrongly named patch released

Please be aware of this special update that was released **for Windows 11** <https://support.microsoft.com/en-us/topic/kb5022370-setup-dynamic-update-for-windows-11-version-21h2-january-19-2023-e8b86249-d1c6-4cee-8969-1cadb07a45e3>

The file offered is named "windows10.0-kb5022370-x64_216ed6897b0f0194f9d48d2142b9f806b69e07f8.cab", but should be named windows1_**1**_.0

## Prerequisites

**Attention**
This can only be done in an automated fashion, if the disk:

* is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk) and
* if the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified.

A description of each parameter comes with the script.

## Adressing the recent script offered by Microsoft

Microsoft release their own script officially on <https://support.microsoft.com/en-us/topic/kb5025175-updating-the-winre-partition-on-deployed-devices-to-address-security-vulnerabilities-in-cve-2022-41099-ba6621fa-5a9f-48f1-9ca3-e13eb56fb589>.

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

1. Backup WinRE - the script does this even if you specify to delete the backup later.
    * This **disables** the Recovery Agent so that the .wim file can be backed up elsewhere.
    * This also verifies that the Recovery Agent can be safely disabled and that the .wim is accessible.
2. Mount the WinRE using the new method that was provided here <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre?view=windows-11#apply-the-update-to-a-running-pc>
3. Apply whatever you provided to the script (as of writing drivers or patches)
4. Dismount the image and try to commit the changes
5. Enable the Recovery Agent

All in all, the script does exactly the same thing. Although by accident, because apparently this re-signs the partition
or the .wim so that Secure Boot/BitLocker can still trust the recovery partition. If you think about it, this makes sense, because
otherwise an attacker could just replace the .wim in the unprotected partition.

So far, I haven't received any reports of Secure Boot or BitLocker itself acting up (unless the script never fully ran!).
If you used this script to apply your patches, you should be fine. The obvious caveat here is that I'm not an MS
employee and cannot vouch for the accuracy of the information provided by what I have just described. You still use this
script at your own risk!

## Latest changes

28.07.2023:

* Added new switch OnlyCreateWinREDrive which allows for the creation of a non-existing WinRE drive. However, right now you still
need to have the WinRE.wim in place. The default location is %systemroot%\System32\Recovery\ - unhide system files in explorer.
* Resize-Recoverypartition now checks for GPT. MBR with legacy BIOS is **not supported**
* This is the last time minor changes will be added here to the README, unless they're major changes. Check <https://github.com/MHimken/WinRE-Customization/blob/main/changelog.md> for more changes.

17.07.2023:

* This script can also help with CVE-2023-24932 (<https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24932>)
which requires to apply a SafeOS (SOS) Patch to WinRE. You can find these by using this link to the catalog
<https://www.catalog.update.microsoft.com/Search.aspx?q=2023-07+safe+os>. However, in my research I couldn't manage to ever break
anything with resetting any machine - it still kept working. You're welcome to report feedback if you find any issues

### Older Updates

* MUI support added (Major change)
  * Removed all text based verifications and replaced them
* Now accepts GDRDU, LCU, SOS and DU as patch inputs (Major change)
  * Merged several functions that did almost the same - added detection methods accordingly
  * Renamed several parameters to reflect function merges
* Verbose removed for now, needs to be switch to cmdletbind
* Added "AbortIfFailed"

Thanks to everyone that helped build this, especially <https://homotechsual.dev/>
