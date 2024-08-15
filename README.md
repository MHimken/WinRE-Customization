# WinRE-Customization

Customizes WinRE - recent updates can be found in the changelog. This script applies patches and drivers. Will resize and create recovery partition if required.

This script was initially created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required.

Please read <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre> to learn which patches you should apply! GDR-DU and LCU should only be applied to fix major issues, they take about 8-10 minutes. SOS and DUs are extremly small and take seconds to apply (less than a minute).

## Applies to

As of 15.08.24 this script can be used to remidiate issues around the following KBs that require manual interaction:

- [August 2024: KB5042562](https://support.microsoft.com/en-us/topic/kb5042562-guidance-for-blocking-rollback-of-virtualization-based-security-vbs-related-security-updates-b2e7ebf4-f64d-4884-a390-38d63171b8d3)
- [TBD: KB5025885](https://support.microsoft.com/en-us/topic/kb5025885-how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_update_boot_media) - this is still in optional, but will be enforced in the future.
- [Fixing CVE-2022-41099](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41099) which requires adding a Safe OS (SOS) Update.


## Prerequisites

The script generally tries to detect states that it can not handle. Please consult the log (CMTrace compatible). If you encounter a scenario, that needs fixing please contact me or open an issue so I can investigate.

**Attention**
This can only be done in an automated fashion, if the disk:

- is formatted in UEFI using GPT partitions (this is verified) and
- if the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified.

A description of each parameter comes with the script.

## Adressing the script offered by Microsoft

Microsoft released their own script officially on <https://support.microsoft.com/en-us/topic/kb5025175-updating-the-winre-partition-on-deployed-devices-to-address-security-vulnerabilities-in-cve-2022-41099-ba6621fa-5a9f-48f1-9ca3-e13eb56fb589>.

In it the following information is given:
>If the BitLocker TPM protector is present, reconfigures WinRE for BitLocker service.
>**Important** This step is not present in most third-party scripts for applying updates to the WinRE image.

Which most likely refers to this snippet from their code (trimmed empty lines)

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

The order for this script is (because it made the most sense to me)

1. Backup WinRE - the script does this even if you specify to delete the backup later.
    - This **disables** the Recovery Agent so that the .wim file can be backed up elsewhere.
    - This also verifies that the Recovery Agent can be safely disabled and that the .wim is accessible.
2. Mount the WinRE using the new method that was provided here <https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre?view=windows-11#apply-the-update-to-a-running-pc>
3. Apply whatever you provided to the script (as of writing drivers or patches)
4. Dismount the image and try to commit the changes
5. Enable the Recovery Agent

All in all, the script does exactly the same thing. Although by accident, because it seems to re-sign the partition
or the .wim, so that Secure Boot/BitLocker can still trust the recovery partition. If you think about it, this makes sense because
otherwise an attacker could just replace the .wim in the unprotected partition.

So far, I haven't received any reports of Secure Boot or BitLocker itself acting up (unless the script never fully ran!).
If you used this script to apply your patches, you should be fine. The obvious caveat here is that I'm not an MS
employee and cannot vouch for the accuracy of the information provided by what I have just described. You still use this
script at your own risk!

## Noteworthy content

Relevant CVEs:
[CVE-2022-41099](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41099)
[CVE-2024-20666](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-20666)

Relevant patches:

- [Windows Server 2022 - KB5034439](https://support.microsoft.com/en-us/topic/kb5034439-windows-recovery-environment-update-for-windows-server-2022-january-9-2024-6f9d26e6-784c-4503-a3c6-0beedda443ca)
- [Windows 11 21H2 - KB5034440](https://support.microsoft.com/en-us/topic/kb5034440-windows-recovery-environment-update-for-windows-11-version-21h2-january-9-2024-1e07724a-3547-40f5-99ff-862cc48fd523)
- [Windows 10 - KB5034441](https://support.microsoft.com/en-us/topic/kb5034441-windows-recovery-environment-update-for-windows-10-version-21h2-and-22h2-january-9-2024-62c04204-aaa5-4fee-a02a-2fdea17075a8)

Thanks to everyone that helped build this, especially <https://homotechsual.dev/>
