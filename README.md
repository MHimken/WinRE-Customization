# WinRE-Customization
Customizes WinRE. This script applies patches and drivers. Will resize recovery partition if required.

This script was created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 

Please read https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/add-update-to-winre to learn which patches you should apply! GDR-DU and LCU should only be applied to fix major issues, they take about 8-10 minutes. SOS and DUs are extremly small and take seconds to apply (less than a minute).

#Wrongly named patch released!
Please be aware of this special update that was released **For Windows 11** https://support.microsoft.com/en-us/topic/kb5022370-setup-dynamic-update-for-windows-11-version-21h2-january-19-2023-e8b86249-d1c6-4cee-8969-1cadb07a45e3

The file coming is named "windows10.0-kb5022370-x64_216ed6897b0f0194f9d48d2142b9f806b69e07f8.cab", but should be named windows1**1**.0

**Attention**
This can only be done in an automated fashion, if the disk:
* is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk) and
* if the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified.

A description of each parameter comes with the script. 

Thanks to everyone that helped build this, especially https://homotechsual.dev/

Latest changes
- MUI support added (Major change)
    * Removed all text based verifications and replaced them 
- Now accepts GDRDU, LCU, SOS and DU as patch inputs (Major change)
    * Merged several functions that did almost the same - added detection methods accordingly
    * Renamed several parameters to reflect function merges
- Verbose removed for now, needs to be switch to cmdletbind
- Added "AbortIfFailed"