# WinRE-Customization
Customizes WinRE. This script applies patches and drivers. Will resize recovery partition if required.

This script was created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 

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