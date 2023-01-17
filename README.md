# WinRE-Customization
Customizes WinRE. This script applies patches and drivers. Will resize recovery partition if required.

This script was created to automate remediation of CVE-2022-41099, however it can be used to patch WinRE monthly and automated as well. The script will verify the size of your recovery partition and resize it if required. 

**Attention**
This can only be done in an automated fashion, if the disk:
* is formatted as recommended for UEFI (with the recovery partition being at the very end of the disk) and
* if the sysdrive has enough space and no blocking files to shrink it to the required size - this is verified.

A description of each parameter comes with the script. 

Thanks to everyone that helped build this, especially https://homotechsual.dev/
