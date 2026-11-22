<#
.SYNOPSIS
    Folder and file pickers for the Patch-WinRE GUI.
.DESCRIPTION
    Dot-sourced by Start-PatchWinREGUI.ps1. The folder picker uses the Windows file dialog (IFileOpenDialog) in folder mode,
    which supports typing a path and an initial folder. If the COM dialog is not available, System.Windows.Forms.FolderBrowserDialog is used.
    Files are selected with Microsoft.Win32.OpenFileDialog.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: PatchWinREGUI.FolderPicker.ps1
    Initial creation date: 2026-11-19
    Last change: 2026-11-19
    Changes: Initial version
#>

$PatchWinREFolderPickerSource = @'
using System;
using System.Runtime.InteropServices;

namespace PatchWinREGui
{
    [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7")]
    internal class FileOpenDialogComObject { }

    [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFileOpenDialog
    {
        [PreserveSig] int Show(IntPtr parent);
        void SetFileTypes(uint cFileTypes, IntPtr rgFilterSpec);
        void SetFileTypeIndex(uint iFileType);
        void GetFileTypeIndex(out uint piFileType);
        void Advise(IntPtr pfde, out uint pdwCookie);
        void Unadvise(uint dwCookie);
        void SetOptions(uint fos);
        void GetOptions(out uint pfos);
        void SetDefaultFolder(IShellItem psi);
        void SetFolder(IShellItem psi);
        void GetFolder(out IShellItem ppsi);
        void GetCurrentSelection(out IShellItem ppsi);
        void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
        void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
        void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
        void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
        void GetResult(out IShellItem ppsi);
        void AddPlace(IShellItem psi, int fdap);
        void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
        void Close(int hr);
        void SetClientGuid(ref Guid guid);
        void ClearClientData();
        void SetFilter(IntPtr pFilter);
        void GetResults(out IntPtr ppenum);
        void GetSelectedItems(out IntPtr ppsai);
    }

    [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IShellItem
    {
        void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
        void GetParent(out IShellItem ppsi);
        void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        void Compare(IShellItem psi, uint hint, out int piOrder);
    }

    public static class FolderPicker
    {
        private const uint FosPickFolders = 0x20;
        private const uint FosForceFileSystem = 0x40;
        private const uint FosPathMustExist = 0x800;
        private const uint SigdnFileSysPath = 0x80058000;
        private const int ErrorCancelled = unchecked((int)0x800704C7);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
        private static extern void SHCreateItemFromParsingName(string pszPath, IntPtr pbc, ref Guid riid, out IShellItem ppv);

        // Returns the selected folder, null if the dialog was cancelled. Throws if the dialog cannot be shown.
        public static string Show(IntPtr owner, string title, string initialFolder)
        {
            IFileOpenDialog dialog = (IFileOpenDialog)new FileOpenDialogComObject();
            try
            {
                uint options;
                dialog.GetOptions(out options);
                dialog.SetOptions(options | FosPickFolders | FosForceFileSystem | FosPathMustExist);
                if (!String.IsNullOrEmpty(title)) { dialog.SetTitle(title); }
                if (!String.IsNullOrEmpty(initialFolder) && System.IO.Directory.Exists(initialFolder))
                {
                    try
                    {
                        Guid shellItemGuid = typeof(IShellItem).GUID;
                        IShellItem folderItem;
                        SHCreateItemFromParsingName(initialFolder, IntPtr.Zero, ref shellItemGuid, out folderItem);
                        dialog.SetFolder(folderItem);
                    }
                    catch (COMException) { }
                }
                int hr = dialog.Show(owner);
                if (hr == ErrorCancelled) { return null; }
                if (hr != 0) { Marshal.ThrowExceptionForHR(hr); }
                IShellItem result;
                dialog.GetResult(out result);
                string path;
                result.GetDisplayName(SigdnFileSysPath, out path);
                return path;
            }
            finally
            {
                Marshal.ReleaseComObject(dialog);
            }
        }
    }
}
'@
if (-not ('PatchWinREGui.FolderPicker' -as [type])) {
    Add-Type -TypeDefinition $PatchWinREFolderPickerSource -Language CSharp
}

function Get-PatchWinREExistingFolder {
    # Returns the path or its nearest existing parent folder, or '' if none exists.
    param(
        [AllowEmptyString()]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $Candidate = $Path.Trim()
    try {
        while ($Candidate) {
            if ([System.IO.Directory]::Exists($Candidate)) { return $Candidate }
            $Parent = [System.IO.Path]::GetDirectoryName($Candidate.TrimEnd('\'))
            if (-not $Parent -or $Parent -eq $Candidate) { break }
            $Candidate = $Parent
        }
    } catch {
        return ''
    }
    return ''
}

function Get-PatchWinREWindowHandle {
    param(
        [object]$Window
    )
    if ($null -eq $Window) { return [IntPtr]::Zero }
    return (New-Object System.Windows.Interop.WindowInteropHelper -ArgumentList $Window).Handle
}

function Select-PatchWinREFolder {
    <#
    .SYNOPSIS
        Shows a folder picker and returns the selected folder with a trailing backslash, or $null if cancelled.
    #>
    param(
        [object]$Window,
        [string]$Title = 'Select a folder',
        [AllowEmptyString()]
        [string]$InitialFolder = ''
    )
    $StartFolder = Get-PatchWinREExistingFolder -Path $InitialFolder
    $Selected = $null
    try {
        $Selected = [PatchWinREGui.FolderPicker]::Show((Get-PatchWinREWindowHandle -Window $Window), $Title, $StartFolder)
    } catch {
        Write-Log -Message ('Windows folder dialog failed, using the classic dialog: {0}' -f $_.Exception.Message) -Component 'FolderPicker' -Type 2
        $Dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        try {
            $Dialog.Description = $Title
            $Dialog.ShowNewFolderButton = $true
            if ($StartFolder) { $Dialog.SelectedPath = $StartFolder }
            if ($Dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $Selected = $Dialog.SelectedPath }
        } finally {
            $Dialog.Dispose()
        }
    }
    if ([string]::IsNullOrWhiteSpace($Selected)) { return $null }
    if (-not $Selected.EndsWith('\')) { $Selected += '\' }
    return $Selected
}

function Select-PatchWinREFile {
    <#
    .SYNOPSIS
        Shows a file picker and returns the selected file, or $null if cancelled.
    .PARAMETER Filter
        Filter in the format "Description|*.ext;*.ext2".
    #>
    param(
        [object]$Window,
        [string]$Title = 'Select a file',
        [string]$Filter = 'All files|*.*',
        [AllowEmptyString()]
        [string]$InitialPath = ''
    )
    $Dialog = New-Object Microsoft.Win32.OpenFileDialog
    $Dialog.Title = $Title
    $Dialog.Filter = $Filter
    $Dialog.CheckFileExists = $true
    $Dialog.Multiselect = $false
    if (-not [string]::IsNullOrWhiteSpace($InitialPath)) {
        $Value = $InitialPath.Trim()
        if ([System.IO.File]::Exists($Value)) {
            $Dialog.InitialDirectory = [System.IO.Path]::GetDirectoryName($Value)
            $Dialog.FileName = [System.IO.Path]::GetFileName($Value)
        } else {
            $Folder = Get-PatchWinREExistingFolder -Path $Value
            if ($Folder) { $Dialog.InitialDirectory = $Folder }
        }
    }
    if ($Dialog.ShowDialog($Window) -eq $true) { return $Dialog.FileName }
    return $null
}
