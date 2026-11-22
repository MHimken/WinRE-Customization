<#
.SYNOPSIS
    Child process runner for the Patch-WinRE GUI.
.DESCRIPTION
    Dot-sourced by Start-PatchWinREGUI.ps1 and by the Pester tests. Contains no WPF code.
    - ProcessRunner (C#): starts powershell.exe with redirected output. Lines are queued by background threads and drained
      by the GUI timer, so the window never waits for the process.
    - Every run gets its own folder below %TEMP% with an ACL that only allows Administrators and SYSTEM (or the current user
      when the GUI is not elevated). The temporary script is written there and the folder is deleted after the run.
    - Cancel stops the whole process tree with taskkill.exe /T /F, because Process.Kill in .NET Framework stops only one process.
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: PatchWinREGUI.Runner.ps1
    Initial creation date: 2026-11-19
    Last change: 2026-11-19
    Changes: Initial version
#>

$PatchWinREProcessRunnerSource = @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace PatchWinREGui
{
    public sealed class ProcessRunner : IDisposable
    {
        private readonly Process _process;
        private readonly ConcurrentQueue<string> _lines = new ConcurrentQueue<string>();
        private bool _exitHandled;

        public ProcessRunner(string fileName, string arguments, string workingDirectory)
        {
            _process = new Process();
            _process.StartInfo.FileName = fileName;
            _process.StartInfo.Arguments = arguments;
            _process.StartInfo.WorkingDirectory = workingDirectory;
            _process.StartInfo.UseShellExecute = false;
            _process.StartInfo.CreateNoWindow = true;
            _process.StartInfo.RedirectStandardInput = true;
            _process.StartInfo.RedirectStandardOutput = true;
            _process.StartInfo.RedirectStandardError = true;
            _process.StartInfo.StandardOutputEncoding = new UTF8Encoding(false);
            _process.StartInfo.StandardErrorEncoding = new UTF8Encoding(false);
            _process.OutputDataReceived += (s, e) => { if (e.Data != null) { _lines.Enqueue("O" + e.Data); } };
            _process.ErrorDataReceived += (s, e) => { if (e.Data != null) { _lines.Enqueue("E" + e.Data); } };
        }

        public int Id { get { return _process.Id; } }

        public void Start()
        {
            _process.Start();
            _process.StandardInput.Close();
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
        }

        // True once the process has exited and both output streams are read to the end.
        public bool IsFinished
        {
            get
            {
                if (!_process.HasExited) { return false; }
                if (!_exitHandled) { _process.WaitForExit(); _exitHandled = true; }
                return true;
            }
        }

        public int ExitCode { get { return _process.ExitCode; } }

        // Returns the queued lines. Each line starts with O (standard output) or E (standard error).
        public string[] Drain()
        {
            List<string> result = new List<string>();
            string line;
            while (_lines.TryDequeue(out line)) { result.Add(line); }
            return result.ToArray();
        }

        public void Dispose() { _process.Dispose(); }
    }
}
'@
if (-not ('PatchWinREGui.ProcessRunner' -as [type])) {
    Add-Type -TypeDefinition $PatchWinREProcessRunnerSource -Language CSharp
}

function Test-PatchWinREElevated {
    $Principal = New-Object System.Security.Principal.WindowsPrincipal -ArgumentList ([System.Security.Principal.WindowsIdentity]::GetCurrent())
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PatchWinREPowerShellPath {
    # Windows PowerShell 5.1, independent of the PATH.
    Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
}

function New-PatchWinRERunDirectory {
    <#
    .SYNOPSIS
        Creates a new folder below %TEMP% that only Administrators and SYSTEM can access (current user and SYSTEM if not elevated).
    .DESCRIPTION
        The folder is created with its ACL in one call, inheritance is disabled. The ACL is verified afterwards.
    #>
    param(
        [string]$Prefix = 'PatchWinREGUI',
        [string]$BasePath = [System.IO.Path]::GetTempPath()
    )
    $Path = Join-Path -Path $BasePath -ChildPath ('{0}_{1}' -f $Prefix, [guid]::NewGuid().ToString('N'))
    if ([System.IO.Directory]::Exists($Path) -or [System.IO.File]::Exists($Path)) {
        throw "The temporary folder $Path already exists."
    }
    $SystemSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-18'
    if (Test-PatchWinREElevated) {
        $OwnerSid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    } else {
        $OwnerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    }
    $Security = New-Object System.Security.AccessControl.DirectorySecurity
    $Security.SetAccessRuleProtection($true, $false)
    $Inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $Propagation = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($Sid in @($OwnerSid, $SystemSid)) {
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Sid, ([System.Security.AccessControl.FileSystemRights]::FullControl), $Inheritance, $Propagation, ([System.Security.AccessControl.AccessControlType]::Allow)
        $Security.AddAccessRule($Rule)
    }
    $Directory = [System.IO.Directory]::CreateDirectory($Path, $Security)
    $Applied = $Directory.GetAccessControl()
    $Allowed = @($OwnerSid.Value, $SystemSid.Value)
    $Unexpected = @($Applied.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $Allowed -notcontains $_.IdentityReference.Value })
    if (-not $Applied.AreAccessRulesProtected -or $Unexpected.Count -gt 0) {
        Remove-PatchWinRERunDirectory -Path $Path
        throw "The temporary folder $Path did not receive the expected permissions."
    }
    return $Path
}

function Remove-PatchWinRERunDirectory {
    param(
        [AllowEmptyString()]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Directory]::Exists($Path)) { return $true }
    for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
        try {
            [System.IO.Directory]::Delete($Path, $true)
            return $true
        } catch {
            Start-Sleep -Milliseconds 200
        }
    }
    return $false
}

function Start-PatchWinREChildScript {
    <#
    .SYNOPSIS
        Writes a script into a new protected run folder and starts it in a hidden powershell.exe with redirected output.
    .OUTPUTS
        Run object with Runner, Id, Directory, ScriptFile, Started, Kind, Preview, Cancelled, Entries, LastEntry and Output.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content,
        [ValidateSet('Run', 'Check')]
        [string]$Kind = 'Run',
        [string]$FileName = 'Invoke-PatchWinRE.ps1',
        [string]$WorkingDirectory = $env:SystemRoot,
        [switch]$Preview
    )
    $Directory = New-PatchWinRERunDirectory
    try {
        $ScriptFile = Join-Path -Path $Directory -ChildPath $FileName
        [System.IO.File]::WriteAllText($ScriptFile, $Content, (New-Object System.Text.UTF8Encoding -ArgumentList $true))
        $Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $ScriptFile
        $Runner = New-Object PatchWinREGui.ProcessRunner -ArgumentList (Get-PatchWinREPowerShellPath), $Arguments, $WorkingDirectory
        $Runner.Start()
    } catch {
        [void](Remove-PatchWinRERunDirectory -Path $Directory)
        throw
    }
    [PSCustomObject]@{
        Runner     = $Runner
        Id         = $Runner.Id
        Directory  = $Directory
        ScriptFile = $ScriptFile
        Started    = Get-Date
        Kind       = $Kind
        Preview    = [bool]$Preview
        Cancelled  = $false
        Entries    = New-Object System.Collections.Generic.List[object]
        Output     = New-Object System.Collections.Generic.List[string]
        LastEntry  = $null
    }
}

function Stop-PatchWinREProcessTree {
    # Stops the process and all its child processes (DISM, reagentc, diskpart). Returns the taskkill output.
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )
    $TaskKill = Join-Path -Path $env:SystemRoot -ChildPath 'System32\taskkill.exe'
    try { [void](Get-Process -Id $ProcessId -ErrorAction Stop) }
    catch { return 'The child process had already exited.' }
    $Output = & $TaskKill /PID $ProcessId /T /F 2>&1 | ForEach-Object { "$_" }
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        $StillRunning = $false
        try {
            [void](Get-Process -Id $ProcessId -ErrorAction Stop)
            $StillRunning = $true
        } catch { $StillRunning = $false }
        if ($StillRunning) { throw ('taskkill.exe failed with exit code {0}: {1}' -f $ExitCode, (@($Output) -join ' ').Trim()) }
    }
    return (@($Output) -join ' ').Trim()
}

function Save-PatchWinREOutput {
    <#
    .SYNOPSIS
        Saves the displayed output with a short header as UTF-8 text.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [AllowEmptyCollection()]
        [string[]]$Header = @(),
        [AllowEmptyCollection()]
        [object[]]$Entry = @()
    )
    $Lines = New-Object System.Collections.Generic.List[string]
    foreach ($Line in $Header) { $Lines.Add($Line) }
    if ($Header.Count -gt 0) { $Lines.Add('') }
    foreach ($Item in $Entry) { $Lines.Add([string]$Item.Display) }
    [System.IO.File]::WriteAllLines($Path, $Lines.ToArray(), (New-Object System.Text.UTF8Encoding -ArgumentList $true))
}
