<#
.SYNOPSIS
    Runs Patch-WinRE.ps1 against mocked system commands.
.DESCRIPTION
    Test support script. It builds a fake Windows folder (ReAgent.xml, WinRE.wim) below the scenario root, runs a copy
    of Patch-WinRE.ps1 without "#Requires -RunAsAdministrator" in which $env:SYSTEMROOT points to that fake folder and
    replaces every system command Patch-WinRE.ps1 uses (reagentc, dism, diskpart, Storage and DISM cmdlets) with global
    aliases to mock functions.
    State changing mocks print "MOCK-MUTATION: <command>" so tests can verify what would have been changed.
    Run this script in its own powershell.exe process, because the mocks are defined globally.
.PARAMETER ScriptPath
    Path to Patch-WinRE.ps1.
.PARAMETER ScenarioFile
    JSON file with the properties Root, WinREEnabled, RecoveryPartitionSize and Arguments.
    Arguments is an object of Patch-WinRE.ps1 parameter names and values. Use true for switches.
.EXAMPLE
    powershell.exe -NoProfile -File .\Invoke-PatchWinREMocked.ps1 -ScriptPath ..\..\Patch-WinRE.ps1 -ScenarioFile .\scenario.json
.NOTES
    Version: 1.0.0
    Author: Martin Himken
    Original script name: Invoke-PatchWinREMocked.ps1
    Initial creation date: 2026-11-19
    Last change: 2026-11-19
    Changes: 1.0.0 - Initial version
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,
    [Parameter(Mandatory = $true)]
    [string]$ScenarioFile
)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
public class PatchWinREMockMountedImage {
    public string MountStatus;
    public string Path;
}
'@
$Scenario = Get-Content -LiteralPath $ScenarioFile -Raw | ConvertFrom-Json
$Root = $Scenario.Root
$Global:PatchWinREMock = @{
    WinREEnabled          = [bool]$Scenario.WinREEnabled
    RecoveryPartitionSize = [long]$Scenario.RecoveryPartitionSize
    RecoveryAccessPath    = Join-Path -Path $Root -ChildPath 'RecoveryPartition\'
    DiskGuid              = '{8C2F4E91-1D3B-4A7E-9F00-5B6A2C7D8E91}'
    RecoveryOffset        = [long]214748364800
    Mounted               = $false
    BuildRevision         = 1000
    SystemDriveLetter     = $env:SystemDrive.Substring(0, 1)
}

# Fake Windows folder and recovery partition content
$FakeWindows = Join-Path -Path $Root -ChildPath 'Windows'
$FakeRecoveryFolder = Join-Path -Path $FakeWindows -ChildPath 'System32\Recovery'
$OnlineWinREFolder = Join-Path -Path $Global:PatchWinREMock.RecoveryAccessPath -ChildPath 'Recovery\WindowsRE'
New-Item -Path $FakeRecoveryFolder, $OnlineWinREFolder -ItemType Directory -Force | Out-Null
$ReAgentXML = @"
<?xml version='1.0' encoding='utf-8'?>
<WindowsRE version="2.0">
  <WinreBCD id="{4f6b2a10-0000-0000-0000-000000000000}"/>
  <WinreLocation path="\Recovery\WindowsRE" id="0" offset="$($Global:PatchWinREMock.RecoveryOffset)" guid="$($Global:PatchWinREMock.DiskGuid)"/>
  <ImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <PBRImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}" index="0"/>
  <InstallState state="1"/>
</WindowsRE>
"@
Set-Content -LiteralPath (Join-Path -Path $FakeRecoveryFolder -ChildPath 'ReAgent.xml') -Value $ReAgentXML -Encoding UTF8
if ($Global:PatchWinREMock.WinREEnabled) {
    Set-Content -LiteralPath (Join-Path -Path $OnlineWinREFolder -ChildPath 'WinRE.wim') -Value 'fake online WinRE image' -Encoding ASCII
} else {
    Set-Content -LiteralPath (Join-Path -Path $FakeRecoveryFolder -ChildPath 'WinRE.wim') -Value 'fake offline WinRE image' -Encoding ASCII
}
$env:PatchWinREFakeSystemRoot = $FakeWindows

# Copy of the script without the administrator requirement, using the fake Windows folder
$TestCopy = Join-Path -Path $Root -ChildPath 'Patch-WinRE.ps1'
$ScriptLines = Get-Content -LiteralPath $ScriptPath | Where-Object { $_ -notmatch '^#Requires -RunAsAdministrator' } | ForEach-Object { $_ -replace '\$env:SYSTEMROOT', '$env:PatchWinREFakeSystemRoot' }
Set-Content -LiteralPath $TestCopy -Value $ScriptLines -Encoding ASCII

function Global:Write-MockMutation {
    param([string]$Command)
    Write-Host "MOCK-MUTATION: $Command"
}
function Global:Invoke-MockReAgentC {
    $Joined = $args -join ' '
    $Global:LASTEXITCODE = 0
    if ($Joined -match '/info') {
        if ($Global:PatchWinREMock.WinREEnabled) {
            $Status = 'Enabled'
            $Location = '\\?\GLOBALROOT\device\harddisk0\partition4\Recovery\WindowsRE'
        } else {
            $Status = 'Disabled'
            $Location = ''
        }
        return @(
            'Windows Recovery Environment (Windows RE) and system reset configuration'
            'Information:'
            ''
            "    Windows RE status:         $Status"
            "    Windows RE location:       $Location"
            '    Boot Configuration Data (BCD) identifier: 4f6b2a10-0000-0000-0000-000000000000'
            '    Recovery image location:   '
            '    Recovery image index:      0'
            '    Custom image location:     '
            '    Custom image index:        0'
            ''
            'REAGENTC.EXE: Operation Successful.'
        )
    }
    Write-MockMutation "reagentc $Joined"
    if ($Joined -match '/disable') { $Global:PatchWinREMock.WinREEnabled = $false }
    if ($Joined -match '/enable') { $Global:PatchWinREMock.WinREEnabled = $true }
    if ($Joined -match '/mountre') { $Global:PatchWinREMock.Mounted = $true }
    if ($Joined -match '/unmountre') { $Global:PatchWinREMock.Mounted = $false }
    return 'REAGENTC.EXE: Operation Successful.'
}
function Global:Invoke-MockDism {
    Write-MockMutation "dism $($args -join ' ')"
    $Global:LASTEXITCODE = 0
}
function Global:Invoke-MockDiskpart {
    Write-MockMutation "diskpart $($args -join ' ')"
    $Global:LASTEXITCODE = 0
}
function Global:Get-MockPartitionList {
    $State = $Global:PatchWinREMock
    @(
        [pscustomobject]@{ DiskNumber = 0; PartitionNumber = 1; DriveLetter = [char]0; Size = 100MB; Offset = 1048576; GptType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'; AccessPaths = @() }
        [pscustomobject]@{ DiskNumber = 0; PartitionNumber = 2; DriveLetter = [char]0; Size = 16MB; Offset = 105906176; GptType = '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'; AccessPaths = @() }
        [pscustomobject]@{ DiskNumber = 0; PartitionNumber = 3; DriveLetter = [char]$State.SystemDriveLetter; Size = 200GB; Offset = 122683392; GptType = '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'; AccessPaths = @("$($State.SystemDriveLetter):\") }
        [pscustomobject]@{ DiskNumber = 0; PartitionNumber = 4; DriveLetter = [char]0; Size = $State.RecoveryPartitionSize; Offset = $State.RecoveryOffset; GptType = '{de94bba4-06d1-4d40-a16a-bfd50179d6ac}'; AccessPaths = @($State.RecoveryAccessPath) }
    )
}
function Global:Get-MockPartition {
    [CmdletBinding()]
    param(
        [string]$DriveLetter,
        [Nullable[int]]$DiskNumber,
        [Nullable[int]]$PartitionNumber,
        $Volume
    )
    $Partitions = Get-MockPartitionList
    if ($Volume) {
        return $Partitions | Where-Object { $_.PartitionNumber -eq 4 }
    }
    if ($DriveLetter) { $Partitions = $Partitions | Where-Object { "$($_.DriveLetter)" -eq $DriveLetter } }
    if ($PSBoundParameters.ContainsKey('DiskNumber')) { $Partitions = $Partitions | Where-Object { $_.DiskNumber -eq $DiskNumber } }
    if ($PSBoundParameters.ContainsKey('PartitionNumber')) { $Partitions = $Partitions | Where-Object { $_.PartitionNumber -eq $PartitionNumber } }
    $Partitions
}
function Global:Get-MockDisk {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline = $true)]$Partition)
    end { [pscustomobject]@{ DiskNumber = 0; PartitionStyle = 'GPT'; Guid = $Global:PatchWinREMock.DiskGuid } }
}
function Global:Get-MockVolume {
    [CmdletBinding()]
    param(
        [string]$DriveLetter,
        [Parameter(ValueFromPipeline = $true)]$Partition
    )
    process {
        $State = $Global:PatchWinREMock
        $SystemVolume = [pscustomobject]@{ DriveLetter = $State.SystemDriveLetter; Size = 200GB; SizeRemaining = 50GB; FileSystemLabel = 'Windows'; OperationalStatus = 'OK' }
        $RecoveryVolume = [pscustomobject]@{ DriveLetter = $null; Size = $State.RecoveryPartitionSize; SizeRemaining = 300MB; FileSystemLabel = 'Recovery'; OperationalStatus = 'OK' }
        if ($DriveLetter) {
            return $SystemVolume
        }
        if ($Partition) {
            foreach ($Item in $Partition) {
                if ($Item.PartitionNumber -eq 4) { $RecoveryVolume } else { $SystemVolume }
            }
            return
        }
        $SystemVolume
        $RecoveryVolume
    }
}
function Global:Get-MockPartitionSupportedSize {
    [pscustomobject]@{ SizeMin = 80GB; SizeMax = 200GB }
}
function Global:Get-MockWindowsImage {
    [CmdletBinding()]
    param(
        [switch]$Mounted,
        [string]$ImagePath,
        $Index,
        $LogPath,
        $LogLevel
    )
    if ($Mounted) {
        if ($Global:PatchWinREMock.Mounted) {
            $Image = New-Object -TypeName PatchWinREMockMountedImage
            $Image.MountStatus = 'Ok'
            $Image.Path = 'mock'
            return $Image
        }
        return
    }
    [pscustomobject]@{ ImagePath = $ImagePath; SPBuild = $Global:PatchWinREMock.BuildRevision }
}
function Global:Get-MockWindowsPackage {
    [pscustomobject]@{
        PackageName  = "Microsoft-Windows-Foundation-Package~31bf3856ad364e35~amd64~~10.0.26100.$($Global:PatchWinREMock.BuildRevision)"
        ReleaseType  = 'Foundation'
        PackageState = 'Installed'
    }
}
function Global:Add-MockWindowsPackage {
    [CmdletBinding()]
    param($PackagePath, $Path, $LogPath, $LogLevel)
    Write-MockMutation "Add-WindowsPackage $PackagePath"
    $Global:PatchWinREMock.BuildRevision++
}
function Global:Add-MockWindowsDriver {
    Write-MockMutation "Add-WindowsDriver $($args -join ' ')"
}
function Global:Dismount-MockWindowsImage {
    Write-MockMutation 'Dismount-WindowsImage'
    $Global:PatchWinREMock.Mounted = $false
}
function Global:Remove-MockPartition {
    Write-MockMutation "Remove-Partition $($args -join ' ')"
}
function Global:New-MockPartition {
    Write-MockMutation "New-Partition $($args -join ' ')"
}
function Global:Resize-MockPartition {
    Write-MockMutation "Resize-Partition $($args -join ' ')"
}

$MockAliases = @{
    'reagentc'                   = 'Invoke-MockReAgentC'
    'reagentc.exe'               = 'Invoke-MockReAgentC'
    'dism'                       = 'Invoke-MockDism'
    'diskpart'                   = 'Invoke-MockDiskpart'
    'Get-Partition'              = 'Get-MockPartition'
    'Get-Disk'                   = 'Get-MockDisk'
    'Get-Volume'                 = 'Get-MockVolume'
    'Get-PartitionSupportedSize' = 'Get-MockPartitionSupportedSize'
    'Get-WindowsImage'           = 'Get-MockWindowsImage'
    'Get-WindowsPackage'         = 'Get-MockWindowsPackage'
    'Add-WindowsPackage'         = 'Add-MockWindowsPackage'
    'Add-WindowsDriver'          = 'Add-MockWindowsDriver'
    'Dismount-WindowsImage'      = 'Dismount-MockWindowsImage'
    'Remove-Partition'           = 'Remove-MockPartition'
    'New-Partition'              = 'New-MockPartition'
    'Resize-Partition'           = 'Resize-MockPartition'
}
foreach ($Name in $MockAliases.Keys) {
    Set-Alias -Name $Name -Value $MockAliases[$Name] -Scope Global -Force
}

$ScriptArguments = @{}
foreach ($Property in $Scenario.Arguments.PSObject.Properties) {
    $ScriptArguments[$Property.Name] = $Property.Value
}
$ErrorActionPreference = 'Continue'
& $TestCopy @ScriptArguments
$ScriptExitCode = $LASTEXITCODE
Write-Host "MOCK-EXIT: $ScriptExitCode"
exit $ScriptExitCode
