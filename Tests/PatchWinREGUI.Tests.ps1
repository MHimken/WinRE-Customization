#Requires -Version 5.1
<#
.SYNOPSIS
    Tests the Patch-WinRE GUI rules, output parser and read-only system-check evaluator.
.DESCRIPTION
    These tests do not open dialogs or change recovery configuration.
#>
BeforeAll {
    $Script:GuiRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $Script:GuiRoot -ChildPath 'GUI\PatchWinREGUI.Core.ps1')
    . (Join-Path -Path $Script:GuiRoot -ChildPath 'GUI\PatchWinREGUI.Validation.ps1')
    . (Join-Path -Path $Script:GuiRoot -ChildPath 'GUI\PatchWinREGUI.SystemCheck.ps1')
    . (Join-Path -Path $Script:GuiRoot -ChildPath 'GUI\PatchWinREGUI.Runner.ps1')

    $Script:PatchAstTokens = $null
    $Script:PatchAstErrors = $null
    $Script:PatchAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path -Path $Script:GuiRoot -ChildPath 'Patch-WinRE.ps1'),
        [ref]$Script:PatchAstTokens,
        [ref]$Script:PatchAstErrors
    )
    $BindingAttribute = @($Script:PatchAst.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' } | ForEach-Object { $_.Extent.Text }) -join "`r`n"
    $BinderSource = "function Test-PatchWinREParameterBinding {`r`n$BindingAttribute`r`n$($Script:PatchAst.ParamBlock.Extent.Text)`r`n`$PSCmdlet.ParameterSetName`r`n}`r`nExport-ModuleMember -Function Test-PatchWinREParameterBinding"
    $Script:BinderModule = New-Module -Name ('PatchWinREParameterProbe_{0}' -f [guid]::NewGuid().ToString('N')) -ScriptBlock ([scriptblock]::Create($BinderSource))
    Import-Module $Script:BinderModule -Force

    function New-SystemCheckFixture {
        param(
            [string]$PartitionStyle = 'GPT',
            [string]$Status = 'Enabled',
            [object]$SelectedRecovery = $null,
            [object[]]$RecoveryPartitions = @(),
            [object[]]$Partitions = @(),
            [bool]$ImageExists = $true,
            [object[]]$MountedImages = @(),
            [string[]]$Errors = @()
        )
        [PSCustomObject]@{
            ReagentStatusToken = $Status
            ScriptRecoveryDiskNumber = '0'
            ScriptRecoveryPartitionNumber = '4'
            ActualRecoveryDiskNumber = 0
            ActualRecoveryPartitionNumber = 4
            OSDisk = [PSCustomObject]@{ Number = 0; PartitionStyle = $PartitionStyle }
            OSPartition = [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 3; Size = [uint64](100GB) }
            OSVolume = [PSCustomObject]@{ Size = [uint64](500GB); SizeRemaining = [uint64](200GB) }
            SupportedSize = [PSCustomObject]@{ SizeMin = [uint64](100GB); SizeMax = [uint64](450GB) }
            Partitions = $Partitions
            RecoveryPartitions = $RecoveryPartitions
            SelectedRecoveryPartition = $SelectedRecovery
            MountedImages = $MountedImages
            WinREImageChecked = $true
            WinREImageExists = $ImageExists
            WinREImageSize = [uint64](1GB)
            WinREImageVersion = '26100'
            Errors = $Errors
            DriveFreeBytes = @{ 'C:' = [uint64](200GB) }
        }
    }

    function New-SystemCheckState {
        param([string]$Operation = 'ReportOnly')
        $State = New-PatchWinREGuiState -Root $TestDrive
        $State.Operation = $Operation
        $State.WorkingDirectory = Join-Path $TestDrive 'Work'
        $State.BackupDirectory = Join-Path $TestDrive 'Backup'
        $State.MountDirectory = Join-Path $TestDrive 'Mount'
        $State.LogDirectory = Join-Path $TestDrive 'Logs'
        return $State
    }
}

Describe 'Patch-WinRE GUI validation' {
    It 'blocks create plus DoNotExpand when no size was supplied' {
        $State = New-SystemCheckState -Operation 'PatchDUorSOS'
        $State.CreateWinREDrive = $true
        $State.DoNotExpandRecoveryPartition = $true
        $State.UseRecoverySize = $false

        $Result = Test-PatchWinRESizeField -State $State -Operation (Get-PatchWinREOperation -Key $State.Operation)

        $Result.State | Should -Be 'Blocked'
        $Result.Message | Should -Match 'at least 1 GB'
    }

    It 'allows create without DoNotExpand and reports the default size' {
        $State = New-SystemCheckState -Operation 'PatchDUorSOS'
        $State.CreateWinREDrive = $true
        $State.DoNotExpandRecoveryPartition = $false
        $State.UseRecoverySize = $false

        $Result = Test-PatchWinRESizeField -State $State -Operation (Get-PatchWinREOperation -Key $State.Operation)

        $Result.State | Should -Be 'Off'
        $Result.Message | Should -Be 'Not set. The new recovery partition gets 1 GB.'
    }
}

Describe 'Patch-WinRE parameter-set parity' {
    It 'matches the real PowerShell binder for every set-defining parameter combination' {
        $Names = @(Get-PatchWinRESetDefiningParameter)
        $Mismatches = New-Object System.Collections.Generic.List[string]
        for ($Mask = 0; $Mask -lt [math]::Pow(2, $Names.Count); $Mask++) {
            $Present = New-Object System.Collections.Generic.List[string]
            $Arguments = @{}
            for ($Index = 0; $Index -lt $Names.Count; $Index++) {
                if (($Mask -band (1 -shl $Index)) -eq 0) { continue }
                $Name = $Names[$Index]
                $Present.Add($Name)
                switch ($Name) {
                    { $_ -in @('ReplaceWIM', 'CreateWinREDrive', 'AbortIfFailed', 'ReportOnly') } { $Arguments[$Name] = $true; break }
                    'DoNotExpandRecoveryPartition' { $Arguments[$Name] = $true; break }
                    'WIMFilePath' { $Arguments[$Name] = 'C:\fixture.wim'; break }
                    default { $Arguments[$Name] = 'C:\fixture' }
                }
            }
            $Expected = Resolve-PatchWinREParameterSet -Name $Present.ToArray()
            try {
                $Actual = Test-PatchWinREParameterBinding @Arguments -ErrorAction Stop
            } catch {
                $Actual = $null
            }
            if ($Actual -ne $Expected) {
                $Mismatches.Add(('mask {0}: expected {1}, actual {2}' -f $Mask, $Expected, $Actual))
            }
        }

        $Mismatches | Should -BeNullOrEmpty
    }
}

Describe 'Patch-WinRE system-check output parsing' {
    It 'extracts JSON after ProcessRunner stream prefixes and ordinary output' {
        $Discovery = ConvertFrom-PatchWinRESystemCheckOutput -Lines @(
            'OPreparing read-only checks'
            'OPATCHWINRE-JSON:'
            'O{"ReagentStatusToken":"Enabled","Errors":[]}'
        )

        $Discovery.ReagentStatusToken | Should -Be 'Enabled'
        @($Discovery.Errors).Count | Should -Be 0
    }

    Describe 'Patch-WinRE child runner' {
        It 'captures UTF-8 output and error streams, then removes its protected run folder' {
            $Run = Start-PatchWinREChildScript -Content "[Console]::WriteLine('runner-out'); [Console]::Error.WriteLine('runner-err')" -WorkingDirectory $env:TEMP
            $Lines = New-Object System.Collections.Generic.List[string]
            try {
                $Acl = Get-Acl -LiteralPath $Run.Directory
                $Acl.AreAccessRulesProtected | Should -BeTrue
                $AllowedSids = @('S-1-5-18')
                if (Test-PatchWinREElevated) { $AllowedSids += 'S-1-5-32-544' }
                else { $AllowedSids += [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
                $UnexpectedAces = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object { $AllowedSids -notcontains $_.IdentityReference.Value })
                $UnexpectedAces | Should -BeNullOrEmpty

                $Deadline = (Get-Date).AddSeconds(15)
                do {
                    foreach ($Line in $Run.Runner.Drain()) { $Lines.Add($Line) }
                    if ($Run.Runner.IsFinished) { break }
                    Start-Sleep -Milliseconds 50
                } while ((Get-Date) -lt $Deadline)
                if (-not $Run.Runner.IsFinished) { throw 'Child process did not finish in time.' }
                foreach ($Line in $Run.Runner.Drain()) { $Lines.Add($Line) }

                $Lines | Should -Contain 'Orunner-out'
                $Lines | Should -Contain 'Erunner-err'
            } finally {
                $Run.Runner.Dispose()
                [void](Remove-PatchWinRERunDirectory -Path $Run.Directory)
            }
            [System.IO.Directory]::Exists($Run.Directory) | Should -BeFalse
        }

        It 'cancels the specified child process tree' {
            $Run = Start-PatchWinREChildScript -Content 'Start-Sleep -Seconds 30' -WorkingDirectory $env:TEMP
            try {
                [void](Stop-PatchWinREProcessTree -ProcessId $Run.Id)
                $Deadline = (Get-Date).AddSeconds(5)
                while (-not $Run.Runner.IsFinished -and (Get-Date) -lt $Deadline) { Start-Sleep -Milliseconds 50 }
                $Run.Runner.IsFinished | Should -BeTrue
            } finally {
                $Run.Runner.Dispose()
                [void](Remove-PatchWinRERunDirectory -Path $Run.Directory)
            }
        }
    }

    It 'accepts the marker and JSON on one line' {
        $Discovery = ConvertFrom-PatchWinRESystemCheckOutput -Lines @(
            'PATCHWINRE-JSON:{"ReagentStatusToken":"Disabled"}'
        )

        $Discovery.ReagentStatusToken | Should -Be 'Disabled'
    }

    It 'reports missing and invalid JSON explicitly' {
        { ConvertFrom-PatchWinRESystemCheckOutput -Lines @('nothing here') } | Should -Throw '*JSON result marker*'
        { ConvertFrom-PatchWinRESystemCheckOutput -Lines @('PATCHWINRE-JSON:{bad}') } | Should -Throw '*invalid JSON*'
    }

    It 'emits a parseable read-only discovery script' {
        $Tokens = $null
        $ParseErrors = $null

        [void][System.Management.Automation.Language.Parser]::ParseInput(
            (New-PatchWinRESystemCheckScript),
            [ref]$Tokens,
            [ref]$ParseErrors
        )

        $ParseErrors | Should -BeNullOrEmpty
    }
}

Describe 'Patch-WinRE system-check evaluation' {
    It 'keeps Report only findings at Review when the disk is MBR or recovery is missing' {
        $State = New-SystemCheckState -Operation 'ReportOnly'
        $Discovery = New-SystemCheckFixture -PartitionStyle 'MBR' -Status 'Unknown' -ImageExists $false

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        $Result.Title | Should -Be 'REVIEW'
        @($Result.Findings | Where-Object { $_.State -eq 'Blocked' }).Count | Should -Be 0
        @($Result.Findings | Where-Object { $_.Topic -eq 'Recovery partition' -and $_.State -eq 'Review' }).Count | Should -Be 1
    }

    It 'blocks patching when the selected recovery partition is missing' {
        $State = New-SystemCheckState -Operation 'PatchDUorSOS'
        $Source = Join-Path $TestDrive 'patches'
        [void][System.IO.Directory]::CreateDirectory($Source)
        [System.IO.File]::WriteAllText((Join-Path $Source 'update.cab'), 'fixture')
        $State.PatchFilesDUorSOS = $Source
        $Discovery = New-SystemCheckFixture -SelectedRecovery $null

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        @($Result.Findings | Where-Object { $_.Topic -eq 'Recovery partition' -and $_.State -eq 'Blocked' }).Count | Should -Be 1
        $Result.Title | Should -Be 'BLOCKED'
    }

    It 'reviews an incomplete partition inventory instead of treating it as no recovery partition' {
        $State = New-SystemCheckState -Operation 'PatchDUorSOS'
        $Discovery = New-SystemCheckFixture
        $Discovery.Partitions = $null
        $Discovery.RecoveryPartitions = $null

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        @($Result.Findings | Where-Object { $_.Topic -eq 'Recovery partition' -and $_.State -eq 'Review' }).Count | Should -Be 1
        @($Result.Findings | Where-Object { $_.Topic -eq 'Recovery partition' -and $_.State -eq 'Blocked' }).Count | Should -Be 0
    }

    It 'reviews an unreadable WinRE image location instead of treating the image as missing' {
        $State = New-SystemCheckState -Operation 'ReportOnly'
        $Discovery = New-SystemCheckFixture -ImageExists $false
        $Discovery.WinREImageChecked = $false

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        @($Result.Findings | Where-Object { $_.Topic -eq 'WinRE image' -and $_.State -eq 'Review' }).Count | Should -Be 1
        @($Result.Findings | Where-Object { $_.Topic -eq 'WinRE image' -and $_.State -eq 'Blocked' }).Count | Should -Be 0
    }

    It 'blocks when the script would select a different one-digit reagentc location' {
        $State = New-SystemCheckState -Operation 'ReportOnly'
        $Recovery = [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 14; Size = [uint64](2GB); SizeRemaining = [uint64](1GB) }
        $Partitions = @(
            [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 3; Size = [uint64](100GB); GptType = 'Primary' }
            [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 14; Size = [uint64](2GB); GptType = 'Recovery' }
        )
        $Discovery = New-SystemCheckFixture -SelectedRecovery $Recovery -RecoveryPartitions @($Recovery) -Partitions $Partitions
        $Discovery.ScriptRecoveryPartitionNumber = '1'
        $Discovery.ActualRecoveryPartitionNumber = 14

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        @($Result.Findings | Where-Object { $_.Topic -eq 'reagentc location' -and $_.State -eq 'Blocked' }).Count | Should -Be 1
    }

    It 'requires shrinkable space for the full size in repartition mode' {
        $State = New-SystemCheckState -Operation 'PatchDUorSOS'
        $Source = Join-Path $TestDrive 'repartition-patches'
        [void][System.IO.Directory]::CreateDirectory($Source)
        [System.IO.File]::WriteAllText((Join-Path $Source 'update.cab'), 'fixture')
        $State.PatchFilesDUorSOS = $Source
        $State.UseRecoverySize = $true
        $State.RecoverySizeGB = '3'
        $Recovery = [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 2; Size = [uint64](1GB); SizeRemaining = [uint64](500MB) }
        $Partitions = @(
            [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 2; Size = [uint64](1GB); GptType = 'Recovery' }
            [PSCustomObject]@{ DiskNumber = 0; PartitionNumber = 3; Size = [uint64](100GB); GptType = 'Primary' }
        )
        $Discovery = New-SystemCheckFixture -SelectedRecovery $Recovery -RecoveryPartitions @($Recovery) -Partitions $Partitions
        $Discovery.SupportedSize = [PSCustomObject]@{ SizeMin = [uint64](448GB); SizeMax = [uint64](450GB) }

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        @($Result.Findings | Where-Object { $_.Topic -eq 'Resize' -and $_.State -eq 'Blocked' -and $_.Message -match 'full new size' }).Count | Should -Be 1
    }

    It 'blocks an already-mounted image for patch operations' {
        $State = New-SystemCheckState -Operation 'PatchDUorSOS'
        $Source = Join-Path $TestDrive 'mounted-patches'
        [void][System.IO.Directory]::CreateDirectory($Source)
        [System.IO.File]::WriteAllText((Join-Path $Source 'update.cab'), 'fixture')
        $State.PatchFilesDUorSOS = $Source
        $Discovery = New-SystemCheckFixture -MountedImages @([PSCustomObject]@{ MountPath = 'C:\Mount'; ImagePath = 'C:\image.wim'; MountStatus = 'Ok' })

        $Result = Get-PatchWinRESystemFinding -Discovery $Discovery -State $State

        @($Result.Findings | Where-Object { $_.Topic -eq 'Mounted images' -and $_.State -eq 'Blocked' }).Count | Should -Be 1
    }

    It 'provides the mode-specific Check System tooltip' {
        Get-PatchWinRESystemCheckTooltip -IsElevated $false -GenerateOnly $false | Should -Be 'Requires administrator mode. Checks WinRE status, partition layout, free space and prerequisites without changing recovery configuration.'
        Get-PatchWinRESystemCheckTooltip -IsElevated $true -GenerateOnly $true | Should -Be 'Unavailable in generate-only mode. Checks WinRE status, partition layout, free space and prerequisites without changing recovery configuration.'
    }

    It 'checks local fixed-drive space and leaves network paths unknown' {
        $Discovery = [PSCustomObject]@{ DriveFreeBytes = ConvertFrom-Json -InputObject '{"C:":1048576}' }

        Get-PatchWinRESystemDriveFreeBytes -Discovery $Discovery -Path 'C:\work' | Should -Be 1048576
        Get-PatchWinRESystemDriveFreeBytes -Discovery $Discovery -Path '\\server\share\work' | Should -BeNullOrEmpty
    }
}
