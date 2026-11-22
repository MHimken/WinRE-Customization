#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies that Patch-WinRE.ps1 -WhatIf changes nothing and that a normal run still performs every step.
.DESCRIPTION
    Runs Patch-WinRE.ps1 through Support\Invoke-PatchWinREMocked.ps1 in a separate Windows PowerShell 5.1 process.
    All system commands are mocked, so no administrator rights are required.
#>
BeforeAll {
    $Script:PatchScriptPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Patch-WinRE.ps1'
    $Script:MockHostPath = Join-Path -Path $PSScriptRoot -ChildPath 'Support\Invoke-PatchWinREMocked.ps1'
    $Script:WindowsPowerShellPath = Join-Path -Path $env:WINDIR -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'

    function Invoke-MockedPatchWinRE {
        param(
            [string]$Name,
            [hashtable]$Arguments,
            [hashtable]$Files = @{},
            [bool]$WinREEnabled = $true,
            [long]$RecoveryPartitionSize = 2GB
        )
        $Root = Join-Path -Path $TestDrive -ChildPath $Name
        $Custom = Join-Path -Path $Root -ChildPath 'Custom'
        New-Item -Path $Root -ItemType Directory -Force | Out-Null
        foreach ($RelativePath in $Files.Keys) {
            $FilePath = Join-Path -Path $Root -ChildPath $RelativePath
            New-Item -Path (Split-Path -Path $FilePath -Parent) -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath $FilePath -Value $Files[$RelativePath] -Encoding ASCII
        }
        $ScriptArguments = @{
            WorkingDirectory = "$Custom\"
            BackupDirectory  = "$Custom\WinREBackups\"
            MountDirectory   = "$Custom\WinREMount\"
            LogDirectory     = "$Custom\Logs\"
        }
        foreach ($Key in $Arguments.Keys) {
            if ($Arguments[$Key] -is [string]) {
                $ScriptArguments[$Key] = $Arguments[$Key].Replace('<ROOT>', $Root)
            } else {
                $ScriptArguments[$Key] = $Arguments[$Key]
            }
        }
        $ScenarioFile = Join-Path -Path $Root -ChildPath 'scenario.json'
        @{
            Root                  = $Root
            WinREEnabled          = $WinREEnabled
            RecoveryPartitionSize = $RecoveryPartitionSize
            Arguments             = $ScriptArguments
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ScenarioFile -Encoding UTF8
        $Output = & $Script:WindowsPowerShellPath -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script:MockHostPath -ScriptPath $Script:PatchScriptPath -ScenarioFile $ScenarioFile 2>&1 | ForEach-Object { "$_" }
        [pscustomobject]@{
            ExitCode  = $LASTEXITCODE
            Output    = $Output
            Mutations = @($Output | Where-Object { $_ -like 'MOCK-MUTATION: *' })
            WhatIf    = @($Output | Where-Object { $_ -like 'What if: *' })
            Root      = $Root
            Custom    = $Custom
        }
    }
}

Describe 'Patch-WinRE.ps1 -WhatIf' {
    Context 'Patching with backups to delete' {
        BeforeAll {
            $Result = Invoke-MockedPatchWinRE -Name 'PreviewPatch' -Arguments @{
                PatchFilesGDRDUorLCU = '<ROOT>\patch'
                DeleteBackups        = $true
                WhatIf               = $true
            } -Files @{
                'patch\windows11.0-kb5000001-x64.msu' = 'lcu'
                'patch\ssu-26100.1-x64.msu'           = 'ssu'
                'Custom\WinREBackups\WinREold.wim'    = 'old image'
                'Custom\WinREBackups\ReAgentold.xml'  = 'old xml'
            }
        }
        It 'Exits with 0' {
            $Result.ExitCode | Should -Be 0
        }
        It 'Does not run any state changing command' {
            $Result.Mutations | Should -BeNullOrEmpty
        }
        It 'Reports <Change>' -ForEach @(
            @{ Change = 'mounting'; Pattern = 'Mount WinRE image' }
            @{ Change = 'the SSU'; Pattern = 'Add package .*ssu-26100' }
            @{ Change = 'the LCU'; Pattern = 'Add package .*kb5000001' }
            @{ Change = 'committing'; Pattern = 'commit changes and unmount' }
            @{ Change = 'deleting backups'; Pattern = 'Delete backup' }
        ) {
            ($Result.WhatIf -match $Pattern) | Should -Not -BeNullOrEmpty
        }
        It 'Does not create the mount or log folder' {
            Join-Path -Path $Result.Custom -ChildPath 'WinREMount' | Should -Not -Exist
            Join-Path -Path $Result.Custom -ChildPath 'Logs' | Should -Not -Exist
        }
        It 'Keeps the existing backups' {
            @(Get-ChildItem -Path (Join-Path -Path $Result.Custom -ChildPath 'WinREBackups')).Count | Should -Be 2
        }
        It 'Ends with the preview summary' {
            $Result.Output | Should -Contain 'T:1 C:WinREPatchCore M:Preview finished - no changes were applied'
        }
    }
    Context 'Resizing the recovery partition' {
        BeforeAll {
            $Result = Invoke-MockedPatchWinRE -Name 'PreviewResize' -RecoveryPartitionSize 500MB -Arguments @{
                RecoveryDriveSizeInGB = 1GB
                WhatIf                = $true
            }
        }
        It 'Exits with 0 without changing anything' {
            $Result.ExitCode | Should -Be 0
            $Result.Mutations | Should -BeNullOrEmpty
        }
        It 'Reports the partition plan for the disk' {
            ($Result.WhatIf -match 'remove recovery partition 4, shrink .* on target "Disk 0"') | Should -Not -BeNullOrEmpty
        }
    }
    Context 'Replacing the WIM' {
        BeforeAll {
            $Result = Invoke-MockedPatchWinRE -Name 'PreviewReplace' -Arguments @{
                ReplaceWIM  = $true
                WIMFilePath = '<ROOT>\new.wim'
                WhatIf      = $true
            } -Files @{ 'new.wim' = 'new image' }
        }
        It 'Exits with 0 without changing anything' {
            $Result.ExitCode | Should -Be 0
            $Result.Mutations | Should -BeNullOrEmpty
        }
        It 'Reports the replacement but does not copy the WIM' {
            ($Result.WhatIf -match 'Replace with .*new\.wim') | Should -Not -BeNullOrEmpty
            Join-Path -Path $Result.Root -ChildPath 'Windows\System32\Recovery\WinRE.wim' | Should -Not -Exist
        }
    }
}

Describe 'Patch-WinRE.ps1 without -WhatIf' {
    Context 'Patching' {
        BeforeAll {
            $Result = Invoke-MockedPatchWinRE -Name 'RunPatch' -Arguments @{
                PatchFilesGDRDUorLCU = '<ROOT>\patch'
                ToConsole            = $true
            } -Files @{ 'patch\windows11.0-kb5000001-x64.msu' = 'lcu' }
        }
        It 'Exits with 0 without error records' {
            $Result.ExitCode | Should -Be 0
            ($Result.Output -match 'Exception|FullyQualifiedErrorId') | Should -BeNullOrEmpty
        }
        It 'Runs every step in order' {
            $Steps = foreach ($Mutation in $Result.Mutations) {
                $Parts = ($Mutation -replace '^MOCK-MUTATION: ', '') -split ' '
                if ($Parts[0] -eq 'reagentc') { "reagentc $($Parts[1])" } else { $Parts[0] }
            }
            $Steps | Should -Be @(
                'reagentc /enable'
                'reagentc /mountre'
                'Add-WindowsPackage'
                'dism'
                'reagentc /unmountre'
                'reagentc /disable'
                'reagentc /enable'
            )
        }
        It 'Does not report What if' {
            $Result.WhatIf | Should -BeNullOrEmpty
        }
        It 'Creates a backup of the current WinRE' {
            @(Get-ChildItem -Path (Join-Path -Path $Result.Custom -ChildPath 'WinREBackups') -Filter '*.wim').Count | Should -Be 1
        }
    }
}
