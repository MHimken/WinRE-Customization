function New-PatchWinREBindingProbe {
    <#
    .SYNOPSIS
        Creates a harmless function with the exact param block and CmdletBinding of Patch-WinRE.ps1.
    .DESCRIPTION
        The probe only returns the resolved parameter set name and the bound parameters, so parameter
        binding can be tested without running any servicing code or requiring administrator rights.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string]$FunctionName = 'Invoke-PatchWinREProbe'
    )
    $Tokens = $null
    $ParseErrors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$Tokens, [ref]$ParseErrors)
    if ($ParseErrors.Count -gt 0) {
        throw "Patch-WinRE.ps1 has parse errors: $($ParseErrors[0].Message)"
    }
    $AttributeText = ($Ast.ParamBlock.Attributes | ForEach-Object { $_.Extent.Text }) -join "`n"
    $ParamText = $Ast.ParamBlock.Extent.Text
    if ($ParamText -notmatch '^\s*\[CmdletBinding') {
        $ParamText = $AttributeText + "`n" + $ParamText
    }
    $FunctionText = "function global:$FunctionName {`n$ParamText`n[pscustomobject]@{ ParameterSetName = `$PSCmdlet.ParameterSetName; Bound = `$PSBoundParameters; WhatIf = [bool]`$WhatIfPreference } }"
    . ([scriptblock]::Create($FunctionText))
}
function Get-PatchWinREHelpExample {
    <#
    .SYNOPSIS
        Returns the command line of every .EXAMPLE in the comment based help of Patch-WinRE.ps1.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath
    )
    $Lines = Get-Content -LiteralPath $ScriptPath
    $InExample = $false
    $Index = 0
    foreach ($Line in $Lines) {
        if ($Line -match '^\s*\.EXAMPLE') { $InExample = $true; $Index++; continue }
        if ($Line -match '^\s*\.[A-Z]+') { $InExample = $false }
        if ($Line -match '^#>') { break }
        if ($InExample -and $Line -match '^\s*(Patch-WinRE\.ps1.*)$') {
            [pscustomobject]@{ Index = $Index; CommandLine = $Matches[1].Trim() }
        }
    }
}
