<#
.NOTES
===========================================================================
Created on:   	09/2019
Created by:   	Mark Warneke & Alexander Sehr
Organization: 	Microsoft
Reference:      https://github.com/MarkWarneke
===========================================================================
#>

# Load module and dependencies
. "$PSScriptRoot\lib\Shared.ps1"
$FunctionHelpTestExceptions = Get-Content -Path "$ModuleBase\Test\lib\Help.Exceptions.txt"

Describe "PSScriptAnalyzer rule-sets" -Tag ScriptAnalyzer {

    $Rules = Get-ScriptAnalyzerRule
    $scripts = Get-ChildItem $ModuleBase -Include *.ps1, *.psm1, *.psd1 -Recurse | Where-Object fullname -notmatch 'classes'

    foreach ( $Script in $scripts ) {
        Context "Script '$($script.FullName)'" {

            foreach ( $rule in $rules ) {
                # Skip all rules that are on the exclusions list
                if ($FunctionHelpTestExceptions -contains $rule.RuleName) { continue }
                It "Rule [$rule]" {

                    (Invoke-ScriptAnalyzer -Path $script.FullName -IncludeRule $rule.RuleName ).Count | Should Be 0
                }
            }
        }
    }
}


Describe "General project validation: $moduleName" -Tag Build {
    BeforeAll {
        Get-Module $ModuleName | Remove-Module
    }
    It "Module '$moduleName' can import cleanly" {
        { Import-Module $ModuleBase\$ModuleName.psd1 -force } | Should Not Throw
    }
}


Describe "Exported functions evaluation" -Tag Build {

    $manifest = Import-PowerShellDataFile $moduleManifestPath
    $commandPrefix = $manifest.DefaultCommandPrefix

    BeforeAll {
        Get-Module $ModuleName | Remove-Module
        Import-Module $ModuleBase\$ModuleName.psd1 -force
    }

    # Build the expected functions from the public folder
    $plainPublicFunctions = (Get-ChildItem -Path "$ModuleBase\Public" -Filter '*.ps1').BaseName
    $expectedFunctions = @()
    foreach ($func in $plainPublicFunctions) {
        $functionParts = $func.Split('-')
        $expectedFunction = "{0}-{1}{2}" -f $functionParts[0], $commandPrefix , $functionParts[1]
        $expectedFunctions += $expectedFunction
    }

    # Get the actually exported functions by the module
    $actualFunctions = (Get-Module -Name $ModuleName).ExportedFunctions

    # Run the tests
    foreach ($expectedFunction in $expectedFunctions) {
        It "Correct export of $expectedFunction" {
            $actualFunctions.ContainsKey($expectedFunction) | Should Be $true
        }
    }
}