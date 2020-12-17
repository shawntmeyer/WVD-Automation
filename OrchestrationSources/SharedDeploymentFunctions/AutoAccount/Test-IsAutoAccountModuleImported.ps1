<#
.SYNOPSIS
Function to check if the module is imported

.DESCRIPTION
Function to check if the module is imported

.PARAMETER ResourceGroupName
The name of the resource group containing the automation account

.PARAMETER AutomationAccountName
The name of the automation account

.PARAMETER ModuleName
The name of the module to check for

.EXAMPLE
Test-IsAutoAccountModuleImported -ModuleName 'AzureAD' -ResourceGroupName 'Auto-RG' -AutomationAccountName 'CustomAuto'

Check if the module 'AzureAD' was imported to automation account 'ÇustomAuto' in resource group 'Auto-RG'
#>
function Test-IsAutoAccountModuleImported {
    param(
        [Parameter(Mandatory)]
        [string] $ResourceGroupName,

        [Parameter(Mandatory)]
        [string] $AutomationAccountName,

        [Parameter(Mandatory)]
        [string] $ModuleName
    )

    begin {
        Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)
    }

    process {
        $IsModuleImported = $false
        $tryCount = 1
        $maxTries = 15 
        while (-not $IsModuleImported -and $tryCount -lt $maxTries) { 
    
            $moduleCheckInputObject = @{
                ResourceGroupName     = $ResourceGroupName 
                AutomationAccountName = $AutomationAccountName
                Name                  = $ModuleName 
                ErrorAction           = 'SilentlyContinue'
            }
            $IsModule = Get-AzAutomationModule @moduleCheckInputObject

            if ($IsModule.ProvisioningState -eq "Succeeded") {
                $IsModuleImported = $true
                Write-Verbose "Successfully $ModuleName module imported into Automation Account Modules..."
            }
            else {
                Write-Verbose ("Waiting 10 seconds for module import of '{0}' into automation account [{1}|{2}]" -f $ModuleName, $tryCount, $maxTries)
                $tryCount++;
                Start-Sleep 10 
            }
        }
    }
    
    end {
        Write-Debug ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}