<#
.SYNOPSIS
Import and publish a new runbook to the given automation account

.DESCRIPTION
Import and publish a new runbook to the given automation account

.PARAMETER orchestrationFunctionsPath
Path to the functions folders at the root of the runbook script

.PARAMETER AutomationAccountName
The name of the automation account

.PARAMETER AutomationAccountRGName
The name of the resource group containing the automation account

.PARAMETER ScalingRunbookName
Name of the scaling runbook to create
#>
function New-RunbookImport {
    
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [string] $orchestrationFunctionsPath,

        [Parameter(Mandatory)]
        [string] $AutomationAccountName,

        [Parameter(Mandatory)]
        [string] $AutomationAccountRGName,

        [Parameter(Mandatory)]
        [string] $ScalingRunbookName
    )

    Write-Verbose "====================="
    Write-Verbose "== CREATE RUNBOOK  =="

    $getRunbookInputObject = @{
        AutomationAccountName = $AutomationAccountName
        ResourceGroupName     = $AutomationAccountRGName
        Name                  = $ScalingRunbookName
    }
    $existingRunbook = Get-AzAutomationRunbook @getRunbookInputObject -ErrorAction SilentlyContinue
    if (-not $existingRunbook) {
        $runbookImportInputObject = @{
            AutomationAccountName = $AutomationAccountName
            Name                  = $ScalingRunbookName
            Path                  = "$orchestrationFunctionsPath\AutoAccount\Runbooks\HostPoolScaling.ps1"
            ResourceGroupName     = $AutomationAccountRGName
            Type                  = 'PowerShell'
        }
        if ($PSCmdlet.ShouldProcess("Runbook '$ScalingRunbookName'", "Import")) {
            Import-AzAutomationRunbook @runbookImportInputObject
        }
    } 
    else {
        Write-Verbose "Runbook '$ScalingRunbookName' already exists in the automation account '$AutomationAccountName'"
    }

    Write-Verbose "======================"
    Write-Verbose "== PUBLISH RUNBOOK  =="

    if ((Get-AzAutomationRunbook -ResourceGroupName $AutomationAccountRGName -AutomationAccountName $AutomationAccountName -Name $ScalingRunbookName).State -ne 'Published') {
        $publishRunbookInputObject = @{
            AutomationAccountName = $AutomationAccountName
            ResourceGroupName     = $AutomationAccountRGName
            Name                  = $ScalingRunbookName
        }
        if ($PSCmdlet.ShouldProcess("Runbook '$ScalingRunbookName'", "Publish")) {
            $null = Publish-AzAutomationRunbook @publishRunbookInputObject
            Write-Verbose "Published runbook"
        }
    }
    else {
        Write-Verbose "Runbook '$ScalingRunbookName' already published"
    }
}