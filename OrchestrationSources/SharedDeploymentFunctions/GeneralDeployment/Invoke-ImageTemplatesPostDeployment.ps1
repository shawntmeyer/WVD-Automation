<#
.SYNOPSIS
Run the Post-Deployment for the image template deployment

.DESCRIPTION
Run the Post-Deployment for the image template deployment
- Trigger new image creation
- Wait for the image creation process to complete

.PARAMETER orchestrationFunctionsPath
Path to the required functions

.PARAMETER ResourceGroupName
Resource group to create the image in

.PARAMETER ImageTemplateName
Name of the image template

.PARAMETER synchronouslyWaitForImageBuild
Control whether to wait for the image creation

.PARAMETER Confirm
Optional. Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Optional.  Dry run of the script

.EXAMPLE
Invoke-ImageTemplatesPostDeployment -orchestrationFunctionsPath $currentDir -ResourceGroupName 'imagingRG' -ImageTemplateName 'myTemplate'

Deploy the image template post-deployment using resource group 'imagingRG' for the image template 'myTemplate'
#>
function Invoke-ImageTemplatesPostDeployment {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string] $orchestrationFunctionsPath,

        [Parameter(Mandatory)]
        [string] $ResourceGroupName,
        
        [Parameter(Mandatory)]
        [string] $ImageTemplateName,

        [Parameter(Mandatory = $false)]
        [bool] $synchronouslyWaitForImageBuild = $false
    )


    begin {
        Write-Verbose ("[{0} entered]" -f $MyInvocation.MyCommand)

        . "$orchestrationFunctionsPath\Imaging\Wait-ForImageBuild.ps1"
    }

    process {
        Write-Verbose "####################################"
        Write-Verbose "## 1 - TRIGGER NEW IMAGE CREATION ##"
        Write-Verbose "####################################"
        if ($PSCmdlet.ShouldProcess("New image creation of template [$ImageTemplateName]", "Trigger")) {   
            $resourceActionInputObject = @{
                ResourceName      = $ImageTemplateName
                ResourceGroupName = $ResourceGroupName
                ResourceType      = 'Microsoft.VirtualMachineImages/imageTemplates' 
                Action            = 'Run' 
                Force             = $true
            }     
            Invoke-AzResourceAction @resourceActionInputObject
        }

        if ($synchronouslyWaitForImageBuild) {
            Write-Verbose "#####################################"
            Write-Verbose "## 2 - WAIT FOR NEW IMAGE CREATION ##"
            Write-Verbose "#####################################"

            if ($PSCmdlet.ShouldProcess("For image creation of template [$ImageTemplateName]", "Wait")) {        
                $waitForImageInputObject = @{
                    ResourceGroupName = $ResourceGroupName
                    ImageTemplateName = $ImageTemplateName
                }
                Wait-ForImageBuild @waitForImageInputObject
            }
        }
    }
    
    end {
        Write-Verbose ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}