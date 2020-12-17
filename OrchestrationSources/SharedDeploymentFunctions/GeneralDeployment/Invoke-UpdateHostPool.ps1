<#
.SYNOPSIS
Run the Image Update process for the given host pool resource

.DESCRIPTION
Run the Image Update process for the given host pool resource
- Update the host pool

.PARAMETER orchestrationFunctionsPath
Mandatory. Path to the required functions

.PARAMETER HostPoolName
Mandatory. Name of the hostpool to process

.PARAMETER HostPoolRGName
Mandatory. Resource group of the hostpool to process

.PARAMETER LogoffDeadline
Mandatory. Logoff Deadline in yyyyMMddHHmm

.PARAMETER LogOffMessageTitle
Mandatory. Title of the popup the users receive when they get notified of their dawning session cancelation 

.PARAMETER LogOffMessageBody
Mandatory. Message of the popup the users receive when they get notified of their dawning session cancelation

.PARAMETER UtcOffset
Mandatory. Offset to UTC in hours

.PARAMETER DeleteVMDeadline
Optional. Controls when to delete the host pool VMs (Very Destructive) in yyyyMMddHHmm

.PARAMETER MarketplaceImageVersion
Optional. Version of the used marketplace image. Mandatory if 'CustomImageReferenceId' is not provided.

.PARAMETER MarketplaceImagePublisher
Optional. Publisher of the used marketplace image. Mandatory if 'CustomImageReferenceId' is not provided.

.PARAMETER MarketplaceImageOffer
Optional. Offer of the used marketplace image. Mandatory if 'CustomImageReferenceId' is not provided.

.PARAMETER MarketplaceImageSku
Optional. Sku of the used marketplace image. Mandatory if 'CustomImageReferenceId' is not provided.

.PARAMETER MarketplaceImageLocation
Optional. Location of the used marketplace image. Mandatory if 'CustomImageReferenceId' is not provided and 'MarketplaceImageVersion' equals 'latest'.

.PARAMETER CustomImageReferenceId
Optional. Full Reference to Custom Image.
/subscriptions/<SubscriptionID>/resourceGroups/<ResourceGroupName>/providers/Microsoft.Compute/galleries/<ImageGalleryName>/images/<ImageDefinitionName>/versions/<version>
Mandatory if 'MarketplaceImage'-Parameters are not provided.

.PARAMETER LAWorkspaceName
Optional. Name of an OMS workspace to send host-pool image update process logs to

.PARAMETER Confirm
Optional. Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Optional. Dry run of the script

.EXAMPLE
Invoke-UpdateHostPool @functionInput

Invoke the update host pool orchestration script with the given parameters
#>
function Invoke-UpdateHostPool {

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string] $orchestrationFunctionsPath,

        [Parameter(Mandatory)]
        [string] $HostPoolName,
    
        [Parameter(Mandatory)]
        [string] $HostPoolRGName,
    
        [Parameter(Mandatory)]
        [string] $LogOffMessageTitle,
    
        [Parameter(Mandatory)]
        [string] $LogOffMessageBody,
        
        [Parameter(Mandatory)]
        [string] $UtcOffset,
    
        [Parameter(Mandatory)]
        [string] $LogoffDeadline, # Logoff Deadline in yyyyMMddHHmm

        [Parameter(Mandatory = $false)]
        [string] $DeleteVMDeadline = (Get-Date -Format yyyyMMddHHmm),
    
        [Parameter(Mandatory = $false)]
        [string] $MarketplaceImageVersion,
        
        [Parameter(Mandatory = $false)]
        [string]$MarketplaceImagePublisher,

        [Parameter(Mandatory = $false)]
        [string]$MarketplaceImageOffer,

        [Parameter(Mandatory = $false)]
        [string]$MarketplaceImageSku,

        [Parameter(Mandatory = $false)]
        [string]$MarketplaceImageLocation,

        [Parameter(Mandatory = $false)]
        [string] $CustomImageReferenceId,

        [Parameter(mandatory = $false)]
        [string] $LAWorkspaceName = ''
    )

    begin {
        Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)

        . "$orchestrationFunctionsPath\Imaging\Update-WVDHostPool.ps1"
    }

    process {

        Write-Verbose "################################"
        Write-Verbose "## 1 - UPDATE HOST POOL IMAGE ##"
        Write-Verbose "################################"

        $hostPoolImageUpdateInputObject = @{
            HostPoolName       = $HostPoolName
            HostPoolRGName     = $HostPoolRGName
            LogoffDeadline     = $LogoffDeadline
            LogOffMessageTitle = $LogOffMessageTitle
            LogOffMessageBody  = $LogOffMessageBody
            UtcOffset          = $UtcOffset
            DeleteVMDeadline   = $DeleteVMDeadline
        }

        if (-not [String]::IsNullOrEmpty($LAWorkspaceName)) {
            $hostPoolImageUpdateInputObject += @{ 
                LAWorkspaceName = $LAWorkspaceName
            }
        }

        if (-not [String]::IsNullOrEmpty($CustomImageReferenceId)) {
            $hostPoolImageUpdateInputObject += @{ 
                customImageReferenceId = $CustomImageReferenceId 
            }
        }
        else {
            $hostPoolImageUpdateInputObject += @{ 
                MarketplaceImageVersion   = $MarketplaceImageVersion
                MarketplaceImagePublisher = $MarketplaceImagePublisher
                MarketplaceImageOffer     = $MarketplaceImageOffer
                MarketplaceImageSku       = $MarketplaceImageSku 
            }
            if (-not [String]::IsNullOrEmpty($MarketplaceImageLocation)) {
                $hostPoolImageUpdateInputObject += @{ 
                    MarketplaceImageLocation = $MarketplaceImageLocation
                }
            }
        }

        if ($PSCmdlet.ShouldProcess("Host pool image update process", "Invoke")) {        
            Update-WVDHostPool @hostPoolImageUpdateInputObject -Verbose
        }
        Write-Verbose "Host pool image update process executed"
    }
}