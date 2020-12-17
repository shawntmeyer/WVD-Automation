<#
.SYNOPSIS
Run the Post-Deployment for the host pool deployment

.DESCRIPTION
Run the Post-Deployment for the host pool deployment
- Upload required data to the host pool

.PARAMETER orchestrationFunctionsPath
Mandatory. Path to the required functions

.PARAMETER HostPoolName
Mandatory. Name of the hostpool to process

.PARAMETER HostPoolRGName
Mandatory. Resource group of the hostpool to process

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

.PARAMETER timeoutInMinutes
The time in minutes reserved to check for the health state.

.PARAMETER waitInSeconds
Optional. The time to wait in between the host-pool health checks in seconds.

.EXAMPLE
Invoke-HostPoolPostDeployment -orchestrationFunctionsPath $currentDir -HostPoolName 'myhostPool' -HostPoolRGName 'hostPoolRg' -customImageReferenceId '/subscriptions/65862f1e-947f-4dd6-bd50-319d3c84eb36/resourceGroups/bsd-imaging-rg/providers/Microsoft.Compute/galleries/CustomerNameSharedImages/images/WIN10-20H2-DISPATCHER/versions/0.24322.55884'

Invoke the host pool post-deployment with a custom image reference

.EXAMPLE
Invoke-HostPoolPostDeployment -orchestrationFunctionsPath $currentDir -HostPoolName 'myhostPool' -HostPoolRGName 'hostPoolRg' -MarketplaceImageVersion 'latest' -MarketplaceImagePublisher 'MicrosoftWindowsDesktop' -MarketplaceImageOffer 'office-365' -MarketplaceImageSku '19h2-evd-o365pp' -MarketplaceImageLocation 'francecentral'

Invoke the host pool post-deployment with a marketplace image
#>
function Invoke-HostPoolPostDeployment {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $orchestrationFunctionsPath,

        [Parameter(Mandatory)]
        [string] $HostPoolName,

        [Parameter(Mandatory)]
        [string] $HostPoolRGName,

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

        [Parameter(Mandatory = $false)]
        [int] $timeoutInMinutes = 10,

        [Parameter(Mandatory = $false)]
        [int] $waitInSeconds = 15
    )

    begin {
        Write-Verbose ("[{0} entered]" -f $MyInvocation.MyCommand)
        . "$orchestrationFunctionsPath\Imaging\Confirm-HostPoolHealth.ps1"
    }

    process {
        Write-Verbose "#################################################################"
        Write-Verbose "## 1 - Check and wait for the host pool VMs to come up healthy ##"
        Write-Verbose "#################################################################"

        $HealthCheckInputObject = @{
            HostPoolName     = $HostPoolName
            HostPoolRGName   = $HostPoolRGName
            timeoutInMinutes = $timeoutInMinutes
        }

        if (-not [String]::IsNullOrEmpty($customImageReferenceId)) {
            $HealthCheckInputObject += @{ customImageReferenceId = $customImageReferenceId }
        }

        else {
            $HealthCheckInputObject += @{ 
                MarketplaceImageVersion   = $MarketplaceImageVersion 
                MarketplaceImagePublisher = $MarketplaceImagePublisher
                MarketplaceImageOffer     = $MarketplaceImageOffer
                MarketplaceImageSku       = $MarketplaceImageSku
            }
            if ($MarketplaceImageVersion -eq 'latest') {
                $HealthCheckInputObject += @{
                    MarketplaceImageLocation = $MarketplaceImageLocation
                }
            }                        
        }
        Confirm-HostPoolHealth @HealthCheckInputObject -Verbose
    }
    
    end {
        Write-Verbose ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}