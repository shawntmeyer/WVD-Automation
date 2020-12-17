<#
.SYNOPSIS
Check and wait until all session hosts in the provided host pools appear healthy

.DESCRIPTION
Check and wait until all session hosts in the provided host pools appear healthy

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
Confirm-HostPoolHealth -orchestrationFunctionsPath $currentDir -HostPoolName 'myhostPool' -HostPoolRGName 'hostPoolRg' -customImageReferenceId '/subscriptions/65862f1e-947f-4dd6-bd50-319d3c84eb36/resourceGroups/bsd-imaging-rg/providers/Microsoft.Compute/galleries/CustomerNameSharedImages/images/WIN10-20H2-DISPATCHER/versions/0.24322.55884'

Invoke health check with a custom image reference

.EXAMPLE
Confirm-HostPoolHealth -HostPoolName 'myhostPool' -HostPoolRGName 'hostPoolRg' -MarketplaceImageVersion 'latest' -MarketplaceImagePublisher 'MicrosoftWindowsDesktop' -MarketplaceImageOffer 'office-365' -MarketplaceImageSku '19h2-evd-o365pp' -MarketplaceImageLocation 'francecentral'

Invoke health check with a marketplace image
#>
function Confirm-HostPoolHealth {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $HostPoolName,

        [Parameter(Mandatory)]
        [string] $HostPoolRGName,

        [Parameter(ParameterSetName = 'MarketPlaceImage', Mandatory)]
        [string] $MarketplaceImageVersion,
        
        [Parameter(ParameterSetName = 'MarketPlaceImage', Mandatory)]
        [string]$MarketplaceImagePublisher,

        [Parameter(ParameterSetName = 'MarketPlaceImage', Mandatory)]
        [string]$MarketplaceImageOffer,

        [Parameter(ParameterSetName = 'MarketPlaceImage', Mandatory)]
        [string]$MarketplaceImageSku,

        [Parameter(ParameterSetName = 'MarketPlaceImage', Mandatory = $false)]
        [string]$MarketplaceImageLocation,

        [Parameter(ParameterSetName = 'CustomSIGImage', Mandatory)]
        [string] $CustomImageReferenceId,

        [Parameter(Mandatory = $false)]
        [int] $timeoutInMinutes = 10,

        [Parameter(Mandatory = $false)]
        [int] $waitInSeconds = 15
    )

    if ($PSCmdlet.ParameterSetName -eq 'MarketPlaceImage') {
        if ($MarketplaceImageVersion -eq 'latest') {
            $getImageInputObject = @{
                Location      = $MarketplaceImageLocation
                PublisherName = $MarketplaceImagePublisher 
                Offer         = $MarketplaceImageOffer 
                Sku           = $MarketplaceImageSku
            }
            $availableVersions = Get-AzVMImage @getImageInputObject | Select-Object Version
            $latestVersion = (($availableVersions.Version -as [Version[]]) | Measure-Object -Maximum).Maximum
            Write-Verbose "Running with Marketplace Image version [$latestVersion]"
            [Version]$TargetImageVersion = $latestVersion
        }
        else {
            Write-Verbose "Running with Marketplace Image version [$MarketplaceImageVersion]"
            [Version]$TargetImageVersion = $MarketplaceImageVersion
        }
    }
    else {
        Write-Verbose "Running with Custom Image"
        $ACustomImageID = $CustomImageReferenceId.Split("/")
        [Version]$TargetImageVersion = $ACustomImageID[$ACustomImageID.Count - 1]
    }

    $latestVMs = Get-AzVm -ResourceGroupName $HostPoolRGName -Status | Where-Object { $_.Tags.ImageVersion -eq $TargetImageVersion }
    $latestVMNames = $latestVMs.Name    

    $stopwatch = [system.diagnostics.stopwatch]::StartNew()
    $allVMsHealthy = $false
    while (-not $allVMsHealthy -and $stopwatch.Elapsed.Minutes -le $timeoutInMinutes) {

        $sessionHosts = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $HostPoolRGName -ErrorAction SilentlyContinue | Sort-Object 'SessionHostName'
        if (-not $sessionHosts) {
            Write-Verbose "RESULT: No session hosts deployed. Skipping further resource group level tagging."
            return
        }

        $latestSessionHosts = New-Object -TypeName "System.Collections.ArrayList"
        foreach ($sessionHost in $sessionHosts) {
            $vmName = $SessionHost.Name.Split("/")[1].split('.')[0]
            if ($latestVMNames -contains $vmName) {
                $null = $latestSessionHosts.Add($sessionHost)
            }
        }

        $unhealthyVMs = $latestSessionHosts | Where-Object { $_.Status -ne 'Available' }
        if ($unhealthyVMs.Count -eq 0) {
            Write-Verbose "RESULT: All VMs are in a healthy state." -Verbose
            $allVMsHealthy = $true
        }

        Write-Verbose ("There are still [{0}] session hosts in an unhealthy state. Waiting for [{1}] seconds. Minutes to timeout [{2}:{3} min|{4} min]" -f $unhealthyVMs.Count, $waitInSeconds, $stopwatch.Elapsed.Minutes, $stopwatch.Elapsed.Seconds, $timeoutInMinutes) -Verbose
        Start-Sleep $waitInSeconds
    }    
    $stopwatch.Stop()

    Write-Verbose "Healthy session hosts:" -Verbose
    Write-Verbose "======================" -Verbose
    $healthySessionHosts = $latestSessionHosts | Where-Object { $_.Status -eq 'Available' }
    if ($healthySessionHosts.Count -gt 0) {
        Write-Verbose ($healthySessionHosts | Select-Object Name, Status | Sort-Object Name | Format-Table | Out-String) -Verbose
    }
    else {
        Write-Warning "- NONE"
    }   

    Write-Verbose "Unhealthy session hosts:" -Verbose
    Write-Verbose "========================" -Verbose
    if ($unhealthyVMs.Count -gt 0) {
        Write-Verbose ($unhealthyVMs | Select-Object Name, Status | Sort-Object Name | Format-Table | Out-String) -Verbose
    }
    else {
        Write-Verbose "- NONE" -Verbose
    }

    if($allVMsHealthy) {
        return
    }

    throw ("RESULT: Even after the [{0}] minute timeout there are still [{1}] session hosts in an unhealthy state." -f $timeoutInMinutes, $unhealthyVMs.Count)
}