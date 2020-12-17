<#
.SYNOPSIS
Trigger the deployment of a given module

.DESCRIPTION
Trigger the deployment of a given module. The template has to be stored in either a storage account or artifact feed

.PARAMETER parameterFilePath
Mandatory. The parameter file to be used for the deployment

.PARAMETER resourcegroupName
Optional. The resource group to deploy into if handling a resource group level deployment

.PARAMETER location
Optional. The location to deploy into. If performing a resource group level deployment the location is has usually a default that is pointing to the resource group location

.PARAMETER optionalParameters
Optional. Parameters to provide in addition to the ones in the parameter file

.PARAMETER managementGroupId
Optional. The management group id if deployment to the management group level

.PARAMETER moduleName
Explicit name of the module to deploy. Required to find the module files when using a storage account to store modules

.PARAMETER componentStorageAccountName
Optional. Name of the component storage account that hosts the module files. Required to find the module files when using a storage account to store modules

.PARAMETER componentStorageContainerName
Optional. Name of the container in the storage account that hosts the module files. Required to find the module files when using a storage account to store modules

.PARAMETER moduleVersion
Optional. Explicit version of the module to deploy. Required to find the module files when using a storage account to store modules
Does not have to be provided in case of the artifact feed as downloading the correct version is already handled during the artifacts download

.PARAMETER modulePackagePath
Optional. Path to module folder if downloaded previously. This should be the case when using an artifact feed.

.EXAMPLE
Invoke-GeneralDeployment -resourcegroupName 'bsd-prod-dispatcher-hostpool-rg' -modulePackagePath '/azp/agent/_work/3/s/ModulePackages/WVDHostPool' -parameterFilePath $parameterFilePath

Deploy a host pool into the resource group 'bsd-prod-dispatcher-hostpool-rg' using the previously downloaded modile files in path '/azp/agent/_work/3/s/ModulePackages/WVDHostPool'

.EXAMPLE
Invoke-GeneralDeployment -resourcegroupName 'bsd-prod-dispatcher-hostpool-rg' -modulePackagePath '/azp/agent/_work/3/s/ModulePackages/WVDHostPool' -parameterFilePath $parameterFilePath -location 'WestEurope'

Deploy a host pool into the resource group 'bsd-prod-dispatcher-hostpool-rg' using the previously downloaded modile files in path '/azp/agent/_work/3/s/ModulePackages/WVDHostPool' using the explicit location 'WestEurope'

.EXAMPLE
Invoke-GeneralDeployment -modulePackagePath '/azp/agent/_work/3/s/ModulePackages/ResourceGroup' -parameterFilePath $parameterFilePath -location WestEurope

Deploy a resource group into location 'WestEurope' using the previously downloaded modile files in path '/azp/agent/_work/3/s/ModulePackages/WVDHostPool'

.EXAMPLE
Invoke-GeneralDeployment -componentStorageContainerName 'components' -componentStorageAccountName 'wvdtemplatestore' -moduleName 'ResourceGroup' -moduleVersion '0.0.1' -parameterFilePath $parameterFilePath -location WestEurope

Deploy a resource group with version '0.0.1' into location 'WestEurope' using the module files stored in the storage account 'wvdtemplatestore'
#>
function Invoke-GeneralDeployment {

  [CmdletBinding()]
  param(   
    [Parameter(Mandatory)]
    [string] $parameterFilePath,

    [Parameter(Mandatory = $false)]
    [string] $resourcegroupName,

    [Parameter(Mandatory = $false)]
    [string] $location,

    [Parameter(Mandatory = $false)]
    [hashtable] $optionalParameters,
    
    [Parameter(Mandatory = $false)]
    [string] $managementGroupId,

    [Parameter(
      Mandatory, 
      ParameterSetName = "StorageAccountArtifacts"
    )]
    [string] $moduleName,

    [Parameter(
      Mandatory, 
      ParameterSetName = "StorageAccountArtifacts"
    )]
    [string] $componentStorageAccountName,

    [Parameter(
      Mandatory, 
      ParameterSetName = "StorageAccountArtifacts"
    )]
    [string] $componentStorageContainerName,
    
    [Parameter(
      Mandatory, 
      ParameterSetName = "StorageAccountArtifacts"
    )]
    [string] $moduleVersion,

    [Parameter(
      Mandatory, 
      ParameterSetName = "DevOpsArtifacts"
    )]
    [string] $modulePackagePath
  )

  begin {
    Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)
  }

  process {
    $DeploymentInputs = @{}
    if ($modulePackagePath) {
      Write-Verbose "Deploying with Artifact-Feed modules" -Verbose
      $templateFilePath = Join-Path $modulePackagePath 'deploy.json'
      $DeploymentInputs += @{ TemplateFile = $templateFilePath }
      $moduleName = Split-Path $modulePackagePath -Leaf
      $deploymentFile = ConvertFrom-Json (Get-Content $templateFilePath -Raw)
    }
    else {
      Write-Verbose "Deploying with storage account modules" -Verbose
      $storageAccount = Get-AzResource -Name $componentStorageAccountName -ResourceType 'Microsoft.Storage/storageAccounts'
      $SASKey = (Get-AzStorageAccountKey -AccountName $storageAccount.Name -ResourceGroupName $storageAccount.ResourceGroupName)[0]
      $templateUri = 'https://{0}.blob.core.windows.net/{1}/Modules/ARM/{2}/{3}/deploy.json?{4}' -f $componentStorageAccountName, $componentStorageContainerName, $moduleName, $moduleVersion, $SASKey.Value
      $DeploymentInputs += @{ TemplateUri = $templateUri }
      $deploymentFile = Invoke-RestMethod -Uri $templateUri -Method 'GET'
    }

    Write-Verbose "Parameters are" -Verbose
    $param = ConvertFrom-Json (Get-Content -Raw -Path $parameterFilePath)
    $paramSet = @{ }
    $param.parameters | Get-Member -MemberType NoteProperty | ForEach-Object { 
      $key = $_.Name
      $value = $param.parameters.($_.Name).Value
      if ($value -is [string]) {
        $formattedValue = $value.subString(0, [System.Math]::Min(15, $value.Length))
        if ($value.Length -gt 40) {
          $formattedValue += '...'
        }
      }
      else {
        $formattedValue = $value
      }
      $paramSet[$key] = $formattedValue
    }
    Write-Verbose ($paramSet | Format-Table | Out-String) -Verbose

    Write-Verbose "Additional Parameters are"
    Write-Verbose ($optionalParameters | Format-Table | Out-String) -Verbose

    $DeploymentInputs += @{
      Name                  = ("{0}-{1}" -f $moduleName, (Get-Date -Format yyyMMddHHmmss))
      TemplateParameterFile = $parameterFilePath
      Verbose               = $true
      ErrorAction           = "Stop"
    }

    if (-not ([String]::IsNullOrEmpty($location))) {
      $DeploymentInputs += @{
        Location = $location
      }
    }

    Foreach ($key in $optionalParameters.Keys) {
      $DeploymentInputs += @{
        $key = $optionalParameters.Item($key)
      }
    }

    $deploymentSchema = $deploymentFile.'$schema' # Works with PS7
    Write-Verbose "Evaluating schema [$deploymentSchema]" -Verbose
    switch -regex ($deploymentSchema) {
      '\/deploymentTemplate.json#$' {
        Write-Verbose 'Handling resource group level deployment' -Verbose
        $Deployment = New-AzResourceGroupDeployment @DeploymentInputs -ResourceGroupName $resourcegroupName
        break
      }
      '\/subscriptionDeploymentTemplate.json#$' {
        Write-Verbose 'Handling subscription level deployment' -Verbose
        $Deployment = New-AzSubscriptionDeployment @DeploymentInputs
        break
      }
      '\/managementGroupDeploymentTemplate.json#$' {
        Write-Verbose 'Handling management group level deployment' -Verbose
        $DeploymentInputs += @{ ManagementGroupId = $managementGroupId } 
        $Deployment = New-AzManagementGroupDeployment @DeploymentInputs
        break
      }
      '\/tenantDeploymentTemplate.json#$' {
        Write-Verbose 'Handling tenant level deployment' -Verbose
        $Deployment = New-AzTenantDeployment @DeploymentInputs
        break
      }
      default {
        throw "[$deploymentSchema] is a non-supported ARM template schema"
      }
    }

    if ($Deployment.Outputs) {
      foreach ($Outputkey in $Deployment.Outputs.Keys) {
        Write-Verbose "Set [$Outputkey] deployment output as pipeline environment variable" -Verbose
        Write-Host ("##vso[task.setvariable variable={0};isOutput=true]{1}" -f $Outputkey, $Deployment.Outputs[$Outputkey].Value)
      }
    }
    Write-Verbose "Deployment successful" -Verbose
  }

  end {
    Write-Debug ("[{0} existed]" -f $MyInvocation.MyCommand)
  }
}