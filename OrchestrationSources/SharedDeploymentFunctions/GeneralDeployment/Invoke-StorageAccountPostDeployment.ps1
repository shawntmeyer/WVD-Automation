<#
.SYNOPSIS
Run the Post-Deployment for the storage account deployment

.DESCRIPTION
Run the Post-Deployment for the storage account deployment
- Upload required data to the storage account

.PARAMETER orchestrationFunctionsPath
Mandatory. Path to the required functions

.PARAMETER storageAccountName
Mandatory. Name of the storage account to host the deployment files

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
Invoke-StorageAccountPostDeployment -orchestrationFunctionsPath $currentDir -storageAccountName "wvdStorageAccount"

Upload any required data to the storage account
#>
function Invoke-StorageAccountPostDeployment {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory)]
        [string] $orchestrationFunctionsPath,

        [Parameter(Mandatory)]
        [string] $resourceGroupPath,

        [Parameter(Mandatory)]
        [string] $wvdUploadsPath,

        [Parameter(Mandatory)]
        [string] $targetContainer,

        [Parameter(Mandatory)]
        [string] $storageAccountName
    )

    begin {
        Write-Verbose ("[{0} entered]" -f $MyInvocation.MyCommand)
        . "$orchestrationFunctionsPath\Storage\StorageAccountHelperFunctions.ps1"
    }

    process {

        Write-Verbose "###########################################"
        Write-Verbose "## 1 - Download software from public url ##"
        Write-Verbose "###########################################"

        Write-Verbose("##########################################")
        Write-Verbose("## 1.0 - Gather Files                   ##")
        Write-Verbose("##########################################")

        $rgSourcesPath = Join-Path $resourceGroupPath 'Parameters/Uploads'
        $gatherFilesPath = Join-Path $rgSourcesPath 'cse.file.setup.config.json'
        if (Test-Path -Path $gatherFilesPath -ErrorAction 'SilentlyContinue') {
            $filesToGather = (Get-Content $gatherFilesPath -Raw | ConvertFrom-Json).Mapping
            foreach ($fileToGather in $filesToGather) {
                $copyItemInputObject = @{
                    Path        = Join-Path $rgSourcesPath $fileToGather.SourcePath 
                    Destination = Join-Path $wvdUploadsPath $fileToGather.TargetPath
                    Force       = $true
                }
                if ($PSCmdlet.ShouldProcess(("File from [{0}] to [{1}]" -f $copyItemInputObject.Path, $copyItemInputObject.Destination), "Copy")) {
                    Copy-Item @copyItemInputObject | Out-Null
                }
            }
        }

        Write-Verbose("##########################################")
        Write-Verbose("## 1.1 - LOAD DATA                      ##")
        Write-Verbose("##########################################")
        $downloadFilePath = (Join-Path "$wvdUploadsPath/WVDScripts" "downloads.parameters.json")
        if (Test-Path $downloadFilePath -ErrorAction 'SilentlyContinue') {
            $downloadJson = Get-Content -Path $downloadFilePath -Raw -ErrorAction 'Stop'

            try {
                $Downloads = $downloadJson | ConvertFrom-Json -ErrorAction 'Stop'
            }
            catch {
                Write-Error "Configuration JSON content could not be converted to a PowerShell object" -ErrorAction 'Stop'
            }

            Write-Verbose("##########################################")
            Write-Verbose("## 1.2 - EVALUATE                       ##")
            Write-Verbose("##########################################")

            foreach ($Download in $Downloads.WVDImageSoftware) {
                $SoftwareName = $Download.Name
                $OutputFile = (Join-Path "$wvdUploadsPath/WVDScripts" $Download.DestinationFilePath)
                If ($Download.DownloadUrl -ne '') {
                    $DownloadUrl = $Download.DownloadUrl
                }
                Elseif ($Download.WebSiteUrl -ne '' -and $Download.SearchString -ne '') {
                    Write-Output "Extracting latest download Url for '$SoftwareName' from Internet Website."
                    $WebSiteUrl = $Download.WebSiteUrl
                    $SearchString = $Download.SearchString
                    $DownloadUrl = Get-InternetUrl -WebSiteUrl $WebSiteUrl -searchstring $SearchString -ErrorAction SilentlyContinue
                }
                Elseif ($Download.APIUrl -ne '') {
                    $EdgeUpdatesJSON = Invoke-WebRequest -Uri $Download.APIUrl -UseBasicParsing
                    $content = $EdgeUpdatesJSON.content | ConvertFrom-Json
                    $policyfiles = ($content | Where-Object {$_.Product -eq 'Policy'}).releases    
                    $latestpolicyfiles = $policyfiles | Sort-Object ProductVersion | Select-Object -last 1        
                    $EdgeTemplatesUrl = ($latestpolicyfiles.artifacts | Where-Object {$_.location -like '*.zip'}).Location         
                    $Edgereleases = ($content | Where-Object {$_.Product -eq 'Stable'}).releases
                    $latestrelease = $Edgereleases | Where-Object {$_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64'} | Sort-Object ProductVersion | Select-Object -last 1
                    $EdgeUrl = $latestrelease.artifacts.location
                    If ($SoftwareName -eq 'Edge Enterprise') {
                        $DownloadUrl = $EdgeUrl
                    }
                    Elseif ($SoftwareName -eq 'Edge Enterprise Administrative Templates') {
                        $DownloadUrl = $EdgeTemplatesUrl
                    }
                }
                Elseif ($Download.GitHubRepo -ne '') {
                    $Repo = $Download.GitHubRepo
                    $FileNamePattern = $Download.GitHubFileNamePattern
                    $ReleasesUri = "https://api.github.com/repos/$Repo/releases/latest"
                    $DownloadUrl = ((Invoke-RestMethod -Method GET -Uri $ReleasesUri).assets | Where-Object name -like $FileNamePattern ).browser_download_url
                }

                If (($DownloadUrl -ne '') -and ($null -ne $DownloadUrl)) {
                    Write-Output "Download URL = '$DownloadUrl'"
                    Write-Output "Downloading '$SoftwareName' from Internet."
                    Try {
                        Get-InternetFile -Url $DownloadUrl -OutputFile $OutputFile
                        Write-Output "Finished downloading '$SoftwareName' from Internet onto agent for upload to storage account."
                    }
                    Catch {
                        Write-Warning "Error downloading software from '$DownloadUrl'."
                        $outputDir = split-path $outputfile -parent
                        Remove-Item -Path $outputDir -Recurse -Force
                    }

                }
                Else {
                    Write-Warning "No Internet URL found for '$SoftwareName'."
                    $outputDir = split-path $outputfile -parent
                    Remove-Item -Path $outputDir -Recurse -Force
                }             
            }
        }
        else {
            Write-Verbose "No software configured to be downloaded"
        }
        
        Write-Verbose "########################################################"
        Write-Verbose "## 2 - Create zip files for all WVDScripts subfolders ##"
        Write-Verbose "########################################################"

        $zipDestinationFolder = ("{0}/WVDImageSourceZiptoUpload" -f (Split-Path "$wvdUploadsPath/WVDScripts" -Parent))

        $InputObject = @{
            SourceFolderPath      = "$wvdUploadsPath/WVDScripts"
            DestinationFolderPath = $zipDestinationFolder
        }
        if ($PSCmdlet.ShouldProcess("[$wvdUploadsPath/WVDScripts] subfolders as .zip and store them into [$zipDestinationFolder]", "Compress")) {
            Compress-SubFolderContents @InputObject -Verbose
            Write-Verbose "WVD Customization Source Files compression finished"
        }

        Write-Verbose ("##########################################")
        Write-Verbose ("## 3 - Upload to storage account        ##")
        Write-Verbose ("##########################################")

        $InputObject = @{
            ResourceGroupName  = (Get-AzResource -Name $storageAccountName -ResourceType 'Microsoft.Storage/storageAccounts').ResourceGroupName
            StorageAccountName = $storageAccountName
            contentDirectories = $zipDestinationFolder
            targetContainer    = $targetContainer
        }
        if ($PSCmdlet.ShouldProcess("Image Source content into storage account '$storageAccountName'", "Add Content to")) {
            Add-ContentToBlobContainer @InputObject -Verbose
            Write-Verbose "Storage account content upload invocation finished"
        }
    }

    end {
        Write-Verbose ("[{0} exited]" -f $MyInvocation.MyCommand)
    }
}