<#
.SYNOPSIS
Extract the download URL from a website based on a search string. Uses a matching search string by prepending and appending a wildcard character to the string.

.DESCRIPTION


.PARAMETER Url
Specifies the URI to search for a link.

.PARAMETER SearchString
Specifies the search string that is used to find a matching hyperlink.

.EXAMPLE
Get-InternetUrl -WebSiteUrl "http://www.microsoft.com/software/wvd" -SearchString "FSLogix"

Searches the provided website url for a hyperlink with the searchstring "FSLogix" contained in it and returns the url. 
#>

Function Get-InternetUrl {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory,
            HelpMessage = "Specifies the website that contains a link to the desired download."
        )]
        [uri]$WebSiteUrl,

        [Parameter(
            Mandatory,
            HelpMessage = "Specifies the search string. Wildcard '*' can be used."    
        )]
        [string]$SearchString
    )

    Try {
        Write-Verbose "Now extracting download URL from '$WebSiteUrl'."
        $HTML = Invoke-WebRequest -Uri $WebSiteUrl -UseBasicParsing
        $Links = $HTML.Links
        $ahref = $null
        $ahref=@()
        $ahref = ($Links | Where-Object {$_.href -like "*$searchstring*"})
        If ($ahref.count -eq 0 -or $null -eq $ahref) {
            $ahref = ($Links | Where-Object {$_.OuterHTML -like "*$searchstring*"})
        }
        
        If ($ahref.Count -gt 0) {
            Write-Verbose "Download URL = '$($ahref[0].href)'"
            Return $ahref[0].href
        }
        Else {
            Write-Warning "No download URL found using search term."
            Return $null
        }
    }
    Catch {
        Write-Error "Error Downloading HTML and determining link for download."
        Return
    }
}

<#
.SYNOPSIS
Downloads the file located at the specified url and saves it to the output file location.

.DESCRIPTION
Downloads the file located at the specified url and saves it to the output file location.

.PARAMETER Url
Specifies the URI to search for a link.

.PARAMETER OutputFile
Specifies the search string that is used to find a matching hyperlink.

.EXAMPLE
Get-InternetFile -Url "aka.ms/fslogix_install" -OutputFile "c:\temp\FSLogix.zip"

#>

Function Get-InternetFile {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory,
            HelpMessage = "The Uniform Resource Location for the download."
        )]
        [uri]$url,
        [Parameter(
            Mandatory,
            HelpMessage = "The output file name including path."    
        )]
        [string]$outputfile

    )

    $start_time = Get-Date 
    $wc = New-Object System.Net.WebClient
    Write-Verbose "Downloading file at '$url' to '$outputfile'."
    Try {
        $wc.DownloadFile($url, $outputfile)
    
        $time = (Get-Date).Subtract($start_time).Seconds
        
        Write-Verbose "Time taken: '$time' seconds."
        if (Test-Path -Path $outputfile) {
            $totalSize = (Get-Item $outputfile).Length / 1MB
            Write-Verbose "Download was successful. Final file size: '$totalsize' mb"
        }
    }
    Catch {
        Write-Error "Error downloading file. Please check url."
        Return
    }
}

<#
.SYNOPSIS
Compress Scripts and Executable files to a zip archive.

.DESCRIPTION
This cmdlet performs compression for all content of each subfolder of a specified source folder into a specified destination folder.

.PARAMETER SourceFolderPath
Specifies the location containing subfolders to be compressed.

.PARAMETER DestinationFolderPath
Specifies the location for the .zip files.

.PARAMETER CompressionLevel
Specifies how much compression to apply when creating the archive file. Fastest as default.

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
    Compress-SubFolderContents -SourceFolderPath "\\path\to\sourcefolder" -DestinationFolderPath "\\path\to\destinationfolder"

    Creates the "\\path\to\destinationfolder" if not existing
    Moves there the scriptExtensionMasterInstaller.ps1 master script for CSE
    For each subfolder in "\\path\to\sourcefolder" creates an archive with the fastest compression level named "subfolder.zip" in the "\\path\to\destinationfolder".
#>

function Compress-SubFolderContents {

    [CmdletBinding(SupportsShouldProcess = $True)]
    param(
        [Parameter(
            Mandatory,
            HelpMessage = "Specifies the location containing subfolders to be compressed."
        )]
        [string] $SourceFolderPath,

        [Parameter(
            Mandatory,
            HelpMessage = "Specifies the location for the .zip files."
        )]
        [string] $DestinationFolderPath,

        [Parameter(
            Mandatory = $false,
            HelpMessage = "Specifies how much compression to apply when creating the archive file. Fastest as default."
        )]
        [string] $CompressionLevel = "Fastest"
    )

    
    Write-Verbose "## Checking destination folder existance $DestinationFolderPath"
    If (!(Test-path $DestinationFolderPath)) {
        Write-Verbose "Not existing, creating..."
        New-Item -ItemType "directory" -Path $DestinationFolderPath
    }

    Write-Verbose "## Create archives "
    $subfolders = Get-ChildItem $SourceFolderPath | Where-Object {$_.PSISContainer}
    foreach ($sf in $subfolders){
        try {
            $sfname = $sf.Name + ".zip"
            $destinationFilePath = Join-Path -Path $DestinationFolderPath -ChildPath ($sfname)
            $sourceFilePath = Join-Path -Path $sf.FullName -ChildPath "*"

            Write-Verbose "Working on subfolder $sf"
            Write-Verbose "Archive will be created from path $sourceFilePath"
            Write-Verbose "Archive will be stored as $destinationFilePath"
            
            $CompressInputObject = @{
                Path = $sourceFilePath
                DestinationPath = $destinationFilePath
                CompressionLevel = $CompressionLevel   
                Force = $true 
            }

            Write-Verbose "Starting compression...."
            if ($PSCmdlet.ShouldProcess("Required files from $sourceFilePath to $destinationFilePath", "Compress")) {
                Compress-Archive @CompressInputObject
            }
            Write-Verbose "Compression completed."
        }
        catch {
            Write-Error "Compression FAILED: $_"
        } 
    }
}

<#
.SYNOPSIS
Upload Scripts and Executable files needed to customize WVD VMs to the created Storage Accounts blob containers.

.DESCRIPTION
This cmdlet uploads files specifiied in the contentToUpload-sourcePath parameter to the blob specified in the contentToUpload-targetBlob parameter to the specified Azure Storage Account.

.PARAMETER ResourceGroupName
Name of the resource group that contains the Storage account to update.

.PARAMETER StorageAccountName
Name of the Storage account to update.

.PARAMETER contentToUpload
Optional. Array with a contentmap to upload.
E.g. $( @{ sourcePath = 'WVDScripts'; targetBlob = 'wvdscripts' })

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
    Add-ContentToBlobContainer -ResourceGroupName "RG01" -StorageAccountName "storageaccount01"

    Uploads files contained in the WVDScripts Repo folder and the files contained in the WVDScaling Repo folder
    respectively to the "wvdscripts" blob container and to the "wvdScaling" blob container in the Storage Account "storageaccount01"
    of the Resource Group "RG01"

.EXAMPLE
    Add-ContentToBlobContainer -ResourceGroupName "RG01" -StorageAccountName "storageaccount01" -contentToUpload $( @{ sourcePath = 'WVDScripts'; targetBlob = 'wvdscripts' })
    
    Uploads files contained in the WVDScripts Repo folder to the "wvdscripts" blob container in the Storage Account "storageaccount01"
    of the Resource Group "RG01"
#>
function Add-ContentToBlobContainer {
    [CmdletBinding(SupportsShouldProcess = $True)]
    param(
        [Parameter(
            Mandatory,
            HelpMessage = "Specifies the name of the resource group that contains the Storage account to update."
        )]
        [string] $ResourceGroupName,

        [Parameter(
            Mandatory,
            HelpMessage = "Specifies the name of the Storage account to update."
        )]
        [string] $StorageAccountName,

        [Parameter(
            Mandatory,
            HelpMessage = "The paths to the content to upload."
        )]
        [string[]] $contentDirectories,

        [Parameter(
            Mandatory,
            HelpMessage = "The name of the container to upload to."
        )]
        [string] $targetContainer
    )

    Write-Verbose "Getting storage account context."
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName -ErrorAction Stop
    $ctx = $storageAccount.Context

    foreach ($contentDirectory in $contentDirectories) {

        try {
            Write-Verbose "Processing content in path: [$contentDirectory]"
    
            Write-Verbose "Testing local path"
            If (-Not (Test-Path -Path $contentDirectory)) {
                throw "Testing local paths FAILED: Cannot find content path to upload [$contentDirectory]"
            }
            Write-Verbose "Getting files to be uploaded..."
            $scriptsToUpload = Get-ChildItem -Path $contentDirectory -ErrorAction 'Stop'
            Write-Verbose "Files to be uploaded:"
            Write-Verbose ($scriptsToUpload.Name | Format-List | Out-String)

            Write-Verbose "Testing blob container"
            Get-AzStorageContainer -Name $targetContainer -Context $ctx -ErrorAction 'Stop' | Out-Null
            Write-Verbose "Testing blob container SUCCEEDED"
    
            if ($PSCmdlet.ShouldProcess("Files to the '$targetContainer' container", "Upload")) {
                $scriptsToUpload | Set-AzStorageBlobContent -Container $targetContainer -Context $ctx -Force -ErrorAction 'Stop' | Out-Null
            }
            Write-Verbose ("[{0}] files in directory [{1}] uploaded to container [{2}]" -f $scriptsToUpload.Count, $contentDirectory, $targetContainer)
        }
        catch {
            Write-Error "Upload FAILED: $_"
        }
    }
}

<#
.SYNOPSIS
Add a Blob Specific SAS token to a Uri in a file.

.DESCRIPTION
This cmdlet generates a storage account Shared Access Signature token good for 3 hours and then dynamically adds the token to the specified file by replacing <SAS> with the token in the file.

.PARAMETER filepath
the path to the file to be updated with the signature

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
    Set-BlobSASInFile -FilePath "c:\windows\temp\filename.ps1"

    Replaces <SAS> in filename.ps1 with a SAS token from the storage account referenced in the ps1.
#>
function Set-BlobSASInFile {

	[CmdletBinding(SupportsShouldProcess)]
	param (
		[Parameter()]
		[string] $filePath
	)

	$FileContent = Get-Content -Path $filePath
    $saslines = $FileContent | Where-Object { $_ -like "*<SAS>*" } | ForEach-Object { $_.Trim() }
    
 	Write-Verbose ("Found [{0}] lines with sas tokens (<SAS>) to replace" -f $saslines.Count)

	foreach ($line in $saslines) {
		Write-Verbose "Evaluate line [$line]" -Verbose
		$null = $line -cmatch "https.*<SAS>"
		$fullPath = $Matches[0].Replace('https://', '').Replace('<SAS>', '')
        $pathElements = $fullPath.Split('/')
        $containerName = $pathElements[1]
        $fileName = $pathElements[2]
        $storageAccountName = $pathElements[0].Replace('.blob.core.windows.net', '')

		$storageAccountResource = Get-AzResource -Name $storageAccountName -ResourceType 'Microsoft.Storage/storageAccounts'

		if(-not $storageAccountResource) {
			throw "Storage account [$storageAccountName] not found"
		}

		$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $storageAccountResource.ResourceGroupName -Name $storageAccountName)[0].Value
        $storageContext = New-AzStorageContext $StorageAccountName -StorageAccountKey $storageAccountKey
        
	    $sasToken = New-AzStorageBlobSASToken -Container $containerName -Blob $fileName -Permission 'r' -StartTime (Get-Date) -ExpiryTime (Get-Date).AddHours(2) -Context $storageContext

		$newString = $line.Replace('<SAS>', $sasToken)

		$FileContent = $FileContent.Replace($line, $newString)
	}
		
	if ($PSCmdlet.ShouldProcess("File in path [$filePath]", "Overwrite")) {
		Set-Content -Path $filePath -Value $FileContent -Force
	}
}

<#
.SYNOPSIS
Add a Container Specific SAS token to a Uri in a file.

.DESCRIPTION
This cmdlet generates a storage account Shared Access Signature token good for 3 hours and then dynamically adds the token to the specified file by replacing <SAS> with the token in the file.

.PARAMETER filepath
the path to the file to be updated with the signature

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
    Set-ContainerSaSinFile -FilePath "c:\windows\temp\filename.ps1"

    Replaces <SAS> in filename.ps1 with a SAS token from the storage account referenced in the ps1.
#>
function Set-ContainerSASInFile {

	[CmdletBinding(SupportsShouldProcess)]
	param (
        [Parameter(Mandatory)]
        [string] $StorageAccount,
        [Parameter(Mandatory)]
		[string] $Container,
		[Parameter(Mandatory)]
		[string] $filePath
	)

	$FileContent = Get-Content -Path $filePath
    $saslines = $FileContent | Where-Object { $_ -like "*<SAS>*" } | ForEach-Object { $_.Trim() }
    
    If ($saslines.count -gt 0) {
        Write-Verbose ("Found [{0}] lines with sas tokens (<SAS>) to replace" -f $saslines.Count)
        $storageAccountResource = Get-AzResource -Name $storageAccount -ResourceType 'Microsoft.Storage/storageAccounts'

		if(-not $storageAccountResource) {
			throw "Storage account [$storageAccount] not found"
        }

        $storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $storageAccountResource.ResourceGroupName -Name $storageAccount)[0].Value
        $storageContext = New-AzStorageContext $StorageAccount -StorageAccountKey $storageAccountKey
        $sasToken = New-AzStorageContainerSASToken -Name $Container -Permission 'rl' -StartTime (Get-Date) -ExpiryTime (Get-Date).AddHours(2) -Context $storageContext
        Foreach ($line in $saslines) {
            $newString = $line.Replace('<SAS>', $sasToken)
            $FileContent = $FileContent.Replace($line, $newString)
        }

        if ($PSCmdlet.ShouldProcess("File in path [$filePath]", "Overwrite")) {
            Set-Content -Path $filePath -Value $FileContent -Force
        }
    }
}