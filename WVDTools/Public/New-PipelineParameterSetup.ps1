<#
.SYNOPSIS
Generate the deployment parameter files required by the WVD deployment using the provided values

.DESCRIPTION
The files are generated from the templates in the "templateFolderPath".
Every value defined as [KeyWord] is replaced with a token of the .psd1 file store in the "parameterSourcePath"
The resulting files are stored in the given path with the same name as the templates, but without the ".template" in their name

.PARAMETER templateFolderPath
The path to the templates folder
Can contain any time of file with '[keyword]' tokens

.PARAMETER parameterSourcePath
The path to the file containing the values for the given keywords (must be a .psd1 file)

.PARAMETER targetFolderPath
The folder to store the resulting parameter files in.

.PARAMETER templateSeachPattern
The pattern to select the desired template files with. Default is "*"

.PARAMETER recurse
Search recursively in the provided targetFolderPath

.PARAMETER maintainFolderStructure
Controls whether or not to store the output files in the same folder structure as the source templates 

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
New-WVDToolsPipelineParameterSetup -targetFolderPath 'C:\dev\ip\WVD-Automation\WVDTools\bin'

Generates the requried tokenized parameter files in path 'C:\dev\ip\WVD-Automation\WVDTools\bin'

.EXAMPLE
New-WVDToolsPipelineParameterSetup -targetFolderPath 'C:\dev\ip\WVD-Automation\WVDTools\bin' -templateSeachPattern "wvd*"

Generates the requried tokenized parameter files matching the file pattern 'wvd*' in path 'C:\dev\ip\WVD-Automation\WVDTools\bin'

.EXAMPLE
New-WVDToolsPipelineParameterSetup -targetFolderPath 'C:\Users\user\Desktop\Test' -Verbose -recurse -maintainFolderStructure

Generate the required tokenized parameter files in the target folder 'Test' while recreating the data/folder structure found in the default template folder
#>
function New-PipelineParameterSetup {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [string] $templateFolderPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "static\templates\pipelineInput"),

        [Parameter(Mandatory = $false)]
        [string] $parameterSourcePath = (Join-Path (Split-Path $PSScriptRoot -Parent) "static\appliedParameters.psd1"),

        [Parameter(Mandatory)]
        [string] $targetFolderPath,

        [Parameter(Mandatory = $false)]
        [string] $templateSeachPattern = "*",

        [Parameter(Mandatory = $false)]
        [switch] $recurse,

        [Parameter(Mandatory = $false)]
        [switch] $maintainFolderStructure
    )

    Write-Verbose "Load parameters file from '$parameterSourcePath'"
    $parametersObject = Import-PowerShellDataFile -Path $parameterSourcePath

    Write-Verbose "Load templates from '$templateFolderPath'"
    $filesInputObject = @{
        Path    = $templateFolderPath 
        Include = $templateSeachPattern 
        Recurse = $recurse
    }
    $templatePaths = Get-ChildItem @filesInputObject | Where-Object { $_.Attributes -eq 'Archive' } |  ForEach-Object { $_.FullName }
    foreach ($templatePath in $templatePaths) {

        Write-Verbose "Load template from '$templatePath'"
        $content = Get-Content -Path $templatePath

        Write-Verbose "Replace tokens"
        foreach ($key in $parametersObject.Keys) {
            if ($parametersObject[$key] -is [string]) {
                $content = $content.Replace("[$key]", $parametersObject[$key])
            }
            elseif ($parametersObject[$key] -is [bool]) {
                # Required for e.g. bool
                $content = $content.Replace(('"[{0}]"' -f $key), $parametersObject[$key].ToString().ToLower())
                $content = $content.Replace(('[{0}]' -f $key), $parametersObject[$key].ToString().ToLower()) # for e.g. variable file
            }
            else {
                # Required for e.g. integer
                $content = $content.Replace(('"[{0}]"' -f $key), $parametersObject[$key])
                $content = $content.Replace(('[{0}]' -f $key), $parametersObject[$key]) # for e.g. variable file
            }
        }

        $fileName = (Split-Path -Path $templatePath -Leaf).Replace('template.', '')
        
        if ($maintainFolderStructure -and ((Split-Path $templatePath -Parent) -ne $templateFolderPath)) {
            Write-Verbose "Template resides in subfolder. Recreating storage structure"
                
            $subPath = (Split-Path $templatePath -Parent).Replace($templateFolderPath, '')
            $subFolders = $subPath.Split('\')
                
            $tempPath = $targetFolderPath
            foreach ($folder in $subFolders) {
                $tempPath = Join-Path $tempPath $folder  
                if (-not (Test-Path $tempPath)) {
                    Write-Verbose "Path to folder '$folder' not existing. Creating"
                    if ($PSCmdlet.ShouldProcess("Folder in path '$tempPath'", "Create")) {
                        $null = New-Item -ItemType Directory -Path $tempPath
                    }
                }
            }
            $targetPath = Join-Path $tempPath $fileName
        }
        else {
            $targetPath = Join-Path $targetFolderPath $fileName
        }

        if (-not (Test-Path $targetPath)) {
            Write-Verbose "Generate file '$targetPath'"
            if ($PSCmdlet.ShouldProcess("File in path '$targetPath'", "Create")) {
                $null = New-Item -ItemType File -Path $targetPath
            }
        }
        if ($PSCmdlet.ShouldProcess("File in path '$targetPath'", "Update")) {
            Set-Content -Value $content -Path $targetPath
        }
    }
}