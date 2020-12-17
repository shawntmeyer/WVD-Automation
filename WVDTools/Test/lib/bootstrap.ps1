<#
.SYNOPSIS
!This script is not officially supported by Microsoft.!cls
Installed requested PowerShell Module

.DESCRIPTION
!This script is not officially supported by Microsoft.!
Checks if the provided module is already on the computer
If not with the correct version or exsisting at all, the script tries to downlaod and install the module.

There are two options.
1. runs `install-module` on the PSGallery
2. runs git actions
a. clone on from the provided repository
b. pull from the master

The module is then loaded with `import-module`

.PARAMETER RequiredModule
Module to be loaded

.PARAMETER Path
Path of the root folder, will download remote repositories there

.PARAMETER Scope
Scope of the installation, for PSGallery

.PARAMETER Test
Will not checkout to master branch

.EXAMPLE
Install-Dependency -RequiredModule @{ ModuleSpecification = @{ ModuleName = "Pester"; RequiredVersion = "4.4.1" }; Repository = "PSGallery" } -Path "C:/dev" -Scope "User"

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     4.4.1      Pester                              {Add-AssertionOperator, AfterAll, AfterEach, AfterEachFeature...}

.EXAMPLE
Install-Dependency -RequiredModule @{ ModuleSpecification = @{ ModuleName = "Shared"; RequiredVersion = "0.0.0" }; Repository = "https://contoso.visualstudio.com/DefaultCollection/apps/_git/contoso-az-automation-vnet"" } -Path "../" -Scope "User"

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.1.0      Shared                         {...}

Notice, RequiredVersion 0.0.0 will indicate latest, if remote git repository is provided, the version number is not considered
Notice the Path is relative to the execution of the script. It uses `(Get-Item $PSScriptRoot).parent.parent.FullName`

.NOTES
This command will only clone the master branch.
If you want to reuse the cloned repo you have to reset the fetch. (Git version 1.8.2.)
Run:
`git config remote.origin.fetch "+refs/heads/*:refs/remotes/origin/*"`
`git fetch origin`
Now it will in sync with the origin

===========================================================================
Created on:   	09/2019
Created by:   	Mark Warneke & Alexander Sehr
Organization: 	Microsoft
Reference:      https://github.com/MarkWarneke
===========================================================================
#>



#region script
[CmdletBinding()]
param(
    # Select scope of module
    [ValidateSet("CurrentUser", "AllUsers")]
    [string] $Scope = "CurrentUser",
    [switch] $test = $false
)

$Path = (Get-Item $PSScriptRoot).parent.parent.FullName

$RequiredModules = Import-LocalizedData -BaseDirectory $PSScriptRoot -FileName RequiredTestModules

if (!$RequiredModules) {
    Write-Warning 'Required Modules not found, no dependencies imported'
}
else {
    Write-Verbose "Load install"
    Import-Module "$PSScriptRoot\install.psm1"

    Write-Verbose "Install Dependencies"
    Install-Dependency -RequiredModule $RequiredModules -Path $Path -Scope $Scope -Test:$Test
}
