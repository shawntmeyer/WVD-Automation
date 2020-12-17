#Requires -RunAsAdministrator

<#
    Install and configure FSLogix

    CSE based on instructions at:
        https://docs.microsoft.com/en-us/azure/virtual-desktop/create-host-pools-user-profile#configure-the-fslogix-profile-container
#>

[cmdletbinding()]

param(
    [parameter(Mandatory, ValueFromPipeline)]
    [object]$registryValues,
	
	[parameter(Mandatory, ValueFromPipeline)]
    [object]$localGroupValues
)

##########
# Helper #
##########
#region Functions
function LogInfo($message) {
    Log "Info" $message
}

function LogError($message) {
    Log "Error" $message
}

function LogSkip($message) {
    Log "Skip" $message
}
function LogWarning($message) {
    Log "Warning" $message
}

function Log {

    <#
    .SYNOPSIS
   Creates a log file and stores logs based on categories with tab seperation

    .PARAMETER category
    Category to put into the trace

    .PARAMETER message
    Message to be loged

    .EXAMPLE
    Log 'Info' 'Message'

    #>

    Param (
        $category = 'Info',
        [Parameter(Mandatory)]
        $message
    )

    $date = get-date
    $content = "[$date]`t$category`t`t$message`n"
    Write-Verbose "$content" -verbose

    if (! $script:Log) {
        $File = Join-Path $env:TEMP "log.log"
        Write-Error "Log file not found, create new $File"
        $script:Log = $File
    }
    else {
        $File = $script:Log
    }
    Add-Content $File $content -ErrorAction Stop
}

function Set-Logger {
    <#
    .SYNOPSIS
    Sets default log file and stores in a script accessible variable $script:Log
    Log File name "executionCustomScriptExtension_$date.log"

    .PARAMETER Path
    Path to the log file

    .EXAMPLE
    Set-Logger
    Create a logger in
    #>

    Param (
        [Parameter(Mandatory)]
        $Path
    )

    # Create central log file with given date

    $date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"

    $scriptName = (Get-Item $PSCommandPath ).Basename
    $scriptName = $scriptName -replace "-", ""

    Set-Variable logFile -Scope Script
    $script:logFile = "executionCustomScriptExtension_" + $scriptName + "_" + $date + ".log"

    if ((Test-Path $path ) -eq $false) {
        $null = New-Item -Path $path -type directory
    }

    $script:Log = Join-Path $path $logfile

    Add-Content $script:Log "Date`t`t`tCategory`t`tDetails"
}
#endregion


Set-Logger "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\executionLog\FSLogix" # inside "executionCustomScriptExtension_$scriptName_$date.log"

#####################
# Configure FSLogix #
#####################

Write-Verbose "In function count: $($testArr.Count)"
$testArr

LogInfo("##################################")
LogInfo("# 1. Configure Registry Settings #")
LogInfo("##################################")

foreach ($regSetting in $registryValues) {
	LogInfo ("")			
	LogInfo("Checking if RegexPath '"+$regSetting.keyPath+"' exists...")

	if (-not (Test-Path $regSetting.keyPath)) {
		LogInfo("RegexPath '"+$regSetting.keyPath+"' not existing. Creating")
		New-Item -Path $regSetting.keyPath -Force | Out-Null
	}
	else {
		LogInfo("RegexPath '"+$regSetting.keyPath+"' already existing. Creation skipped")
	}
	LogInfo("Configuring Key values...")

	$regSetting.keyValues | ForEach-Object {
		LogInfo('Creating entry "{0}" of type "{1}" with value "{2}" in path "{3}"' -f $_.Name, $_.Type, $_.Value, $regSetting.keyPath)
		$inputObject = @{
			Path         = $regSetting.keyPath
			Name         = $_.Name
			Value        = $_.Value
			PropertyType = $_.Type
		}
		New-ItemProperty @inputObject -Force | Out-Null
	}
}

LogInfo("#############################")
LogInfo("# 2. Configure Local Groups #")
LogInfo("#############################")

foreach ($groupSetting in $localGroupValues) {
	LogInfo ("")
	LogInfo ("Configuring local group '"+ $groupSetting.localGroupName +"'...")
	$currentMembers = (Get-LocalGroupMember -Group $groupSetting.localGroupName).Name
	LogInfo ("Current members for group '"+ $groupSetting.localGroupName +"' are "+ $currentMembers)
	LogInfo ("Desired members for group '"+ $groupSetting.localGroupName +"' are "+ $groupSetting.members)
	foreach ($desiredMember in $groupSetting.members) {
		if (-not($currentMembers -contains $desiredMember)) {
			LogInfo ("Adding member '"+ $desiredMember +"' to group "+ $groupSetting.localGroupName)
			Add-LocalGroupMember -Group $groupSetting.localGroupName -Member $desiredMember
		}
	}
	foreach ($currentMember in $currentMembers) {
		if (-not($groupSetting.members -contains $currentMember)) {
			LogInfo ("Removing current member '"+ $currentMember +"' from group "+ $groupSetting.localGroupName)
			Remove-localGroupMember -Group $groupSetting.localGroupName -Member $currentMember
		}
	}	
	
	LogInfo ("Group '"+ $groupSetting.localGroupName +"' configured ")
	$currentMembers = (Get-LocalGroupMember -Group $groupSetting.localGroupName).Name
	LogInfo ("Current members after configuration are "+ $currentMembers)
}
