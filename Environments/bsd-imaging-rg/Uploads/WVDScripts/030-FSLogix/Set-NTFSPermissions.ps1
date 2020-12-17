#Requires -RunAsAdministrator


<#
    Assign Storage Account File Share Permissions

    CSE based on instructions at:
        https://docs.microsoft.com/en-us/azure/storage/files/storage-files-active-directory-enable
        https://docs.microsoft.com/en-us/azure/storage/files/storage-how-to-use-files-windows

    Using New-PSDrive to mount the drive. A good alternative is 'net use'.

        # For a  not domain joined machine:
        net use $driveLetter \\$storageAccountName.file.core.windows.net\$fileShareName $storageAccountKey /user:Azure\$storageAccountName

        # For a domain joned machine (avoids keys):
        net use $driveLetter: \\$storageAccountName.file.core.windows.net\$fileShareName
#>

[cmdletbinding()]
param(
    [Parameter(
        Mandatory,
        HelpMessage = 'NTFS Settings containing share and target users data'
    )]
    [Object] $NTFSSettings
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
        [string] $Path
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

# Mount the drive

foreach ($setting in $NTFSSettings) {
    LogInfo ("")
    LogInfo('###################')
    LogInfo('# MOUNT THE DRIVE #')
    LogInfo('###################')

    # The value given to the root parameter of the New-PSDrive cmdlet is the host address for the storage account,
    # <storage-account>.file.core.windows.net for Azure Public Regions. $fileShare.StorageUri.PrimaryUri.Host is
    # used because non-Public Azure regions, such as sovereign clouds or Azure Stack deployments, will have different
    # hosts for Azure file shares (and other storage resources).

    $credential = New-Object System.Management.Automation.PSCredential -ArgumentList "AZURE\$($setting.filesharestorageaccountname)", $setting.fileShareStorageAccountKey
    $fileshareuri = "\\{0}.file.core.windows.net\{1}" -f $setting.filesharestorageaccountname, $setting.filesharename
	
    $driveInputObject = @{
        Name       = $setting.driveLetter
        PSProvider = 'FileSystem'
        Root       = $fileShareUri
        Credential = $credential
    }
    LogInfo("Try to get drive '$setting.driveLetter'")
    if (-not (Get-PSDrive -Name $setting.driveLetter -ErrorAction SilentlyContinue)) {
        LogInfo('Mount Drive "{0}" from root "{1}"' -f $driveInputObject.Name, $driveInputObject.Root)
        try {
            New-PSDrive @driveInputObject -Persist -Verbose
        }
        catch {
            Write-Error $_.Exception.Message
            throw $_
        }

        $drive = Get-PSDrive -Name $setting.driveLetter
        LogInfo("Drive mounted: {0}" -f ($drive | Format-List | Out-String))
    }
    else {
        LogInfo('Drive "{0}" from root "{1}" already mounted' -f $driveInputObject.Name, $driveInputObject.Root)
    }

    LogInfo('########################')
    LogInfo('# SET NTFS PERMISSIONS #')
    LogInfo('########################')

    LogInfo('Cleanup domain name')
    $setting.domain = ($setting.domain).Replace('.onmicrosoft.com', '')

    # Assign permissions
    $command = "icacls {0}: /grant ('{1}\{2}:(M)'); icacls {0}: /grant ('Creator Owner:(OI)(CI)(IO)(M)'); icacls {0}: /remove ('Authenticated Users'); icacls {0}: /remove ('Builtin\Users')" -f $setting.driveLetter, $setting.domain, $setting.targetGroup
    LogInfo("Run ACL command: '$command'")
    Invoke-Expression -Command $command
    LogInfo("ACLs set")
    LogInfo("Read ACLs")
    $readCommand = "icacls {0}:" -f $setting.driveLetter
    LogInfo("Run command: '$readCommand'")
    $info = Invoke-Expression -Command $readCommand
    LogInfo($info | Format-List | Out-String)
    
    LogInfo('#####################')
    LogInfo('# UNMOUNT THE DRIVE #')
    LogInfo('#####################')
    
    LogInfo('Remove Drive "{0}" from root "{1}"' -f $driveInputObject.Name, $driveInputObject.Root)
    try {
        Remove-PSDrive -Name $driveInputObject.Name -Verbose
    }
    catch {
        Write-Error $_.Exception.Message
        throw $_
    }
}