Param
(
    # Outlook Email Cached Sync Time
    [Parameter(Mandatory = $false)]
    [ValidateSet("Not Configured", "3 days", "1 week", "2 weeks", "1 month", "3 months", "6 months", "12 months", "24 months", "36 months", "60 months", "All")]
    [string]$EmailCacheTime = "Not Configured",

    # Outlook Calendar Sync Mode. See https://support.microsoft.com/en-us/help/2768656/outlook-performance-issues-when-there-are-too-many-items-or-folders-in
    [Parameter(Mandatory = $false)]
    [ValidateSet("Not Configured", "Inactive", "Primary Calendar Only", "All Calendar Folders")]
    [string]$CalendarSync = "Not Configured",

    # Outlook Calendar Sync Months. See https://support.microsoft.com/en-us/help/2768656/outlook-performance-issues-when-there-are-too-many-items-or-folders-in
    [Parameter(Mandatory = $false)]
    [ValidateSet("Not Configured", "1", "3", "6", "12")]
    [string]$CalendarSyncMonths = "Not Configured",

    #Disable Windows Update
    [Parameter(Mandatory = $false)]
    [bool]$DisableUpdates
)

#region Initialization
$SoftwareName = 'Office_365_ProPlus'
[String]$Script:LogDir = "$($env:SystemRoot)\Logs\ImagePrep"
If (-not(Test-Path -Path $Script:LogDir)) {
    New-Item -Path "$($env:SystemRoot)\Logs" -Name ImagePrep -ItemType Dir -Force
}
[string]$Script:LogName = "Install-$SoftwareName.log"
If (Test-Path "$Script:LogDir\$Script:LogName") {
    Remove-Item "$Script:LogDir\$Script:LogName" -Force
}
#endregion

#region Supporting Functions
Function Write-Log {
    <#
        .SYNOPSIS
	        Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.
        .DESCRIPTION
	        Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.
        .PARAMETER Message
	        The message to write to the log file or output to the console.
        .PARAMETER Severity
	        Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
	        Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)
        .PARAMETER Source
	        The source of the message being logged.
        .PARAMETER ScriptSection
	        The heading for the portion of the script that is being executed. Default is: $script:installPhase.
        .PARAMETER LogType
	        Choose whether to write a CMTrace.exe compatible log file or a Legacy text log file.
        .PARAMETER LogFileDirectory
	        Set the directory where the log file will be saved.
        .PARAMETER LogFileName
	        Set the name of the log file.
        .PARAMETER MaxLogFileSizeMB
	        Maximum file size limit for log file in megabytes (MB). Default is 10 MB.
        .PARAMETER WriteHost
	        Write the log message to the console.
        .PARAMETER ContinueOnError
	        Suppress writing log message to console on failure to write message to log file. Default is: $true.
        .PARAMETER PassThru
	        Return the message that was passed to the function
        .PARAMETER DebugMessage
	        Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.
        .PARAMETER LogDebugMessage
	        Debug messages only get logged if this parameter is set to $true in the config XML file.
        .EXAMPLE
	        Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'
        .EXAMPLE
	        Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'
        .NOTES
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [AllowEmptyCollection()]
        [string[]]$Message,
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateRange(1, 3)]
        [int16]$Severity = 1,
        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [string]$Source = '',
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('CMTrace', 'Legacy')]
        [string]$LogType = "CMTrace",
        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileDirectory = $Script:LogDir,
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNullorEmpty()]
        [string]$LogFileName = $Script:LogName,
        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullorEmpty()]
        [decimal]$MaxLogFileSizeMB = 100,
        [Parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullorEmpty()]
        [boolean]$WriteHost = $true,
        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNullorEmpty()]
        [boolean]$ContinueOnError = $true,
        [Parameter(Mandatory = $false, Position = 9)]
        [switch]$PassThru = $false
    )
	
    Begin {
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		
        ## Logging Variables
        #  Log file date/time
        [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) { [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes }
        [string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
        #  Initialize variables
        [boolean]$ExitLoggingFunction = $false
        #  Check if the script section is defined
        [boolean]$SoftwareNameDefined = [boolean](-not [string]::IsNullOrEmpty($SoftwareName))
        #  Get the file name of the source script
        Try {
            If ($script:MyInvocation.Value.ScriptName) {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
            }
            Else {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
            }
        }
        Catch {
            $ScriptSource = ''
        }
		
        ## Create script block for generating CMTrace.exe compatible log entry
        [scriptblock]$CMTraceLogString = {
            Param (
                [string]$lMessage,
                [string]$lSource,
                [int16]$lSeverity
            )
            "<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
        }
		
        ## Create script block for writing log entry to the console
        [scriptblock]$WriteLogLineToHost = {
            Param (
                [string]$lTextLogLine,
                [int16]$lSeverity
            )
            If ($WriteHost) {
                #  Only output using color options if running in a host which supports colors.
                If ($Host.UI.RawUI.ForegroundColor) {
                    Switch ($lSeverity) {
                        3 { Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black' }
                        2 { Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                        1 { Write-Host -Object $lTextLogLine }
                    }
                }
                #  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
                Else {
                    Write-Output -InputObject $lTextLogLine
                }
            }
        }
		
        ## Create the directory where the log file will be saved
        If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
            Try {
                $null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
            }
            Catch {
                [boolean]$ExitLoggingFunction = $true
                #  If error creating directory, write message to console
                If (-not $ContinueOnError) {
                    Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $SoftwareName :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                }
                Return
            }
        }
		
        ## Assemble the fully qualified path to the log file
        [string]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
    }
    Process {
        ## Exit function if logging is disabled
		
        ForEach ($Msg in $Message) {
            ## If the message is not $null or empty, create the log entry for the different logging methods
            [string]$CMTraceMsg = ''
            [string]$ConsoleLogLine = ''
            [string]$LegacyTextLogLine = ''
            If ($Msg) {
                #  Create the CMTrace log message
                If ($SoftwareNameDefined) { [string]$CMTraceMsg = "[$SoftwareName] :: $Msg" }
				
                #  Create a Console and Legacy "text" log entry
                [string]$LegacyMsg = "[$LogDate $LogTime]"
                If ($SoftwareNameDefined) { [string]$LegacyMsg += " [$SoftwareName]" }
                If ($Source) {
                    [string]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
                    Switch ($Severity) {
                        3 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg" }
                        2 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg" }
                        1 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg" }
                    }
                }
                Else {
                    [string]$ConsoleLogLine = "$LegacyMsg :: $Msg"
                    Switch ($Severity) {
                        3 { [string]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg" }
                        2 { [string]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg" }
                        1 { [string]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg" }
                    }
                }
            }
			
            ## Execute script block to create the CMTrace.exe compatible log entry
            [string]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity
			
            ## Choose which log type to write to file
            If ($LogType -ieq 'CMTrace') {
                [string]$LogLine = $CMTraceLogLine
            }
            Else {
                [string]$LogLine = $LegacyTextLogLine
            }
			
            Try {
                $LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
            }
            Catch {
                If (-not $ContinueOnError) {
                    Write-Host -Object "[$LogDate $LogTime] [$SoftwareName] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                }
            }
						
            ## Execute script block to write the log entry to the console if $WriteHost is $true
            & $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
        }
    }
    End {
        ## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
        Try {
            If ((-not $ExitLoggingFunction) -and (-not $DisableLogging)) {
                [IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
                [decimal]$LogFileSizeMB = $LogFile.Length / 1MB
                If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0)) {
                    ## Change the file extension to "lo_"
                    [string]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
                    [hashtable]$ArchiveLogParams = @{ ScriptSection = $SoftwareName; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }
					
                    ## Log message about archiving the log file
                    $ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
                    Write-Log -Message $ArchiveLogMessage @ArchiveLogParams
					
                    ## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
                    Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'
					
                    ## Start new log file and Log message about archiving the old log file
                    $NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
                    Write-Log -Message $NewLogMessage @ArchiveLogParams
                }
            }
        }
        Catch {
            ## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
        }
        Finally {
            If ($PassThru) { Write-Output -InputObject $Message }
        }
    }
}

Function Set-RegistryValue {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]$Key,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        $Value,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Binary', 'DWord', 'ExpandString', 'MultiString', 'None', 'QWord', 'String', 'Unknown')]
        [Microsoft.Win32.RegistryValueKind]$Type = 'String'
    )

    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

    If (-not (Get-ItemProperty -LiteralPath $key -Name $Name -ErrorAction 'SilentlyContinue')) {
        If (-not (Test-Path -LiteralPath $key -ErrorAction 'Stop')) {
            Try {
                Write-Log -Message "Create registry key [$key]." -Source ${CmdletName}
                # No forward slash found in Key. Use New-Item cmdlet to create registry key
                If ((($Key -split '/').Count - 1) -eq 0) {
                    $null = New-Item -Path $key -ItemType 'Registry' -Force -ErrorAction 'Stop'
                }
                # Forward slash was found in Key. Use REG.exe ADD to create registry key
                Else {
                    $null = & reg.exe Add "$($Key.Substring($Key.IndexOf('::') + 2))"
                    If ($global:LastExitCode -ne 0) {
                        Throw "Failed to create registry key [$Key]"
                    }
                }
            }
            Catch {
                Throw
            }
        }
        Write-Log -Message "Set registry key value: [$key] [$name = $value]." -Source ${CmdletName}
        $null = New-ItemProperty -LiteralPath $key -Name $name -Value $value -PropertyType $Type -ErrorAction 'Stop'
    }
    ## Update registry value if it does exist
    Else {
        If ($Name -eq '(Default)') {
            ## Set Default registry key value with the following workaround, because Set-ItemProperty contains a bug and cannot set Default registry key value
            $null = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').OpenSubKey('', 'ReadWriteSubTree').SetValue($null, $value)
        }
        Else {
            Write-Log -Message "Update registry key value: [$key] [$name = $value]." -Source ${CmdletName}
            $null = Set-ItemProperty -LiteralPath $key -Name $name -Value $value -ErrorAction 'Stop'
        }
    }
}

Function Update-LocalGPOTextFile {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('Computer', 'User')]
        [string]$scope,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]$RegistryKeyPath,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]$RegistryValue,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]$RegistryData,
        [Parameter(Mandatory = $true, Position = 4)]
        [ValidateSet('DWORD', 'String')]
        [string]$RegistryType,
        [string]$outputDir = "$Script:LogDir\LGPO",
        [string]$outfileprefix = $SoftwareName
    )

    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    # Convert $RegistryType to UpperCase to prevent LGPO errors.
    $ValueType = $RegistryType.ToUpper()
    # Change String type to SZ for text file
    If ($ValueType -eq 'STRING') { $ValueType = 'SZ' }
    # Replace any incorrect registry entries for the format needed by text file.
    $modified = $false
    $SearchStrings = 'HKLM:\', 'HKCU:\', 'HKEY_CURRENT_USER:\', 'HKEY_LOCAL_MACHINE:\'
    ForEach ($String in $SearchStrings) {
        If ($RegistryKeyPath.StartsWith("$String") -and $modified -ne $true) {
            $index = $String.Length
            $RegistryKeyPath = $RegistryKeyPath.Substring($index, $RegistryKeyPath.Length - $index)
            $modified = $true
        }
    }
    
    #Create the output file if needed.
    $Outfile = "$OutputDir\$Outfileprefix-$Scope.txt"
    If (-not (Test-Path -LiteralPath $Outfile)) {
        If (-not (Test-Path -LiteralPath $OutputDir -PathType 'Container')) {
            Try {
                $null = New-Item -Path $OutputDir -Type 'Directory' -Force -ErrorAction 'Stop'
            }
            Catch {}
        }
        $null = New-Item -Path $outputdir -Name "$OutFilePrefix-$Scope.txt" -ItemType File -ErrorAction Stop
    }

    Write-Log -message "Adding registry information to '$outfile' for LGPO.exe" -Source ${CmdletName}
    # Update file with information
    Add-Content -Path $Outfile -Value $Scope
    Add-Content -Path $Outfile -Value $RegistryKeyPath
    Add-Content -Path $Outfile -Value $RegistryValue
    Add-Content -Path $Outfile -Value "$($ValueType):$RegistryData"
    Add-Content -Path $Outfile -Value ""
}

Function Invoke-LGPO {
    [CmdletBinding()]
    Param (
        [string]$InputDir = "$Script:LogDir\LGPO",
        [string]$SearchTerm = "$SoftwareName"
    )
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    Write-Log -message "Gathering Registry text files for LGPO from '$InputDir'" -Source ${CmdletName}
    $InputFiles = Get-ChildItem -Path $InputDir -Filter "$SearchTerm*.txt"
    ForEach ($RegistryFile in $inputFiles) {
        $TxtFilePath = $RegistryFile.FullName
        Write-Log -Message "Now applying settings from '$txtFilePath' to Local Group Policy via LGPO.exe." -Source ${CmdletName}
        $lgpo = Start-Process -FilePath "$env:SystemRoot\System32\lgpo.exe" -ArgumentList "/t `"$TxtFilePath`"" -Wait -PassThru
        Write-Log -Message "'lgpo.exe' exited with code [$($lgpo.ExitCode)]." -Source ${CmdletName}
    }
}

#endregion

## MAIN
$Ref = "https://docs.microsoft.com/en-us/azure/virtual-desktop/install-office-on-wvd-master-image"
Write-Log -Message "Installing Office in accordance with '$Ref'."
[string]$ODT = "$PSScriptRoot\OfficeDeploymentTool.exe"
Write-Log -Message "Extracting setup and configuration files from Office Deployment Tool."
[string]$SetupDir = "$PSScriptRoot\Setup"
$Null = New-Item -Path $PSScriptRoot -Name Setup -ItemType Directory -Force
[string]$AdminTemplatesDir = "$PSScriptRoot\AdminTemplates"
$null = New-Item -Path $PSScriptRoot -Name AdminTemplates -ItemType Directory -Force 
$null = Start-Process -FilePath $ODT -ArgumentList "/Extract:`"$SetupDir`" /quiet" -Wait
$aSetupFiles = (Get-ChildItem -Path "$SetupDir" -filter '*setup*.exe')
If (-not ($aSetupFiles)) {
    Write-Log -message "Office Setup executable not found." -Severity 3
    Exit
}
$null = Copy-Item -Path "$PSScriptRoot\Configuration.xml" -Destination "$SetupDir" -Force
$O365Setup = $aSetupFiles[0].FullName
Write-Log -Message "Installing Office 365 ProPlus with cmdline: '$O365SEtup /Configure `"$SetupDir\Configuration.xml`"'."
$Installer = Start-Process -FilePath "$O365Setup" -ArgumentList "/configure `"$SetupDir\Configuration.xml`"" -Wait -PassThru 
Write-Log -message "Office Setup exited with code [$($Installer.ExitCode)]"
$O365TemplatesExe = "$PSScriptRoot\AdminTemplates_x64.exe"
Write-Log -Message "Extracting Administrative Templates'."
$null = Start-Process -FilePath $O365TemplatesExe -ArgumentList "/extract:`"$AdminTemplatesDir`" /quiet" -Wait
Write-Log -message "Copying ADMX and ADML files to PolicyDefinitions folder."
$null = Get-ChildItem -Path $AdminTemplatesDir -File -Recurse -Filter '*.admx' | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$env:WINDIR\PolicyDefinitions\" -Force }
$null = Get-ChildItem -Path $AdminTemplatesDir -Directory -Recurse | Where-Object {$_.Name -eq 'en-us'} | Get-ChildItem -File -recurse -include '*.adml' | ForEach-Object { Copy-Item -Path $_.FullName -Destination "$env:WINDIR\PolicyDefinitions\en-us" -Force }

Write-Log -Message "Update User LGPO registry text file."
# Turn off insider notifications
Write-Log -Message "Disabling Office Insider Notifications"
Update-LocalGPOTextFile -Scope User -RegistryKeyPath 'Software\policies\microsoft\office\16.0\common' -RegistryValue InsiderSlabBehavior -RegistryType DWord -RegistryData 2

If (($EmailCacheTime -ne 'Not Configured') -or ($CalendarSync -ne 'Not Configured') -or ($CalendarSyncMonths -ne 'Not Configured')) {
    # Enable Outlook Cached Mode
    Write-Log -Message "Enabling and configuring Outlook Cached Mode."
    Update-LocalGPOTextFile -Scope User -RegistryKeyPath 'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode' -RegistryValue 'Enable' -RegistryType DWord -RegistryData 1
}
        
# Cached Exchange Mode Settings: https://support.microsoft.com/en-us/help/3115009/update-lets-administrators-set-additional-default-sync-slider-windows
If ($EmailCacheTime -eq '3 days') { $SyncWindowSetting = 0; $SyncWindowSettingDays = 3 }
If ($EmailCacheTime -eq '1 week') { $SyncWindowSetting = 0; $SyncWindowSettingDays = 7 }
If ($EmailCacheTime -eq '2 weeks') { $SyncWindowSetting = 0; $SyncWindowSettingDays = 14 }
If ($EmailCacheTime -eq '1 month') { $SyncWindowSetting = 1 }
If ($EmailCacheTime -eq '3 months') { $SyncWindowSetting = 3 }
If ($EmailCacheTime -eq '6 months') { $SyncWindowSetting = 6 }
If ($EmailCacheTime -eq '12 months') { $SyncWindowSetting = 12 }
If ($EmailCacheTime -eq '24 months') { $SyncWindowSetting = 24 }
If ($EmailCacheTime -eq '36 months') { $SyncWindowSetting = 36 }
If ($EmailCacheTime -eq '60 months') { $SyncWindowSetting = 60 }
If ($EmailCacheTime -eq 'All') { $SyncWindowSetting = 0; $SyncWindowSettingDays = 0 }

If ($SyncWindowSetting) {
    Write-Log -Message "Configuring Outlook to cache email for '$EmailCacheTime'."
    Update-LocalGPOTextFile -Scope User -RegistryKeyPath 'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode' -RegistryValue 'SyncWindowSetting' -RegistryType DWORD -RegistryData $SyncWindowSetting
}
If ($SyncWindowSettingDays) {
    Update-LocalGPOTextFile -Scope User -RegistryKeyPath 'Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode' -RegistryValue 'SyncWindowSettingDays' -RegistryType DWORD -RegistryData $SyncWindowSettingDays
}

# Calendar Sync Settings: https://support.microsoft.com/en-us/help/2768656/outlook-performance-issues-when-there-are-too-many-items-or-folders-in
If ($CalendarSync -eq 'Inactive') {
    $CalendarSyncWindowSetting = 0 
}
If ($CalendarSync -eq 'Primary Calendar Only') {
    $CalendarSyncWindowSetting = 1
}
If ($CalendarSync -eq 'All Calendar Folders') {
    $CalendarSyncWindowSetting = 2
}

If ($CalendarSyncWindowSetting) {
    Write-Log -Message "Configuring Outlook to cache '$CalendarSync'."
    Reg LOAD HKLM\DefaultUser "$env:SystemDrive\Users\Default User\NtUser.dat"
    Set-RegistryValue -Key 'HKLM:\DefaultUser\Software\Policies\Microsoft\Office16.0\Outlook\Cached Mode' -Name CalendarSyncWindowSetting -Type DWord -Value $CalendarSyncWindowSetting
    If ($CalendarSyncMonths -ne 'Not Configured') {
        Set-RegistryValue -Key 'HKCU:\DefaultUser\Software\Policies\Microsoft\Office\16.0\Outlook\Cached Mode' -Name CalendarSyncWindowSettingMonths -Type DWord -Value $CalendarSyncMonths
    }
    REG UNLOAD HKLM\DefaultUser
}
Write-Log -Message "Update Computer LGPO registry text file."
$RegistryKeyPath = 'SOFTWARE\Policies\Microsoft\Office\16.0\Common\OfficeUpdate'
# Hide Office Update Notifications
Write-Log -Message "Hiding Office Update Notifications"
Update-LocalGPOTextFile -scope Computer -RegistryKeyPath $RegistryKeyPath -RegistryValue 'HideUpdateNotifications' -RegistryType DWord -RegistryData 1
# Hide and Disable Updates
Write-Log -Message "Hiding the option to configure updates."
Update-LocalGPOTextFile -Scope Computer -RegistryKeyPath $RegistryKeyPath -RegistryValue 'HideEnableDisableUpdates' -RegistryType DWord -RegistryData 1
If ($DisableUpdates) {
    # Disable Updates
    Write-Log -Message "Disabling Office 365 ProPlus automatic updates."            
    Update-LocalGPOTextFile -Scope Computer -RegistryKeyPath $RegistryKeyPath -RegistryValue 'EnableAutomaticUpdates' -RegistryType DWord -RegistryData 0
}
Invoke-LGPO -SearchTerm "$SoftwareName"
Write-Log -Message "Completed '$SoftwareName' Installation and Configuration"

