<#      
    .DESCRIPTION
    Main script performing the Windows Image Customization. Executed steps:
    - download all zip files specified in zipfiles array ($zipfiles)
    - find all ZIP files in the downloaded folder (including subfolder).
    - extract all ZIP files to Sources folder by also creating the folder.
    - each ZIP is extracted to a subfolder Sources\<XXX>-<ZIP file name without extension> where XXX is a number starting at 000.
    - find all wvd_image_*.ps1 files in Sources subfolders.
    - execute all wvd_image_*.ps1 scripts found in Sources subfolders in the order of folder names.       
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $storageaccount = '<storageaccount>',
    [Parameter()]
    [string] $container = '<container>',
    [Parameter()]
    [string] $SASToken = '<SAS>',
    [Parameter()]
    [string] $BuildDir = "c:\BuildArtifacts"
)
#region variables
$environment = 'Dev'
$domainsuffix = 'core.tbl.com'
$zipfiles = "000-LGPO.zip", "001-RemoveApps.zip","010-VSC++Redistributables.zip", `
    "011-SQLNativeClient.zip", "015-ReportBuilder.zip","016-PowerBIDesktop.zip",`
    "030-FSLogix.zip", "040-Office365.zip","050-OneDrive.zip","060-Teams.zip", "070-Edge.zip",`
    "502-HXGN-ILM-17.0.zip", "503-HXGN-ILA-19.1.zip","511-HXGN-ICAD_NET-9.4.50158.zip", `
    "515-HXGN-CADDBM-9.4.50158.zip","520-HXGN-iDispatcher-9.4.50163.zip",`
    "530-HXGN-BWIInformerClient-9.4.01285.zip","535-HXGN-InformerClient-9.4.50075.zip", `
    "540-HXGN-MobilePublicSafety-9.4.50206.zip","900-WindowsConfig.zip"
#endregion

#region Initialization
[string]$Script:Path = $MyInvocation.MyCommand.Definition
[string]$Script:Name = [IO.Path]::GetFileNameWithoutExtension($Script:Path)
[String]$Script:LogDir = "$($env:SystemRoot)\Logs\ImagePrep"
If (-not(Test-Path -Path $BuildDir)) {
    $null = New-Item -Path $BuildDir -ItemType Directory -Force
}
If (-not(Test-Path -Path $Script:LogDir)) {
    $null = New-Item -Path "$($env:SystemRoot)\Logs" -Name ImagePrep -ItemType Dir -Force
}
[string]$Script:LogName = "$Script:Name.log"

#Cleanup Log Directory from Previous Runs
If (Test-Path "$Script:LogDir\$Script:Name.log") {
    Remove-Item "$Script:LogDir\$Script:Name.log" -Force
}
If (Test-Path "$Script:LogDir\LGPO") {
    Remove-Item -Path "$Script:LogDir\LGPO" -Recurse -Force
}
#endregion

#region Functions
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
        [boolean]$Script:SectionDefined = [boolean](-not [string]::IsNullOrEmpty($Script:Section))
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
                    Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $Script:Section :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
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
                If ($Script:SectionDefined) { [string]$CMTraceMsg = "[$Script:Section] :: $Msg" }
				
                #  Create a Console and Legacy "text" log entry
                [string]$LegacyMsg = "[$LogDate $LogTime]"
                If ($Script:SectionDefined) { [string]$LegacyMsg += " [$Script:Section]" }
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
                    Write-Host -Object "[$LogDate $LogTime] [$Script:Section] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
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
                    [hashtable]$ArchiveLogParams = @{ ScriptSection = $Script:Section; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }
					
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

Function Get-BlobwithSAS {
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
    [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    $start_time = Get-Date 
    $wc = New-Object System.Net.WebClient
    Write-Log -message "Attempting to download storage blob from '$url' to '$outputfile'." -source ${CmdletName}
    Try {
        $wc.DownloadFile($url, $outputfile)    
        $time = (Get-Date).Subtract($start_time).Seconds        
        Write-Log -message "Time taken: '$time' seconds." -source ${CmdletName}
        $totalSize = (Get-Item $outputfile).Length / 1MB
        Write-Log -message "Download was successful. Final file size: '$totalsize' mb" -source ${CmdletName}
    }
    Catch {
        Write-Log -message "Error downloading blob." -severity 2 -source ${CmdletName}
        Return
    }
}

#endregion

$ErrorActionPreference = 'Stop'
Write-Log -Message "Starting Image Customization Script. Current working dir: $((Get-Location).Path)"

Write-Log -Message "Configuring DNS Client Suffix Search List for DNS Name Resolution."
$OrgSuffixSearchList = (Get-DnsClientGlobalSetting).SuffixSearchList
$NewSuffixSearchList = $OrgSuffixSearchList
$NewSuffixSearchList += $domainsuffix
Set-DnsClientGlobalSetting -suffixsearchlist $NewSuffixSearchList

$Script:Section = "Source Download"
Write-Log -Message "Downloading zip files containing customization scripts from storage account."

ForEach ($zipfile in $zipfiles) {
    $zipfile = $zipfile
    [string]$url = "https://" + "$storageaccount" + ".blob.core.windows.net/" + "$container" + "/" + "$zipfile" + "$sastoken"
    Get-BlobwithSAS -url "$url" -OutputFile "$BuildDir\$zipfile" -ErrorAction SilentlyContinue
    If (-not (Test-Path -Path "$BuildDir\$zipfile")) {
        Write-Log -message "Trying to download storage blob again using lowercase blob name."
        $zipfile = $zipfile.ToLower()
        [string]$url = "https://" + "$storageaccount" + ".blob.core.windows.net/" + "$container" + "/" + "$zipfile" + "$sastoken"
        Get-BlobwithSAS -url "$url" -OutputFile "$BuildDir\$zipfile" -ErrorAction SilentlyContinue
    }
}

$Script:Section = "Source Unpack"

Write-Log -message "Unpacking zip files"

$zipSeachInputObject = @{
    Filter  = "*.zip" 
    Recurse = $true
}
if (-not [String]::IsNullOrEmpty($BuildDir)) {
    $zipSeachInputObject['Path'] = $BuildDir
}
$zipPackages = Get-ChildItem @zipSeachInputObject | Sort-Object -Property BaseName
if ($zipPackages) {
    Write-Log -Message "Found $($zipPackages.count) zip packages"
}
else {
    Write-Log -message "No zip files found in the directory" -severity 2
}

foreach ($zip in $zipPackages) {
    Write-Log -message "Unpacking $($zip.FullName)"
    Expand-Archive -Path $zip.FullName -DestinationPath "$BuildDir\Sources\$($zip.BaseName)" -force
}
$Script:Section = "Script Sequencing"
Write-Log -message "Unpacking completed - Searching for wvd_image_*.ps1 files"

$PsScriptsToRun = Get-ChildItem -path "$BuildDir\Sources" -Filter "wvd_image_*.ps1" -Recurse | Sort-Object -Property FullName

if ($PsScriptsToRun) {
    Write-Log "Found $($PsScriptsToRun.count) scripts"
}
else {
    Write-Log -message "No scripts found in the directory" -severity 2
}
$Script:Section = "Script Execution"
foreach ($scr in $PsScriptsToRun) {
    $ScriptHelp = get-help $($scr.FullName)
    If ($ScriptHelp) {
        $ScriptParams = $ScriptHelp.Parameters
        If ($ScriptParams | Where-Object {$_.Parameter.Name -eq 'Environment'}) {
            Write-Log -message "Script requires 'Environment' Parameter. Running '$($scr.FullName) -Environment $Environment'"
            & $scr.FullName -Environment $Environment
        }
        Else {
            Write-Log -message "Running $($scr.FullName)"
            & $scr.FullName 
        }
    }
    Else {
        Write-Log -message "Running $($scr.FullName)"
        & $scr.FullName
    }
}

$Script:Section = "Cleanup"

Write-Log -Message "Returning DNS Suffix Search List back to default."
Set-DnsClientGlobalSetting -SuffixSearchList $OrgSuffixSearchList
Write-Log -Message "Performing script downloads cleanup."

Write-Log -Message "Cleaning up Source Downloads." -Verbose
Remove-Item -Path "$BuildDir\*.zip" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$BuildDir\Sources\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$BuildDir\Sources" -Recurse -Force -ErrorAction SilentlyContinue

Write-Log -message "Master Customization Script complete."