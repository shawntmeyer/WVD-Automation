<#
.SYNOPSIS
    Install RSAT features for Windows 10 1809 or later.
    
.DESCRIPTION
    Install RSAT features for Windows 10 1809 or later. All features are installed online from Microsoft Update thus the script requires Internet access

.PARAM Basic
    Installs only ADDS, DHCP, DNS, GPO, ServerManager

.NOTES
    Filename: Install-RSAT.ps1
    Version: 1.2
    
#> 

[CmdletBinding()]
param(
    [parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$Basic
)

if (-not ($PSBoundParameters["Basic"])) {
    Write-Verbose -Verbose "Script is installing all available RSAT features"
    $Install = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat*" -AND $_.State -eq "NotPresent"}
    if ($null -ne $Install) {
        foreach ($Item in $Install) {
            $RsatItem = $Item.Name
            Write-Verbose -Verbose "Adding $RsatItem to Windows"
            try {
                Add-WindowsCapability -Online -Name $RsatItem
                }
            catch [System.Exception]
                {
                Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
                Write-Warning -Message $_.Exception.Message
                }
        }
    }
    else {
        Write-Verbose -Verbose "All RSAT features seems to be installed already"
    }
}
Else {
    Write-Verbose -Verbose "Script is running without -All parameter. Installing basic RSAT features"
    # Querying for what I see as the basic features of RSAT. Modify this if you think something is missing. :-)
    $Install = Get-WindowsCapability -Online | Where-Object {$_.Name -like "Rsat.ActiveDirectory*" -OR $_.Name -like "Rsat.DHCP.Tools*" -OR $_.Name -like "Rsat.Dns.Tools*" -OR $_.Name -like "Rsat.GroupPolicy*" -OR $_.Name -like "Rsat.ServerManager*" -AND $_.State -eq "NotPresent" }
    if ($null -ne $Install) {
        foreach ($Item in $Install) {
            $RsatItem = $Item.Name
            Write-Verbose -Verbose "Adding $RsatItem to Windows"
            try {
                Add-WindowsCapability -Online -Name $RsatItem
                }
            catch [System.Exception]
                {
                Write-Verbose -Verbose "Failed to add $RsatItem to Windows"
                Write-Warning -Message $_.Exception.Message
                }
        }
    }
    else {
        Write-Verbose -Verbose "The basic features of RSAT seems to be installed already"
    }
}