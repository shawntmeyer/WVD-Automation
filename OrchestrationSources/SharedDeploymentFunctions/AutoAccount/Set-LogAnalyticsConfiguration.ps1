function Set-LogAnalyticsConfiguration {

    param(
        [Parameter(Mandatory)]
        [string] $LAWorkspaceName
    )

    begin {
        Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)    

        . "$PSScriptRoot/New-Signature.ps1"
        . "$PSScriptRoot/Send-LogAnalyticsData.ps1"
    }

    process {

        if (-not ($LAWorkspace = Get-AzOperationalInsightsWorkspace | Where-Object { $_.Name -eq $LAWorkspaceName })) {
            throw "Provided log analytic workspace doesn't exist in your Subscription."
        }

        $WorkSpace = Get-AzOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $LAWorkspace.ResourceGroupName -Name $LAWorkspaceName -WarningAction Ignore
        $LogAnalyticsPrimaryKey = $Workspace.PrimarySharedKey
        $LogAnalyticsWorkspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $LAWorkspace.ResourceGroupName -Name $LAWorkspaceName).CustomerId.GUID

        # Specify the name of the record type that you'll be creating
        [string]$TenantScaleLogType = "WVDTenantScale_CL"
        # Specify a field with the created time for the records

        # Custom WVDTenantScale Table
        $CustomLogWVDTenantScale = '[{ "hostpoolName":" ", "logmessage": " " }]'

        # Submit the data to the API endpoint
        Write-Verbose "Send custom log to workspace [$LAWorkspaceName]"
        $sendLAInputObject = @{
            customerId = $LogAnalyticsWorkspaceId 
            sharedKey  = $LogAnalyticsPrimaryKey 
            Body       = ([System.Text.Encoding]::UTF8.GetBytes($CustomLogWVDTenantScale)) 
            logType    = $TenantScaleLogType
        }
        $null = Send-LogAnalyticsData @sendLAInputObject
    }
    end {
        Write-Debug ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}