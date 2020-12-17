function New-AutomationConnectionAsset {

    param(
        [Parameter(Mandatory)]
        [string] $resourceGroup, 
        
        [Parameter(Mandatory)]
        [string] $automationAccountName,
        
        [Parameter(Mandatory)]
        [string] $connectionAssetName, 

        [Parameter(Mandatory)]
        [string] $connectionTypeName, 

        [Parameter(Mandatory)]
        [System.Collections.Hashtable] $connectionFieldValues 
    )
        

    begin {
        Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)
    }

    process {
        Write-Verbose "Remove current run as connection"
        $removeConnectionInputObject = @{
            ResourceGroupName     = $resourceGroup 
            AutomationAccountName = $automationAccountName 
            Name                  = $connectionAssetName 
            Force                 = $true 
            ErrorAction           = 'SilentlyContinue'
        }
        Remove-AzAutomationConnection @removeConnectionInputObject
        
        Write-Verbose "Add new run as connection"
        $newConnectionInputObject = @{
            ResourceGroupName     = $ResourceGroup 
            AutomationAccountName = $automationAccountName 
            Name                  = $connectionAssetName 
            ConnectionTypeName    = $connectionTypeName 
            ConnectionFieldValues = $connectionFieldValues
        }
        New-AzAutomationConnection @newConnectionInputObject
    }

    end {
        Write-Debug ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}