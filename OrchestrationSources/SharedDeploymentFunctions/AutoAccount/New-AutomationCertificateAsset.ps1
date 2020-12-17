function New-AutomationCertificateAsset {

    param(
        [Parameter(Mandatory)]
        [string] $resourceGroup, 
    
        [Parameter(Mandatory)]
        [string] $automationAccountName,
    
        [Parameter(Mandatory)]
        [string] $certifcateAssetName,
    
        [Parameter(Mandatory)]
        [string] $certPath, 

        [Parameter(Mandatory)]
        [SecureString] $CertPassword, 

        [Parameter(Mandatory)]
        [Boolean] $Exportable
    )

    begin {
        Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)
    }

    process {
        Remove-AzAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $certifcateAssetName -ErrorAction SilentlyContinue
        New-AzAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Path $certPath -Name $certifcateAssetName -Password $CertPassword -Exportable:$Exportable | write-verbose
    }

    end {
        Write-Debug ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}
