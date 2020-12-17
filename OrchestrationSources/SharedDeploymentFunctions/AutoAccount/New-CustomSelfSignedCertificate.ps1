function New-CustomSelfSignedCertificate {

    param(
        [Parameter(Mandatory)]
        [string] $certificateName, 

        [Parameter(Mandatory)]
        [securestring] $selfSignedCertPassword,

        [Parameter(Mandatory)]
        [string] $certPath, 

        [Parameter(Mandatory)]
        [string] $certPathCer, 

        [Parameter(Mandatory)]
        [string] $AutoAccountRunAsCertExpiryInMonths 
    ) 

    begin {
        Write-Debug ("[{0} entered]" -f $MyInvocation.MyCommand)
    }

    process {
        $certInputObject = @{
            DnsName           = $certificateName 
            CertStoreLocation = 'cert:\LocalMachine\My'
            KeyExportPolicy   = 'Exportable' 
            Provider          = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            NotAfter          = (Get-Date).AddMonths($AutoAccountRunAsCertExpiryInMonths) 
            HashAlgorithm     = 'SHA256'
        }
        $Cert = New-SelfSignedCertificate @certInputObject

        Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $Cert.Thumbprint) -FilePath $certPath -Password $selfSignedCertPassword -Force | Write-Verbose
        Export-Certificate -Cert ("Cert:\localmachine\my\" + $Cert.Thumbprint) -FilePath $certPathCer -Type CERT | Write-Verbose
    }
    
    end {
        Write-Debug ("[{0} existed]" -f $MyInvocation.MyCommand)
    }
}