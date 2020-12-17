# Create the function to create and post the request
function Send-LogAnalyticsData {

    param(
        [Parameter(Mandatory)]
        [string] $customerId, 

        [Parameter(Mandatory)]
        [string] $sharedKey,

        [Parameter(Mandatory)]
        [Byte[]] $body, 
        
        [Parameter(Mandatory)]
        [string] $logType
    )

    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [datetime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $signatureInputObject = @{
        customerId    = $customerId 
        sharedKey     = $sharedKey 
        Date          = $rfc1123date 
        contentLength = $contentLength 
        Method        = $method 
        ContentType   = $contentType 
        resource      = $resource
    }
    $signature = New-Signature @signatureInputObject

    $headers = @{
        "Authorization"        = $signature
        "Log-Type"             = $logType
        "x-ms-date"            = $rfc1123date
        "time-generated-field" = (Get-Date).GetDateTimeFormats(115)
    }

    $webRequestInputObject = @{
        Uri         = $uri 
        Method      = $method 
        ContentType = $contentType 
        Headers     = $headers 
        Body        = $body
    }
    $response = Invoke-WebRequest @webRequestInputObject -UseBasicParsing
    return $response.StatusCode
}