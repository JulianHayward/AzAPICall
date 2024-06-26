$apiEndPoint = $azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph
$apiEndPointVersion = '/v1.0'
$api = "/groups/$((New-Guid).guid)"
$optionalQueryParameters = ''

#$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
$uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

$azAPICallPayload = @{
    uri                    = $uri
    method                 = 'GET'
    currentTask            = " '$($azAPICallConf['azAPIEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Group List Members (id: $($group.id))'"
    AzAPICallConfiguration = $azAPICallConf
}
Write-Host $azAPICallPayload.currentTask

$AzApiCallResult = AzAPICall @azAPICallPayload
$AzApiCallResult

$AzApiCallResultStatusCode = AzAPICall @azAPICallPayload -listenOn 'StatusCode'
if ($AzApiCallResultStatusCode -eq 404) {
    $true
}