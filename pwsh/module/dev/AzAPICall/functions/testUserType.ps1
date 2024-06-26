function testUserType {
    param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    $userType = 'n/a'
    if ($AzAPICallConfiguration['checkContext'].Account.Type -eq 'User') {
        $currentTask = 'Check AAD UserType'
        Logging -preventWriteOutput $true -logMessage " $currentTask"
        $uri = $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph + '/v1.0/me?$select=userType,id'
        $method = 'GET'
        $checkUserTypeParametersSplat = @{
            AzAPICallConfiguration = $AzAPICallConfiguration
            uri                    = $uri
            method                 = $method
            currentTask            = $currentTask
            listenOn               = 'Content'
        }
        $checkUserType = AzAPICall @checkUserTypeParametersSplat -initState
        $userType = $checkUserType

        Logging -preventWriteOutput $true -logMessage "  AAD UserType: $($userType.userType); AAD identityId: $($userType.id)" -logMessageForegroundColor 'Yellow'
        Logging -preventWriteOutput $true -logMessage '  AAD UserType check succeeded' -logMessageForegroundColor 'Green'
    }
    return $userType
}