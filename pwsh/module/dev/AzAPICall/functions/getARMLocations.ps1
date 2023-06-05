function getARMLocations {
    [CmdletBinding()]Param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    $currentTask = 'Get ARM locations'
    Logging -logMessage "  $currentTask"
    $uri = "$(($AzAPICallConfiguration['azAPIEndpointUrls']).ARM)/subscriptions/$(($AzAPICallConfiguration['checkContext']).Subscription.Id)/locations?api-version=2020-01-01"
    $method = 'GET'
    $getARMLocations = AzAPICall -uri $uri -method $method -currentTask $currentTask -AzAPICallConfiguration $AzAPICallConfiguration

    if ($getARMLocations.Count -gt 0) {
        Logging -logMessage "   Get ARM locations succeeded (locations count: '$($getARMLocations.Count)')" -logMessageForegroundColor 'Green'
        $AzApiCallConfiguration['htParameters'].ARMLocations = $getARMLocations.name
    }
    else {
        Logging -logMessage "   Get ARM locations failed (locations count: '$($getARMLocations.Count)')"
        Throw 'Error - check the last console output for details'
    }
}