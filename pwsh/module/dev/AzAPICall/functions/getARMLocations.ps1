function getARMLocations {
    [CmdletBinding()]Param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    $currentTask = 'Get ARM locations'
    Logging -logMessage "  $currentTask"
    if (($AzAPICallConfiguration['checkContext']).Subscription.Id) {
        $uri = "$(($AzAPICallConfiguration['azAPIEndpointUrls']).ARM)/subscriptions/$(($AzAPICallConfiguration['checkContext']).Subscription.Id)/locations?api-version=2020-01-01"
        $method = 'GET'
        $getARMLocationsParametersSplat = @{
            AzAPICallConfiguration = $AzAPICallConfiguration
            uri                    = $uri
            method                 = $method
            currentTask            = $currentTask
        }
        $getARMLocations = AzAPICall @getARMLocationsParametersSplat -initState

        if ($getARMLocations.Count -gt 0) {
            Logging -logMessage "   Get ARM locations succeeded (locations count: '$($getARMLocations.Count)')" -logMessageForegroundColor 'Green'
            $getARMLocationsPhysical = $getARMLocations.where({ $_.metadata.regiontype -eq 'physical' })
            if ($getARMLocationsPhysical.Count -gt 0) {
                Logging -logMessage "    $($getARMLocationsPhysical.Count) physical ARM locations found" -logMessageForegroundColor 'Green'
                $AzApiCallConfiguration['htParameters'].ARMLocations = $getARMLocationsPhysical.name | Sort-Object
                foreach ($location in $getARMLocationsPhysical) {
                    $AzApiCallConfiguration['azAPIEndpointUrls']."ARM$($location.name.tolower())" = $AzApiCallConfiguration['azAPIEndpointUrls'].ARM -replace 'https://', "https://$($location.name)."
                    $locationDomain = $AzApiCallConfiguration['azAPIEndpointUrls'].ARM -replace 'https://', "$($location.name)."
                    $AzApiCallConfiguration['azAPIEndpoints'].($locationDomain) = "ARM$($location.name.tolower())"
                }
            }
            else {
                Logging -logMessage '   Could not find any physical ARM locations'
                Throw 'Error - check the last console output for details'
            }
        }
        else {
            Logging -logMessage "   Get ARM locations failed (locations count: '$($getARMLocations.Count)')"
            Throw 'Error - check the last console output for details'
        }
    }
    else {
        Logging -logMessage "   Get ARM locations not possible (no subscription in current context). Either use parameter -SubscriptionId4AzContext (initAzAPICall -SubscriptionId4AzContext 'subscriptionId') or if you do not have any subscriptions then you won´t be able to address regional endpoints e.g. 'https://westeurope.management.azure.com/' (info: parameter `$SkipAzContextSubscriptionValidation = $SkipAzContextSubscriptionValidation)"
        $AzApiCallConfiguration['htParameters'].ARMLocations = @()
    }
}