function testSubscription {
    [CmdletBinding()]Param(
        [Parameter(Mandatory)]
        [guid]
        $SubscriptionId4Test,

        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    $currentTask = "Check Subscription: '$SubscriptionId4Test'"
    Logging -logMessage "  $currentTask"
    $uri = "$(($AzAPICallConfiguration['azAPIEndpointUrls']).ARM)/subscriptions/$($SubscriptionId4Test)?api-version=2020-01-01"
    $method = 'GET'
    $testSubscription = AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -AzAPICallConfiguration $AzAPICallConfiguration

    if ($testSubscription.subscriptionPolicies.quotaId -like 'AAD*' -or $testSubscription.state -ne 'Enabled') {
        if ($testSubscription.subscriptionPolicies.quotaId -like 'AAD*') {
            Logging -logMessage "   SubscriptionId '$SubscriptionId4Test' quotaId: '$($testSubscription.subscriptionPolicies.quotaId)'"
        }
        if ($testSubscription.state -ne 'Enabled') {
            Logging -logMessage "   SubscriptionId '$SubscriptionId4Test' state: '$($testSubscription.state)'"
        }
        Logging -logMessage "   Subscription check - SubscriptionId: '$SubscriptionId4Test' - please define another Subscription (Subscription criteria: quotaId notLike 'AAD*'; state = enabled)"
        Logging -logMessage "   Use parameter: -SubscriptionId4AzContext (e.g. -SubscriptionId4AzContext '66f7c01a-ca6c-4ec2-a80b-34cc2dbda7d7')"
        Throw 'Error - check the last console output for details'
    }
    else {
        $AzApiCallConfiguration['htParameters'].subscriptionQuotaId = $testSubscription.subscriptionPolicies.quotaId
        Logging -logMessage "   Subscription check succeeded (quotaId: '$($testSubscription.subscriptionPolicies.quotaId)')" -logMessageForegroundColor 'Green'
    }
}