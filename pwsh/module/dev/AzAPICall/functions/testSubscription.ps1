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
    Write-Host "  $currentTask"
    $uri = "$(($AzAPICallConfiguration['azAPIEndpointUrls']).ARM)/subscriptions/$($SubscriptionId4Test)?api-version=2020-01-01"
    $method = 'GET'
    $testSubscription = AzAPICall -uri $uri -method $method -currentTask $currentTask -listenOn 'Content' -AzAPICallConfiguration $AzAPICallConfiguration

    if ($testSubscription.subscriptionPolicies.quotaId -like 'AAD*' -or $testSubscription.state -ne 'Enabled') {
        if ($testSubscription.subscriptionPolicies.quotaId -like 'AAD*') {
            Write-Host "   SubscriptionId '$SubscriptionId4Test' quotaId: '$($testSubscription.subscriptionPolicies.quotaId)'"
        }
        if ($testSubscription.state -ne 'Enabled') {
            Write-Host "   SubscriptionId '$SubscriptionId4Test' state: '$($testSubscription.state)'"
        }
        Write-Host "   Subscription check - SubscriptionId: '$SubscriptionId4Test' - please define another Subscription (Subscription criteria: quotaId notLike 'AAD*'; state = enabled)"
        Throw 'Error - check the last console output for details'
    }
    else {
        $AzApiCallConfiguration['htParameters'].subscriptionQuotaId = $testSubscription.subscriptionPolicies.quotaId
        Write-Host "   Subscription check succeeded (quotaId: '$($testSubscription.subscriptionPolicies.quotaId)')" -ForegroundColor Green
    }
}