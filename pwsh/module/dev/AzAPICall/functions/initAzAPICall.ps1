function initAzAPICall {

    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [bool]
        $DebugAzAPICall,

        [Parameter()]
        [guid]
        $SubscriptionId4AzContext,

        [Parameter()]
        [string]
        $GithubRepository = 'aka.ms/AzAPICall'
    )

    $AzAccountsVersion = testAzModules

    $AzAPICallConfiguration = @{}
    $AzAPICallConfiguration['htParameters'] = $null
    $AzAPICallConfiguration['htParameters'] = setHtParameters -AzAccountsVersion $AzAccountsVersion -GithubRepository $GithubRepository -DebugAzAPICall $DebugAzAPICall
    Write-Host '  AzAPICall htParameters:'
    Write-Host ($AzAPICallConfiguration['htParameters'] | format-table -AutoSize | Out-String)
    Write-Host '  Create htParameters succeeded' -ForegroundColor Green

    $AzAPICallConfiguration['arrayAPICallTracking'] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $AzAPICallConfiguration['htBearerAccessToken'] = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))

    Write-Host ' Get Az context'
    try {
        $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
    }
    catch {
        $_
        Write-Host '  Get Az context failed'
        Throw 'Error - check the last console output for details'
    }
    if (-not $AzAPICallConfiguration['checkContext']) {
        Write-Host '  Get Az context failed: No context found. Please connect to Azure (run: Connect-AzAccount -tenantId <tenantId>) and re-run the script'
        Throw 'Error - check the last console output for details'
    }
    Write-Host '  Get Az context succeeded' -ForegroundColor Green

    $AzAPICallConfiguration = setAzureEnvironment -AzAPICallConfiguration $AzAPICallConfiguration

    Write-Host ' Check Az context'
    $AzAPICallConfiguration['accountId'] = $AzAPICallConfiguration['checkContext'].Account.Id
    $AzAPICallConfiguration['accountType'] = $AzAPICallConfiguration['checkContext'].Account.Type
    Write-Host "  Az context AccountId: '$($AzAPICallConfiguration['accountId'] )'" -ForegroundColor Yellow
    Write-Host "  Az context AccountType: '$($AzAPICallConfiguration['accountType'])'" -ForegroundColor Yellow

    
    if ($SubscriptionId4AzContext) {
        Write-Host "  Parameter -SubscriptionId4AzContext: '$SubscriptionId4AzContext'"
        if ($AzAPICallConfiguration['checkContext'].Subscription.Id -ne $SubscriptionId4AzContext) {

            testSubscription -SubscriptionId4Test $SubscriptionId4AzContext -AzAPICallConfiguration $AzAPICallConfiguration

            Write-Host "  Setting Az context to SubscriptionId: '$SubscriptionId4AzContext'"
            try {
                $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
            }
            catch {
                Write-Host $_
                Throw 'Error - check the last console output for details'
            }
            $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
            Write-Host "  New Az context: $($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))"
        }
        else {
            Write-Host "  Stay with current Az context: $($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))"
        }
    }
    else {
        testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
    }

    if (-not $AzAPICallConfiguration['checkContext'].Subscription) {
        $AzAPICallConfiguration['checkContext'] | Format-list | Out-String
        Write-Host '  Check Az context failed: Az context is not set to any Subscription'
        Write-Host '  Set Az context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script'
        Write-Host '  OR'
        Write-Host '  Use parameter -SubscriptionId4Test - e.g. .\AzGovVizParallel.ps1 -SubscriptionId4Test <subscriptionId>'
        Throw 'Error - check the last console output for details'
    }
    else {
        Write-Host '  Az context check succeeded' -ForegroundColor Green
    }

    $AzAPICallConfiguration['htParameters'].userType = testUserType -AzApiCallConfiguration $AzAPICallConfiguration

    Write-Output $AzAPICallConfiguration
}
