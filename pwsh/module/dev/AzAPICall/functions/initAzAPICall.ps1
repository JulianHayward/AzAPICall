function initAzAPICall {

    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [bool]
        $DebugAzAPICall = $false,

        [Parameter()]
        [ValidateSet('Debug', 'Error', 'Host', 'Information', 'Output', 'Progress', 'Verbose', 'Warning')]
        $WriteMethod = 'Host',

        [Parameter()]
        [ValidateSet('Debug', 'Error', 'Host', 'Information', 'Output', 'Progress', 'Verbose', 'Warning')]
        $DebugWriteMethod = 'Host',

        [Parameter()]
        [string]
        $SubscriptionId4AzContext,

        [Parameter()]
        [bool]
        $SkipAzContextSubscriptionValidation = $false,

        [Parameter()]
        [string]
        $GitHubRepository = 'aka.ms/AzAPICall',

        [Parameter()]
        [object]
        $AzAPICallCustomRuleSet
    )

    $AzAPICallConfiguration = @{}
    $AzAPICallConfiguration['htParameters'] = @{}
    $AzAPICallConfiguration['htParameters'].writeMethod = $WriteMethod
    $AzAPICallConfiguration['htParameters'].debugWriteMethod = $DebugWriteMethod

    $AzAPICallVersion = getAzAPICallVersion
    Logging -preventWriteOutput $true -logMessage " AzAPICall $AzAPICallVersion"

    $AzAccountsVersion = testAzModules

    $AzAPICallConfiguration['AzAPICallRuleSet'] = @{}
    if ($AzAPICallCustomRuleSet) {
        $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler = $AzAPICallCustomRuleSet.AzAPICallErrorHandler
    }
    else {
        $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler = $funcAzAPICallErrorHandler
    }

    $AzAPICallConfiguration['htParameters'] += setHtParameters -AzAccountsVersion $AzAccountsVersion -gitHubRepository $GitHubRepository -DebugAzAPICall $DebugAzAPICall
    Logging -preventWriteOutput $true -logMessage '  AzAPICall htParameters:'
    Logging -preventWriteOutput $true -logMessage $($AzAPICallConfiguration['htParameters'] | Format-Table -AutoSize | Out-String)
    Logging -preventWriteOutput $true -logMessage '  Create htParameters succeeded' -logMessageForegroundColor 'Green'

    $AzAPICallConfiguration['arrayAPICallTracking'] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $AzAPICallConfiguration['htBearerAccessToken'] = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))

    Logging -preventWriteOutput $true -logMessage ' Get Az context'
    try {
        $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
    }
    catch {
        $_
        Logging -preventWriteOutput $true -logMessage '  Get Az context failed' -logMessageWriteMethod 'Error'
        Throw 'Error - check the last console output for details'
    }

    if (-not $AzAPICallConfiguration['checkContext']) {
        Logging -preventWriteOutput $true -logMessage '  Get Az context failed: No context found. Please connect to Azure (run: Connect-AzAccount -tenantId <tenantId>) and re-run the script' -logMessageWriteMethod 'Error'
        Throw 'Error - check the last console output for details'
    }
    Logging -preventWriteOutput $true -logMessage '  Get Az context succeeded' -logMessageForegroundColor 'Green'

    $AzAPICallConfiguration = setAzureEnvironment -AzAPICallConfiguration $AzAPICallConfiguration

    Logging -preventWriteOutput $true -logMessage ' Check Az context'
    Logging -preventWriteOutput $true -logMessage "  Az context AccountId: '$($AzAPICallConfiguration['checkContext'].Account.Id)'" -logMessageForegroundColor 'Yellow'
    Logging -preventWriteOutput $true -logMessage "  Az context AccountType: '$($AzAPICallConfiguration['checkContext'].Account.Type)'" -logMessageForegroundColor 'Yellow'
    $AzApiCallConfiguration['htParameters'].accountType = $($AzAPICallConfiguration['checkContext'].Account.Type)

    if ($SubscriptionId4AzContext -match ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$') -and $SkipAzContextSubscriptionValidation -eq $true) {
        Logging -preventWriteOutput $true -logMessage " Contradictory use of parameters: `$SubscriptionId4AzContext == $($SubscriptionId4AzContext) AND `$SkipAzContextSubscriptionValidation == '$($SkipAzContextSubscriptionValidation)'" -logMessageForegroundColor 'DarkRed'
        Logging -preventWriteOutput $true -logMessage " Setting parameter `$SkipAzContextSubscriptionValidation to '`$false'" -logMessageForegroundColor 'DarkRed'
        $SkipAzContextSubscriptionValidation = $false
        Logging -preventWriteOutput $true -logMessage " Parameter `$SkipAzContextSubscriptionValidation == '$($SkipAzContextSubscriptionValidation)'" -logMessageForegroundColor 'DarkRed'
    }

    if ($SubscriptionId4AzContext -match ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$')) {
        Logging -preventWriteOutput $true -logMessage "  Parameter -SubscriptionId4AzContext: '$SubscriptionId4AzContext'"
        if ($AzAPICallConfiguration['checkContext'].Subscription.Id -ne $SubscriptionId4AzContext) {

            testSubscription -SubscriptionId4Test $SubscriptionId4AzContext -AzAPICallConfiguration $AzAPICallConfiguration

            Logging -preventWriteOutput $true -logMessage "  Setting Az context to SubscriptionId: '$SubscriptionId4AzContext'"
            try {
                $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
            }
            catch {
                Logging -preventWriteOutput $true -logMessage $_
                Throw 'Error - check the last console output for details'
            }
            $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
            Logging -preventWriteOutput $true -logMessage "  New Az context: $($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))"
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Stay with current Az context: $($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))"
        }
    }
    else {
        if (-not [string]::IsNullOrWhiteSpace($AzAPICallConfiguration['checkContext'].Subscription.Id)) {
            testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
        }
    }

    if (-not $AzAPICallConfiguration['checkContext'].Subscription -and $SkipAzContextSubscriptionValidation -eq $false) {
        $AzAPICallConfiguration['checkContext'] | Format-List | Out-String
        Logging -preventWriteOutput $true -logMessage '  Check Az context failed: Az context is not set to any Subscription'
        Logging -preventWriteOutput $true -logMessage '  Set Az context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script'
        Logging -preventWriteOutput $true -logMessage '  OR'
        Logging -preventWriteOutput $true -logMessage '  Use parameter -SubscriptionId4AzContext - e.g. .\AzGovVizParallel.ps1 -SubscriptionId4AzContext <subscriptionId>'
        Throw 'Error - check the last console output for details'
    }
    else {
        Logging -preventWriteOutput $true -logMessage "   Az context Tenant: '$($AzAPICallConfiguration['checkContext'].Tenant.Id)'" -logMessageForegroundColor 'Yellow'
        if ($SkipAzContextSubscriptionValidation -eq $false) {
            Logging -preventWriteOutput $true -logMessage "   Az context Subscription: $($AzAPICallConfiguration['checkContext'].Subscription.Name) [$($AzAPICallConfiguration['checkContext'].Subscription.Id)] (state: $($AzAPICallConfiguration['checkContext'].Subscription.State))" -logMessageForegroundColor 'Yellow'
        }
        else {
            Logging -preventWriteOutput $true -logMessage "   Az context Subscription check skipped (`$SkipAzContextSubscriptionValidation == $($SkipAzContextSubscriptionValidation))" -logMessageForegroundColor 'Yellow'
        }
        Logging -preventWriteOutput $true -logMessage '  Az context check succeeded' -logMessageForegroundColor 'Green'
    }

    $AzApiCallConfiguration['htParameters'].userType = testUserType -AzApiCallConfiguration $AzAPICallConfiguration

    return $AzAPICallConfiguration
}
