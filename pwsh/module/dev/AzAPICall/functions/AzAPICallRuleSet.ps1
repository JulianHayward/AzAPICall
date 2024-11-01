function AzAPICallErrorHandler {
    #Logging -preventWriteOutput $true -logMessage ' * BuiltIn RuleSet'

    $doRetry = $false
    $defaultErrorInfo = "[AzAPICallErrorHandler $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounter); uri:`"$uri`"; return: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'>"

    switch ($uri) {
        #ARM
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.PolicyInsights/policyStates/latest/summarize*" } { $getARMPolicyComplianceStates = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.Authorization/roleAssignmentScheduleInstances*" } { $getARMRoleAssignmentScheduleInstances = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/*/providers/microsoft.insights/diagnosticSettings*" } { $getARMDiagnosticSettingsMg = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/microsoft.insights/diagnosticSettingsCategories*" } { $getARMDiagnosticSettingsResource = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.CostManagement/query*" } { $getARMCostManagement = $true }
        #{ $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/*" } { $getARMARG = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/pricings*" } { $getARMMDfC = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/securescores*" } { $getARMMdFC = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/securityContacts*" } { $getARMMdFCSecurityContacts = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/settings*" } { $getARMMdFCSecuritySettings = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/federatedIdentityCredentials*" } { $getARMManagedIdentityUserAssignedFederatedIdentityCredentials = $true }
        #MicrosoftGraph
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/applications*" } { $getMicrosoftGraphApplication = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/groups/*/transitiveMembers/`$count" } { $getMicrosoftGraphGroupMembersTransitiveCount = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/servicePrincipals/*/getMemberGroups" } { $getMicrosoftGraphServicePrincipalGetMemberGroups = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentSchedules*" } { $getMicrosoftGraphRoleAssignmentSchedules = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentScheduleInstances*" } { $getMicrosoftGraphRoleAssignmentScheduleInstances = $true }
    }

    if ($catchResult.error.code -like '*BadGateway*' -or $actualStatusCodePhrase -like '*BadGateway*' -or $catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq 500 -or $actualStatusCode -eq 502) {
        $maxTries = 15
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit (after $maxTries tries)"
            #Throw 'Error - check the last console output for details'
            $exitMsg = "AzAPICall: exit (after $maxTries tries)"
        }
        else {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: try again in $tryCounter second(s)"
            $doRetry = $true
            Start-Sleep -Seconds $tryCounter
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
    }

    if ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*' -or $catchResult.error.code -like '*TokenExpired*') {
        if ($catchResult.error.code -eq 'InvalidAuthenticationTokenTenant') {
            if ($currentTask -like "getTenantId for subscriptionId '*'") {
                #handeled in #region getTenantId for subscriptionId
            }
            else {
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - Wrong tenant, skipping this request - break"
                $response = @{
                    action = 'break'
                }
                return $response
            }
        }
        else {
            $sleepSeconds = 3
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint) - sleep $sleepSeconds second and try again"
            $doRetry = $true
            Start-Sleep -Seconds $sleepSeconds
            #Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint)"
            if ($targetEndPoint -like 'ARM*' -and $targetEndPoint -ne 'ARM') {
                $targetEndPoint = 'ARM'
            }
            createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
    }

    #region getTenantId for subscriptionId
    if ($currentTask -like "getTenantId for subscriptionId '*'" -and $uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*" ) {
        Logging -preventWriteOutput $true -logMessage "[AzAPICallErrorHandler $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask"
        $return = [System.Collections.ArrayList]@()
        if ($catchResult.error.code -eq 'SubscriptionNotFound' -and $actualStatusCode -eq 404) {
            $null = $return.Add('SubscriptionNotFound Tenant unknown')
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return)'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = $return
            }
            return $response
        }
        elseif ($catchResult.error.code -eq 'AuthorizationFailed' -and $actualStatusCode -eq 403) {
            $null = $return.Add($AzApiCallConfiguration['checkcontext'].tenant.id)
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return)'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = $return
            }
            return $response
        }
        elseif ($catchResult.error.code -eq 'InvalidAuthenticationTokenTenant' -and $actualStatusCode -eq 401) {
            $pattern = "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/(.*?)\?api-version=2020-01-01"
            if ([regex]::Match($uri, $pattern).Groups[1].Value) {
                $ObjectGuid = [System.Guid]::empty
                if ([System.Guid]::TryParse([regex]::Match($uri, $pattern).Groups[1].Value, [System.Management.Automation.PSReference]$ObjectGuid)) {

                    if ($catchResult.error.message -like '*It must match the tenant*') {
                        $patternTenant = "It must match the tenant '$($AzAPICallConfiguration['azAPIEndpointUrls'].IssuerUri)/(.*?)/'"

                        if ([regex]::Match($catchResult.error.message, $patternTenant).Groups[1].Value) {
                            $null = $return.Add([regex]::Match($catchResult.error.message, $patternTenant).Groups[1].Value)
                            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return)'"
                            $response = @{
                                action    = 'return' #break or return or returnCollection
                                returnVar = $return
                            }
                            return $response
                        }
                    }

                    if ($catchResult.error.message -like '*It must match one of the tenants*') {
                        $patternTenants = "It must match one of the tenants '(.*?)'"
                        $result = [regex]::Match($catchResult.error.message, $patternTenants).Groups[1].Value
                        $results = $result -split ','
                        foreach ($resultTenants in $results) {
                            $pattern = "$($AzAPICallConfiguration['azAPIEndpointUrls'].IssuerUri)/(.*?)/"
                            if ([System.Guid]::TryParse([regex]::Match($resultTenants, $pattern).Groups[1].Value, [System.Management.Automation.PSReference]$ObjectGuid)) {
                                $null = $return.Add([regex]::Match($resultTenants, $pattern).Groups[1].Value)
                            }
                        }
                        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return -join ', ')'"
                        $response = @{
                            action    = 'return' #break or return or returnCollection
                            returnVar = $return
                        }
                        return $response
                    }
                }
                else {
                    $null = $return.Add('Tenant unknown')
                    Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return)'"
                    $response = @{
                        action    = 'return' #break or return or returnCollection
                        returnVar = $return
                    }
                    return $response
                }
            }
            else {
                $null = $return.Add("Tenant unknown - unexpected uri '$uri' for currentTask '$currentTask'")
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return)'"
                $response = @{
                    action    = 'return' #break or return or returnCollection
                    returnVar = $return
                }
                return $response
            }
        }
        else {
            $null = $return.Add('unexpected')
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return '$($return)'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = $return
            }
            return $response
        }
    }
    #endregion getTenantId for subscriptionId

    if ($validateAccess -and ($catchResult.error.code -eq 'Authorization_RequestDenied' -or $actualStatusCode -eq 403 -or $actualStatusCode -eq 400)) {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return 'failed'" -logMessageForegroundColor 'DarkRed'
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'failed'
        }
        return $response
    }

    elseif (
        $getARMPolicyComplianceStates -and (
            $catchResult.error.code -like '*ResponseTooLarge*' -or
            -not $catchResult.error.code
        )
    ) {
        if ($catchResult.error.code -like '*ResponseTooLarge*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: Response too large, skipping this scope - return 'ResponseTooLarge'"
            $response = @{
                action    = 'return' #break or return
                returnVar = 'ResponseTooLarge'
            }
            return $response
        }
        if (-not $catchResult.error.code) {
            #seems API now returns null instead of 'ResponseTooLarge'
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: Response empty - handle like 'Response too large', skipping this scope - return 'ResponseTooLarge'"
            $response = @{
                action    = 'return' #break or return
                returnVar = 'ResponseTooLarge'
            }
            return $response
        }
    }

    elseif ($catchResult.error.code -eq 'DisallowedProvider') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping Subscription - return 'DisallowedProvider'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'DisallowedProvider'
        }
        return $response
    }

    elseif ($catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
        $doRetry = $true
        Start-Sleep -Seconds $tryCounter
        $response = @{
            action = 'retry' #break or return or returnCollection or retry
        }
        return $response
    }

    elseif ($currentTask -like 'Getting Resource Properties*') {
        if ($catchResult.error.code -eq 'ResourceGroupNotFound' -or $catchResult.error.code -eq 'ResourceNotFound') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - return 'ResourceOrResourcegroupNotFound'"
            $response = @{
                action    = 'return' #break or return
                returnVar = 'ResourceOrResourcegroupNotFound'
            }
            return $response
        }
    }

    elseif ($catchResult.error.code -like '*AuthorizationFailed*') {
        if ($validateAccess) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return 'failed'"
            $response = @{
                action    = 'return' #break or return
                returnVar = 'failed'
            }
            return $response
        }
        else {
            $script:retryAuthorizationFailedCounter++
            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                if ($unhandledErrorAction -ne 'ContinueQuiet') {
                    Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
                    Logging -preventWriteOutput $true -logMessage "!1348780b Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
                    Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: $retryAuthorizationFailed retries failed - EXIT"
                    Logging -preventWriteOutput $true -logMessage 'Parameters:'
                    foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                        Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                    }
                }
                $script:retryAuthorizationFailedCounter = $null
                #Throw 'Error: check the last console output for details'
                $exitMsg = 'AzAPICall: exit'
            }
            else {
                $doRetry = $true
                if ($retryAuthorizationFailedCounter -gt 2) {
                    $sleepSecondsAuthorizationFailed = 5
                    if ($retryAuthorizationFailedCounter -gt 3) {
                        $sleepSecondsAuthorizationFailed = 10
                    }
                    Start-Sleep -Seconds $sleepSecondsAuthorizationFailed
                    $response = @{
                        action = 'retry' #break or return or returnCollection or retry
                    }
                    return $response
                }

                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
                $response = @{
                    action = 'retry' #break or return or returnCollection or retry
                }
                return $response
            }
        }
    }

    elseif (($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 405) -or ($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 404)) {
        if ($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 405) {
            #https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation-considerations#errors
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: skipping resource Managed Identity - return 'SupportForFederatedIdentityCredentialsNotEnabled'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'SupportForFederatedIdentityCredentialsNotEnabled'
            }
            return $response
        }
        if ($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 404) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: skipping resource Managed Identity (NotFound) - return 'NotFound'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NotFound'
            }
            return $response
        }
    }

    elseif (
        $getARMCostManagement -and (
            $catchResult.error.code -eq 404 -or
            $catchResult.error.code -eq 'AccountCostDisabled' -or
            $catchResult.error.code -eq 'SubscriptionCostDisabled' -or
            $catchResult.error.message -like '*does not have any valid subscriptions*' -or
            $catchResult.error.code -eq 'Unauthorized' -or
            ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') -or
            ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') -or
            $catchResult.error.code -eq 'IndirectCostDisabled' -or
            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') -or
            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') -or
            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*too many subscriptions*')
        )

    ) {
        if ($catchResult.error.code -eq 404) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems Subscriptions was created only recently - skipping"
            $response = @{
                action = 'returnCollection' #break or return or returnCollection
            }
            return $response
        }

        if ($catchResult.error.code -eq 'AccountCostDisabled') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems Access to cost data has been disabled for this Account - skipping CostManagement - return 'AccountCostDisabled'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'AccountCostDisabled'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'SubscriptionCostDisabled') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems Access to cost data has been disabled for this Subscription - skipping CostManagement for this Subscription - return 'SubscriptionCostDisabled'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'SubscriptionCostDisabled'
            }
            return $response
        }

        if ($catchResult.error.message -like '*does not have any valid subscriptions*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems there are no valid Subscriptions present - skipping CostManagement on MG level - return 'NoValidSubscriptions'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NoValidSubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'Unauthorized') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception - return 'Unauthorized'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'Unauthorized'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception - return 'OfferNotSupported'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'OfferNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception - return 'InvalidQueryDefinition'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'InvalidQueryDefinition'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*too many subscriptions*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems there are too many Subscriptions present - skipping CostManagement on MG level - return 'tooManySubscriptions'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'tooManySubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: handling as exception - return 'NonValidWebDirectAIRSOfferType'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NonValidWebDirectAIRSOfferType'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: handling as exception - return 'NotFoundNotSupported'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NotFoundNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'IndirectCostDisabled') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: handling as exception - return 'IndirectCostDisabled'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'IndirectCostDisabled'
            }
            return $response
        }
    }

    elseif ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: uncertain object status - skipping - return 'Request_ResourceNotFound'"
        $response = @{
            action    = 'return' #break or return
            returnVar = 'Request_ResourceNotFound'
        }
        return $response
    }

    elseif ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') {
        $maxTries = 7
        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit (after $maxTries tries)"
            #Throw 'Error - check the last console output for details'
            $exitMsg = "AzAPICall: exit (after $maxTries tries)"
        }
        else {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: sleeping $($sleepSec) seconds"
            $doRetry = $true
            Start-Sleep -Seconds $sleepSec
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }

    }

    elseif ($currentTask -eq 'Checking AAD UserType' -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: cannot get the executing user´s userType information (member/guest) - return 'unknown'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'unknown'
        }
        return $response
    }

    elseif ($getMicrosoftGraphApplication -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: skip Application | Guest not enough permissions - return 'skipApplications'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'skipApplications'
            }
            return $response
        }
        else {
            if ($unhandledErrorAction -ne 'ContinueQuiet') {
                Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
                Logging -preventWriteOutput $true -logMessage "!841be622 Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: EXIT"
                Logging -preventWriteOutput $true -logMessage 'Parameters:'
                foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                    Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                }
            }
            #Throw 'Authorization_RequestDenied'
            $exitMsg = 'AzAPICall: Authorization_RequestDenied exit'
        }
    }

    elseif ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest' -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
        Logging -preventWriteOutput $true -logMessage 'Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'
        Logging -preventWriteOutput $true -logMessage "AAD Role 'Directory readers' is required for your Guest User Account!"
        #Throw 'Error - check the last console output for details'
        $exitMsg = 'AzAPICall: Guest_Authorization_RequestDenied exit'
    }

    elseif ($catchResult.error.code -like '*BlueprintNotFound*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems Blueprint definition is gone - skipping - return 'BlueprintNotFound'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'BlueprintNotFound'
        }
        return $response
    }

    elseif (($actualStatusCode -eq 429 -and $catchResult.error.code -eq 'OperationNotAllowed') -or
        $catchResult.error.code -eq 'ResourceRequestsThrottled' -or
        $catchResult.error.code -eq 429 -or
        $catchResult.error.code -eq 'RateLimiting' -or
        $catchResult.code -eq 'TooManyRequests' -or
        $actualStatusCode -eq 429
    ) {
        $doRetry = $true
        $sleepSeconds = 10
        if ($actualStatusCode -eq 429 -and $catchResult.error.code -eq 'OperationNotAllowed') {
            $sleepSeconds = ($sleepSeconds + $tryCounter)
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! (08c926e7) sleeping $sleepSeconds seconds"
            Write-Host $($catchResult | ConvertTo-Json -Depth 99) -ForegroundColor DarkGreen
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        if ($catchResult.error.code -eq '429' -or $catchResult.error.code -eq 429 -or $actualStatusCode -eq 429) {
            if ($catchResult.error.message -like '*60 seconds*') {
                $sleepSeconds = (60 + $tryCounter)
            }
            else {
                $sleepSeconds = ($sleepSeconds + ($tryCounter * 10))
            }
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! (83f5e825) sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        if ($catchResult.error.code -eq 'ResourceRequestsThrottled' -or $catchResult.error.code -eq 'RateLimiting' -or $catchResult.code -eq 'TooManyRequests') {
            $sleepSeconds = 4
            $sleepSeconds = ($sleepSeconds + ($tryCounter * 5))
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! (1cc3d413) sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }

        $sleepSeconds = ($sleepSeconds + $tryCounter)
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! (2b0e9fba) sleeping $sleepSeconds seconds"
        Start-Sleep -Seconds $sleepSeconds
        $response = @{
            action = 'retry' #break or return or returnCollection or retry
        }
        return $response
    }

    elseif (
            (($getMicrosoftGraphRoleAssignmentSchedules) -and (
            ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
            ($catchResult.error.code -eq 'TenantNotOnboarded') -or
            ($catchResult.error.code -eq 'InvalidResourceType') -or
            ($catchResult.error.code -eq 'InvalidResource')
        ) -or ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource')
                        )
    ) {
        if ($catchResult.error.code -eq 'ResourceNotOnboarded') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return 'ResourceNotOnboarded'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'ResourceNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'TenantNotOnboarded') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return 'TenantNotOnboarded'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'TenantNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResourceType') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return 'InvalidResourceType'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'InvalidResourceType'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResource') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: return 'InvalidResource'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'InvalidResource'
            }
            return $response
        }
    }

    elseif ($getARMRoleAssignmentScheduleInstances -and ($actualStatusCode -eq 400 -or $actualStatusCode -eq 500)) {

        if ($catchResult.error.code -eq 'AadPremiumLicenseRequired') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping - return 'AadPremiumLicenseRequired'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'AadPremiumLicenseRequired'
            }
            return $response
        }
        else {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping - return 'RoleAssignmentScheduleInstancesError'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'RoleAssignmentScheduleInstancesError'
            }
            return $response
        }
    }

    elseif ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping - return 'InvalidResourceType'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'InvalidResourceType'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'InsufficientPermissions' -or $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or $catchResult.message -eq 'An error has occurred.' -or $catchResult.error.code -eq 'GeneralError') {
        $maxTries = 7
        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
        if ($tryCounter -gt $maxTries) {
            #Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
            $exitMsg = "AzAPICall: exit (after $maxTries tries)"
            #Throw 'Error - check the last console output for details'
        }
        else {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: sleeping $($sleepSec) seconds"
            $doRetry = $true
            Start-Sleep -Seconds $sleepSec
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
    }

    elseif (($getARMMDfC -or $getARMMdFCSecurityContacts -or $getARMMdFCSecuritySettings) -and $catchResult.error.code -eq 'Subscription Not Registered') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping Subscription - return 'SubscriptionNotRegistered'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'SubscriptionNotRegistered'
        }
        return $response
    }

    elseif ($getARMMdFCSecurityContacts -and $actualStatusCode -eq 400) {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: invalid MDfC Security Contacts configuration - return 'azgvzerrorMessage_$($catchResult.error.message)'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = "azgvzerrorMessage_$($catchResult.error.message)"
        }
        return $response
    }

    elseif ($getARMDiagnosticSettingsResource -and (
                ($catchResult.error.code -like '*ResourceNotFound*') -or
                ($catchResult.code -like '*ResourceNotFound*') -or
                ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                ($catchResult.code -like '*ResourceGroupNotFound*') -or
                ($catchResult.code -eq 'ResourceTypeNotSupported') -or
                ($catchResult.code -eq 'ResourceProviderNotSupported') -or
                ($catchResult.message -like '*invalid character*') -or
                ($actualStatusCode -eq 404 -and $catchResult.error.code -eq 'InvalidResourceType') #microsoft.datafactory/datafactories
        )
    ) {
        if (($actualStatusCode -eq 404 -and $catchResult.error.code -eq 'InvalidResourceType') -or $catchResult.message -like '*invalid character*' -or $catchResult.error.code -like '*ResourceNotFound*' -or $catchResult.code -like '*ResourceNotFound*' -or $catchResult.error.code -like '*ResourceGroupNotFound*' -or $catchResult.code -like '*ResourceGroupNotFound*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: The resourceId '$($resourceId)' will be skipped - return 'skipResource'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'skipResource'
            }
            return $response
        }

        if ($catchResult.code -eq 'ResourceTypeNotSupported' -or $catchResult.code -eq 'ResourceProviderNotSupported') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: return 'ResourceTypeOrResourceProviderNotSupported'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'ResourceTypeOrResourceProviderNotSupported'
            }
            return $response
        }
    }

    elseif ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: maximum number of groups exceeded, skipping; docs: https://docs.microsoft.com/pt-br/previous-versions/azure/ad/graph/api/functions-and-actions#getmembergroups-get-group-memberships-transitive-- - return 'Directory_ResultSizeLimitExceeded'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'Directory_ResultSizeLimitExceeded'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'RoleDefinitionDoesNotExist') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: RBAC RoleDefinition does not exist - return 'RoleDefinitionDoesNotExist'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'RoleDefinitionDoesNotExist'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'ClassicAdministratorListFailed') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: ClassicAdministrators not applicable - return 'ClassicAdministratorListFailed'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'ClassicAdministratorListFailed'
        }
        return $response
    }

    elseif ($targetEndPoint -eq 'Kusto' -and ($actualStatusCode -eq '401' -or $actualStatusCode -eq 401)) {
        $maxTries = 7
        if ($tryCounter -gt $maxTries) {
            #Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
            $exitMsg = "AzAPICall: exit (requesting new bearer token '$targetEndpoint' ($targetCluster) - max retry of '$maxTries' reached)"
            #Throw 'Error - check the last console output for details'
        }
        else {
            $sleepSeconds = 2
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token '$targetEndpoint' ($targetCluster) - sleep $sleepSeconds seconds and try again (max retry: $maxTries)"
            $doRetry = $true
            createBearerToken -targetEndPoint 'Kusto' -TargetCluster $targetCluster -AzAPICallConfiguration $AzAPICallConfiguration
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
    }

    else {
        if (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and -not $catchResult -and $tryCounter -lt 6) {
            if ($actualStatusCode -eq 204 -and $getARMCostManagement) {
                $response = @{
                    action = 'returnCollection' #break or return or returnCollection
                }
                return $response
            }
            else {
                $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: try again in $sleepSec second(s)"
                $doRetry = $true
                Start-Sleep -Seconds $sleepSec
                $response = @{
                    action = 'retry' #break or return or returnCollection or retry
                }
                return $response
            }
        }
        elseif (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and $catchResult -and $tryCounter -lt 6) {
            $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: try again in $sleepSec second(s)"
            $doRetry = $true
            Start-Sleep -Seconds $sleepSec
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        else {
            if ($unhandledErrorAction -ne 'ContinueQuiet') {
                Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
                Logging -preventWriteOutput $true -logMessage "!f97434b8 Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: $unhandledErrorAction"
                Logging -preventWriteOutput $true -logMessage 'Parameters:'
                foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                    Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                }
            }
            if ($getARMCostManagement) {
                Logging -preventWriteOutput $true -logMessage 'If Consumption data is not that important for you, do not use parameter: -DoAzureConsumption (however, please still report the issue - thank you)'
            }
        }
    }

    if ($doRetry -eq $false) {
        if ($unhandledErrorAction -in @('Continue', 'ContinueQuiet')) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo $exitMsg - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'Green'
            $response = @{
                action = 'break'
            }
            return $response
        }
        else {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo $exitMsg - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
            Throw 'Error - check the last console output for details'
        }
    }

}
$script:funcAzAPICallErrorHandler = $function:AzAPICallErrorHandler.ToString()