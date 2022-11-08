function AzAPICallErrorHandler {
    #Logging -preventWriteOutput $true -logMessage ' * BuiltIn RuleSet'

    $defaultErrorInfo = "$currentTask try #$($tryCounter); return: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'>"
    switch ($uri) {
        #ARM
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.PolicyInsights/policyStates/latest/summarize*" } { $getARMPolicyComplianceStates = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.Authorization/roleAssignmentScheduleInstances*" } { $getARMRoleAssignmentScheduleInstances = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/*/providers/microsoft.insights/diagnosticSettings*" } { $getARMDiagnosticSettingsMg = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/microsoft.insights/diagnosticSettingsCategories*" } { $getARMDiagnosticSettingsResource = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.CostManagement/query*" } { $getARMCostManagement = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/*" } { $getARMARG = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/pricings*" } { $getARMMDfC = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/securescores*" } { $getARMMdFC = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/securityContacts*" } { $getARMMdFCSecurityContacts = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/federatedIdentityCredentials*" } { $getARMManagedIdentityUserAssignedFederatedIdentityCredentials = $true }
        #MicrosoftGraph
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/applications*" } { $getMicrosoftGraphApplication = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/groups/*/transitiveMembers/`$count" } { $getMicrosoftGraphGroupMembersTransitiveCount = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/servicePrincipals/*/getMemberGroups" } { $getMicrosoftGraphServicePrincipalGetMemberGroups = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentSchedules*" } { $getMicrosoftGraphRoleAssignmentSchedules = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentScheduleInstances*" } { $getMicrosoftGraphRoleAssignmentScheduleInstances = $true }
    }

    #region getTenantId for subscriptionId
    if ($currentTask -like "getTenantId for subscriptionId '*'" -and $uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*" ) {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: trying to return Tenant Id (arrayList)"
        $return = [System.Collections.ArrayList]@()
        if ($catchResult.error.code -eq 'SubscriptionNotFound' -and $actualStatusCode -eq 404) {
            $null = $return.Add('SubscriptionNotFound Tenant unknown')
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = $return
            }
            return $response
        }
        elseif ($catchResult.error.code -eq 'AuthorizationFailed' -and $actualStatusCode -eq 403) {
            $null = $return.Add($AzApiCallConfiguration['checkcontext'].tenant.id)
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = $return
            }
            return $response
        }
        elseif ($catchResult.error.code -eq 'InvalidAuthenticationTokenTenant' -and $actualStatusCode -eq 401) {
            $pattern = "$($azapicallconf['azAPIEndpointUrls'].ARM)/subscriptions/(.*?)\?api-version=2020-01-01"
            if ([regex]::Match($uri, $pattern).Groups[1].Value) {
                $ObjectGuid = [System.Guid]::empty
                if ([System.Guid]::TryParse([regex]::Match($uri, $pattern).Groups[1].Value, [System.Management.Automation.PSReference]$ObjectGuid)) {

                    if ($catchResult.error.message -like '*It must match the tenant*') {
                        $patternTenant = "It must match the tenant 'https://sts.windows.net/(.*?)/'"

                        if ([regex]::Match($catchResult.error.message, $patternTenant).Groups[1].Value) {
                            $null = $return.Add([regex]::Match($catchResult.error.message, $patternTenant).Groups[1].Value)
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
                            Write-Host $resultTenants -ForegroundColor DarkGray
                            $pattern = 'https://sts.windows.net/(.*?)/'
                            if ([System.Guid]::TryParse([regex]::Match($resultTenants, $pattern).Groups[1].Value, [System.Management.Automation.PSReference]$ObjectGuid)) {
                                $return.Add([regex]::Match($resultTenants, $pattern).Groups[1].Value)
                            }
                        }

                        $response = @{
                            action    = 'return' #break or return or returnCollection
                            returnVar = $return
                        }
                        return $response
                    }
                }
                else {
                    $null = $return.Add('Tenant unknown')
                    $response = @{
                        action    = 'return' #break or return or returnCollection
                        returnVar = $return
                    }
                    return $response
                }
            }
            else {
                $null = $return.Add("Tenant unknown - unexpected uri '$uri' for currentTask '$currentTask'")
                $response = @{
                    action    = 'return' #break or return or returnCollection
                    returnVar = $return
                }
                return $response
            }
        }
        else {
            $null = $return.Add('unexpected')
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = $return
            }
            return $response
        }
    }
    #endregion getTenantId for subscriptionId

    if ($validateAccess -and ($catchResult.error.code -eq 'Authorization_RequestDenied' -or $actualStatusCode -eq 403 -or $actualStatusCode -eq 400)) {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo" -logMessageForegroundColor 'DarkRed'
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
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: Response too large, skipping this scope."
            $response = @{
                action    = 'return' #break or return
                returnVar = 'ResponseTooLarge'
            }
            return $response
        }
        if (-not $catchResult.error.code) {
            #seems API now returns null instead of 'ResponseTooLarge'
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: Response empty - handle like 'Response too large', skipping this scope."
            $response = @{
                action    = 'return' #break or return
                returnVar = 'ResponseTooLarge'
            }
            return $response
        }
    }

    elseif ($catchResult.error.code -eq 'DisallowedProvider') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping Subscription"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'DisallowedProvider'
        }
        return $response
    }

    elseif ($catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
        Start-Sleep -Seconds $tryCounter
    }

    elseif ($catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*BadGatewayConnection*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq '500') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: try again in $tryCounter second(s)"
        Start-Sleep -Seconds $tryCounter
    }

    elseif ($catchResult.error.code -like '*AuthorizationFailed*') {
        if ($validateAccess) {
            #Logging -preventWriteOutput $true -logMessage " $currentTask <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'>" -logMessageForegroundColor "DarkRed"
            $response = @{
                action    = 'return' #break or return
                returnVar = 'failed'
            }
            return $response
        }
        else {
            $script:retryAuthorizationFailedCounter ++
            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
                Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: $retryAuthorizationFailed retries failed - EXIT"
                Logging -preventWriteOutput $true -logMessage 'Parameters:'
                foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                    Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                }
                $script:retryAuthorizationFailedCounter = $null
                Throw 'Error: check the last console output for details'
            }
            else {
                if ($retryAuthorizationFailedCounter -gt 2) {
                    Start-Sleep -Seconds 5
                }
                if ($retryAuthorizationFailedCounter -gt 3) {
                    Start-Sleep -Seconds 10
                }
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
            }
        }
    }

    elseif ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*') {
        $maxTriesCreateToken = 7
        $sleepSecCreateToken = @(1, 1, 1, 2, 3, 5, 10, 20, 30)[$tryCounter]
        if ($tryCounter -gt 1) {
            if ($tryCounter -gt $maxTriesCreateToken) {
                Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint) - EXIT"
                Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository)" -logMessageForegroundColor 'Yellow'
                Throw 'Error - check the last console output for details'
            }
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint) - sleep $($sleepSecCreateToken) seconds and try again"
            Start-Sleep -Seconds $sleepSecCreateToken
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint)"
        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
    }

    elseif (($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 405) -or ($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 404)) {
        if ($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 405) {
            #https://learn.microsoft.com/en-us/azure/active-directory/develop/workload-identity-federation-considerations#errors
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: skipping resource Managed Identity (SupportForFederatedIdentityCredentialsNotEnabled)"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'SupportForFederatedIdentityCredentialsNotEnabled'
            }
            return $response
        }
        if ($getARMManagedIdentityUserAssignedFederatedIdentityCredentials -and $actualStatusCode -eq 404) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: skipping resource Managed Identity (NotFound)"
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
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems Access to cost data has been disabled for this Account - skipping CostManagement"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'AccountCostDisabled'
            }
            return $response
        }

        if ($catchResult.error.message -like '*does not have any valid subscriptions*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems there are no valid Subscriptions present - skipping CostManagement on MG level"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NoValidSubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'Unauthorized') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'Unauthorized'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'OfferNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'InvalidQueryDefinition'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*too many subscriptions*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems there are too many Subscriptions present - skipping CostManagement on MG level"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'tooManySubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NonValidWebDirectAIRSOfferType'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'NotFoundNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'IndirectCostDisabled') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'IndirectCostDisabled'
            }
            return $response
        }
    }

    elseif ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: uncertain object status - skipping for now :)"
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
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
            Throw 'Error - check the last console output for details'
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: sleeping $($sleepSec) seconds"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($currentTask -eq 'Checking AAD UserType' -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: cannot get the executing user´s userType information (member/guest) - proceeding as 'unknown'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'unknown'
        }
        return $response
    }

    elseif ($getMicrosoftGraphApplication -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: skip Application | Guest not enough permissions"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'skipApplications'
            }
            return $response
        }
        else {
            Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
            Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: EXIT"
            Logging -preventWriteOutput $true -logMessage 'Parameters:'
            foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
            }
            Throw 'Authorization_RequestDenied'
        }
    }

    elseif ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest' -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
        Logging -preventWriteOutput $true -logMessage 'Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'
        Logging -preventWriteOutput $true -logMessage "AAD Role 'Directory readers' is required for your Guest User Account!"
        Throw 'Error - check the last console output for details'
    }

    elseif ($catchResult.error.code -like '*BlueprintNotFound*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: seems Blueprint definition is gone - skipping for now :)"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'BlueprintNotFound'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'ResourceRequestsThrottled' -or $catchResult.error.code -eq '429' -or $catchResult.error.code -eq 'RateLimiting') {
        $sleepSeconds = 11
        if ($catchResult.error.code -eq 'ResourceRequestsThrottled') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
        if ($catchResult.error.code -eq '429') {
            if ($catchResult.error.message -like '*60 seconds*') {
                $sleepSeconds = 60
            }
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
        if ($catchResult.error.code -eq 'RateLimiting') {
            $sleepSeconds = 5
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
    }

    elseif ($getARMARG -and $catchResult.error.code -eq 'BadRequest') {
        $sleepSec = @(1, 1, 2, 3, 5, 7, 9, 10, 13, 15, 20, 25, 30, 45, 60, 60, 60, 60)[$tryCounter]
        $maxTries = 15
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - capitulation after $maxTries attempts"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'capitulation'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: try again (trying $maxTries times) in $sleepSec second(s)"
        Start-Sleep -Seconds $sleepSec
    }

    elseif (
            ((<#$getARMRoleAssignmentSchedules -or #>$getMicrosoftGraphRoleAssignmentSchedules) -and (
            ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
            ($catchResult.error.code -eq 'TenantNotOnboarded') -or
            ($catchResult.error.code -eq 'InvalidResourceType') -or
            ($catchResult.error.code -eq 'InvalidResource')
        ) -or ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource')
                        )
    ) {
        if ($catchResult.error.code -eq 'ResourceNotOnboarded') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'ResourceNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'TenantNotOnboarded') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'TenantNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResourceType') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'InvalidResourceType'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResource') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'InvalidResource'
            }
            return $response
        }
    }

    elseif ($getARMRoleAssignmentScheduleInstances -and ($actualStatusCode -eq 400 -or $actualStatusCode -eq 500)) {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping"
        if ($catchResult.error.code -eq 'AadPremiumLicenseRequired') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'AadPremiumLicenseRequired'
            }
        }
        else {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'RoleAssignmentScheduleInstancesError'
            }
        }
        return $response
    }

    elseif ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') {
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
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
            Throw 'Error - check the last console output for details'
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: sleeping $($sleepSec) seconds"
        Start-Sleep -Seconds $sleepSec
    }

    elseif (($getARMMDfC -or $getARMMdFCSecurityContacts) -and $catchResult.error.code -eq 'Subscription Not Registered') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: skipping Subscription"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'SubscriptionNotRegistered'
        }
        return $response
    }

    elseif ($getARMMdFCSecurityContacts -and $actualStatusCode -eq 400) {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: invalid MDfC Security Contacts configuration"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = "azgvzerrorMessage_$($catchResult.error.message)"
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'Request_UnsupportedQuery') {
        $sleepSec = @(1, 3, 7, 10, 15, 20, 30)[$tryCounter]
        $maxTries = 5
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - capitulation after $maxTries attempts"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'Request_UnsupportedQuery'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: try again (trying $maxTries times) in $sleepSec second(s)"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($getARMDiagnosticSettingsResource -and (
                ($catchResult.error.code -like '*ResourceNotFound*') -or
                ($catchResult.code -like '*ResourceNotFound*') -or
                ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                ($catchResult.code -like '*ResourceGroupNotFound*') -or
                ($catchResult.code -eq 'ResourceTypeNotSupported') -or
                ($catchResult.code -eq 'ResourceProviderNotSupported') -or
                ($catchResult.message -like '*invalid character*')
        )
    ) {
        if ($catchResult.message -like '*invalid character*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: The resourceId '$($resourceId)' will be skipped"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'skipResource'
            }
            return $response
        }
        if ($catchResult.error.code -like '*ResourceNotFound*' -or $catchResult.code -like '*ResourceNotFound*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: The resourceId '$($resourceId)' will be skipped"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'skipResource'
            }
            return $response
        }
        if ($catchResult.error.code -like '*ResourceGroupNotFound*' -or $catchResult.code -like '*ResourceGroupNotFound*') {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: The resourceId '$($resourceId)' will be skipped"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'skipResource'
            }
            return $response
        }
        if ($catchResult.code -eq 'ResourceTypeNotSupported' -or $catchResult.code -eq 'ResourceProviderNotSupported') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'ResourceTypeOrResourceProviderNotSupported'
            }
            return $response
        }
    }

    elseif ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: maximum number of groups exceeded, skipping; docs: https://docs.microsoft.com/pt-br/previous-versions/azure/ad/graph/api/functions-and-actions#getmembergroups-get-group-memberships-transitive--"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'Directory_ResultSizeLimitExceeded'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'RoleDefinitionDoesNotExist') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: RBAC RoleDefinition does not exist"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'RoleDefinitionDoesNotExist'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'ClassicAdministratorListFailed') {
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: ClassicAdministrators not applicable"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnVar = 'ClassicAdministratorListFailed'
        }
        return $response
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
                Start-Sleep -Seconds $sleepSec
            }
        }
        elseif (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and $catchResult -and $tryCounter -lt 6) {
            $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: try again in $sleepSec second(s)"
            Start-Sleep -Seconds $sleepSec
        }
        else {
            Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
            Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - (plain : $catchResult) - AzAPICall: $unhandledErrorAction"
            Logging -preventWriteOutput $true -logMessage 'Parameters:'
            foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
            }
            if ($getARMCostManagement) {
                Logging -preventWriteOutput $true -logMessage 'If Consumption data is not that important for you, do not use parameter: -DoAzureConsumption (however, please still report the issue - thank you)'
            }
            switch ($unhandledErrorAction) {
                'Continue' {
                    break
                }
                'Stop' {
                    Throw 'Error - check the last console output for details'
                }
            }
        }
    }
}
$script:funcAzAPICallErrorHandler = $function:AzAPICallErrorHandler.ToString()