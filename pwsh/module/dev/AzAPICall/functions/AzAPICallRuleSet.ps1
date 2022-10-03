#needs special handling

function AzAPICallErrorHandler {
    #Logging -preventWriteOutput $true -logMessage ' * BuiltIn RuleSet'

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
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/securityContacts*" } { $getARMMdFC = $true }
        #MicrosoftGraph
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/applications*" } { $getMicrosoftGraphApplication = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/groups/*/transitiveMembers/`$count" } { $getMicrosoftGraphGroupMembersTransitiveCount = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/servicePrincipals/*/getMemberGroups" } { $getMicrosoftGraphServicePrincipalGetMemberGroups = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentSchedules*" } { $getMicrosoftGraphRoleAssignmentSchedules = $true }
        { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentScheduleInstances*" } { $getMicrosoftGraphRoleAssignmentScheduleInstances = $true }
    }

    if ($validateAccess -and ($catchResult.error.code -eq 'Authorization_RequestDenied' -or $actualStatusCode -eq 403 -or $actualStatusCode -eq 400)) {
        Logging -preventWriteOutput $true -logMessage "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -logMessageForegroundColor 'DarkRed'
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'failed'
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
            Logging -preventWriteOutput $true -logMessage "Info: $currentTask - (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) Response too large, skipping this scope."
            $response = @{
                action    = 'return' #break or return
                returnMsg = 'ResponseTooLarge'
            }
            return $response
        }
        if (-not $catchResult.error.code) {
            #seems API now returns null instead of 'ResponseTooLarge'
            Logging -preventWriteOutput $true -logMessage "Info: $currentTask - (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) Response empty - handle like 'Response too large', skipping this scope."
            $response = @{
                action    = 'return' #break or return
                returnMsg = 'ResponseTooLarge'
            }
            return $response
        }
    }

    elseif ($catchResult.error.code -eq 'DisallowedProvider') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' skipping Subscription"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'DisallowedProvider'
        }
        return $response
    }

    elseif ($catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
        Start-Sleep -Seconds $tryCounter
    }

    elseif ($catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*BadGatewayConnection*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq '500') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again in $tryCounter second(s)"
        Start-Sleep -Seconds $tryCounter
    }

    elseif ($catchResult.error.code -like '*AuthorizationFailed*') {
        if ($validateAccess) {
            #Logging -preventWriteOutput $true -logMessage "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -logMessageForegroundColor "DarkRed"
            $response = @{
                action    = 'return' #break or return
                returnMsg = 'failed'
            }
            return $response
        }
        else {
            $script:retryAuthorizationFailedCounter ++
            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
                Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
                Logging -preventWriteOutput $true -logMessage "$currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - EXIT"
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
                Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
            }
        }
    }

    elseif ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
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
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
            $response = @{
                action = 'returnCollection' #break or return or returnCollection
            }
            return $response
        }

        if ($catchResult.error.code -eq 'AccountCostDisabled') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Access to cost data has been disabled for this Account - skipping CostManagement"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'AccountCostDisabled'
            }
            return $response
        }

        if ($catchResult.error.message -like '*does not have any valid subscriptions*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems there are no valid Subscriptions present - skipping CostManagement on MG level"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'NoValidSubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'Unauthorized') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'Unauthorized'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'OfferNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'InvalidQueryDefinition'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*too many subscriptions*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems there are too many Subscriptions present - skipping CostManagement on MG level"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'tooManySubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'NonValidWebDirectAIRSOfferType'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'NotFoundNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'IndirectCostDisabled') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'IndirectCostDisabled'
            }
            return $response
        }
    }

    elseif ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain object status - skipping for now :)"
        $response = @{
            action    = 'return' #break or return
            returnMsg = 'Request_ResourceNotFound'
        }
        return $response
    }

    elseif ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') {
        $maxTries = 7
        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
            Throw 'Error - check the last console output for details'
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($currentTask -eq 'Checking AAD UserType' -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) cannot get the executing user´s userType information (member/guest) - proceeding as 'unknown'"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'unknown'
        }
        return $response
    }

    elseif ($getMicrosoftGraphApplication -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - skip Application | Guest not enough permissions"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'skipApplications'
            }
            return $response
        }
        else {
            Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
            Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
            Logging -preventWriteOutput $true -logMessage "$currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
            Logging -preventWriteOutput $true -logMessage 'Parameters:'
            foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
            }
            Throw 'Authorization_RequestDenied'
        }
    }

    elseif ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest' -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
        Logging -preventWriteOutput $true -logMessage 'Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'
        Logging -preventWriteOutput $true -logMessage "AAD Role 'Directory readers' is required for your Guest User Account!"
        Throw 'Error - check the last console output for details'
    }

    elseif ($catchResult.error.code -like '*BlueprintNotFound*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Blueprint definition is gone - skipping for now :)"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'BlueprintNotFound'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'ResourceRequestsThrottled' -or $catchResult.error.code -eq '429' -or $catchResult.error.code -eq 'RateLimiting') {
        $sleepSeconds = 11
        if ($catchResult.error.code -eq 'ResourceRequestsThrottled') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
        if ($catchResult.error.code -eq '429') {
            if ($catchResult.error.message -like '*60 seconds*') {
                $sleepSeconds = 60
            }
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
        if ($catchResult.error.code -eq 'RateLimiting') {
            $sleepSeconds = 5
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' - throttled! sleeping $sleepSeconds seconds"
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
                returnMsg = 'capitulation'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
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
                returnMsg = 'ResourceNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'TenantNotOnboarded') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'TenantNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResourceType') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'InvalidResourceType'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResource') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'InvalidResource'
            }
            return $response
        }
    }

    elseif ($getARMRoleAssignmentScheduleInstances -and ($actualStatusCode -eq 400 -or $actualStatusCode -eq 500)) {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - skipping"
        if ($catchResult.error.code -eq 'AadPremiumLicenseRequired') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'AadPremiumLicenseRequired'
            }
        }
        else {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'RoleAssignmentScheduleInstancesError'
            }
        }
        return $response
    }

    elseif ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') {
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'InvalidResourceType'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'InsufficientPermissions' -or $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or $catchResult.message -eq 'An error has occurred.' -or $catchResult.error.code -eq 'GeneralError') {
        $maxTries = 7
        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
            Throw 'Error - check the last console output for details'
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($getARMMDfC -and $catchResult.error.code -eq 'Subscription Not Registered') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' skipping Subscription"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'SubscriptionNotRegistered'
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
                returnMsg = 'Request_UnsupportedQuery'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($getARMDiagnosticSettingsResource -and (
                ($catchResult.error.code -like '*ResourceNotFound*') -or
                ($catchResult.code -like '*ResourceNotFound*') -or
                ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                ($catchResult.code -like '*ResourceGroupNotFound*') -or
                ($catchResult.code -eq 'ResourceTypeNotSupported') -or
                ($catchResult.code -eq 'ResourceProviderNotSupported')
        )
    ) {
        if ($catchResult.error.code -like '*ResourceNotFound*' -or $catchResult.code -like '*ResourceNotFound*') {
            Logging -preventWriteOutput $true -logMessage "  ResourceGone | The resourceId '$($resourceId)' seems meanwhile deleted."
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'meanwhile_deleted_ResourceNotFound'
            }
            return $response
        }
        if ($catchResult.error.code -like '*ResourceGroupNotFound*' -or $catchResult.code -like '*ResourceGroupNotFound*') {
            Logging -preventWriteOutput $true -logMessage "  ResourceGone | ResourceGroup not found - the resourceId '$($resourceId)' seems meanwhile deleted."
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'meanwhile_deleted_ResourceGroupNotFound'
            }
            return $response
        }
        if ($catchResult.code -eq 'ResourceTypeNotSupported' -or $catchResult.code -eq 'ResourceProviderNotSupported') {
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnMsg = 'ResourceTypeOrResourceProviderNotSupported'
            }
            return $response
        }
    }

    elseif ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) maximum number of groups exceeded, skipping; docs: https://docs.microsoft.com/pt-br/previous-versions/azure/ad/graph/api/functions-and-actions#getmembergroups-get-group-memberships-transitive--"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'Directory_ResultSizeLimitExceeded'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'RoleDefinitionDoesNotExist') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) RBAC RoleDefinition does not exist"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'RoleDefinitionDoesNotExist'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'ClassicAdministratorListFailed') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) ClassicAdministrators not applicable"
        $response = @{
            action    = 'return' #break or return or returnCollection
            returnMsg = 'ClassicAdministratorListFailed'
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
                Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                Start-Sleep -Seconds $sleepSec
            }
        }
        elseif (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and $catchResult -and $tryCounter -lt 6) {
            $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
            Start-Sleep -Seconds $sleepSec
        }
        else {
            Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
            Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
            Logging -preventWriteOutput $true -logMessage "$currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
            Logging -preventWriteOutput $true -logMessage 'Parameters:'
            foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
            }
            if ($getARMCostManagement) {
                Logging -preventWriteOutput $true -logMessage 'If Consumption data is not that important for you, do not use parameter: -DoAzureConsumption (however, please still report the issue - thank you)'
            }
            Throw 'Error - check the last console output for details'
        }
    }
}
$script:funcAzAPICallErrorHandler = $function:AzAPICallErrorHandler.ToString()