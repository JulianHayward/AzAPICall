function AzAPICall {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER uri
    Parameter description

    .PARAMETER method
    Parameter description

    .PARAMETER currentTask
    Parameter description

    .PARAMETER body
    Parameter description

    .PARAMETER listenOn
    Parameter description

    .PARAMETER caller
    Parameter description

    .PARAMETER consistencyLevel
    Parameter description

    .PARAMETER validateAccess
    Parameter description

    .PARAMETER noPaging
    Parameter description

    .EXAMPLE
    PS C:\> $aadgroups = AzAPICall -uri "https://graph.microsoft.com/v1.0/groups?`$top=999&`$filter=(mailEnabled eq false and securityEnabled eq true)&`$select=id,createdDateTime,displayName,description&`$orderby=displayName asc" -method "GET" -currentTask "Microsoft Graph API: Get - Groups" -listenOn "Value" -consistencyLevel "eventual" -noPaging $true

    .NOTES
    General notes
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $uri,

        [Parameter()]
        [string]
        $method,

        [Parameter()]
        [string]
        $currentTask,

        [Parameter()]
        [string]
        $body,

        [Parameter()]
        [string]
        $listenOn,

        [Parameter()]
        [string]
        $caller,

        [Parameter()]
        [string]
        $consistencyLevel,

        [Parameter()]
        [switch]
        $noPaging,

        [Parameter()]
        [switch]
        $validateAccess,

        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    function debugAzAPICall {
        param (
            [Parameter(Mandatory)]
            [string]
            $debugMessage
        )

        if ($doDebugAzAPICall -or $tryCounter -gt 3) {
            if ($doDebugAzAPICall) { Write-Host "  DEBUGTASK: $debugMessage" -ForegroundColor $debugForeGroundColor }
            if (-not $doDebugAzAPICall -and $tryCounter -gt 3) { Write-Host "  Forced DEBUG: $debugMessage" -ForegroundColor $debugForeGroundColor }
        }
    }

    #Set defaults
    if (-not $method) { $method = 'GET' }
    if (-not $currentTask) { $currentTask = $method + ' ' + $uri }
    if ($validateAccess) { $noPaging = $true }

    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    $retryAuthorizationFailed = 5
    $retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0

    $debugForeGroundColor = 'Cyan'
    if ($AzAPICallConfiguration['htParameters'].debugAzAPICall -eq $true) {
        $doDebugAzAPICall = $true
        if ($caller -like 'CustomDataCollection*') {
            $debugForeGroundColors = @('DarkBlue', 'DarkGreen', 'DarkCyan', 'Cyan', 'DarkMagenta', 'DarkYellow', 'Blue', 'Magenta', 'Yellow', 'Green')
            $debugForeGroundColorsCount = $debugForeGroundColors.Count
            $randomNumber = Get-Random -Minimum 0 -Maximum ($debugForeGroundColorsCount - 1)
            $debugForeGroundColor = $debugForeGroundColors[$randomNumber]
        }
    }

    do {
        $uriSplitted = $uri.split('/')
        if (-not ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])) {
            Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
        }

        $targetEndpoint = ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])

        if (-not $AzAPICallConfiguration['htBearerAccessToken'].($targetEndpoint)) {
            createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
        }

        $unexpectedError = $false

        $Header = @{
            'Content-Type'  = 'application/json';
            'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)"
        }
        if ($consistencyLevel) {
            $Header = @{
                'Content-Type'     = 'application/json';
                'Authorization'    = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)";
                'ConsistencyLevel' = "$consistencyLevel"
            }
        }

        #needs special handling
        switch ($uri) {
            #ARM
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.PolicyInsights/policyStates/latest/summarize*" } { $getARMPolicyComplianceStates = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.Authorization/roleAssignmentSchedules*" } { $getARMRoleAssignmentSchedules = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.Management/managementGroups/*/providers/microsoft.insights/diagnosticSettings*" } { $getARMDiagnosticSettingsMg = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/microsoft.insights/diagnosticSettingsCategories*" } { $getARMDiagnosticSettingsResource = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.CostManagement/query*" } { $getARMCostManagement = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/subscriptions/*/providers/Microsoft.Security/pricings*" } { $getARMMDfC = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/*" } { $getARMARG = $true }
            #MicrosoftGraph
            #{ $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/groups/*/transitiveMembers" } { $getMicrosoftGraphGroupMembersTransitive = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/applications*" } { $getMicrosoftGraphApplication = $true }
            #{ $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/servicePrincipals*" } { $getMicrosoftGraphServicePrincipal = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/groups/*/transitiveMembers/`$count" } { $getMicrosoftGraphGroupMembersTransitiveCount = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/servicePrincipals/*/getMemberGroups" } { $getMicrosoftGraphServicePrincipalGetMemberGroups = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentSchedules*" } { $getMicrosoftGraphRoleAssignmentSchedules = $true }
            { $_ -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph)/*/roleManagement/directory/roleAssignmentScheduleInstances*" } { $getMicrosoftGraphRoleAssignmentScheduleInstances = $true }
        }

        $startAPICall = Get-Date
        try {
            if ($body) {
                if ($AzApiCallConfiguration['htParameters'].codeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers $Header -UseBasicParsing
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers $Header
                }
            }
            else {
                if ($AzApiCallConfiguration['htParameters'].codeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header -UseBasicParsing
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header
                }
            }
        }
        catch {
            try {
                $catchResultPlain = $_.ErrorDetails.Message
                if ($catchResultPlain) {
                    $catchResult = $catchResultPlain | ConvertFrom-Json -ErrorAction Stop
                }
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        $endAPICall = Get-Date
        $durationAPICall = NEW-TIMESPAN -Start $startAPICall -End $endAPICall

        if (-not $notTryCounter) {
            $tryCounter++
        }
        $notTryCounter = $false

        #API Call Tracking
        $tstmp = (Get-Date -Format 'yyyyMMddHHmmssms')
        $null = $AzApiCallConfiguration['arrayAPICallTracking'].Add([PSCustomObject]@{
                CurrentTask                          = $currentTask
                TargetEndpoint                       = $targetEndpoint
                Uri                                  = $uri
                Method                               = $method
                TryCounter                           = $tryCounter
                TryCounterUnexpectedError            = $tryCounterUnexpectedError
                RetryAuthorizationFailedCounter      = $retryAuthorizationFailedCounter
                RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                TimeStamp                            = $tstmp
                Duration                             = $durationAPICall.TotalSeconds
            })

        debugAzAPICall -debugMessage "attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'"
        if ($unexpectedError -eq $false) {
            debugAzAPICall -debugMessage 'unexpectedError: false'
            if ($azAPIRequest.StatusCode -notin 200..204) {
                debugAzAPICall -debugMessage "apiStatusCode: '$($azAPIRequest.StatusCode)'"
                if (
                    $catchResult.error.code -like '*GatewayTimeout*' -or
                    $catchResult.error.code -like '*BadGatewayConnection*' -or
                    $catchResult.error.code -like '*InvalidGatewayHost*' -or
                    $catchResult.error.code -like '*ServerTimeout*' -or
                    $catchResult.error.code -like '*ServiceUnavailable*' -or
                    $catchResult.code -like '*ServiceUnavailable*' -or
                    $catchResult.error.code -like '*MultipleErrorsOccurred*' -or
                    $catchResult.code -like '*InternalServerError*' -or
                    $catchResult.error.code -like '*InternalServerError*' -or
                    $catchResult.error.code -like '*RequestTimeout*' -or
                    $catchResult.error.code -like '*AuthorizationFailed*' -or
                    $catchResult.error.code -like '*ExpiredAuthenticationToken*' -or
                    $catchResult.error.code -like '*Authentication_ExpiredToken*' -or
                    $catchResult.error.code -like '*UnknownError*' -or
                    $catchResult.error.code -like '*BlueprintNotFound*' -or
                    $catchResult.error.code -eq '500' -or
                    $catchResult.error.code -eq 'ResourceRequestsThrottled' -or
                    $catchResult.error.code -eq '429' -or
                    $catchResult.error.code -eq 'InsufficientPermissions' -or
                    $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or
                    $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or
                    $catchResult.message -eq 'An error has occurred.' -or
                    $catchResult.error.code -eq 'Request_UnsupportedQuery' -or
                    $catchResult.error.code -eq 'GeneralError' -or
                    $catchResult.error.code -like '*InvalidAuthenticationToken*' -or
                    (
                        $getARMPolicyComplianceStates -and (
                            ($catchResult.error.code -like '*ResponseTooLarge*') -or
                            (-not $catchResult.error.code)
                        )
                    ) -or
                    (
                        $getARMCostManagement -and (
                            ($catchResult.error.code -eq 404) -or
                            ($catchResult.error.code -eq 'AccountCostDisabled') -or
                            ($catchResult.error.message -like '*does not have any valid subscriptions*') -or
                            ($catchResult.error.code -eq 'Unauthorized') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') -or
                            ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') -or
                            ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') -or
                            ($catchResult.error.code -eq 'IndirectCostDisabled')
                        )
                    ) -or
                    $catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*' -or
                    #(($getMicrosoftGraphApplication -or $getMicrosoftGraphServicePrincipal -or $getMicrosoftGraphGroupMembersTransitive -or $getMicrosoftGraphGroupMembersTransitiveCount) -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or
                    ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') -or
                    (($getMicrosoftGraphApplication) -and $catchResult.error.code -like '*Authorization_RequestDenied*') -or
                    ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') -or
                    ($getARMARG -and $catchResult.error.code -eq 'BadRequest') -or
                    (
                        ($getARMRoleAssignmentSchedules -or $getMicrosoftGraphRoleAssignmentSchedules) -and (
                            ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
                            ($catchResult.error.code -eq 'TenantNotOnboarded') -or
                            ($catchResult.error.code -eq 'InvalidResourceType') -or
                            ($catchResult.error.code -eq 'InvalidResource')
                        )
                    ) -or
                    ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource') -or
                    ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') -or
                    (
                        $validateAccess -and (
                            $catchResult.error.code -eq 'Authorization_RequestDenied'
                        )
                    ) -or
                    (
                        $getARMMDfC -and (
                            $catchResult.error.code -eq 'Subscription Not Registered'
                        )
                    ) -or
                    (
                        $getARMDiagnosticSettingsResource -and (
                            ($catchResult.error.code -like '*ResourceNotFound*') -or
                            ($catchResult.code -like '*ResourceNotFound*') -or
                            ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                            ($catchResult.code -like '*ResourceGroupNotFound*') -or
                            ($catchResult.code -eq 'ResourceTypeNotSupported')
                        )
                    ) -or
                    ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*')

                ) {
                    if (
                        ($getARMPolicyComplianceStates -and (
                            ($catchResult.error.code -like '*ResponseTooLarge*') -or
                            (-not $catchResult.error.code))
                        )
                    ) {
                        if ($catchResult.error.code -like '*ResponseTooLarge*') {
                            Write-Host "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response too large, skipping this scope."
                            return [string]'ResponseTooLarge'
                        }
                        if (-not $catchResult.error.code) {
                            #seems API now returns null instead of 'ResponseTooLarge'
                            Write-Host "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response empty - handle like 'Response too large', skipping this scope."
                            return [string]'ResponseTooLarge'
                        }
                    }

                    if ($catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }

                    if ($catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*BadGatewayConnection*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq '500') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }

                    if ($catchResult.error.code -like '*AuthorizationFailed*') {
                        if ($validateAccess) {
                            #Write-Host "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -ForegroundColor DarkRed
                            return [string]'failed'
                        }
                        else {
                            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                                Write-Host '- - - - - - - - - - - - - - - - - - - - '
                                Write-Host "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -ForegroundColor Yellow
                                Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - EXIT"
                                Write-Host ''
                                Write-Host 'Parameters:'
                                foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                                    Write-Host "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                                }
                                Throw 'Error: check the last console output for details'
                            }
                            else {
                                if ($retryAuthorizationFailedCounter -gt 2) {
                                    Start-Sleep -Seconds 5
                                }
                                if ($retryAuthorizationFailedCounter -gt 3) {
                                    Start-Sleep -Seconds 10
                                }
                                Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
                                $retryAuthorizationFailedCounter ++
                            }
                        }
                    }

                    if ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
                    }

                    if (
                        $getARMCostManagement -and (
                            ($catchResult.error.code -eq 404) -or
                            ($catchResult.error.code -eq 'AccountCostDisabled') -or
                            ($catchResult.error.message -like '*does not have any valid subscriptions*') -or
                            ($catchResult.error.code -eq 'Unauthorized') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') -or
                            ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*')
                        )

                    ) {
                        if ($catchResult.error.code -eq 404) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
                            return [PSCustomObject]$apiCallResultsCollection
                        }

                        if ($catchResult.error.code -eq 'AccountCostDisabled') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Access to cost data has been disabled for this Account - skipping CostManagement"
                            return [string]'AccountCostDisabled'
                        }

                        if ($catchResult.error.message -like '*does not have any valid subscriptions*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems there are no valid Subscriptions present - skipping CostManagement"
                            return [string]'NoValidSubscriptions'
                        }

                        if ($catchResult.error.code -eq 'Unauthorized') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'Unauthorized'
                        }

                        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'OfferNotSupported'
                        }

                        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'InvalidQueryDefinition'
                        }

                        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return [string]'NonValidWebDirectAIRSOfferType'
                        }

                        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') {
                            return [string]'NotFoundNotSupported'
                        }

                        if ($catchResult.error.code -eq 'IndirectCostDisabled') {
                            return [string]'IndirectCostDisabled'
                        }
                    }

                    #if (($getMicrosoftGraphApplication -or $getMicrosoftGraphServicePrincipal -or $getMicrosoftGraphGroupMembersTransitive -or $getMicrosoftGraphGroupMembersTransitiveCount) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                    #    Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain object status - skipping for now :)"
                    #    return [string]"Request_ResourceNotFound"
                    #}

                    if ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain object status - skipping for now :)"
                        return [string]'Request_ResourceNotFound'
                    }

                    if ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') {
                        $maxTries = 7
                        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                            Throw 'Error - check the last console output for details'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
                        start-sleep -Seconds $sleepSec
                    }

                    if ($currentTask -eq 'Checking AAD UserType' -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) cannot get the executing user´s userType information (member/guest) - proceeding as 'unknown'"
                        return [string]'unknown'
                    }

                    if ($getMicrosoftGraphApplication -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
                        if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - skip Application (Secrets & Certificates)"
                            return [string]'skipApplications'
                        }
                        <#if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest' -or $AzApiCallConfiguration['htParameters'].userType -eq 'unknown') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult)"
                            if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest') {
                                Write-Host " Your UserType is 'Guest' (member/guest/unknown) in the tenant therefore not enough permissions. You have the following options: [1. request membership to AAD Role 'Directory readers'.] Grant explicit Microsoft Graph API permission." -ForegroundColor Yellow
                            }
                            if ($AzApiCallConfiguration['htParameters'].userType -eq 'unknown') {
                                Write-Host " Your UserType is 'unknown' (member/guest/unknown) in the tenant. Seems you do not have enough permissions geeting AAD related data. You have the following options: [1. request membership to AAD Role 'Directory readers'.]" -ForegroundColor Yellow
                            }
                            Throw 'Authorization_RequestDenied'
                        }#>
                        else {
                            Write-Host '- - - - - - - - - - - - - - - - - - - - '
                            Write-Host "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -ForegroundColor Yellow
                            Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
                            Write-Host ''
                            Write-Host 'Parameters:'
                            foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                                Write-Host "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                            }
                            Throw 'Authorization_RequestDenied'
                        }
                    }

                    if ($validateAccess -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
                        #Write-Host "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -ForegroundColor DarkRed
                        return [string]'failed'
                    }

                    if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest' -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
                        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                        Write-Host 'Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'
                        Write-Host "AAD Role 'Directory readers' is required for your Guest User Account!"
                        Throw 'Error - check the last console output for details'
                    }

                    if ($catchResult.error.code -like '*BlueprintNotFound*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Blueprint definition is gone - skipping for now :)"
                        return [string]'BlueprintNotFound'
                    }

                    if ($catchResult.error.code -eq 'ResourceRequestsThrottled' -or $catchResult.error.code -eq '429') {
                        $sleepSeconds = 11
                        if ($catchResult.error.code -eq 'ResourceRequestsThrottled') {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
                            start-sleep -Seconds $sleepSeconds
                        }
                        if ($catchResult.error.code -eq '429') {
                            if ($catchResult.error.message -like '*60 seconds*') {
                                $sleepSeconds = 60
                            }
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
                            start-sleep -Seconds $sleepSeconds
                        }

                    }

                    if ($getARMARG -and $catchResult.error.code -eq 'BadRequest') {
                        $sleepSec = @(1, 1, 2, 3, 5, 7, 9, 10, 13, 15, 20, 25, 30, 45, 60, 60, 60, 60)[$tryCounter]
                        $maxTries = 15
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - capitulation after $maxTries attempts"
                            return [string]'capitulation'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }

                    if (
                        (($getARMRoleAssignmentSchedules -or $getMicrosoftGraphRoleAssignmentSchedules) -and (
                        ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
                        ($catchResult.error.code -eq 'TenantNotOnboarded') -or
                        ($catchResult.error.code -eq 'InvalidResourceType') -or
                        ($catchResult.error.code -eq 'InvalidResource')
                        ) -or ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource')
                        )
                    ) {
                        if ($catchResult.error.code -eq 'ResourceNotOnboarded') {
                            return [string]'ResourceNotOnboarded'
                        }
                        if ($catchResult.error.code -eq 'TenantNotOnboarded') {
                            return [string]'TenantNotOnboarded'
                        }
                        if ($catchResult.error.code -eq 'InvalidResourceType') {
                            return [string]'InvalidResourceType'
                        }
                        if ($catchResult.error.code -eq 'InvalidResource') {
                            return [string]'InvalidResource'
                        }
                        if ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource') {
                            return [string]'InvalidResource'
                        }
                    }

                    if ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') {
                        return [string]'InvalidResourceType'
                    }

                    if ($catchResult.error.code -eq 'InsufficientPermissions' -or $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or $catchResult.message -eq 'An error has occurred.' -or $catchResult.error.code -eq 'GeneralError') {
                        $maxTries = 7
                        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                            Throw 'Error - check the last console output for details'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
                        start-sleep -Seconds $sleepSec
                    }

                    if ($getARMMDfC -and $catchResult.error.code -eq 'Subscription Not Registered') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' skipping Subscription"
                        return [string]'SubScriptionNotRegistered'
                    }

                    if ($catchResult.error.code -eq 'Request_UnsupportedQuery') {
                        $sleepSec = @(1, 3, 7, 10, 15, 20, 30)[$tryCounter]
                        $maxTries = 5
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - capitulation after $maxTries attempts"
                            return [string]'Request_UnsupportedQuery'
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }

                    if ($getARMDiagnosticSettingsResource -and (
                        ($catchResult.error.code -like '*ResourceNotFound*') -or
                        ($catchResult.code -like '*ResourceNotFound*') -or
                        ($catchResult.error.code -like '*ResourceGroupNotFound*') -or
                        ($catchResult.code -like '*ResourceGroupNotFound*') -or
                        ($catchResult.code -eq 'ResourceTypeNotSupported')
                        )
                    ) {
                        if ($catchResult.error.code -like '*ResourceNotFound*' -or $catchResult.code -like '*ResourceNotFound*') {
                            Write-Host "  ResourceGone | The resourceId '$($resourceId)' seems meanwhile deleted."
                            return [string]'meanwhile_deleted_ResourceNotFound'
                        }
                        if ($catchResult.error.code -like '*ResourceGroupNotFound*' -or $catchResult.code -like '*ResourceGroupNotFound*') {
                            Write-Host "  ResourceGone | ResourceGroup not found - the resourceId '$($resourceId)' seems meanwhile deleted."
                            return [string]'meanwhile_deleted_ResourceGroupNotFound'
                        }
                        if ($catchResult.code -eq 'ResourceTypeNotSupported') {
                            return [string]'ResourceTypeNotSupported'
                        }
                    }

                    if ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*') {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) maximum number of groups exceeded, skipping; docs: https://docs.microsoft.com/pt-br/previous-versions/azure/ad/graph/api/functions-and-actions#getmembergroups-get-group-memberships-transitive--"
                        return 'Directory_ResultSizeLimitExceeded'
                    }
                }
                else {
                    if (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and -not $catchResult -and $tryCounter -lt 6) {
                        if ($azAPIRequest.StatusCode -eq 204 -and $getARMCostManagement) {
                            return [PSCustomObject]$apiCallResultsCollection
                        }
                        else {
                            $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                            Start-Sleep -Seconds $sleepSec
                        }
                    }
                    elseif (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and $catchResult -and $tryCounter -lt 6) {
                        $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }
                    else {
                        Write-Host '- - - - - - - - - - - - - - - - - - - - '
                        Write-Host "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -ForegroundColor Yellow
                        Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
                        Write-Host ''
                        Write-Host 'Parameters:'
                        foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                            Write-Host "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
                        }
                        if ($getARMCostManagement) {
                            Write-Host 'If Consumption data is not that important for you, do not use parameter: -DoAzureConsumption (however, please still report the issue - thank you)'
                        }
                        Throw 'Error - check the last console output for details'
                    }
                }
            }
            else {
                debugAzAPICall -debugMessage "apiStatusCode: '$($azAPIRequest.StatusCode)'"
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq 'Content') {
                    debugAzAPICall -debugMessage "listenOn=content ($((($azAPIRequestConvertedFromJson)).count))"
                    $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                }
                elseif ($listenOn -eq 'ContentProperties') {
                    if (($azAPIRequestConvertedFromJson.properties.rows).Count -gt 0) {
                        <#
                        foreach ($consumptionline in $azAPIRequestConvertedFromJson.properties.rows) {
                            $hlper = $htSubscriptionsMgPath.($consumptionline[1])
                            $null = $apiCallResultsCollection.Add([PSCustomObject]@{
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[0])" = $consumptionline[0]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[1])" = $consumptionline[1]
                                    SubscriptionName                                               = $hlper.DisplayName
                                    SubscriptionMgPath                                             = $hlper.ParentNameChainDelimited
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[2])" = $consumptionline[2]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[3])" = $consumptionline[3]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[4])" = $consumptionline[4]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[5])" = $consumptionline[5]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[6])" = $consumptionline[6]
                                })
                        }
                        #>
                        $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                    }
                }
                else {
                    if (($azAPIRequestConvertedFromJson).value) {
                        debugAzAPICall -debugMessage "listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value).count))"
                        foreach ($entry in $azAPIRequestConvertedFromJson.value) {
                            $null = $apiCallResultsCollection.Add($entry)
                        }
                    }
                    else {
                        debugAzAPICall -debugMessage 'listenOn=default(value) value not exists; return empty array'
                    }
                }

                $isMore = $false
                if (-not $noPaging) {
                    if ($azAPIRequestConvertedFromJson.nextLink) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Write-Host 'nextLinkLog: uri is equal to nextLinkUri'
                                Write-Host "nextLinkLog: uri: $uri"
                                Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                                Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.nextLink
                            $notTryCounter = $true
                        }
                        debugAzAPICall -debugMessage "nextLink: $Uri"
                    }
                    elseif ($azAPIRequestConvertedFromJson.'@oData.nextLink') {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.'@odata.nextLink') {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Write-Host " $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Write-Host 'nextLinkLog: uri is equal to @odata.nextLinkUri'
                                Write-Host "nextLinkLog: uri: $uri"
                                Write-Host "nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson.'@odata.nextLink')"
                                Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.'@odata.nextLink'
                            $notTryCounter = $true
                        }
                        debugAzAPICall -debugMessage "@oData.nextLink: $Uri"
                    }
                    elseif ($azAPIRequestConvertedFromJson.properties.nextLink) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.properties.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Write-Host 'nextLinkLog: uri is equal to nextLinkUri'
                                Write-Host "nextLinkLog: uri: $uri"
                                Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                                Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.properties.nextLink
                            $notTryCounter = $true
                        }
                        debugAzAPICall -debugMessage "nextLink: $Uri"
                    }
                    else {
                        debugAzAPICall -debugMessage 'NextLink: none'
                    }
                }
            }
        }
        else {
            debugAzAPICall -debugMessage 'unexpectedError: true'
            if ($tryCounterUnexpectedError -lt 13) {
                $sleepSec = @(1, 2, 3, 5, 7, 10, 13, 17, 20, 30, 40, 50, , 55, 60)[$tryCounterUnexpectedError]
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 10 times); sleep $sleepSec seconds"
                Write-Host $catchResult
                Start-Sleep -Seconds $sleepSec
            }
            else {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (tried 5 times)/exit"
                Throw 'Error - check the last console output for details'
            }
        }
    }
    until(($azAPIRequest.StatusCode -in 200..204 -and -not $isMore ) -or ($Method -eq 'HEAD' -and $azAPIRequest.StatusCode -eq 404))
    return [PSCustomObject]$apiCallResultsCollection
}
function createBearerToken {

    param (
        [Parameter(Mandatory)]
        [string]
        $targetEndPoint,

        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    Write-Host " +Processing new bearer token request '$targetEndPoint' ($($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint))" -ForegroundColor DarkGray

    if (($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint) {

        $azContext = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = 'letscheck'
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint)")
        }
        catch {
            $catchResult = $_
        }

        if ($catchResult -ne 'letscheck') {
            Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
            Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount -tenantId <tenantId>' to set up your Azure credentials."
            Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount -tenantId <tenantId>'."
            Throw 'Error - check the last console output for details'
        }

        $dateTimeTokenCreated = (get-date -format 'MM/dd/yyyy HH:mm:ss')

        ($AzApiCallConfiguration['htBearerAccessToken']).$targetEndPoint = $newBearerAccessTokenRequest.AccessToken

        $bearerDetails = getJWTDetails -token $newBearerAccessTokenRequest.AccessToken
        $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
        $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
        Write-Host " +Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -ForegroundColor DarkGray
    }
    else {
        Write-Host "targetEndPoint: '$targetEndPoint' unknown"
        throw
    }
}
function getAzAPICallFunctions {
    $functions = @{
        funcAZAPICall         = $function:AzAPICall.ToString()
        funcCreateBearerToken = $function:createBearerToken.ToString()
        funcGetJWTDetails     = $function:getJWTDetails.ToString()
    }
    return $functions
}
function getJWTDetails {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER token
    AccessToken

    .EXAMPLE
    PS C:\> getJWTDetails -token $newBearerAccessTokenRequest.AccessToken

    .NOTES
    General notes
    #>
    param (
        [Parameter(Mandatory)][string]$token
    )
    #JWTDetails https://www.powershellgallery.com/packages/JWTDetails/1.0.2
    if (!$token -contains ('.') -or !$token.StartsWith('eyJ')) { Write-Error 'Invalid token' -ErrorAction Stop }

    #Token
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }

    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json
    Write-Verbose 'JWT Token:'
    Write-Verbose $decodedToken

    #Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
    Write-Verbose 'JWT Signature:'
    Write-Verbose $sig
    $decodedToken | Add-Member -Type NoteProperty -Name 'sig' -Value $sig

    #Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,

    $decodedToken | Add-Member -Type NoteProperty -Name 'expiryDateTime' -Value $localTime

    #Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name 'timeToExpiry' -Value $timeToExpiry

    return $decodedToken
}
function initAzAPICall {

    [CmdletBinding()]
    Param
    (
        [Parameter()]
        [bool]
        $DebugAzAPICall = $false,

        [Parameter()]
        [guid]
        $SubscriptionId4AzContext,

        [Parameter()]
        [string]
        $gitHubRepository = 'aka.ms/AzAPICall'
    )

    $AzAccountsVersion = testAzModules

    $AzAPICallConfiguration = @{}
    $AzAPICallConfiguration['htParameters'] = $null
    $AzAPICallConfiguration['htParameters'] = setHtParameters -AzAccountsVersion $AzAccountsVersion -gitHubRepository $gitHubRepository -DebugAzAPICall $DebugAzAPICall
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
    Write-Host "  Az context AccountId: '$($AzAPICallConfiguration['checkContext'].Account.Id)'" -ForegroundColor Yellow
    Write-Host "  Az context AccountType: '$($AzAPICallConfiguration['checkContext'].Account.Type)'" -ForegroundColor Yellow
    $AzApiCallConfiguration['htParameters'].accountType = $($AzAPICallConfiguration['checkContext'].Account.Type)

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
        Write-Host "   Az context Tenant: '$($AzAPICallConfiguration['checkContext'].Tenant.Id)'" -ForegroundColor Yellow
        Write-Host "   Az context Subscription: $($AzAPICallConfiguration['checkContext'].Subscription.Name) [$($AzAPICallConfiguration['checkContext'].Subscription.Id)] (state: $($AzAPICallConfiguration['checkContext'].Subscription.State))" -ForegroundColor Yellow
        Write-Host '  Az context check succeeded' -ForegroundColor Green
    }

    $AzApiCallConfiguration['htParameters'].userType = testUserType -AzApiCallConfiguration $AzAPICallConfiguration

    Write-Output $AzAPICallConfiguration
}

function setAzureEnvironment {
    param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )
    #Region Test-Environment
    Write-Host ' Set environment endPoint url mapping'

    function testAvailable {
        [CmdletBinding()]Param(
            [string]$EndpointUrl,
            [string]$Endpoint,
            [string]$EnvironmentKey
        )
        Write-Host "  Check endpoint: '$($Endpoint)'; endpoint url: '$($EndpointUrl)'"
        if ([string]::IsNullOrWhiteSpace($EndpointUrl)) {
            if ($Endpoint -eq 'MicrosoftGraph') {
                Write-Host "  Older Az.Accounts version in use (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey) not existing). AzureEnvironmentRelatedUrls -> Setting static Microsoft Graph Url 'https://graph.microsoft.com'"
                return $legacyAzAccountsEnvironmentMicrosoftGraphUrls.($AzApiCallConfiguration['checkContext'].Environment.Name)
            }
            else {
                Write-Host "  Cannot read '$($Endpoint)' endpoint from current context (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey))"
                Write-Host "  Please check current context (Subglobalion criteria: quotaId notLike 'AAD*'; state = enabled); Install latest Az.Accounts version"
                Write-Host ($checkContext | Format-List | Out-String)
                Throw 'Error - check the last console output for details'
            }
        }
        else {
            return [string]($EndpointUrl -replace '\/$')
        }
    }

    #MicrosoftGraph Urls for older Az.Accounts version
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls = @{}
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureCloud'] = 'https://graph.microsoft.com'
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureUSGovernment'] = 'https://graph.microsoft.us'
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureChinaCloud'] = 'https://microsoftgraph.chinacloudapi.cn'
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureGermanCloud'] = 'https://graph.microsoft.de'

    #AzureEnvironmentRelatedUrls
    $AzAPICallConfiguration['azAPIEndpointUrls'] = @{ }
    $AzAPICallConfiguration['azAPIEndpointUrls'].ARM = (testAvailable -Endpoint 'ARM' -EnvironmentKey 'ResourceManagerUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ResourceManagerUrl)
    $AzAPICallConfiguration['azAPIEndpointUrls'].KeyVault = (testAvailable -Endpoint 'KeyVault' -EnvironmentKey 'AzureKeyVaultServiceEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureKeyVaultServiceEndpointResourceId)
    $AzAPICallConfiguration['azAPIEndpointUrls'].LogAnalytics = (testAvailable -Endpoint 'LogAnalytics' -EnvironmentKey 'AzureOperationalInsightsEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureOperationalInsightsEndpointResourceId)
    $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph = (testAvailable -Endpoint 'MicrosoftGraph' -EnvironmentKey 'ExtendedProperties.MicrosoftGraphUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ExtendedProperties.MicrosoftGraphUrl)

    #AzureEnvironmentRelatedTargetEndpoints
    $AzAPICallConfiguration['azAPIEndpoints'] = @{ }
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM -split '/')[2]) = 'ARM'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].KeyVault -split '/')[2]) = 'KeyVault'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].LogAnalytics -split '/')[2]) = 'LogAnalytics'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph -split '/')[2]) = 'MicrosoftGraph'

    Write-Host '  Set environment endPoint url mapping succeeded' -ForegroundColor Green
    Write-Output $AzApiCallConfiguration
}
function setHtParameters {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)][string]$AzAccountsVersion,
        [Parameter(Mandatory)][string]$gitHubRepository,
        [Parameter(Mandatory)][bool]$DebugAzAPICall
    )

    Write-Host ' Create htParameters'
    #region codeRunPlatform
    $onAzureDevOps = $false
    $onAzureDevOpsOrGitHubActions = $false
    if ($env:GITHUB_SERVER_URL -and $env:CODESPACES) {
        $codeRunPlatform = 'GitHubCodespaces'
    }
    elseif ($env:REMOTE_CONTAINERS) {
        $codeRunPlatform = 'RemoteContainers'
    }
    elseif ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
        $codeRunPlatform = 'AzureDevOps'
        $onAzureDevOps = $true
        $onAzureDevOpsOrGitHubActions = $true
    }
    elseif ($PSPrivateMetadata) {
        $codeRunPlatform = 'AzureAutomation'
    }
    elseif ($env:GITHUB_ACTIONS) {
        $codeRunPlatform = 'GitHubActions'
        $onGitHubActions = $true
        $onAzureDevOpsOrGitHubActions = $true
    }
    elseif ($env:ACC_IDLE_TIME_LIMIT -and $env:AZURE_HTTP_USER_AGENT -and $env:AZUREPS_HOST_ENVIRONMENT) {
        $codeRunPlatform = 'CloudShell'
    }
    else {
        $codeRunPlatform = 'Console'
    }
    Write-Host '  codeRunPlatform:' $codeRunPlatform
    #endregion codeRunPlatform


    if ($DebugAzAPICall) {
        write-host '  AzAPICall debug enabled' -ForegroundColor Cyan
    }
    else {
        write-host '  AzAPICall debug disabled' -ForegroundColor Cyan
    }

    #Region Test-HashtableParameter
    return [ordered]@{
        debugAzAPICall               = $DebugAzAPICall
        gitHubRepository             = $gitHubRepository
        psVersion                    = $PSVersionTable.PSVersion
        azAccountsVersion            = $AzAccountsVersion
        azAPICallModuleVersion       = ((Get-Module -Name AzAPICall).Version).ToString()
        codeRunPlatform              = $codeRunPlatform
        onAzureDevOpsOrGitHubActions = [bool]$onAzureDevOpsOrGitHubActions
        onAzureDevOps                = [bool]$onAzureDevOps
        onGitHubActions              = [bool]$onGitHubActions
    }
    #EndRegion Test-HashtableParameter
}
function testAzModules {
    $testCommands = @('Get-AzContext')
    $azModules = @('Az.Accounts')

    Write-Host ' Check required Az modules cmdlets'
    foreach ($testCommand in $testCommands) {
        if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
            Write-Host "  AzModule test failed: cmdlet '$testCommand' not available - install module(s): '$($azModules -join ', ')'" -ForegroundColor Red
            Throw 'Error - check the last console output for details'
        }
        else {
            Write-Host "  Az PS module supporting cmdlet '$testCommand' installed"
        }
    }

    #Write-Host " Collecting Az modules versions"
    foreach ($azModule in $azModules) {
        $azModuleVersion = (Get-InstalledModule -name "$azModule" -ErrorAction Ignore).Version
        if ($azModuleVersion) {
            Write-Host "  Az Module $azModule Version: $azModuleVersion"
            Write-Host '  Required Az modules cmdlets check succeeded' -ForegroundColor Green
            return $azModuleVersion
        }
        else {
            Write-Host "  Az Module $azModule Version: could not be assessed"
            Write-Host '  Required Az modules cmdlets check succeeded' -ForegroundColor Green
            return 'n/a'
        }
    }
}
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
function testUserType {
    param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    $userType = 'n/a'
    if ($AzAPICallConfiguration['checkContext'].Account.Type -eq 'User') {
        $currentTask = 'Check AAD UserType'
        Write-Host " $currentTask"
        $uri = $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph + '/v1.0/me?$select=userType'
        $method = 'GET'
        $checkUserType = AzAPICall -AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -method $method -listenOn 'Content' -currentTask $currentTask

        if ($checkUserType -eq 'unknown') {
            $userType = $checkUserType
        }
        else {
            $userType = $checkUserType.UserType
        }
        Write-Host "  AAD UserType: $($userType)" -ForegroundColor Yellow
        Write-Host '  AAD UserType check succeeded' -ForegroundColor Green
    }
    Write-Output $userType
}
