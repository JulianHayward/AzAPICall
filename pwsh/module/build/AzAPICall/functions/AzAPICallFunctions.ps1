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
        $AzAPICallConfiguration,

        [Parameter()]
        [int32]
        $skipOnErrorCode
    )

    function debugAzAPICall {
        param (
            [Parameter(Mandatory)]
            [string]
            $debugMessage
        )

        if ($doDebugAzAPICall -or $tryCounter -gt 3) {
            if ($doDebugAzAPICall) {
                Logging -preventWriteOutput $true -logMessage "  DEBUGTASK: $debugMessage" -logMessageWriteMethod $azAPICallConfiguration['htParameters'].debugWriteMethod
            }
            if (-not $doDebugAzAPICall -and $tryCounter -gt 3) {
                Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $debugMessage" -logMessageWriteMethod $azAPICallConfiguration['htParameters'].debugWriteMethod
            }
        }
    }

    #Set defaults
    if (-not $method) { $method = 'GET' }
    if (-not $currentTask) {
        $currentTask = $method + ' ' + $uri
        if ($body) {
            $currentTask += ' ' + $body
        }
    }
    if ($validateAccess) { $noPaging = $true }

    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    $retryAuthorizationFailed = 5
    #$retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0

    <#
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
    #>

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
            'Content-Type' = 'application/json';
            'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)"
        }
        if ($consistencyLevel) {
            $Header = @{
                'Content-Type' = 'application/json';
                'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)";
                'ConsistencyLevel' = "$consistencyLevel"
            }
        }

        $startAPICall = Get-Date
        try {
            if ($body) {
                if ($AzApiCallConfiguration['htParameters'].codeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Body $body -Headers $Header -UseBasicParsing
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Body $body -Headers $Header
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
            $actualStatusCode = $azAPIRequest.StatusCode
            $actualStatusCodePhrase = 'OK'
        }
        catch {
            if (-not [string]::IsNullOrWhiteSpace($_.Exception.Response.StatusCode)) {
                if ([int32]($_.Exception.Response.StatusCode.Value__)) {
                    $actualStatusCode = $_.Exception.Response.StatusCode.Value__
                }
                else {
                    $actualStatusCode = 'n/a'
                }

                $actualStatusCodePhrase = $_.Exception.Response.StatusCode
            }
            else {
                $actualStatusCodePhrase = 'n/a'
            }

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
        $durationAPICall = New-TimeSpan -Start $startAPICall -End $endAPICall

        if (-not $notTryCounter) {
            $tryCounter++
        }
        $notTryCounter = $false

        #API Call Tracking
        $tstmp = (Get-Date -Format 'yyyyMMddHHmmssms')
        $null = $AzApiCallConfiguration['arrayAPICallTracking'].Add([PSCustomObject]@{
                CurrentTask = $currentTask
                TargetEndpoint = $targetEndpoint
                Uri = $uri
                Method = $method
                TryCounter = $tryCounter
                TryCounterUnexpectedError = $tryCounterUnexpectedError
                RetryAuthorizationFailedCounter = $retryAuthorizationFailedCounter
                RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                TimeStamp = $tstmp
                Duration = $durationAPICall.TotalSeconds
                StatusCode = $actualStatusCode
                StatusCodePhrase = $actualStatusCodePhrase
            })

        $message = "attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'"
        if ($body) {
            $message += " body: '$($body | Out-String)'"
        }
        debugAzAPICall -debugMessage $message
        if ($unexpectedError -eq $false) {
            debugAzAPICall -debugMessage 'unexpectedError: false'
            if ($actualStatusCode -notin 200..204) {
                if ($listenOn -eq 'StatusCode') {
                    return [int32]$actualStatusCode
                }
                else {
                    debugAzAPICall -debugMessage "apiStatusCode: '$($actualStatusCode)'"
                    $function:AzAPICallErrorHandler = $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler
                    $AzAPICallErrorHandlerResponse = AzAPICallErrorHandler -AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -catchResult $catchResult -currentTask $currentTask -tryCounter $tryCounter -retryAuthorizationFailed $retryAuthorizationFailed
                    Write-Host ($AzAPICallErrorHandlerResponse | ConvertTo-Json)
                    switch ($AzAPICallErrorHandlerResponse.action) {
                        'break' { break }
                        'return' { return [string]$AzAPICallErrorHandlerResponse.returnMsg }
                        'returnCollection' { return [PSCustomObject]$apiCallResultsCollection }
                    }
                }
            }
            else {
                debugAzAPICall -debugMessage "apiStatusCode: '$actualStatusCode'"
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq 'Content') {
                    debugAzAPICall -debugMessage "listenOn=content ($((($azAPIRequestConvertedFromJson)).count))"
                    $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                }
                elseif ($listenOn -eq 'StatusCode') {
                    debugAzAPICall -debugMessage "listenOn=StatusCode ($actualStatusCode)"
                    #$null = $apiCallResultsCollection.Add($actualStatusCode)
                    return [int32]$actualStatusCode
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
                                Logging -preventWriteOutput $true -logMessage " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage 'nextLinkLog: uri is equal to nextLinkUri'
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                                $apiCallResultsCollection = [System.Collections.ArrayList]@()
                                $uri = $initialUri
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.nextLink
                            $notTryCounter = $true
                            if ($uri -match ':443') {
                                $uri = $uri.replace(':443', '')
                            }
                        }
                        debugAzAPICall -debugMessage "nextLink: $Uri"
                    }
                    elseif ($azAPIRequestConvertedFromJson.'@oData.nextLink') {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.'@odata.nextLink') {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage 'nextLinkLog: uri is equal to @odata.nextLinkUri'
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson.'@odata.nextLink')"
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                                Logging -preventWriteOutput $true -logMessage " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage 'nextLinkLog: uri is equal to nextLinkUri'
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                Logging -preventWriteOutput $true -logMessage " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 10 times); sleep $sleepSec seconds"
                Logging -preventWriteOutput $true -logMessage $catchResult
                Start-Sleep -Seconds $sleepSec
            }
            else {
                Logging -preventWriteOutput $true -logMessage " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (tried 5 times)/exit"
                Throw 'Error - check the last console output for details'
            }
        }
    }
    until(
            ($actualStatusCode -in 200..204 -and -not $isMore ) -or
            ($Method -eq 'HEAD' -and $actualStatusCode -eq 404)
    )
    return [PSCustomObject]$apiCallResultsCollection
}
#needs special handling

function AzAPICallErrorHandler {
    #Logging -preventWriteOutput $true -logMessage ' * BuiltIn RuleSet'

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

    if (
        ($getARMPolicyComplianceStates -and (
            ($catchResult.error.code -like '*ResponseTooLarge*') -or
            (-not $catchResult.error.code))
        )
    ) {
        if ($catchResult.error.code -like '*ResponseTooLarge*') {
            Logging -preventWriteOutput $true -logMessage "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response too large, skipping this scope."
            $response = @{
                action = 'return' #break or return
                returnMsg = 'ResponseTooLarge'
            }
            return $response
        }
        if (-not $catchResult.error.code) {
            #seems API now returns null instead of 'ResponseTooLarge'
            Logging -preventWriteOutput $true -logMessage "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response empty - handle like 'Response too large', skipping this scope."
            $response = @{
                action = 'return' #break or return
                returnMsg = 'ResponseTooLarge'
            }
            return $response
        }
    }
    elseif ($catchResult.error.message -like '*The offer MS-AZR-0110P is not supported*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
        Start-Sleep -Seconds $tryCounter
    }

    elseif ($catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*BadGatewayConnection*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq '500') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again in $tryCounter second(s)"
        Start-Sleep -Seconds $tryCounter
    }

    elseif ($catchResult.error.code -like '*AuthorizationFailed*') {
        if ($validateAccess) {
            #Logging -preventWriteOutput $true -logMessage "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -logMessageForegroundColor "DarkRed"
            $response = @{
                action = 'return' #break or return
                returnMsg = 'failed'
            }
            return $response
        }
        else {
            $script:retryAuthorizationFailedCounter ++
            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
                Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
                Logging -preventWriteOutput $true -logMessage "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - EXIT"
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
                Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
            }
        }
    }

    elseif ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
    }

    elseif (
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
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
            $response = @{
                action = 'returnCollection' #break or return or returnCollection
            }
            return $response
        }

        if ($catchResult.error.code -eq 'AccountCostDisabled') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Access to cost data has been disabled for this Account - skipping CostManagement"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'AccountCostDisabled'
            }
            return $response
        }

        if ($catchResult.error.message -like '*does not have any valid subscriptions*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems there are no valid Subscriptions present - skipping CostManagement"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'NoValidSubscriptions'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'Unauthorized') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'Unauthorized'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like '*The offer*is not supported*' -and $catchResult.error.message -notlike '*The offer MS-AZR-0110P is not supported*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'OfferNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'BadRequest' -and $catchResult.error.message -like 'Invalid query definition*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'InvalidQueryDefinition'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like '*have valid WebDirect/AIRS offer type*') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'NonValidWebDirectAIRSOfferType'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'NotFound' -and $catchResult.error.message -like 'Cost management data is not supported for subscription(s)*') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'NotFoundNotSupported'
            }
            return $response
        }

        if ($catchResult.error.code -eq 'IndirectCostDisabled') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'IndirectCostDisabled'
            }
            return $response
        }
    }

    elseif ($targetEndpoint -eq 'MicrosoftGraph' -and $catchResult.error.code -like '*Request_ResourceNotFound*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain object status - skipping for now :)"
        $response = @{
            action = 'return' #break or return
            returnMsg = 'Request_ResourceNotFound'
        }
        return $response
    }

    elseif ($getMicrosoftGraphGroupMembersTransitiveCount -and $catchResult.error.message -like '*count is not currently supported*') {
        $maxTries = 7
        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
            Throw 'Error - check the last console output for details'
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($currentTask -eq 'Checking AAD UserType' -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) cannot get the executing user´s userType information (member/guest) - proceeding as 'unknown'"
        $response = @{
            action = 'return' #break or return or returnCollection
            returnMsg = 'unknown'
        }
        return $response
    }

    elseif ($getMicrosoftGraphApplication -and $catchResult.error.code -like '*Authorization_RequestDenied*') {
        if ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - skip Application | Guest not enough permissions"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'skipApplications'
            }
            return $response
        }
        else {
            Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
            Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
            Logging -preventWriteOutput $true -logMessage "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
            Logging -preventWriteOutput $true -logMessage 'Parameters:'
            foreach ($htParameter in ($AzApiCallConfiguration['htParameters'].Keys | Sort-Object)) {
                Logging -preventWriteOutput $true -logMessage "$($htParameter):$($AzApiCallConfiguration['htParameters'].($htParameter))"
            }
            Throw 'Authorization_RequestDenied'
        }
    }

    elseif ($validateAccess -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
        #Logging -preventWriteOutput $true -logMessage "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -logMessageForegroundColor "DarkRed"
        $response = @{
            action = 'return' #break or return or returnCollection
            returnMsg = 'failed'
        }
        return $response
    }

    elseif ($AzApiCallConfiguration['htParameters'].userType -eq 'Guest' -and $catchResult.error.code -eq 'Authorization_RequestDenied') {
        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
        Logging -preventWriteOutput $true -logMessage 'Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions'
        Logging -preventWriteOutput $true -logMessage "AAD Role 'Directory readers' is required for your Guest User Account!"
        Throw 'Error - check the last console output for details'
    }

    elseif ($catchResult.error.code -like '*BlueprintNotFound*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Blueprint definition is gone - skipping for now :)"
        $response = @{
            action = 'return' #break or return or returnCollection
            returnMsg = 'BlueprintNotFound'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'ResourceRequestsThrottled' -or $catchResult.error.code -eq '429') {
        $sleepSeconds = 11
        if ($catchResult.error.code -eq 'ResourceRequestsThrottled') {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
        if ($catchResult.error.code -eq '429') {
            if ($catchResult.error.message -like '*60 seconds*') {
                $sleepSeconds = 60
            }
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
    }

    elseif ($getARMARG -and $catchResult.error.code -eq 'BadRequest') {
        $sleepSec = @(1, 1, 2, 3, 5, 7, 9, 10, 13, 15, 20, 25, 30, 45, 60, 60, 60, 60)[$tryCounter]
        $maxTries = 15
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - capitulation after $maxTries attempts"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'capitulation'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
        Start-Sleep -Seconds $sleepSec
    }

    elseif (
            (($getARMRoleAssignmentSchedules -or $getMicrosoftGraphRoleAssignmentSchedules) -and (
            ($catchResult.error.code -eq 'ResourceNotOnboarded') -or
            ($catchResult.error.code -eq 'TenantNotOnboarded') -or
            ($catchResult.error.code -eq 'InvalidResourceType') -or
            ($catchResult.error.code -eq 'InvalidResource')
        ) -or ($getMicrosoftGraphRoleAssignmentScheduleInstances -and $catchResult.error.code -eq 'InvalidResource')
                        )
    ) {
        if ($catchResult.error.code -eq 'ResourceNotOnboarded') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'ResourceNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'TenantNotOnboarded') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'TenantNotOnboarded'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResourceType') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'InvalidResourceType'
            }
            return $response
        }
        if ($catchResult.error.code -eq 'InvalidResource') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'InvalidResource'
            }
            return $response
        }
    }

    elseif ($getARMDiagnosticSettingsMg -and $catchResult.error.code -eq 'InvalidResourceType') {
        $response = @{
            action = 'return' #break or return or returnCollection
            returnMsg = 'InvalidResourceType'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'InsufficientPermissions' -or $catchResult.error.code -eq 'ClientCertificateValidationFailure' -or $catchResult.error.code -eq 'GatewayAuthenticationFailed' -or $catchResult.message -eq 'An error has occurred.' -or $catchResult.error.code -eq 'GeneralError') {
        $maxTries = 7
        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
            Throw 'Error - check the last console output for details'
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
        Start-Sleep -Seconds $sleepSec
    }

    elseif ($getARMMDfC -and $catchResult.error.code -eq 'Subscription Not Registered') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' skipping Subscription"
        $response = @{
            action = 'return' #break or return or returnCollection
            returnMsg = 'SubScriptionNotRegistered'
        }
        return $response
    }

    elseif ($catchResult.error.code -eq 'Request_UnsupportedQuery') {
        $sleepSec = @(1, 3, 7, 10, 15, 20, 30)[$tryCounter]
        $maxTries = 5
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - capitulation after $maxTries attempts"
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'Request_UnsupportedQuery'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
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
                action = 'return' #break or return or returnCollection
                returnMsg = 'meanwhile_deleted_ResourceNotFound'
            }
            return $response
        }
        if ($catchResult.error.code -like '*ResourceGroupNotFound*' -or $catchResult.code -like '*ResourceGroupNotFound*') {
            Logging -preventWriteOutput $true -logMessage "  ResourceGone | ResourceGroup not found - the resourceId '$($resourceId)' seems meanwhile deleted."
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'meanwhile_deleted_ResourceGroupNotFound'
            }
            return $response
        }
        if ($catchResult.code -eq 'ResourceTypeNotSupported' -or $catchResult.code -eq 'ResourceProviderNotSupported') {
            $response = @{
                action = 'return' #break or return or returnCollection
                returnMsg = 'ResourceTypeOrResourceProviderNotSupported'
            }
            return $response
        }
    }

    elseif ($getMicrosoftGraphServicePrincipalGetMemberGroups -and $catchResult.error.code -like '*Directory_ResultSizeLimitExceeded*') {
        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) maximum number of groups exceeded, skipping; docs: https://docs.microsoft.com/pt-br/previous-versions/azure/ad/graph/api/functions-and-actions#getmembergroups-get-group-memberships-transitive--"
        $response = @{
            action = 'return' #break or return or returnCollection
            returnMsg = 'Directory_ResultSizeLimitExceeded'
        }
        return $response
    }
    else {
        if (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and -not $catchResult -and $tryCounter -lt 6) {
            if ($azAPIRequest.StatusCode -eq 204 -and $getARMCostManagement) {
                $response = @{
                    action = 'returnCollection' #break or return or returnCollection
                }
                return $response
            }
            else {
                $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
                Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                Start-Sleep -Seconds $sleepSec
            }
        }
        elseif (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and $catchResult -and $tryCounter -lt 6) {
            $sleepSec = @(3, 7, 12, 20, 30, 45, 60)[$tryCounter]
            Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
            Start-Sleep -Seconds $sleepSec
        }
        else {
            Logging -preventWriteOutput $true -logMessage '- - - - - - - - - - - - - - - - - - - - '
            Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository) and provide the following dump" -logMessageForegroundColor 'Yellow'
            Logging -preventWriteOutput $true -logMessage "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
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
function createBearerToken {

    param (
        [Parameter(Mandatory)]
        [string]
        $targetEndPoint,

        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    Logging -logMessage " +Processing new bearer token request '$targetEndPoint' ($($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint))"

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
            Logging -logMessage "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -logMessageWriteMethod 'Error'
            Logging -logMessage "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount -tenantId <tenantId>' to set up your Azure credentials."
            Logging -logMessage "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount -tenantId <tenantId>'."
            Throw 'Error - check the last console output for details'
        }

        $dateTimeTokenCreated = (get-date -format 'MM/dd/yyyy HH:mm:ss')

        ($AzApiCallConfiguration['htBearerAccessToken']).$targetEndPoint = $newBearerAccessTokenRequest.AccessToken

        $bearerDetails = getJWTDetails -token $newBearerAccessTokenRequest.AccessToken
        $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
        $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
        Logging -logMessage " +Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
    }
    else {
        Logging -logMessage "targetEndPoint: '$targetEndPoint' unknown" -logMessageWriteMethod 'Error'
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
function getAzAPICallRuleSet {
    return $function:AzAPICallErrorHandler.ToString()
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
    if (!$token -contains ('.') -or !$token.StartsWith('eyJ')) { Logging -preventWriteOutput $true -logMessage 'Invalid token' -logMessageWriteMethod 'Error' -ErrorAction Stop }

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

    #Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
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
        [ValidateSet('Debug', 'Error', 'Host', 'Information', 'Output', 'Progress', 'Verbose', 'Warning')]
        $writeMethod = 'Host',

        [Parameter()]
        [ValidateSet('Debug', 'Error', 'Host', 'Information', 'Output', 'Progress', 'Verbose', 'Warning')]
        $debugWriteMethod = 'Host',

        [Parameter()]
        [guid]
        $SubscriptionId4AzContext,

        [Parameter()]
        [string]
        $GitHubRepository = 'aka.ms/AzAPICall',

        [Parameter()]
        [object]
        $AzAPICallCustomRuleSet
    )

    $AzAPICallConfiguration = @{}
    $AzAPICallConfiguration['htParameters'] = @{}
    $AzAPICallConfiguration['htParameters'].writeMethod = $writeMethod
    $AzAPICallConfiguration['htParameters'].debugWriteMethod = $debugWriteMethod

    $AzAccountsVersion = testAzModules

    $AzAPICallConfiguration['AzAPICallRuleSet'] = @{}
    if ($AzAPICallCustomRuleSet) {
        $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler = $AzAPICallCustomRuleSet.AzAPICallErrorHandler
    }
    else {
        $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler = $funcAzAPICallErrorHandler
    }


    $AzAPICallConfiguration['htParameters'] = setHtParameters -AzAccountsVersion $AzAccountsVersion -gitHubRepository $GitHubRepository -DebugAzAPICall $DebugAzAPICall
    Logging -preventWriteOutput $true -logMessage '  AzAPICall htParameters:'
    Logging -preventWriteOutput $true -logMessage "($AzAPICallConfiguration['htParameters'] | format-table -AutoSize | Out-String)"
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

    if ($SubscriptionId4AzContext) {
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
        testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
    }

    if (-not $AzAPICallConfiguration['checkContext'].Subscription) {
        $AzAPICallConfiguration['checkContext'] | Format-list | Out-String
        Logging -preventWriteOutput $true -logMessage '  Check Az context failed: Az context is not set to any Subscription'
        Logging -preventWriteOutput $true -logMessage '  Set Az context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script'
        Logging -preventWriteOutput $true -logMessage '  OR'
        Logging -preventWriteOutput $true -logMessage '  Use parameter -SubscriptionId4Test - e.g. .\AzGovVizParallel.ps1 -SubscriptionId4Test <subscriptionId>'
        Throw 'Error - check the last console output for details'
    }
    else {
        Logging -preventWriteOutput $true -logMessage "   Az context Tenant: '$($AzAPICallConfiguration['checkContext'].Tenant.Id)'" -logMessageForegroundColor 'Yellow'
        Logging -preventWriteOutput $true -logMessage "   Az context Subscription: $($AzAPICallConfiguration['checkContext'].Subscription.Name) [$($AzAPICallConfiguration['checkContext'].Subscription.Id)] (state: $($AzAPICallConfiguration['checkContext'].Subscription.State))" -logMessageForegroundColor 'Yellow'
        Logging -preventWriteOutput $true -logMessage '  Az context check succeeded' -logMessageForegroundColor 'Green'
    }

    $AzApiCallConfiguration['htParameters'].userType = testUserType -AzApiCallConfiguration $AzAPICallConfiguration

    return $AzAPICallConfiguration
}

function Logging {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $logMessage,

        [Parameter(Mandatory = $false)]
        [string]
        $logMessageForegroundColor = $debugForeGroundColor,

        [Parameter(Mandatory = $false)]
        [string]
        $logMessageWriteMethod = $azAPICallConfiguration['htParameters'].writeMethod,

        [Parameter(Mandatory = $false)]
        [bool]
        $preventWriteOutput
    )

    if (-not $logMessageForegroundColor) {
        $logMessageForegroundColor = 'Cyan'
    }

    if (-not $logMessageWriteMethod -or $preventWriteOutput) {
        if (-not $logMessageWriteMethod -and $logMessageWriteMethod -ne 'Output' ) {
            $logMessageWriteMethod = 'Warning'
        }
    }

    switch ($logMessageWriteMethod) {
        'Debug' { Write-Debug $logMessage }
        'Error' { Write-Error $logMessage }
        'Host' { Write-Host $logMessage -ForegroundColor $logMessageForegroundColor }
        'Information' { Write-Information $logMessage }
        'Output' { Write-Output $logMessage }
        'Progress' { Write-Progress $logMessage }
        'Verbose' { Write-Verbose $logMessage -verbose }
        'Warning' { Write-Warning $logMessage }
        Default { Write-Host $logMessage -ForegroundColor $logMessageForegroundColor }
    }
}
function setAzureEnvironment {
    param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )
    #Region Test-Environment
    Logging -preventWriteOutput $true -logMessage ' Set environment endPoint url mapping'

    function testAvailable {
        [CmdletBinding()]Param(
            [string]$EndpointUrl,
            [string]$Endpoint,
            [string]$EnvironmentKey
        )
        Logging -preventWriteOutput $true -logMessage "  Check endpoint: '$($Endpoint)'; endpoint url: '$($EndpointUrl)'"
        if ([string]::IsNullOrWhiteSpace($EndpointUrl)) {
            if ($Endpoint -eq 'MicrosoftGraph') {
                Logging -preventWriteOutput $true -logMessage "  Older Az.Accounts version in use (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey) not existing). AzureEnvironmentRelatedUrls -> Setting static Microsoft Graph Url '$($legacyAzAccountsEnvironmentMicrosoftGraphUrls.($AzApiCallConfiguration['checkContext'].Environment.Name))'"
                return $legacyAzAccountsEnvironmentMicrosoftGraphUrls.($AzApiCallConfiguration['checkContext'].Environment.Name)
            }
            else {
                Logging -preventWriteOutput $true -logMessage "  Cannot read '$($Endpoint)' endpoint from current context (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey))"
                Logging -preventWriteOutput $true -logMessage "  Please check current context (Subglobalion criteria: quotaId notLike 'AAD*'; state = enabled); Install latest Az.Accounts version"
                Logging -preventWriteOutput $true -logMessage ($checkContext | Format-List | Out-String)
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

    Logging -preventWriteOutput $true -logMessage '  Set environment endPoint url mapping succeeded' -logMessageForegroundColor 'Green'
    return $AzApiCallConfiguration
}
function setHtParameters {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]
        $AzAccountsVersion,

        [Parameter(Mandatory)]
        [string]
        $GitHubRepository,

        [Parameter(Mandatory)]
        [bool]
        $DebugAzAPICall
    )

    Logging -preventWriteOutput $true -logMessage ' Create htParameters'
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
    Logging -preventWriteOutput $true -logMessage "  codeRunPlatform: $codeRunPlatform"
    #endregion codeRunPlatform


    if ($DebugAzAPICall) {
        Logging -preventWriteOutput $true -logMessage '  AzAPICall debug enabled' -logMessageForegroundColor 'Cyan'
    }
    else {
        Logging -preventWriteOutput $true -logMessage '  AzAPICall debug disabled' -logMessageForegroundColor 'Cyan'
    }

    #Region Test-HashtableParameter
    $htParam = [ordered]@{
        debugAzAPICall               = $DebugAzAPICall
        gitHubRepository             = $GitHubRepository
        psVersion                    = $PSVersionTable.PSVersion
        azAccountsVersion            = $AzAccountsVersion
        azAPICallModuleVersion       = ((Get-Module -Name AzAPICall).Version).ToString()
        codeRunPlatform              = $codeRunPlatform
        onAzureDevOpsOrGitHubActions = [bool]$onAzureDevOpsOrGitHubActions
        onAzureDevOps                = [bool]$onAzureDevOps
        onGitHubActions              = [bool]$onGitHubActions
    }

    return ($AzAPICallConfiguration['htParameters'] += $htParam)
    #EndRegion Test-HashtableParameter
}
function testAzModules {
    $testCommands = @('Get-AzContext')
    $azModules = @('Az.Accounts')

    Logging -preventWriteOutput $true -logMessage ' Check required Az modules cmdlets'
    foreach ($testCommand in $testCommands) {
        if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
            Logging -preventWriteOutput $true -logMessage "  AzModule test failed: cmdlet '$testCommand' not available - install module(s): '$($azModules -join ', ')'" -logMessageForegroundColor 'Red'
            Throw 'Error - check the last console output for details'
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Az PS module supporting cmdlet '$testCommand' installed"
        }
    }

    #Logging -preventWriteOutput $true -logMessage " Collecting Az modules versions"
    foreach ($azModule in $azModules) {
        $azModuleVersion = (Get-InstalledModule -name "$azModule" -ErrorAction Ignore).Version
        if ($azModuleVersion) {
            Logging -preventWriteOutput $true -logMessage "  Az Module $azModule Version: $azModuleVersion"
            Logging -preventWriteOutput $true -logMessage '  Required Az modules cmdlets check succeeded' -logMessageForegroundColor 'Green'
            return $azModuleVersion
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Az Module $azModule Version: could not be assessed"
            Logging -preventWriteOutput $true -logMessage '  Required Az modules cmdlets check succeeded' -logMessageForegroundColor 'Green'
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
        Throw 'Error - check the last console output for details'
    }
    else {
        $AzApiCallConfiguration['htParameters'].subscriptionQuotaId = $testSubscription.subscriptionPolicies.quotaId
        Logging -logMessage "   Subscription check succeeded (quotaId: '$($testSubscription.subscriptionPolicies.quotaId)')" -logMessageForegroundColor 'Green'
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
        Logging -preventWriteOutput $true -logMessage " $currentTask"
        $uri = $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph + '/v1.0/me?$select=userType'
        $method = 'GET'
        $checkUserType = AzAPICall -AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -method $method -listenOn 'Content' -currentTask $currentTask

        if ($checkUserType -eq 'unknown') {
            $userType = $checkUserType
        }
        else {
            $userType = $checkUserType.UserType
        }
        Logging -preventWriteOutput $true -logMessage "  AAD UserType: $($userType)" -logMessageForegroundColor 'Yellow'
        Logging -preventWriteOutput $true -logMessage '  AAD UserType check succeeded' -logMessageForegroundColor 'Green'
    }
    return $userType
}
