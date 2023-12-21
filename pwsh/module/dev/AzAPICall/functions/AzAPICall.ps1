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

    .PARAMETER skipOnErrorCode
    Parameter description

    .PARAMETER unhandledErrorAction
    Parameter description
      Used to either "Stop" (Default), "Continue", or "ContinueQuiet" when encountering an Unhandled Error
        "Stop" Throws the Error which terminates processing
        "Continue" outputs the error with Parameter Dump and continues processing
        "ContinueQuiet" outputs the error without Parameter Dump and continues processing

    .PARAMETER noPaging
    Parameter description

    .PARAMETER skipAsynchronousAzureOperation
    Parameter description
        Microsoft documentation: https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations

    .PARAMETER notWaitForAsynchronousAzureOperationToFinish
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
        [ValidateSet('StatusCode', 'Headers', 'Content', 'ContentProperties', 'Raw', 'Value')]
        $listenOn = 'Value',

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
        [int32[]]
        $skipOnErrorCode,

        [Parameter()]
        [string]
        [ValidateSet('Stop', 'Continue', 'ContinueQuiet')]
        $unhandledErrorAction = 'Stop',

        [Parameter()]
        [string]
        $saResourceGroupName,

        [Parameter()]
        [switch]
        $skipAsynchronousAzureOperation,

        [Parameter()]
        [switch]
        $notWaitForAsynchronousAzureOperationToFinish
    )

    function debugAzAPICall {
        param (
            [Parameter(Mandatory)]
            [string]
            $debugMessage
        )

        if ($doDebugAzAPICall -or $tryCounter -gt 3) {
            if ($doDebugAzAPICall) {
                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault DEBUGTASK: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
            }
            if (-not $doDebugAzAPICall -and $tryCounter -gt 3) {
                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Forced DEBUG: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
            }
        }
    }

    #Set defaults
    $logMessageDefault = "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)]"

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
    $tryCounterConnectionRelatedError = 0
    $asynchronousAzureOperationTryCounter = 0
    $retryAuthorizationFailed = 5
    #$retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0


    #$debugForeGroundColor = 'Cyan'
    if ($AzAPICallConfiguration['htParameters'].debugAzAPICall -eq $true) {
        $doDebugAzAPICall = $true
        # if ($caller -like 'CustomDataCollection*') {
        #     $debugForeGroundColors = @('DarkBlue', 'DarkGreen', 'DarkCyan', 'Cyan', 'DarkMagenta', 'DarkYellow', 'Blue', 'Magenta', 'Yellow', 'Green')
        #     $debugForeGroundColorsCount = $debugForeGroundColors.Count
        #     $randomNumber = Get-Random -Minimum 0 -Maximum ($debugForeGroundColorsCount - 1)
        #     $debugForeGroundColor = $debugForeGroundColors[$randomNumber]
        # }
    }


    do {
        if ($uri -notlike 'https://*') {
            Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Forced DEBUG: $currentTask -> check uri: '$uri' - EXIT"
            Throw "Error - check uri: '$uri'"
        }

        $uriSplitted = $uri.split('/')
        if ($AzAPICallConfiguration['azAPIEndpointUrls'].Storage.where({ $uriSplitted[2] -match $_ })) {
            $targetEndpoint = 'Storage'
        }
        elseif ($uriSplitted[2] -like "*$($AzAPICallConfiguration['azAPIEndpointUrls'].Kusto)") {
            $targetEndpoint = 'Kusto'
        }
        else {
            if (-not ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])) {
                if ($uriSplitted[2] -like "*.$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM.replace('https://',''))") {
                    $armUriSplitted = $uriSplitted[2].split('.')
                    if ($armUriSplitted[0] -in $AzApiCallConfiguration['htParameters'].ARMLocations) {
                        if (($AzApiCallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM).replace('https://', '')))) {
                            #$targetEndpoint = 'ARM'
                            $targetEndpoint = ($AzApiCallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM).replace('https://', '')))
                        }
                        else {
                            Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "$logMessageDefault Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
                        Logging -preventWriteOutput $true -logMessage "!c712e5a2 Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository)" -logMessageForegroundColor 'Yellow'
                        Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
                    }
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$logMessageDefault Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
                    Logging -preventWriteOutput $true -logMessage "!ab981d8f Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository)" -logMessageForegroundColor 'Yellow'
                    Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
                }
            }
            else {
                $targetEndpoint = ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])
            }
        }

        if ($targetEndpoint -eq 'Kusto') {
            $targetCluster = "$($uriSplitted[0])//$($uriSplitted[2])"
            if (-not $AzAPICallConfiguration['htBearerAccessToken'].($targetCluster)) {
                createBearerToken -targetEndPoint $targetEndpoint -TargetCluster $targetCluster -AzAPICallConfiguration $AzAPICallConfiguration
            }
        }
        else {
            if ($targetEndPoint -like 'ARM*' -and $targetEndPoint -ne 'ARM') {
                if (-not $AzAPICallConfiguration['htBearerAccessToken'].ARM) {
                    createBearerToken -targetEndPoint 'ARM' -AzAPICallConfiguration $AzAPICallConfiguration
                }
            }
            else {
                if (-not $AzAPICallConfiguration['htBearerAccessToken'].($targetEndpoint)) {
                    createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
                }
            }
        }


        $unexpectedError = $false
        $connectionRelatedError = $false

        if ($targetEndpoint -eq 'Storage') {
            $Header = @{
                'Content-Type'  = 'application/json';
                'x-ms-version'  = '2021-04-10';
                'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)"
            }
        }
        else {
            if ($targetEndpoint -eq 'Kusto') {
                $Header = @{
                    'Content-Type'  = 'application/json';
                    'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetCluster)"
                }
            }
            else {
                if ($targetEndPoint -like 'ARM*' -and $targetEndPoint -ne 'ARM') {
                    $Header = @{
                        'Content-Type'  = 'application/json';
                        'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].ARM)"
                    }
                }
                else {
                    $Header = @{
                        'Content-Type'  = 'application/json';
                        'Authorization' = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)"
                    }
                }
            }

            if ($consistencyLevel) {
                $Header = @{
                    'Content-Type'     = 'application/json';
                    'Authorization'    = "Bearer $($AzAPICallConfiguration['htBearerAccessToken'].$targetEndpoint)";
                    'ConsistencyLevel' = "$consistencyLevel"
                }
            }
        }

        ######### REST CALL
        $startAPICall = Get-Date
        $rawException = $null
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
            if ($azAPIRequest.StatusDescription) {
                $actualStatusCodePhrase = $azAPIRequest.StatusDescription
            }
            elseif ($azAPIRequest.StatusCode) {
                $actualStatusCodePhrase = [System.Net.HttpStatusCode]$azAPIRequest.StatusDescription
            }
            else {
                $actualStatusCodePhrase = 'n/a'
            }
        }
        catch {
            $rawException = $_
            if ($rawException.tostring() -eq 'No such host is known.' -or $rawException.tostring() -eq 'Connection timed out') {
                $tryCounterConnectionRelatedError++
                $connectionRelatedError = $true
                $connectionRelatedErrorPhrase = $rawException
            }
            else {
                if (-not [string]::IsNullOrWhiteSpace($rawException.Exception.Response.StatusCode)) {
                    if ([int32]($rawException.Exception.Response.StatusCode.Value__)) {
                        $actualStatusCode = $rawException.Exception.Response.StatusCode.Value__
                    }
                    else {
                        $actualStatusCode = 'n/a'
                    }
                    $actualStatusCodePhrase = $rawException.Exception.Response.StatusCode
                }
                else {
                    $actualStatusCodePhrase = 'n/a'
                }

                try {
                    $catchResultPlain = $rawException.ErrorDetails.Message
                    if ($catchResultPlain) {
                        $catchResult = $catchResultPlain | ConvertFrom-Json -ErrorAction Stop
                    }
                }
                catch {
                    $catchResult = $catchResultPlain
                    $tryCounterUnexpectedError++
                    if ($targetEndpoint -eq 'Storage' -and $catchResult -like '*InvalidAuthenticationInfoServer*The token is expired.') {
                        Logging -preventWriteOutput $true -logMessage " $logMessageDefault $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                    elseif ($targetEndpoint -eq 'Storage' -and $catchResult -like '*AuthorizationFailure*' -or $catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*' -or $catchResult -like '*name or service not known*') {
                        if ($catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*') {
                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionDenied'"
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionMismatch' - this error might occur due to only recently applied RBAC permissions"
                            }

                            if ($saResourceGroupName) {
                                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault $currentTask - Contribution request: please verify if the Storage Account's ResourceGroup '$($saResourceGroupName)' is a managed Resource Group, if yes please check if the Resource Group Name is listed here: https://github.com/JulianHayward/AzSchnitzels/blob/main/info/managedResourceGroups.txt"
                            }

                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                return 'AuthorizationPermissionDenied'
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                return 'AuthorizationPermissionMismatch'
                            }
                        }

                        if ($catchResult -like '*AuthorizationFailure*') {
                            Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationFailure'"
                            return 'AuthorizationFailure'
                        }
                        if ($catchResult -like '*name or service not known*') {
                            Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Forced DEBUG: $currentTask -> $catchResult -> returning string 'ResourceUnavailable'"
                            return 'ResourceUnavailable'
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "$logMessageDefault $currentTask try #$($tryCounterUnexpectedError) $($rawException)"
                        $unexpectedError = $true
                    }
                }
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
                CurrentTask                          = $currentTask
                TargetEndpoint                       = $targetEndpoint
                Uri                                  = $uri
                Method                               = $method
                TryCounter                           = $tryCounter
                TryCounterUnexpectedError            = $tryCounterUnexpectedError
                TryCounterConnectionRelatedError     = $tryCounterConnectionRelatedError
                RetryAuthorizationFailedCounter      = $retryAuthorizationFailedCounter
                RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                TimeStamp                            = $tstmp
                Duration                             = $durationAPICall.TotalSeconds
                StatusCode                           = $actualStatusCode
                StatusCodePhrase                     = $actualStatusCodePhrase
                RawException                         = $rawException
            })

        $message = "attempt#$($tryCounter) processing: $($currenttask) method: '$method' uri: '$($uri)'"

        if ($body) {
            $message += " body: '$($body | Out-String)'"
        }

        debugAzAPICall -debugMessage $message
        if ($unexpectedError -eq $false -and $connectionRelatedError -eq $false) {
            debugAzAPICall -debugMessage 'unexpectedError: false'
            if ($actualStatusCode -notin 200..204) {
                #if the token has exired it would only return statuscode 401 (ExpiredAuthenticationToken) and not the actual statuscode
                if ($listenOn -eq 'StatusCode' -and ($actualStatusCode -ne 401 -and $catchResult.error.code -ne 'ExpiredAuthenticationToken')) {
                    return [int32]$actualStatusCode
                }
                else {
                    debugAzAPICall -debugMessage "apiStatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))"
                    if ($actualStatusCode -in $skipOnErrorCode) {
                        debugAzAPICall -debugMessage "skipOnErrorCode: '$($skipOnErrorCode-join ', ')' == apiStatusCode: '$($actualStatusCode)' -> skip"
                        break
                    }

                    $function:AzAPICallErrorHandler = $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler
                    $AzAPICallErrorHandlerResponse = AzAPICallErrorHandler #-AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -catchResult $catchResult -currentTask $currentTask -tryCounter $tryCounter -retryAuthorizationFailed $retryAuthorizationFailed

                    if ($AzAPICallErrorHandlerResponse.action -eq 'retry' -or $AzAPICallErrorHandlerResponse.action -eq 'break' -or $AzAPICallErrorHandlerResponse.action -eq 'return' -or $AzAPICallErrorHandlerResponse.action -eq 'returnCollection') {
                        if ($AzAPICallErrorHandlerResponse.action -eq 'retry') {
                            debugAzAPICall -debugMessage "$logMessageDefault $currentTask - retry"
                        }
                        if ($AzAPICallErrorHandlerResponse.action -eq 'break') {
                            break
                        }
                        if ($AzAPICallErrorHandlerResponse.action -eq 'return') {
                            return $AzAPICallErrorHandlerResponse.returnVar
                        }
                        if ($AzAPICallErrorHandlerResponse.action -eq 'returnCollection') {
                            return $apiCallResultsCollection
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "$logMessageDefault `$AzAPICallErrorHandlerResponse.action unexpected (`$AzAPICallErrorHandlerResponse.action = '$($AzAPICallErrorHandlerResponse.action)') - breaking" -logMessageForegroundColor 'darkred'
                        break
                    }

                }
            }
            else {
                $isMore = $false

                debugAzAPICall -debugMessage "apiStatusCode: '$actualStatusCode' ($($actualStatusCodePhrase))"

                #####ToDo: KSJH - METHODs: PUT POST PATCH DELETE?
                # TODO: Only for ARM?
                # TODO: Example with RunCommand (return 200 + provisionState or Status). If status isn't Succeeded, Failed or Canceled, then it's still running. Max. Re-try counter + sleep. Exit strategy + message for the user how to handle it later
                if (-not $skipAsynchronousAzureOperation -and (($actualStatusCode -eq 200 -and $actualStatusCodePhrase -eq 'OK') -or ($actualStatusCode -eq 201 -and $actualStatusCodePhrase -eq 'Created') -or ($actualStatusCode -eq 202 -and $actualStatusCodePhrase -eq 'Accepted'))) {
                    if ($azAPIRequest.Headers.'Azure-AsyncOperation' -or $azAPIRequest.Headers.'Location') {
                        debugAzAPICall -debugMessage 'Copying the $azAPIRequest to $initialAzAPIRequest'
                        $initialAzAPIRequest = $azAPIRequest

                        debugAzAPICall -debugMessage 'Clear the array apiCallResultsCollection'
                        $apiCallResultsCollection = [System.Collections.ArrayList]@()

                        $isMore = $true

                        $initialBody = $body
                        $body = $null

                        $initialMethod = $method
                        $method = 'GET'

                        $notTryCounter = $true

                        if ($azAPIRequest.Headers.'Azure-AsyncOperation') {
                            $uri = $azAPIRequest.Headers.'Azure-AsyncOperation'
                            #$notTryCounter = $true
                            debugAzAPICall -debugMessage "Azure-AsyncOperation: $Uri"
                        }
                        elseif ($azAPIRequest.Headers.'Location') {
                            $uri = $azAPIRequest.Headers.'Location'
                            #$notTryCounter = $true
                            debugAzAPICall -debugMessage "Headers.Location: $Uri"
                        }

                        if ($azAPIRequest.Headers.'Retry-After') {
                            $retryAfter = [double]::Parse($azAPIRequest.Headers.'Retry-After')
                            $notTryCounter = $true
                            debugAzAPICall -debugMessage "Headers.'Retry-After': $retryAfter"
                            #debugAzAPICall -debugMessage "Start-Sleep -Seconds $retryAfter"
                            Logging -preventWriteOutput $true -logMessage "  $logMessageDefault AsyncOperation Retry-After (API): $retryAfter seconds"
                            $null = Start-Sleep -Seconds $retryAfter
                        }
                        else {
                            $retryAfter = Get-Random -Minimum 1 -Maximum 17
                            Logging -preventWriteOutput $true -logMessage "  $logMessageDefault AsyncOperation Retry-After (Random): $retryAfter seconds"
                            $null = Start-Sleep -Seconds $retryAfter
                        }
                    }

                    $azAPIRequestContent = $azAPIRequest.Content | ConvertFrom-Json
                    $azAPIRequestContentStatus = $azAPIRequestContent.status
                    $azAPIRequestContentProvisionState = $azAPIRequestContent.provisionState
                    $azAPIRequestContentPropertiesProvisionState = $azAPIRequestContent.properties.provisioningState

                    if ($azAPIRequestContentStatus -or $azAPIRequestContentProvisionState -or $azAPIRequestContentPropertiesProvisionState) {
                        debugAzAPICall -debugMessage 'Clear the array apiCallResultsCollection'
                        $initApiCallResultsCollection = $apiCallResultsCollection.Clone()
                        $apiCallResultsCollection = [System.Collections.ArrayList]@()

                        if ($azAPIRequestContentStatus -and ($azAPIRequestContentProvisionState -or $azAPIRequestContentPropertiesProvisionState)) {
                            Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Content.status and (Content.provisionState or Content.properties.provisionState) exists" -logMessageForegroundColor 'darkred'

                            if ($azAPIRequestContentStatus -ne $azAPIRequestContentProvisionState) {
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Content.status ($azAPIRequestContentStatus) and Content.provisionState ($azAPIRequestContentProvisionState) aren't equal" -logMessageForegroundColor 'darkred'
                                Throw "AzureAsyncOperation - Content.status ($azAPIRequestContentStatus) and Content.provisionState ($azAPIRequestContentProvisionState) aren't equal"
                            }
                            elseif ($azAPIRequestContentStatus -ne $azAPIRequestContentPropertiesProvisionState) {
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Content.status ($azAPIRequestContentStatus) and Content.properties.provisionState ($azAPIRequestContentPropertiesProvisionState) aren't equal" -logMessageForegroundColor 'darkred'
                                Throw "AzureAsyncOperation - Content.status ($azAPIRequestContentStatus) and Content.properties.provisionState ($azAPIRequestContentPropertiesProvisionState) aren't equal"
                            }
                            else {
                                $requestStatus = $azAPIRequestContentStatus
                                debugAzAPICall -debugMessage "Content.status and (Content.provisionState or Content.properties.provisionState): $requestStatus"
                            }
                        }
                        else {
                            if ($azAPIRequestContentStatus) {
                                $requestStatus = $azAPIRequestContentStatus
                                debugAzAPICall -debugMessage "Content.status: $requestStatus"
                            }
                            if ($azAPIRequestContentProvisionState) {
                                $requestStatus = $azAPIRequestContentProvisionState
                                debugAzAPICall -debugMessage "Content.provisionState: $requestStatus"
                            }
                            if ($azAPIRequestContentPropertiesProvisionState) {
                                $requestStatus = $azAPIRequestContentPropertiesProvisionState
                                debugAzAPICall -debugMessage "Content.properties.provisionState: $requestStatus"
                            }
                        }

                        debugAzAPICall -debugMessage "requestStatus: $requestStatus"

                        if (-not $notWaitForAsynchronousAzureOperationToFinish) {
                            if ($requestStatus -in @('Succeeded', 'Failed', 'Canceled')) {
                                debugAzAPICall -debugMessage "requestStatus has an finished state: $requestStatus"
                                $isMore = $false
                                $notTryCounter = $false
                            }
                            elseif ($asynchronousAzureOperationTryCounter -le 10) {
                                $asynchronousAzureOperationTryCounter++
                                debugAzAPICall -debugMessage "asynchronousAzureOperationTryCounter: $asynchronousAzureOperationTryCounter of 10"
                                $isMore = $true
                                $notTryCounter = $true

                                $retryAfter = Get-Random -Minimum 10 -Maximum 60
                                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault AsyncOperation Retry-After (Random): $retryAfter seconds"
                                $null = Start-Sleep -Seconds $retryAfter
                            }
                            elseif ($asynchronousAzureOperationTryCounter -ge 10) {
                                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault The AsyncOperation is still not finished after 10 retries. Save the current state in your code and do another request on the asynchronous Azure operation uri '$uri'. Continue with the next resource" -logMessageForegroundColor 'darkred'
                                Logging -preventWriteOutput $true -logMessage "  $logMessageDefault If you don't want to wait for the asynchronous Azure operation to finish, please use the ''-parameter." -logMessageForegroundColor 'darkred'
                            }
                        }
                        else {
                            Logging -preventWriteOutput $true -logMessage "  $logMessageDefault Used 'notWaitForAsynchronousAzureOperationToFinish'-parameter. Won't wait till the finished state of the asynchronous Azure operation has been reached. Actual status is '$requestStatus'." -logMessageForegroundColor 'yellow'
                        }
                    }
                }

                # TODO: To be discussed: Everything below in an else-statement? till row 635?

                if ($targetEndPoint -eq 'Storage') {
                    try {
                        $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                    }
                    catch {
                        $azAPIRequestConvertedFromJson = ($azAPIRequest.Content)
                        try {
                            $storageResponseXML = [xml]($azAPIRequestConvertedFromJson -replace '^.*?<', '<')
                        }
                        catch {
                            debugAzAPICall -debugMessage "non JSON object; return as is ($((($azAPIRequestConvertedFromJson).gettype()).Name))"
                        }
                    }
                }
                else {
                    try {
                        $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                    }
                    catch {
                        if ($_.Exception.Message -like '*different casing*') {
                            Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Command 'ConvertFrom-Json' failed: $($_.Exception.Message)" -logMessageForegroundColor 'darkred'
                            Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Trying command 'ConvertFrom-Json -AsHashtable'" -logMessageForegroundColor 'darkred'
                            try {
                                $azAPIRequestConvertedFromJsonAsHashTable = ($azAPIRequest.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' succeeded. Please file an issue at the AzAPICall GitHub repository (aka.ms/AzAPICall) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                                #$azAPIRequestConvertedFromJsonAsHashTable | ConvertTo-Json -Depth 99
                                if ($currentTask -like 'Getting Resource Properties*') {
                                    return 'convertfromJSONError'
                                }
                                Throw 'throwing - Command ConvertFrom-Json failed (*different casing*)'
                            }
                            catch {
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' failed" -logMessageForegroundColor 'darkred'
                                #$_
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' failed. Please file an issue at the AzAPICall GitHub repository (aka.ms/AzAPICall) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                                #$azAPIRequest.Content
                                if ($currentTask -like 'Getting Resource Properties*') {
                                    return 'convertfromJSONError'
                                }
                                Throw 'throwing - Command ConvertFrom-Json -AsHashtable failed (*different casing*)'
                            }
                        }
                        else {
                            # Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Command 'ConvertFrom-Json' failed (not *different casing*). Please file an issue at the AzAPICall GitHub repository (aka.ms/AzAPICall) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                            # Write-Host $_.Exception.Message
                            # Write-Host $_

                            #Throw 'throwing - Command ConvertFrom-Json failed (not *different casing*)'
                            $contentTypeName = 'unknown'
                            if ($azAPIRequest.Content.GetType()) {
                                $contentTypeName = "$($azAPIRequest.Content.GetType().Name) ($($azAPIRequest.Content.GetType().BaseType))"
                            }
                            Logging -preventWriteOutput $true -logMessage "$logMessageDefault '$currentTask' uri='$uri' Returning response content (`$azAPIRequest.Content) as is [$contentTypeName]" -logMessageForegroundColor 'DarkGray'
                            return $azAPIRequest.Content
                        }
                    }
                }

                if ($listenOn -eq 'Headers') {
                    debugAzAPICall -debugMessage "listenOn=Headers ($((($azAPIRequest.Headers)).count))"
                    $null = $apiCallResultsCollection.Add($azAPIRequest.Headers)
                }
                elseif ($listenOn -eq 'Content') {
                    debugAzAPICall -debugMessage "listenOn=Content ($((($azAPIRequestConvertedFromJson)).count))"
                    if ($uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/*") {
                        $null = $apiCallResultsCollection.AddRange($azAPIRequestConvertedFromJson.data)
                    }
                    else {
                        $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                    }
                }
                elseif ($listenOn -eq 'StatusCode') {
                    debugAzAPICall -debugMessage "listenOn=StatusCode ($actualStatusCode)"
                    #$null = $apiCallResultsCollection.Add($actualStatusCode)
                    return [int32]$actualStatusCode
                }
                elseif ($listenOn -eq 'ContentProperties') {
                    debugAzAPICall -debugMessage "listenOn=ContentProperties ($(($azAPIRequestConvertedFromJson.properties.rows).count))"
                    if (($azAPIRequestConvertedFromJson.properties.rows).Count -gt 0) {
                        $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                    }
                }
                elseif ($listenOn -eq 'Raw') {
                    debugAzAPICall -debugMessage "listenOn=Raw ($(($azAPIRequest).count))"

                    if ($initialAzAPIRequest -and $requestStatus -notin @('Succeeded', 'Failed', 'Canceled')) {
                        debugAzAPICall -debugMessage 'adding the initial request to the output for later processing'
                        $azAPIRequest | Add-Member -Type NoteProperty -Name initialAzAPIRequest -Value $initialAzAPIRequest
                    }

                    $null = $apiCallResultsCollection.Add($azAPIRequest)
                }
                else {
                    if (($azAPIRequestConvertedFromJson).value) {
                        debugAzAPICall -debugMessage "listenOn=Default(Value) value exists ($((($azAPIRequestConvertedFromJson).value).count))"
                        foreach ($entry in $azAPIRequestConvertedFromJson.value) {
                            $null = $apiCallResultsCollection.Add($entry)
                        }
                    }
                    else {
                        debugAzAPICall -debugMessage 'listenOn=Default(Value) value not exists; return empty array'
                    }
                }

                # TODO: To be discussed: Should the Async task located here?

                if (-not $noPaging) {
                    if (-not [string]::IsNullOrWhiteSpace($azAPIRequestConvertedFromJson.nextLink)) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " $logMessageDefault $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: uri is equal to nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                    elseif ($azAPIRequestConvertedFromJson.'$skipToken' -and $uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/*") {
                        $isMore = $true
                        if ($body) {
                            $bodyHt = $body | ConvertFrom-Json -AsHashtable
                            if ($bodyHt.options) {
                                if ($bodyHt.options.'$skiptoken') {
                                    if ($bodyHt.options.'$skiptoken' -eq $azAPIRequestConvertedFromJson.'$skipToken') {
                                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                            Logging -preventWriteOutput $true -logMessage " $logMessageDefault $currentTask restartDueToDuplicateSkipTokenCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                            Throw 'Error - check the last console output for details'
                                        }
                                        else {
                                            $restartDueToDuplicateNextlinkCounter++
                                            debugAzAPICall -debugMessage "skipTokenLog: `$skipToken: $($azAPIRequestConvertedFromJson.'$skipToken') is equal to previous skipToken"
                                            debugAzAPICall -debugMessage 'skipTokenLog: re-starting'
                                            $bodyht.options.remove('$skiptoken')
                                            debugAzAPICall -debugMessage "`$body: $($bodyHt | ConvertTo-Json -Depth 99 | Out-String)"
                                        }
                                    }
                                    else {
                                        $bodyHt.options.'$skiptoken' = $azAPIRequestConvertedFromJson.'$skipToken'
                                    }
                                }
                                else {
                                    $bodyHt.options.'$skiptoken' = $azAPIRequestConvertedFromJson.'$skipToken'
                                }
                            }
                            else {
                                $bodyHt.options = @{}
                                $bodyHt.options.'$skiptoken' = $azAPIRequestConvertedFromJson.'$skipToken'
                            }
                            debugAzAPICall -debugMessage "`$body: $($bodyHt | ConvertTo-Json -Depth 99 | Out-String)"
                            $body = $bodyHt | ConvertTo-Json -Depth 99
                        }

                        $notTryCounter = $true
                        debugAzAPICall -debugMessage "`$skipToken: $($azAPIRequestConvertedFromJson.'$skipToken')"
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($azAPIRequestConvertedFromJson.'@oData.nextLink')) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.'@odata.nextLink') {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " $logMessageDefault $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: uri is equal to @odata.nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson.'@odata.nextLink')"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                                Logging -preventWriteOutput $true -logMessage " $logMessageDefault $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: uri is equal to nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "$logMessageDefault nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                    elseif ($storageResponseXML.EnumerationResults.NextMarker) {
                        debugAzAPICall -debugMessage "NextMarker found: $($storageResponseXML.EnumerationResults.NextMarker)"
                    }
                    else {
                        debugAzAPICall -debugMessage 'NextLink/skipToken/NextMarker: none' # TODO: KS/JH: Check if we should add here as well a re-try or location property
                    }
                }
            }
        }
        else {


            if ($connectionRelatedError) {
                debugAzAPICall -debugMessage 'connectionRelatedError: true'
                $maxtryCounterConnectionRelatedError = 6
                if ($tryCounterConnectionRelatedError -lt ($maxtryCounterConnectionRelatedError + 1)) {
                    $sleepSecConnectionRelatedError = @(1, 1, 2, 4, 8, 16, 32, 64, 128)[$tryCounterConnectionRelatedError]
                    Logging -preventWriteOutput $true -logMessage "$logMessageDefault $currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (trying $maxtryCounterConnectionRelatedError times); sleep $sleepSecConnectionRelatedError seconds"
                    #Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecConnectionRelatedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$logMessageDefault $currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (tried $($tryCounterConnectionRelatedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
                    if ($unhandledErrorAction -in @('Continue', 'ContinueQuiet')) {
                        break
                    }
                    else {
                        Throw 'Error - check the last console output for details'
                    }
                }
            }

            if ($unexpectedError) {
                debugAzAPICall -debugMessage 'unexpectedError: true'
                $maxtryUnexpectedError = 6
                if ($tryCounterUnexpectedError -lt ($maxtryUnexpectedError + 1)) {
                    $sleepSecUnexpectedError = @(1, 1, 2, 4, 8, 16, 32, 64, 128)[$tryCounterUnexpectedError]
                    Logging -preventWriteOutput $true -logMessage "$logMessageDefault $currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (trying $maxtryUnexpectedError times); sleep $sleepSecUnexpectedError seconds"
                    Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecUnexpectedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$logMessageDefault $currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (tried $($tryCounterUnexpectedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
                    if ($unhandledErrorAction -in @('Continue', 'ContinueQuiet')) {
                        break
                    }
                    else {
                        Throw 'Error - check the last console output for details'
                    }
                }
            }

        }
    }
    until(
            ($actualStatusCode -in 200..204 -and -not $isMore ) -or
            ($Method -eq 'HEAD' -and $actualStatusCode -eq 404)
    )
    return [PSCustomObject]$apiCallResultsCollection
}