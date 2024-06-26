﻿function AzAPICall {
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
        $initState
    )

    if ($initState) {
        if ($AzApiCallConfiguration['AzAPICallState'] -ne 'initializing') {
            Throw "Error - expected `$AzApiCallConfiguration['AzAPICallState'] == 'initializing' (got: $($AzApiCallConfiguration['AzAPICallState']))"
        }
    }
    else {
        if ($AzApiCallConfiguration['AzAPICallState'] -ne 'operational') {
            Throw 'Error - AzAPICallConfiguration not initialized! https://aka.ms/AzAPICall#initialize-azapicall'
        }
        elseif ($AzApiCallConfiguration['AzAPICallState'] -eq 'initializing') {
            Throw 'Error - In the initAzAPICall stage, the AzAPICall must use switch parameter -initState'
        }
    }

    function debugAzAPICall {
        param (
            [Parameter(Mandatory)]
            [string]
            $debugMessage
        )

        if ($doDebugAzAPICall -or $tryCounter -gt 3) {
            if ($doDebugAzAPICall) {
                Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo DEBUGTASK: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
            }
            if (-not $doDebugAzAPICall -and $tryCounter -gt 3) {
                Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo Forced DEBUG: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
            }
        }
    }

    $azAPICallModuleVersion = $AzApiCallConfiguration['htParameters'].azAPICallModuleVersion
    $script:azAPICallErrorHandlerInfo = "[AzAPICallErrorHandler $azAPICallModuleVersion]"
    $azAPICallInfo = "[AzAPICall $azAPICallModuleVersion]"

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
    $tryCounterConnectionRelatedError = 0
    $script:retryAuthorizationFailed = 5
    $script:retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0
    $isMoreCounter = 0


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
            Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo Forced DEBUG: $currentTask -> check uri: '$uri' - EXIT"
            Throw "Error - check uri: '$uri'"
        }

        $uriSplitted = $uri.split('/')
        if ($AzAPICallConfiguration['azAPIEndpointUrls'].Storage.where({ [System.Text.RegularExpressions.Regex]::Escape($uriSplitted[2]) -like "*$([System.Text.RegularExpressions.Regex]::Escape($_))" })) {
            $targetEndpoint = 'Storage'
        }
        elseif ([System.Text.RegularExpressions.Regex]::Escape($uriSplitted[2]) -like "*$([System.Text.RegularExpressions.Regex]::Escape($AzAPICallConfiguration['azAPIEndpointUrls'].MonitorIngest))") {
            $targetEndpoint = 'MonitorIngest'
        }
        elseif ([System.Text.RegularExpressions.Regex]::Escape($uriSplitted[2]) -like "*$([System.Text.RegularExpressions.Regex]::Escape($AzAPICallConfiguration['azAPIEndpointUrls'].Kusto))") {
            $targetEndpoint = 'Kusto'
        }
        else {
            if (-not ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])) {
                if ($uriSplitted[2] -like "*.$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM.replace('https://',''))") {
                    $armUriSplitted = $uriSplitted[2].split('.')
                    if ($armUriSplitted[0] -in $AzApiCallConfiguration['htParameters'].ARMLocations) {
                        if (($AzApiCallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM).replace('https://', '')))) {
                            $targetEndpoint = ($AzApiCallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM).replace('https://', '')))
                        }
                        else {
                            Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "$azAPICallInfo Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
                        Logging -preventWriteOutput $true -logMessage "!c712e5a2 Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository)" -logMessageForegroundColor 'Yellow'
                        Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
                    }
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
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

        $randomSleepMilisecondsUnits = (1..360).where({ $_ % 15 -eq 0 })

        #Azure Resource Graph throttling
        $script:getARMARG = $false
        if ($uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources*") {
            #https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/guidance-for-throttled-requests#understand-throttling-headers
            $script:getARMARG = $true

            $randomSleepMiliseconds = $randomSleepMilisecondsUnits[(Get-Random -Minimum 0 -Maximum ($randomSleepMilisecondsUnits.Count - 1))]
            Start-Sleep -Milliseconds $randomSleepMiliseconds

            if ((New-TimeSpan -Start ($AzAPICallConfiguration['throttleState'].ARG.tstmpThrottled) -End (Get-Date)).TotalSeconds -le $AzAPICallConfiguration['throttleRules'].ARG.timeWindowSeconds) {

                #optimized for parallel
                if ($AzAPICallConfiguration['throttleState'].ARG.remainingCalls -le 2) {
                    Logging -preventWriteOutput $true -logMessage " $azAPICallInfo $currentTask - AzureResourceGraph throttled - sleeping $($AzAPICallConfiguration['throttleRules'].ARG.timeWindowSeconds) seconds"
                    Start-Sleep -Seconds $AzAPICallConfiguration['throttleRules'].ARG.timeWindowSeconds

                    $AzAPICallConfiguration['throttleState'].ARG = @{
                        remainingCalls = $AzAPICallConfiguration['throttleRules'].ARG.maxQueriesInTimeWindow
                        tstmpThrottled = (Get-Date)
                    }
                }
            }
        }

        $script:getARMCostManagement = $false
        if ($uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)*/providers/Microsoft.CostManagement/query*") {

            $script:getARMCostManagement = $true

            $randomSleepMiliseconds = $randomSleepMilisecondsUnits[(Get-Random -Minimum 0 -Maximum ($randomSleepMilisecondsUnits.Count - 1))]
            Start-Sleep -Milliseconds $randomSleepMiliseconds

            if ($AzAPICallConfiguration['throttleState'].ARMCostmanagementQuery.isThrottled) {

                if ((New-TimeSpan -Start ($AzAPICallConfiguration['throttleState'].ARMCostmanagementQuery.tstmpThrottled).AddSeconds($AzAPICallConfiguration['throttleState'].ARMCostmanagementQuery.retryAfter) -End (Get-Date)).TotalSeconds -le 0) {
                    Start-Sleep $AzAPICallConfiguration['throttleState'].ARMCostmanagementQuery.retryAfter
                }

                $AzAPICallConfiguration['throttleState'].ARMCostmanagementQuery = @{
                    isThrottled    = $false
                    retryAfter     = 1
                    tstmpThrottled = (Get-Date).AddMinutes(-5)
                }
            }
        }

        $startAPICall = Get-Date
        $rawException = $null
        $actualStatusCode = $null
        $actualStatusCodePhrase = 'n/a'
        try {
            if ($body) {
                if ($AzApiCallConfiguration['htParameters'].codeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Body $body -Headers $Header -UseBasicParsing -ErrorAction Stop
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Body $body -Headers $Header -ErrorAction Stop
                }
            }
            else {
                if ($AzApiCallConfiguration['htParameters'].codeRunPlatform -eq 'AzureAutomation') {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header -UseBasicParsing -ErrorAction Stop
                }
                else {
                    $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header -ErrorAction Stop
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

            if ($getARMARG) {
                $remainingCalls = 15
                if (($azAPIRequest.Headers.'x-ms-user-quota-remaining') -and (($azAPIRequest.Headers.'x-ms-user-quota-remaining')[0] -as [int])) {
                    $remainingCalls = [int]($azAPIRequest.Headers.'x-ms-user-quota-remaining')[0]
                }

                if ($isMore) {
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask - processing nextLink/skipToken #$('{0:d3}' -f $isMoreCounter) - remaining API calls till throttle: $($remainingCalls)/$($AzAPICallConfiguration['throttleRules'].ARG.maxQueriesInTimeWindow)"
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask - remaining API calls till throttle: $($remainingCalls)/$($AzAPICallConfiguration['throttleRules'].ARG.maxQueriesInTimeWindow)"
                }

                $AzAPICallConfiguration['throttleState'].ARG = @{
                    remainingCalls = $remainingCalls
                    tstmpThrottled = (Get-Date).AddSeconds(-5)
                }
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
                        Logging -preventWriteOutput $true -logMessage " $azAPICallInfo $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                    elseif ($targetEndpoint -eq 'Storage' -and $catchResult -like '*AuthorizationFailure*' -or $catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*' -or $catchResult -like '*name or service not known*') {
                        if ($catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*') {
                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionDenied'"
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionMismatch' - this error might occur due to only recently applied RBAC permissions"
                            }

                            if ($saResourceGroupName) {
                                Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo $currentTask - Contribution request: please verify if the Storage Account's ResourceGroup '$($saResourceGroupName)' is a managed Resource Group, if yes please check if the Resource Group Name is listed here: https://github.com/JulianHayward/AzSchnitzels/blob/main/info/managedResourceGroups.txt"
                            }

                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                return 'AuthorizationPermissionDenied'
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                return 'AuthorizationPermissionMismatch'
                            }
                        }

                        if ($catchResult -like '*AuthorizationFailure*') {
                            Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationFailure'"
                            return 'AuthorizationFailure'
                        }
                        if ($catchResult -like '*name or service not known*') {
                            Logging -preventWriteOutput $true -logMessage "  $azAPICallInfo Forced DEBUG: $currentTask -> $catchResult -> returning string 'ResourceUnavailable'"
                            return 'ResourceUnavailable'
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask try #$($tryCounterUnexpectedError) $($rawException)"
                        $unexpectedError = $true
                    }
                }
            }
        }
        $endAPICall = Get-Date
        $durationAPICall = New-TimeSpan -Start $startAPICall -End $endAPICall

        if (-not $notTryCounter) {
            if ($actualStatusCode -ne 429) {
                $tryCounter++
            }
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

        $message = "try#$($tryCounter) processing: $($currenttask) uri: '$($uri)'"

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
                    $AzAPICallErrorHandlerResponse = AzAPICallErrorHandler

                    if ($AzAPICallErrorHandlerResponse.action -eq 'retry' -or $AzAPICallErrorHandlerResponse.action -eq 'break' -or $AzAPICallErrorHandlerResponse.action -eq 'return' -or $AzAPICallErrorHandlerResponse.action -eq 'returnCollection') {
                        if ($AzAPICallErrorHandlerResponse.action -eq 'retry') {
                            debugAzAPICall -debugMessage "$azAPICallInfo $currentTask - retry"
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
                        Logging -preventWriteOutput $true -logMessage "$azAPICallInfo `$AzAPICallErrorHandlerResponse.action unexpected (`$AzAPICallErrorHandlerResponse.action = '$($AzAPICallErrorHandlerResponse.action)') - breaking" -logMessageForegroundColor 'darkred'
                        break
                    }

                }
            }
            else {
                debugAzAPICall -debugMessage "apiStatusCode: '$actualStatusCode' ($($actualStatusCodePhrase))"

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
                            Logging -preventWriteOutput $true -logMessage "$azAPICallInfo '$currentTask' uri='$uri' Command 'ConvertFrom-Json' failed: $($_.Exception.Message)" -logMessageForegroundColor 'darkred'
                            Logging -preventWriteOutput $true -logMessage "$azAPICallInfo '$currentTask' uri='$uri' Trying command 'ConvertFrom-Json -AsHashtable'" -logMessageForegroundColor 'darkred'
                            try {
                                $azAPIRequestConvertedFromJsonAsHashTable = ($azAPIRequest.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' succeeded. Please file an issue at the AzGovViz GitHub repository (aka.ms/AzGovViz) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                                #$azAPIRequestConvertedFromJsonAsHashTable | ConvertTo-Json -Depth 99
                                if ($currentTask -like 'Getting Resource Properties*') {
                                    return 'convertfromJSONError'
                                }
                                Throw 'throwing - Command ConvertFrom-Json failed (*different casing*)'
                            }
                            catch {
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' failed" -logMessageForegroundColor 'darkred'
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' failed. Please file an issue at the AzGovViz GitHub repository (aka.ms/AzGovViz) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                                if ($currentTask -like 'Getting Resource Properties*') {
                                    return 'convertfromJSONError'
                                }
                                Throw 'throwing - Command ConvertFrom-Json -AsHashtable failed (*different casing*)'
                            }
                        }
                        else {
                            $contentTypeName = 'unknown'
                            if ($azAPIRequest.Content.GetType()) {
                                $contentTypeName = "$($azAPIRequest.Content.GetType().Name) ($($azAPIRequest.Content.GetType().BaseType))"
                            }
                            Logging -preventWriteOutput $true -logMessage "$azAPICallInfo '$currentTask' uri='$uri' Returning response content (`$azAPIRequest.Content) as is [$contentTypeName]" -logMessageForegroundColor 'DarkGray'
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
                    if ($getARMARG) {
                        $null = $apiCallResultsCollection.AddRange($azAPIRequestConvertedFromJson.data)
                    }
                    else {
                        $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                    }
                }
                elseif ($listenOn -eq 'StatusCode') {
                    debugAzAPICall -debugMessage "listenOn=StatusCode ($actualStatusCode)"
                    return [int32]$actualStatusCode
                }
                elseif ($listenOn -eq 'ContentProperties') {
                    debugAzAPICall -debugMessage "listenOn=ContentProperties ($(($azAPIRequestConvertedFromJson.properties.rows).count))"
                    if (($azAPIRequestConvertedFromJson.properties.rows).Count -gt 0) {
                        $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                    }
                }
                elseif ($listenOn -eq 'Raw') {
                    debugAzAPICall -debugMessage "listenOn=Raw ($(($azAPIRequest).count))"
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

                if ($isMore) {
                    if (-not $getARMARG) {
                        Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask - processing nextLink/skipToken #$isMoreCounter"
                    }
                }

                $isMore = $false
                if (-not $noPaging) {
                    if (-not [string]::IsNullOrWhiteSpace($azAPIRequestConvertedFromJson.nextLink)) {
                        $isMore = $true
                        $isMoreCounter++
                        if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " $azAPICallInfo $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: uri is equal to nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                    elseif ($azAPIRequestConvertedFromJson.'$skipToken' -and $getARMARG) {
                        $isMore = $true
                        $isMoreCounter++
                        if ($body) {
                            $bodyHt = $body | ConvertFrom-Json -AsHashtable
                            if ($bodyHt.options) {
                                if ($bodyHt.options.'$skiptoken') {
                                    if ($bodyHt.options.'$skiptoken' -eq $azAPIRequestConvertedFromJson.'$skipToken') {
                                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                            Logging -preventWriteOutput $true -logMessage " $azAPICallInfo $currentTask restartDueToDuplicateSkipTokenCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
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
                        $isMoreCounter++
                        if ($uri -eq $azAPIRequestConvertedFromJson.'@odata.nextLink') {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " $azAPICallInfo $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: uri is equal to @odata.nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson.'@odata.nextLink')"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                        $isMoreCounter++
                        if ($uri -eq $azAPIRequestConvertedFromJson.properties.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " $azAPICallInfo $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: uri is equal to nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "$azAPICallInfo nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                        debugAzAPICall -debugMessage 'NextLink/skipToken/NextMarker: none'
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
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (trying $maxtryCounterConnectionRelatedError times); sleep $sleepSecConnectionRelatedError seconds"
                    Start-Sleep -Seconds $sleepSecConnectionRelatedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (tried $($tryCounterConnectionRelatedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
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
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (trying $maxtryUnexpectedError times); sleep $sleepSecUnexpectedError seconds"
                    Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecUnexpectedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$azAPICallInfo $currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (tried $($tryCounterUnexpectedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
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