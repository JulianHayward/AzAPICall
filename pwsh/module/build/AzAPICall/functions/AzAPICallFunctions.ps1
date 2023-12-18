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
        $saResourceGroupName
    )

    function debugAzAPICall {
        param (
            [Parameter(Mandatory)]
            [string]
            $debugMessage
        )

        if ($doDebugAzAPICall -or $tryCounter -gt 3) {
            if ($doDebugAzAPICall) {
                Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] DEBUGTASK: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
            }
            if (-not $doDebugAzAPICall -and $tryCounter -gt 3) {
                Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Forced DEBUG: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
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
    $tryCounterConnectionRelatedError = 0
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
            Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Forced DEBUG: $currentTask -> check uri: '$uri' - EXIT"
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
                        Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
                        Logging -preventWriteOutput $true -logMessage "!c712e5a2 Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository)" -logMessageForegroundColor 'Yellow'
                        Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
                    }
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
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
            $actualStatusCodePhrase = 'OK'
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
                        Logging -preventWriteOutput $true -logMessage " [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                    elseif ($targetEndpoint -eq 'Storage' -and $catchResult -like '*AuthorizationFailure*' -or $catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*' -or $catchResult -like '*name or service not known*') {
                        if ($catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*') {
                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionDenied'"
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionMismatch' - this error might occur due to only recently applied RBAC permissions"
                            }

                            if ($saResourceGroupName) {
                                Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask - Contribution request: please verify if the Storage Account's ResourceGroup '$($saResourceGroupName)' is a managed Resource Group, if yes please check if the Resource Group Name is listed here: https://github.com/JulianHayward/AzSchnitzels/blob/main/info/managedResourceGroups.txt"
                            }

                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                return 'AuthorizationPermissionDenied'
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                return 'AuthorizationPermissionMismatch'
                            }
                        }

                        if ($catchResult -like '*AuthorizationFailure*') {
                            Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationFailure'"
                            return 'AuthorizationFailure'
                        }
                        if ($catchResult -like '*name or service not known*') {
                            Logging -preventWriteOutput $true -logMessage "  [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] Forced DEBUG: $currentTask -> $catchResult -> returning string 'ResourceUnavailable'"
                            return 'ResourceUnavailable'
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounterUnexpectedError) $($rawException)"
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

        $message = "attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'"

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
                            debugAzAPICall -debugMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask - retry"
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
                        Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] `$AzAPICallErrorHandlerResponse.action unexpected (`$AzAPICallErrorHandlerResponse.action = '$($AzAPICallErrorHandlerResponse.action)') - breaking" -logMessageForegroundColor 'darkred'
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
                            Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Command 'ConvertFrom-Json' failed: $($_.Exception.Message)" -logMessageForegroundColor 'darkred'
                            Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Trying command 'ConvertFrom-Json -AsHashtable'" -logMessageForegroundColor 'darkred'
                            try {
                                $azAPIRequestConvertedFromJsonAsHashTable = ($azAPIRequest.Content | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' succeeded. Please file an issue at the AzGovViz GitHub repository (aka.ms/AzGovViz) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                                #$azAPIRequestConvertedFromJsonAsHashTable | ConvertTo-Json -Depth 99
                                if ($currentTask -like 'Getting Resource Properties*') {
                                    return 'convertfromJSONError'
                                }
                                Throw 'throwing - Command ConvertFrom-Json failed (*different casing*)'
                            }
                            catch {
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' failed" -logMessageForegroundColor 'darkred'
                                #$_
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Command 'ConvertFrom-Json -AsHashtable' failed. Please file an issue at the AzGovViz GitHub repository (aka.ms/AzGovViz) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                                #$azAPIRequest.Content
                                if ($currentTask -like 'Getting Resource Properties*') {
                                    return 'convertfromJSONError'
                                }
                                Throw 'throwing - Command ConvertFrom-Json -AsHashtable failed (*different casing*)'
                            }
                        }
                        else {
                            # Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Command 'ConvertFrom-Json' failed (not *different casing*). Please file an issue at the AzGovViz GitHub repository (aka.ms/AzGovViz) and provide a dump (scrub subscription Id and company identifyable names) of the resource (portal JSOn view) - Thank you!" -logMessageForegroundColor 'darkred'
                            # Write-Host $_.Exception.Message
                            # Write-Host $_

                            #Throw 'throwing - Command ConvertFrom-Json failed (not *different casing*)'
                            $contentTypeName = 'unknown'
                            if ($azAPIRequest.Content.GetType()) {
                                $contentTypeName = "$($azAPIRequest.Content.GetType().Name) ($($azAPIRequest.Content.GetType().BaseType))"
                            }
                            Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] '$currentTask' uri='$uri' Returning response content (`$azAPIRequest.Content) as is [$contentTypeName]" -logMessageForegroundColor 'DarkGray'
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

                $isMore = $false
                if (-not $noPaging) {
                    if (-not [string]::IsNullOrWhiteSpace($azAPIRequestConvertedFromJson.nextLink)) {
                        $isMore = $true
                        if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                            if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                Logging -preventWriteOutput $true -logMessage " [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: uri is equal to nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                                            Logging -preventWriteOutput $true -logMessage " [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask restartDueToDuplicateSkipTokenCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
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
                                Logging -preventWriteOutput $true -logMessage " [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: uri is equal to @odata.nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson.'@odata.nextLink')"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                                Logging -preventWriteOutput $true -logMessage " [AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                                Throw 'Error - check the last console output for details'
                            }
                            else {
                                $restartDueToDuplicateNextlinkCounter++
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: uri is equal to nextLinkUri"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: uri: $uri"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                                Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
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
                    Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (trying $maxtryCounterConnectionRelatedError times); sleep $sleepSecConnectionRelatedError seconds"
                    #Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecConnectionRelatedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (tried $($tryCounterConnectionRelatedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
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
                    Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (trying $maxtryUnexpectedError times); sleep $sleepSecUnexpectedError seconds"
                    Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecUnexpectedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "[AzAPICall $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (tried $($tryCounterUnexpectedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
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
function AzAPICallErrorHandler {
    #Logging -preventWriteOutput $true -logMessage ' * BuiltIn RuleSet'

    $doRetry = $false
    $defaultErrorInfo = "[AzAPICallErrorHandler $($AzApiCallConfiguration['htParameters'].azAPICallModuleVersion)] $currentTask try #$($tryCounter); uri:`"$uri`"; return: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'>"

    switch ($uri) {
        #ARMss
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


    if (($catchResult.error.code -like '*BadGateway*' -and $actualStatusCode -eq 502) -or $catchResult.error.code -like '*GatewayTimeout*' -or $catchResult.error.code -like '*BadGatewayConnection*' -or $catchResult.error.code -like '*InvalidGatewayHost*' -or $catchResult.error.code -like '*ServerTimeout*' -or $catchResult.error.code -like '*ServiceUnavailable*' -or $catchResult.code -like '*ServiceUnavailable*' -or $catchResult.error.code -like '*MultipleErrorsOccurred*' -or $catchResult.code -like '*InternalServerError*' -or $catchResult.error.code -like '*InternalServerError*' -or $catchResult.error.code -like '*RequestTimeout*' -or $catchResult.code -like '*RequestTimeout*' -or $catchResult.error.code -like '*UnknownError*' -or $catchResult.error.code -eq '500' -or $catchResult.error.code -eq 500) {
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

    if ($catchResult.error.code -like '*ExpiredAuthenticationToken*' -or $catchResult.error.code -like '*Authentication_ExpiredToken*' -or $catchResult.error.code -like '*InvalidAuthenticationToken*') {
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
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint) - sleep 5 second and try again"
            $doRetry = $true
            Start-Sleep -Seconds 5
            #Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token ($targetEndpoint)"
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
                                $return.Add([regex]::Match($resultTenants, $pattern).Groups[1].Value)
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
                    Start-Sleep -Seconds 5
                    $response = @{
                        action = 'retry' #break or return or returnCollection or retry
                    }
                    return $response
                }
                if ($retryAuthorizationFailedCounter -gt 3) {
                    Start-Sleep -Seconds 10
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
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Write-Host $($catchResult | ConvertTo-Json -Depth 99) -ForegroundColor DarkGreen
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        if ($catchResult.error.code -eq 'ResourceRequestsThrottled') {
            $sleepSeconds = ($sleepSeconds + $tryCounter)
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        if ($catchResult.error.code -eq '429' -or $catchResult.error.code -eq 429) {
            if ($catchResult.error.message -like '*60 seconds*') {
                $sleepSeconds = (60 + $tryCounter)
            }
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        if ($catchResult.error.code -eq 'RateLimiting') {
            $sleepSeconds = 4
            $sleepSeconds = ($sleepSeconds + $tryCounter)
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }
        if ($catchResult.code -eq 'TooManyRequests') {
            $sleepSeconds = 4
            $sleepSeconds = ($sleepSeconds + $tryCounter)
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
            Start-Sleep -Seconds $sleepSeconds
            $response = @{
                action = 'retry' #break or return or returnCollection or retry
            }
            return $response
        }

        $sleepSeconds = ($sleepSeconds + $tryCounter)
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: throttled! sleeping $sleepSeconds seconds"
        Start-Sleep -Seconds $sleepSeconds
        $response = @{
            action = 'retry' #break or return or returnCollection or retry
        }
        return $response
    }

    elseif ($getARMARG -and $catchResult.error.code -eq 'BadRequest') {
        $sleepSec = @(1, 1, 2, 3, 5, 7, 9, 10, 13, 15, 20, 25, 30, 45, 60, 60, 60, 60)[$tryCounter]
        $maxTries = 15
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: capitulation after $maxTries attempts - return 'capitulation'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'capitulation'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: try again (trying $maxTries times) in $sleepSec second(s)"
        $doRetry = $true
        Start-Sleep -Seconds $sleepSec
        $response = @{
            action = 'retry' #break or return or returnCollection or retry
        }
        return $response
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

    elseif (($getARMMDfC -or $getARMMdFCSecurityContacts) -and $catchResult.error.code -eq 'Subscription Not Registered') {
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

    elseif ($catchResult.error.code -eq 'Request_UnsupportedQuery') {
        $sleepSec = @(1, 3, 7, 10, 15, 20, 30)[$tryCounter]
        $maxTries = 5
        if ($tryCounter -gt $maxTries) {
            Logging -preventWriteOutput $true -logMessage " $currentTask - capitulation after $maxTries attempts - return 'Request_UnsupportedQuery'"
            $response = @{
                action    = 'return' #break or return or returnCollection
                returnVar = 'Request_UnsupportedQuery'
            }
            return $response
        }
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: try again (trying $maxTries times) in $sleepSec second(s)"
        $doRetry = $true
        Start-Sleep -Seconds $sleepSec
        $response = @{
            action = 'retry' #break or return or returnCollection or retry
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

    elseif ($targetEndPoint -eq 'Kusto' -and $actualStatusCode -eq '401') {
        $maxTries = 7
        if ($tryCounter -gt $maxTries) {
            #Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: exit"
            $exitMsg = "AzAPICall: exit (requesting new bearer token '$targetEndpoint' ($targetCluster) - max retry of '$maxTries' reached)"
            #Throw 'Error - check the last console output for details'
        }
        else {
            Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo - AzAPICall: requesting new bearer token '$targetEndpoint' ($targetCluster) - sleep 2 second and try again (max retry: $maxTries)"
            $doRetry = $true
            createBearerToken -targetEndPoint 'Kusto' -TargetCluster $targetCluster -AzAPICallConfiguration $AzAPICallConfiguration
            Start-Sleep -Seconds 2
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
        Logging -preventWriteOutput $true -logMessage "$defaultErrorInfo $exitMsg - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
        if ($unhandledErrorAction -in @('Continue', 'ContinueQuiet')) {
            $response = @{
                action = 'break'
            }
            return $response
        }
        else {
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
        $AzAPICallConfiguration,

        [Parameter()]
        [string]
        $TargetCluster
    )

    if ($targetEndPoint -eq 'Storage') {
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' `"$($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)`" ($(($AzApiCallConfiguration['azAPIEndpointUrls']).StorageAuth))"
    }
    elseif ($targetEndPoint -eq 'Kusto') {
        if (-not $TargetCluster) {
            Logging -logMessage " -targetEndPoint: '$targetEndPoint'; -targetCluster undefined: '$TargetCluster'"
            throw " -targetEndPoint: '$targetEndPoint'; -targetCluster undefined: '$TargetCluster'"
        }
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' cluster '$TargetCluster'"
    }
    else {
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' `"$($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)`""
    }

    if (($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint -or $targetEndPoint -eq 'Kusto') {
        function setBearerAccessToken {
            param (
                [Parameter(Mandatory)]
                [string]
                $createdBearerToken,

                [Parameter(Mandatory)]
                [string]
                $targetEndPoint,

                [Parameter(Mandatory)]
                [object]
                $AzAPICallConfiguration,

                [Parameter()]
                [string]
                $TargetCluster
            )

            if ($targetEndPoint -eq 'Kusto') {
                $AzApiCallConfiguration['htBearerAccessToken'].$TargetCluster = $createdBearerToken
            }
            else {
                $AzApiCallConfiguration['htBearerAccessToken'].$targetEndPoint = $createdBearerToken
            }

            $dateTimeTokenCreated = (Get-Date -Format 'MM/dd/yyyy HH:mm:ss')
            $bearerDetails = getJWTDetails -token $createdBearerToken
            $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
            $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry

            if ($targetEndPoint -eq 'Storage') {
                Logging -logMessage " +Bearer token '$targetEndPoint' ($(($AzApiCallConfiguration['azAPIEndpointUrls']).StorageAuth)): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
            elseif ($targetEndPoint -eq 'Kusto') {
                Logging -logMessage " +Bearer token '$targetEndPoint' ($TargetCluster): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
            else {
                Logging -logMessage " +Bearer token '$targetEndPoint': [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
        }

        $azContext = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        try {
            if ($targetEndPoint -eq 'Storage') {
                $tokenRequestEndPoint = ($AzApiCallConfiguration['azAPIEndpointUrls']).StorageAuth
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
            }
            elseif ($targetEndPoint -eq 'Kusto') {
                $tokenRequestEndPoint = $TargetCluster
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -targetCluster $TargetCluster -AzAPICallConfiguration $AzAPICallConfiguration
            }
            else {
                $tokenRequestEndPoint = ($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
            }
        }
        catch {
            if (($AzApiCallConfiguration['htParameters']).codeRunPlatform -eq 'GitHubActions') {
                if (($AzApiCallConfiguration['htParameters']).GitHubActionsOIDC) {
                    if (($AzApiCallConfiguration['htParameters']).GitHubActionsOIDC -eq $true) {
                        if ($_ -like '*AADSTS700024*') {
                            Logging -logMessage " Running on '$(($AzApiCallConfiguration['htParameters']).codeRunPlatform)' OIDC: '$(($AzApiCallConfiguration['htParameters']).GitHubActionsOIDC)' - Getting Bearer Token from Login endpoint '$(($AzApiCallConfiguration['azAPIEndpointUrls']).Login)'"

                            $audience = 'api://AzureADTokenExchange'
                            $url = '{0}&audience={1}' -f $ENV:ACTIONS_ID_TOKEN_REQUEST_URL, $audience
                            $gitHubJWT = Invoke-RestMethod $url -Headers @{Authorization = ('bearer {0}' -f $ENV:ACTIONS_ID_TOKEN_REQUEST_TOKEN) }

                            function createBearerTokenFromLoginEndPoint {
                                param (
                                    [Parameter(Mandatory)]
                                    [string]
                                    $tokenRequestEndPoint,

                                    [Parameter(Mandatory)]
                                    $gitHubJWT,

                                    [Parameter(Mandatory)]
                                    [object]
                                    $AzAPICallConfiguration
                                )

                                $loginUri = "$(($AzApiCallConfiguration['azAPIEndpointUrls']).Login)/{0}/oauth2/v2.0/token" -f "$(($AzApiCallConfiguration['checkContext']).Tenant.Id)"
                                $body = "scope=$($tokenRequestEndPoint)/.default&client_id=$(($AzApiCallConfiguration['checkContext']).Account.Id)&grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}" -f [System.Net.WebUtility]::UrlEncode($gitHubJWT.Value)
                                $bearerToken = Invoke-RestMethod $loginUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction SilentlyContinue

                                <# Output the token
                                $payloadBearerToken = ($bearerToken.access_token -split '\.')[1]
                                if (($payloadBearerToken.Length % 4) -ne 0) {
                                    $payloadBearerToken = $payloadBearerToken.PadRight($payloadBearerToken.Length + 4 - ($payloadBearerToken.Length % 4), '=')
                                }
                                [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadBearerToken)) | ConvertFrom-Json | ConvertTo-Json
                                #>

                                return $bearerToken
                            }

                            $createdBearerToken = (createBearerTokenFromLoginEndPoint -tokenRequestEndPoint $tokenRequestEndPoint -AzAPICallConfiguration $AzAPICallConfiguration -gitHubJWT $gitHubJWT).access_token
                            setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
                        }
                        else {
                            $dumpErrorProcessingNewBearerToken = $true
                        }
                    }
                    else {
                        $dumpErrorProcessingNewBearerToken = $true
                    }
                }
                else {
                    $dumpErrorProcessingNewBearerToken = $true
                }
            }
            else {
                $dumpErrorProcessingNewBearerToken = $true
            }

            if ($dumpErrorProcessingNewBearerToken) {
                Logging -logMessage "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount -tenantId <tenantId>'" -logMessageForegroundColor 'DarkRed'
                #Logging -logMessage "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount -tenantId <tenantId>'." -logMessageForegroundColor 'DarkRed'
                Logging -logMessage "-ERROR processing new bearer token request ($(($AzApiCallConfiguration['htParameters']).codeRunPlatform)) for targetEndPoint '$targetEndPoint' ($($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)): $_" -logMessageWriteMethod 'Error'
                Throw 'Error - check the last console output for details'
            }
        }
    }
    else {
        Logging -logMessage "targetEndPoint: '$targetEndPoint' unknown" -logMessageWriteMethod 'Error'
        throw "targetEndPoint: '$targetEndPoint' unknown"
    }
}
function getARMLocations {
    [CmdletBinding()]Param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    $currentTask = 'Get ARM locations'
    Logging -logMessage "  $currentTask"
    if (($AzAPICallConfiguration['checkContext']).Subscription.Id) {
        $uri = "$(($AzAPICallConfiguration['azAPIEndpointUrls']).ARM)/subscriptions/$(($AzAPICallConfiguration['checkContext']).Subscription.Id)/locations?api-version=2020-01-01"
        $method = 'GET'
        $getARMLocations = AzAPICall -uri $uri -method $method -currentTask $currentTask -AzAPICallConfiguration $AzAPICallConfiguration

        if ($getARMLocations.Count -gt 0) {
            Logging -logMessage "   Get ARM locations succeeded (locations count: '$($getARMLocations.Count)')" -logMessageForegroundColor 'Green'
            $AzApiCallConfiguration['htParameters'].ARMLocations = $getARMLocations.name | Sort-Object
            foreach ($location in $getARMLocations) {
                $AzApiCallConfiguration['azAPIEndpointUrls']."ARM$($location.name.tolower())" = $AzApiCallConfiguration['azAPIEndpointUrls'].ARM -replace 'https://', "https://$($location.name)."
                $AzApiCallConfiguration['azAPIEndpoints'].($AzApiCallConfiguration['azAPIEndpointUrls'].ARM -replace 'https://', "$($location.name).") = "ARM$($location.name.tolower())"
            }
        }
        else {
            Logging -logMessage "   Get ARM locations failed (locations count: '$($getARMLocations.Count)')"
            Throw 'Error - check the last console output for details'
        }
    }
    else {
        Logging -logMessage "   Get ARM locations not possible (no subscription in current context). Either use parameter -SubscriptionId4AzContext (initAzAPICall -SubscriptionId4AzContext <subscriptionId>) or if you do not have any subscriptions then you won´t be able to address regional endpoints e.g. 'https://westeurope.management.azure.com/' (info: parameter `$SkipAzContextSubscriptionValidation = $SkipAzContextSubscriptionValidation)"
        $AzApiCallConfiguration['htParameters'].ARMLocations = @()
    }
}
function getAzAPICallFunctions {
    $functions = @{
        funcAZAPICall         = $function:AzAPICall.ToString()
        funcCreateBearerToken = $function:createBearerToken.ToString()
        funcGetJWTDetails     = $function:getJWTDetails.ToString()
        funcLogging           = $function:Logging.ToString()
    }
    return $functions
}
function getAzAPICallRuleSet {
    return $function:AzAPICallErrorHandler.ToString()
}
function getAzAPICallVersion { return '1.1.86' }

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
        [Parameter(Mandatory)]
        [string]
        $token
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
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,

    $decodedToken | Add-Member -Type NoteProperty -Name 'expiryDateTime' -Value $localTime

    #Time to Expiry
    $timeToExpiry = ($localTime - (Get-Date))
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
        $WriteMethod = 'Host',

        [Parameter()]
        [ValidateSet('Debug', 'Error', 'Host', 'Information', 'Output', 'Progress', 'Verbose', 'Warning')]
        $DebugWriteMethod = 'Host',

        [Parameter()]
        [string]
        $SubscriptionId4AzContext,

        [Parameter()]
        [string]
        $TenantId4AzContext,

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

    $splatHtParameters = @{
        AzAccountsVersion                   = $AzAccountsVersion
        GitHubRepository                    = $GitHubRepository
        DebugAzAPICall                      = $DebugAzAPICall
        SubscriptionId4AzContext            = $SubscriptionId4AzContext
        TenantId4AzContext                  = $TenantId4AzContext
        SkipAzContextSubscriptionValidation = $SkipAzContextSubscriptionValidation
    }
    $AzAPICallConfiguration['htParameters'] += setHtParameters @splatHtParameters
    Logging -preventWriteOutput $true -logMessage ' AzAPICall htParameters:'
    Logging -preventWriteOutput $true -logMessage $($AzAPICallConfiguration['htParameters'] | Format-Table -AutoSize | Out-String)
    Logging -preventWriteOutput $true -logMessage '  Create htParameters succeeded' -logMessageForegroundColor 'Green'

    $AzAPICallConfiguration['arrayAPICallTracking'] = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $AzAPICallConfiguration['htBearerAccessToken'] = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))

    Logging -preventWriteOutput $true -logMessage ' Get Az context'
    try {
        $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
        $AzAPICallConfiguration['htParameters'].azureCloudEnvironment = $AzAPICallConfiguration['checkContext'].environment.Name
        Logging -preventWriteOutput $true -logMessage "  Azure cloud environment: $($AzAPICallConfiguration['htParameters'].azureCloudEnvironment)"
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

    Logging -preventWriteOutput $true -logMessage "  Az context related parameters: -SubscriptionId4AzContext=='$SubscriptionId4AzContext'; -TenantId4AzContext=='$TenantId4AzContext'; -SkipAzContextSubscriptionValidation=='$($SkipAzContextSubscriptionValidation)'"

    if ($SubscriptionId4AzContext -and $SubscriptionId4AzContext -notmatch ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$') -and $SubscriptionId4AzContext -ne 'undefined') {
        Logging -preventWriteOutput $true -logMessage "   Parameter -SubscriptionId4AzContext '$SubscriptionId4AzContext' is invalid, bypass use of the parameter" -logMessageForegroundColor 'Darkred'
        $SubscriptionId4AzContext = $null
    }
    if ($TenantId4AzContext -and $TenantId4AzContext -notmatch ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$') -and $TenantId4AzContext -ne 'undefined') {
        Logging -preventWriteOutput $true -logMessage "   Parameter -TenantId4AzContext '$TenantId4AzContext' is invalid, proceed with current Tenant Id: '$($AzAPICallConfiguration['checkContext'].Tenant.Id)'" -logMessageForegroundColor 'Darkred'
        $TenantId4AzContext = $null
    }

    $newAzContextSet = $false
    if ($SubscriptionId4AzContext -and $SubscriptionId4AzContext -match ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$')) {
        if ($AzAPICallConfiguration['checkContext'].Subscription.Id -ne $SubscriptionId4AzContext) {
            try {
                if ($TenantId4AzContext -and $TenantId4AzContext -match ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$')) {
                    if ($SkipAzContextSubscriptionValidation -eq $false) {
                        testSubscription -SubscriptionId4Test $SubscriptionId4AzContext -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                    Logging -preventWriteOutput $true -logMessage "  Setting Az context to SubscriptionId: '$SubscriptionId4AzContext', TenantId: '$TenantId4AzContext'"
                    $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -TenantId $TenantId4AzContext -ErrorAction Stop
                    $newAzContextSet = $true
                    $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
                }
                else {
                    if ($SkipAzContextSubscriptionValidation -eq $false) {
                        testSubscription -SubscriptionId4Test $SubscriptionId4AzContext -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                    Logging -preventWriteOutput $true -logMessage "  Setting Az context to SubscriptionId: '$SubscriptionId4AzContext'"
                    $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
                    $newAzContextSet = $true
                    $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
                }
            }
            catch {
                Logging -preventWriteOutput $true -logMessage $_
                Throw 'Error - check the last console output for details'
            }
            if ($newAzContextSet) {
                Logging -preventWriteOutput $true -logMessage "  New Az context: Tenant:'$($AzAPICallConfiguration['checkContext'].Tenant.Id)' Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))'"
            }
            else {
                Logging -preventWriteOutput $true -logMessage "  Stay with current Az context: Tenant:'$($AzAPICallConfiguration['checkContext'].Tenant.Id)' Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))'"
            }
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Az context is already set to SubscriptionId: '$SubscriptionId4AzContext'"
            if ($SkipAzContextSubscriptionValidation -eq $false) {
                testSubscription -SubscriptionId4Test $SubscriptionId4AzContext -AzAPICallConfiguration $AzAPICallConfiguration
            }
            Logging -preventWriteOutput $true -logMessage "  Stay with current Az context: Tenant:'$($AzAPICallConfiguration['checkContext'].Tenant.Id)' Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))'"
        }
    }
    else {
        if ($TenantId4AzContext -and $TenantId4AzContext -match ('^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$')) {
            try {
                if ($AzAPICallConfiguration['checkContext'].Tenant.Id -ne $TenantId4AzContext) {
                    Logging -preventWriteOutput $true -logMessage "  Setting Az context to TenantId: '$TenantId4AzContext'"
                    $null = Set-AzContext -TenantId $TenantId4AzContext -ErrorAction Stop
                    $newAzContextSet = $true
                    $AzAPICallConfiguration['checkContext'] = Get-AzContext -ErrorAction Stop
                    if (-not [string]::IsNullOrWhiteSpace($AzAPICallConfiguration['checkContext'].Subscription.Id) -and $SkipAzContextSubscriptionValidation -eq $false) {
                        testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "  Az context is already set to TenantId: '$TenantId4AzContext'"
                    if (-not [string]::IsNullOrWhiteSpace($AzAPICallConfiguration['checkContext'].Subscription.Id) -and $SkipAzContextSubscriptionValidation -eq $false) {
                        testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                }
            }
            catch {
                Logging -preventWriteOutput $true -logMessage $_
                Throw 'Error - check the last console output for details'
            }
            if ($newAzContextSet) {
                Logging -preventWriteOutput $true -logMessage "  New Az context: Tenant:'$($AzAPICallConfiguration['checkContext'].Tenant.Id)' Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))'"
            }
            else {
                Logging -preventWriteOutput $true -logMessage "  Stay with current Az context: Tenant:'$($AzAPICallConfiguration['checkContext'].Tenant.Id)' Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))'"
            }
        }
        elseif (-not [string]::IsNullOrWhiteSpace($AzAPICallConfiguration['checkContext'].Subscription.Id) -and $SkipAzContextSubscriptionValidation -eq $false) {
            testSubscription -SubscriptionId4Test $AzAPICallConfiguration['checkContext'].Subscription.Id -AzAPICallConfiguration $AzAPICallConfiguration
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Stay with current Az context: Tenant:'$($AzAPICallConfiguration['checkContext'].Tenant.Id)' Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))'"
        }
    }

    if (-not $AzAPICallConfiguration['checkContext'].Subscription -and $SkipAzContextSubscriptionValidation -eq $false) {
        $AzAPICallConfiguration['checkContext'] | Format-List | Out-String
        Logging -preventWriteOutput $true -logMessage '  Check Az context failed: Az context is not set to any Subscription'
        Logging -preventWriteOutput $true -logMessage '  Set Az context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script'
        Logging -preventWriteOutput $true -logMessage '  OR'
        Logging -preventWriteOutput $true -logMessage '  Use parameter -SubscriptionId4AzContext - e.g. initAzAPICall -SubscriptionId4AzContext <subscriptionId>'
        Logging -preventWriteOutput $true -logMessage '  OR'
        Logging -preventWriteOutput $true -logMessage '  Use parameter -SkipAzContextSubscriptionValidation - e.g. initAzAPICall -SkipAzContextSubscriptionValidation $true'
        Throw 'Error - check the last console output for details'
    }
    else {
        Logging -preventWriteOutput $true -logMessage "   Az context Tenant: '$($AzAPICallConfiguration['checkContext'].Tenant.Id)'" -logMessageForegroundColor 'Yellow'
        if ($SkipAzContextSubscriptionValidation -eq $false) {
            Logging -preventWriteOutput $true -logMessage "   Az context Subscription: '$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id))' (state: $($AzAPICallConfiguration['checkContext'].Subscription.State))" -logMessageForegroundColor 'Yellow'
        }
        else {
            if ($AzAPICallConfiguration['checkContext'].Subscription) {
                Logging -preventWriteOutput $true -logMessage "   Az context Subscription check skipped (`$SkipAzContextSubscriptionValidation==$($SkipAzContextSubscriptionValidation)); Subscription:'$($AzAPICallConfiguration['checkContext'].Subscription.Name) ($($AzAPICallConfiguration['checkContext'].Subscription.Id)); state: $($AzAPICallConfiguration['checkContext'].Subscription.State)'" -logMessageForegroundColor 'Yellow'
            }
            else {
                Logging -preventWriteOutput $true -logMessage "   Az context Subscription check skipped (`$SkipAzContextSubscriptionValidation==$($SkipAzContextSubscriptionValidation)) - no Subscription in context" -logMessageForegroundColor 'Yellow'
            }
        }
        Logging -preventWriteOutput $true -logMessage '  Az context check succeeded' -logMessageForegroundColor 'Green'
    }

    $userInformation = testUserType -AzApiCallConfiguration $AzAPICallConfiguration
    if ($userInformation -ne 'n/a') {
        $AzApiCallConfiguration['htParameters'].userType = $userInformation.userType
        $AzApiCallConfiguration['htParameters'].userObjectId = $userInformation.id
    }
    else {
        $AzApiCallConfiguration['htParameters'].userType = $userInformation
    }

    getARMLocations -AzApiCallConfiguration $AzAPICallConfiguration

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
        $logMessageWriteMethod = $AzAPICallConfiguration['htParameters'].writeMethod,

        [Parameter(Mandatory = $false)]
        [bool]
        $preventWriteOutput
    )

    if (-not $logMessageForegroundColor) {
        $logMessageForegroundColor = 'Cyan'
    }

    if (-not $logMessageWriteMethod -or ($preventWriteOutput -and $logMessageWriteMethod -eq 'Output')) {
        $logMessageWriteMethod = 'Warning'
    }

    switch ($logMessageWriteMethod) {
        'Debug' { Write-Debug $logMessage }
        'Error' { Write-Error $logMessage }
        'Host' { Write-Host $logMessage -ForegroundColor $logMessageForegroundColor }
        'Information' { Write-Information $logMessage }
        'Output' { Write-Output $logMessage }
        'Progress' { Write-Progress $logMessage }
        'Verbose' { Write-Verbose $logMessage -Verbose }
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
                Logging -preventWriteOutput $true -logMessage "  Please check current context (Subscription criteria: quotaId notLike 'AAD*'; state = enabled); Install latest Az.Accounts version"
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
    $AzAPICallConfiguration['azAPIEndpointUrls'].Login = (testAvailable -Endpoint 'Login' -EnvironmentKey 'ActiveDirectoryAuthority' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ActiveDirectoryAuthority)
    $AzAPICallConfiguration['azAPIEndpointUrls'].Storage = [System.Collections.ArrayList]@()
    $null = $AzAPICallConfiguration['azAPIEndpointUrls'].Storage.Add((testAvailable -Endpoint 'Storage' -EnvironmentKey 'StorageEndpointSuffix' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.StorageEndpointSuffix))
    $null = $AzAPICallConfiguration['azAPIEndpointUrls'].Storage.Add('storage.azure.net')
    Logging -preventWriteOutput $true -logMessage "  Add to endpoint: 'Storage'; endpoint url: 'storage.azure.net'"
    $AzAPICallConfiguration['azAPIEndpointUrls'].StorageAuth = 'https://storage.azure.com'
    if ($AzApiCallConfiguration['checkContext'].Environment.Name -eq 'AzureChinaCloud') {
        $AzAPICallConfiguration['azAPIEndpointUrls'].IssuerUri = 'https://sts.chinacloudapi.cn'
    }
    else {
        $AzAPICallConfiguration['azAPIEndpointUrls'].IssuerUri = 'https://sts.windows.net'
    }
    $AzAPICallConfiguration['azAPIEndpointUrls'].Kusto = 'kusto.windows.net'
    Logging -preventWriteOutput $true -logMessage "  Set endpoint: 'Kusto'; endpoint url: 'kusto.windows.net'"

    #AzureEnvironmentRelatedTargetEndpoints
    $AzAPICallConfiguration['azAPIEndpoints'] = @{ }
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM -split '/')[2]) = 'ARM'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].KeyVault -split '/')[2]) = 'KeyVault'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].LogAnalytics -split '/')[2]) = 'LogAnalytics'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph -split '/')[2]) = 'MicrosoftGraph'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].Login -split '/')[2]) = 'Login'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].Storage)) = 'Storage'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].StorageAuth)) = 'StorageAuth'

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
        $DebugAzAPICall,

        [Parameter(Mandatory = $false)]
        [string]
        $SubscriptionId4AzContext,

        [Parameter(Mandatory = $false)]
        [string]
        $TenantId4AzContext,

        [Parameter(Mandatory)]
        [bool]
        $SkipAzContextSubscriptionValidation
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

    # if ($DebugAzAPICall) {
    #     Logging -preventWriteOutput $true -logMessage '  <_______________________________________' -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage '  AzAPICall preparing ht for return' -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     debugAzAPICall                      = $DebugAzAPICall" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     gitHubRepository                    = $GitHubRepository" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     psVersion                           = $($PSVersionTable.PSVersion)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     azAccountsVersion                   = $AzAccountsVersion" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     azAPICallModuleVersion              = $AzAPICallVersion" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     codeRunPlatform                     = $codeRunPlatform" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     onAzureDevOpsOrGitHubActions        = $([bool]$onAzureDevOpsOrGitHubActions)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     onAzureDevOps                       = $([bool]$onAzureDevOps)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     onGitHubActions                     = $([bool]$onGitHubActions)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     subscriptionId4AzContext            = $($SubscriptionId4AzContext)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     tenantId4AzContext                  = $($TenantId4AzContext)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     skipAzContextSubscriptionValidation = $([bool]$SkipAzContextSubscriptionValidation)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage '  _______________________________________>' -logMessageForegroundColor 'Cyan'
    # }

    #Region Test-HashtableParameter
    $htParameters = [ordered]@{
        debugAzAPICall                      = $DebugAzAPICall
        gitHubRepository                    = $GitHubRepository
        psVersion                           = $PSVersionTable.PSVersion
        azAccountsVersion                   = $AzAccountsVersion
        azAPICallModuleVersion              = $AzAPICallVersion
        codeRunPlatform                     = $codeRunPlatform
        onAzureDevOpsOrGitHubActions        = [bool]$onAzureDevOpsOrGitHubActions
        onAzureDevOps                       = [bool]$onAzureDevOps
        onGitHubActions                     = [bool]$onGitHubActions
        subscriptionId4AzContext            = $subscriptionId4AzContext
        tenantId4AzContext                  = $tenantId4AzContext
        skipAzContextSubscriptionValidation = [bool]$skipAzContextSubscriptionValidation
    }

    return $htParameters
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
        $azModuleVersion = (Get-InstalledModule -Name "$azModule" -ErrorAction Ignore).Version
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

    $currentTask = "Check Subscription: '$SubscriptionId4Test' (criteria: quotaId notLike 'AAD*'; state==enabled)"
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
        Logging -logMessage "   Subscription check - SubscriptionId: '$SubscriptionId4Test' - please define another Subscription (Subscription criteria: quotaId notLike 'AAD*'; state==enabled)"
        Logging -logMessage "   Use parameter: -SubscriptionId4AzContext (e.g. -SubscriptionId4AzContext '66f7c01a-ca6c-4ec2-a80b-34cc2dbda7d7')"
        Throw 'Error - check the last console output for details'
    }
    else {
        $AzApiCallConfiguration['htParameters'].subscriptionQuotaId = $testSubscription.subscriptionPolicies.quotaId
        Logging -logMessage "   Subscription check succeeded - quotaId: '$($testSubscription.subscriptionPolicies.quotaId)'; state: $($testSubscription.state)" -logMessageForegroundColor 'Green'
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
        $uri = $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph + '/v1.0/me?$select=userType,id'
        $method = 'GET'
        $checkUserType = AzAPICall -AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -method $method -listenOn 'Content' -currentTask $currentTask
        $userType = $checkUserType

        Logging -preventWriteOutput $true -logMessage "  AAD UserType: $($userType.userType); AAD identityId: $($userType.id)" -logMessageForegroundColor 'Yellow'
        Logging -preventWriteOutput $true -logMessage '  AAD UserType check succeeded' -logMessageForegroundColor 'Green'
    }
    return $userType
}
