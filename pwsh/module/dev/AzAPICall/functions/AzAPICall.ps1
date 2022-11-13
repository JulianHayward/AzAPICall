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
      Used to either "Stop" (Default) or "Continue" when encountering an Unhandled Error
        "Stop" Throws the Error which terminates processing
        "Continue" outputs the error and continues processing

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
        [ValidateSet('StatusCode', 'Headers', 'Content', 'ContentProperties')]
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
        $skipOnErrorCode,

        [Parameter()]
        [string]
        [ValidateSet('Stop', 'Continue')]
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
                Logging -preventWriteOutput $true -logMessage "  DEBUGTASK: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
            }
            if (-not $doDebugAzAPICall -and $tryCounter -gt 3) {
                Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $currentTask -> $debugMessage" -logMessageWriteMethod $AzAPICallConfiguration['htParameters'].debugWriteMethod
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
            Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $currentTask -> check uri: '$uri' - EXIT"
            Throw "Error - check uri: '$uri'"
        }

        $uriSplitted = $uri.split('/')
        if ($uriSplitted[2] -like "*$($AzAPICallConfiguration['azAPIEndpointUrls'].Storage)") {
            $targetEndpoint = 'Storage'
        }
        else {
            if (-not ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])) {
                Logging -preventWriteOutput $true -logMessage "Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'" -logMessageForegroundColor 'Yellow'
                Logging -preventWriteOutput $true -logMessage "!Please report at $($AzApiCallConfiguration['htParameters'].gitHubRepository)" -logMessageForegroundColor 'Yellow'
                Throw "Error - Unknown targetEndpoint: '$($uriSplitted[2])'; `$uri: '$uri'"
            }
            $targetEndpoint = ($AzApiCallConfiguration['azAPIEndpoints']).($uriSplitted[2])
        }

        if (-not $AzAPICallConfiguration['htBearerAccessToken'].($targetEndpoint)) {
            createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
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
                        Logging -preventWriteOutput $true -logMessage " $currentTask - try #$tryCounter; returned: (StatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))) '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint -AzAPICallConfiguration $AzAPICallConfiguration
                    }
                    elseif ($targetEndpoint -eq 'Storage' -and $catchResult -like '*AuthorizationFailure*' -or $catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*' -or $catchResult -like '*name or service not known*') {
                        if ($catchResult -like '*AuthorizationPermissionDenied*' -or $catchResult -like '*AuthorizationPermissionMismatch*') {
                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionDenied'"
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationPermissionMismatch' - this error might occur due to only recently applied RBAC permissions"
                            }

                            if ($saResourceGroupName) {
                                Logging -preventWriteOutput $true -logMessage "  $currentTask - Contribution request: please verify if the Storage Account's ResourceGroup '$($saResourceGroupName)' is a managed Resource Group, if yes please check if the Resource Group Name is listed here: https://github.com/JulianHayward/AzSchnitzels/blob/main/info/managedResourceGroups.txt"
                            }

                            if ($catchResult -like '*AuthorizationPermissionDenied*') {
                                return 'AuthorizationPermissionDenied'
                            }
                            if ($catchResult -like '*AuthorizationPermissionMismatch*') {
                                return 'AuthorizationPermissionMismatch'
                            }
                        }

                        if ($catchResult -like '*AuthorizationFailure*') {
                            Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $currentTask -> $catchResult -> returning string 'AuthorizationFailure'"
                            return 'AuthorizationFailure'
                        }
                        if ($catchResult -like '*name or service not known*') {
                            Logging -preventWriteOutput $true -logMessage "  Forced DEBUG: $currentTask -> $catchResult -> returning string 'ResourceUnavailable'"
                            return 'ResourceUnavailable'
                        }
                    }
                    else {
                        Logging -preventWriteOutput $true -logMessage "$currentTask try #$($tryCounterUnexpectedError) $($rawException)"
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
            })

        $message = "attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'"

        if ($body) {
            $message += " body: '$($body | Out-String)'"
        }

        debugAzAPICall -debugMessage $message
        if ($unexpectedError -eq $false -and $connectionRelatedError -eq $false) {
            debugAzAPICall -debugMessage 'unexpectedError: false'
            if ($actualStatusCode -notin 200..204) {
                if ($listenOn -eq 'StatusCode') {
                    return [int32]$actualStatusCode
                }
                else {
                    debugAzAPICall -debugMessage "apiStatusCode: '$($actualStatusCode)' ($($actualStatusCodePhrase))"
                    if ($actualStatusCode -eq $skipOnErrorCode) {
                        debugAzAPICall -debugMessage "skipOnErrorCode: '$($skipOnErrorCode)' == apiStatusCode: '$($actualStatusCode)' -> skip"
                        break
                    }
                    $function:AzAPICallErrorHandler = $AzAPICallConfiguration['AzAPICallRuleSet'].AzAPICallErrorHandler
                    $AzAPICallErrorHandlerResponse = AzAPICallErrorHandler -AzAPICallConfiguration $AzAPICallConfiguration -uri $uri -catchResult $catchResult -currentTask $currentTask -tryCounter $tryCounter -retryAuthorizationFailed $retryAuthorizationFailed
                    # switch ($AzAPICallErrorHandlerResponse.action) {
                    #     'break' { break }
                    #     'return' { return $AzAPICallErrorHandlerResponse.returnVar }
                    #     'returnCollection' { return $apiCallResultsCollection }
                    # }
                    if ($AzAPICallErrorHandlerResponse.action -eq 'break' -or $AzAPICallErrorHandlerResponse.action -eq 'return' -or $AzAPICallErrorHandlerResponse.action -eq 'returnCollection') {
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
                        Logging -preventWriteOutput $true -logMessage "`$AzAPICallErrorHandlerResponse.action unexpected (`$AzAPICallErrorHandlerResponse.action = '$($AzAPICallErrorHandlerResponse.action)') - breaking" -logMessageForegroundColor 'darkred'
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
                            $storageResponseXML = [xml]([string]$azAPIRequestConvertedFromJson -replace $azAPIRequestConvertedFromJson.Substring(0, 3))
                        }
                        catch {
                            debugAzAPICall -debugMessage "non JSON object; return as is ($((($azAPIRequestConvertedFromJson).gettype()).Name))"
                        }
                    }
                }
                else {
                    $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                }

                if ($listenOn -eq 'Headers') {
                    debugAzAPICall -debugMessage "listenOn=Headers ($((($azAPIRequest.Headers)).count))"
                    $null = $apiCallResultsCollection.Add($azAPIRequest.Headers)
                }

                if ($listenOn -eq 'Content') {
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
                    elseif ($azAPIRequestConvertedFromJson.'$skipToken' -and $uri -like "$($AzApiCallConfiguration['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/*") {
                        $isMore = $true
                        if ($body) {
                            $bodyHt = $body | ConvertFrom-Json -AsHashtable
                            if ($bodyHt.options) {
                                if ($bodyHt.options.'$skiptoken') {
                                    if ($bodyHt.options.'$skiptoken' -eq $azAPIRequestConvertedFromJson.'$skipToken') {
                                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                                            Logging -preventWriteOutput $true -logMessage " $currentTask restartDueToDuplicateSkipTokenCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
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
                    Logging -preventWriteOutput $true -logMessage "$currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (trying $maxtryCounterConnectionRelatedError times); sleep $sleepSecConnectionRelatedError seconds"
                    #Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecConnectionRelatedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$currentTask try #$($tryCounterConnectionRelatedError) 'connectionRelatedError' occurred '$connectionRelatedErrorPhrase' (tried $($tryCounterConnectionRelatedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
                    if ($unhandledErrorAction -eq 'Continue') {
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
                    Logging -preventWriteOutput $true -logMessage "$currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (trying $maxtryUnexpectedError times); sleep $sleepSecUnexpectedError seconds"
                    Logging -preventWriteOutput $true -logMessage $catchResult
                    Start-Sleep -Seconds $sleepSecUnexpectedError
                }
                else {
                    Logging -preventWriteOutput $true -logMessage "$currentTask try #$($tryCounterUnexpectedError) 'unexpectedError' occurred (tried $($tryCounterUnexpectedError - 1) times) - unhandledErrorAction: $unhandledErrorAction" -logMessageForegroundColor 'DarkRed'
                    if ($unhandledErrorAction -eq 'Continue') {
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