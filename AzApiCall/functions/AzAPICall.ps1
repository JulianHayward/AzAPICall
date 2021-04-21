function AzAPICall
{
    <#
    .SYNOPSIS
        Send request against API call and handle auth and errors
    
    .DESCRIPTION
        Send request against API call and handle auth and errors
    
    .PARAMETER uri
        url from API Endpoint

    .PARAMETER Method
        Method for api request
    
    .PARAMETER currentTask
        For debuging help
    
    .PARAMETER listenON
        some Endpoint return different Outputs
    
    .PARAMETER body
        Add a body to the API Call
        
    .EXAMPLE
        PS C:\> AzAPICall -uri 'https://graph.microsoft.com/beta/directoryRoles' -Method Get -currentTask "Collecting AADDirectoryRoles"

        Get all AzureAD Directory Roles
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)][string]$uri,

        [Parameter(Mandatory = $true)][ValidateSet("GET","PUT","DELETE","POST","PATCH","HEAD")][string]$method,

        [Parameter(Mandatory = $false)][string]$currentTask = "DefaultTask",

        [Parameter(Mandatory = $false)][ValidateSet("Content","ContentProperties","CSV","StatusCode")][string]$listenOn,

        [Parameter(Mandatory = $false)]$body,

        [Parameter(Mandatory = $false)]$consistencylevel
    )

    $tryCounter = 0
    $tryCounterUnexpectedError = 0
    $retryAuthorizationFailed = 5
    $retryAuthorizationFailedCounter = 0
    $apiCallResultsCollection = [System.Collections.ArrayList]@()
    $initialUri = $uri
    $restartDueToDuplicateNextlinkCounter = 0
    if ($htParameters.DebugAzAPICall -eq $true) {
        if ($caller -like "CustomDataCollection*") {
            $debugForeGroundColors = @('DarkBlue', 'DarkGreen', 'DarkCyan', 'Cyan', 'DarkMagenta', 'DarkYellow', 'Blue', 'Magenta', 'Yellow', 'Green')
            $debugForeGroundColorsCount = $debugForeGroundColors.Count
            $randomNumber = Get-Random -Minimum 0 -Maximum ($debugForeGroundColorsCount - 1)
            $debugForeGroundColor = $debugForeGroundColors[$randomNumber]
        }
        else {
            $debugForeGroundColor = "Cyan"
        }
    }
    Set-AzApiCallEnvironment
    do {
        if ($script:arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "AzManagementAPI"
            #check if valid Token exist
            checkToken -targetEndpoint $targetEndpoint
            $bearerToUse = $script:htBearerAccessToken.$targetEndpoint.AccessToken
        }
        elseif ($uri -like "*dev.azure*") {
            $targetEndpoint = "AzDevOps"
            #check if valid Token exist
            checkToken -targetEndpoint $targetEndpoint
            $bearerToUse = $script:htBearerAccessToken.$targetEndpoint.AccessToken
        }
        elseif ($uri -like "*api.powerbi*") {
            $targetEndpoint = "MsPowerBi"
            #check if valid Token exist
            checkToken -targetEndpoint $targetEndpoint
            $bearerToUse = $script:htBearerAccessToken.$targetEndpoint.AccessToken
        }
        elseif ($uri -like "*graph.microsoft*"){
            $targetEndpoint = "MsGraphAPI"
            #check if valid Token exist
            checkToken -targetEndpoint $targetEndpoint
            $bearerToUse = $script:htBearerAccessToken.$targetEndpoint.AccessToken
        }
        else {
            Throw "No valid Endpoint! Check URL or provide an issue to https://github.com/JulianHayward/AzAPICall/issues"
        }

        #API Call Tracking
        $tstmp = (Get-Date -format "yyyyMMddHHmmssms")
        $null = $script:arrayAPICallTracking.Add([PSCustomObject]@{
                CurrentTask                          = $currentTask
                TargetEndpoint                       = $targetEndpoint
                Uri                                  = $uri
                Method                               = $method
                TryCounter                           = $tryCounter
                TryCounterUnexpectedError            = $tryCounterUnexpectedError
                RetryAuthorizationFailedCounter      = $retryAuthorizationFailedCounter
                RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                TimeStamp                            = $tstmp
            })
        
        if ($caller -eq "CustomDataCollection") {
            $null = $script:arrayAPICallTrackingCustomDataCollection.Add([PSCustomObject]@{
                    CurrentTask                          = $currentTask
                    TargetEndpoint                       = $targetEndpoint
                    Uri                                  = $uri
                    Method                               = $method
                    TryCounter                           = $tryCounter
                    TryCounterUnexpectedError            = $tryCounterUnexpectedError
                    RetryAuthorizationFailedCounter      = $retryAuthorizationFailedCounter
                    RestartDueToDuplicateNextlinkCounter = $restartDueToDuplicateNextlinkCounter
                    TimeStamp                            = $tstmp
                })
        }

        $Header = @{
            "Content-Type" = "application/json";
            "Authorization" = "Bearer $bearerToUse"
        }
        if ($consistencylevel) { 
            $Header = @{
                "Content-Type" = "application/json";
                "Authorization" = "Bearer $bearerToUse";
                "consistencylevel" = "$consistencylevel"
            }
        }

        $unexpectedError = $false
        $tryCounter++
        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "  DEBUGTASK: attempt#$($tryCounter) processing: $($currenttask)" -ForegroundColor $debugForeGroundColor }
        try {
            if ($body) {
                #write-host "has BODY"
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers $Header -UseBasicParsing
            }
            else {
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header -UseBasicParsing
            }
        }
        catch {
            try {
                if ($Method -like "Head" -and $targetEndpoint -eq "AzManagementAPI") { 
                    $catchResult = $_.Exception.Response
                }
                else { 
                    $catchResultPlain = $_.ErrorDetails.Message
                    $catchResult = ($catchResultPlain | ConvertFrom-Json -ErrorAction SilentlyContinue)
                }
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }

        if ($unexpectedError -eq $false) {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: false" -ForegroundColor $debugForeGroundColor }
            if ($azAPIRequest.StatusCode -eq 203 -and $targetEndPoint -eq "AZDevOps") {
                Write-Host "Debug: get devops token or use Private Access Token -> Unauthorize: HTTP Code 203"
                createBearerToken -targetEndPoint $targetEndpoint
            }
            if ($azAPIRequest.StatusCode -notin 200..204) {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" -ForegroundColor $debugForeGroundColor }
                if ($catchResult.error.code -like "*GatewayTimeout*" -or
                    $catchResult.error.code -like "*BadGatewayConnection*" -or
                    $catchResult.error.code -like "*InvalidGatewayHost*" -or
                    $catchResult.error.code -like "*ServerTimeout*" -or
                    $catchResult.error.code -like "*ServiceUnavailable*" -or
                    $catchResult.code -like "*ServiceUnavailable*" -or
                    $catchResult.error.code -like "*MultipleErrorsOccurred*" -or
                    $catchResult.code -like "*InternalServerError*" -or
                    $catchResult.error.code -like "*InternalServerError*" -or
                    $catchResult.error.code -like "*RequestTimeout*" -or
                    $catchResult.error.code -like "*AuthorizationFailed*" -or
                    $catchResult.error.code -like "*ExpiredAuthenticationToken*" -or
                    $catchResult.error.code -like "*Authentication_ExpiredToken*" -or
                    $catchResult.error.code -like "*ResponseTooLarge*" -or
                    $catchResult.error.code -like "*InvalidAuthenticationToken*" -or
                    $catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*" -or
                    $catchResult.error.code -like "*UnknownError*" -or
                    $catchResult.error.code -eq "500" -or
                    $catchResult.error.code -like "*throttled*") {
                    if ($catchResult.error.code -like "*ResponseTooLarge*") {
                        Write-Host "###### LIMIT #################################"
                        Write-Host "Hitting LIMIT getting Policy Compliance States!"
                        Write-Host "ErrorCode: $($catchResult.error.code)"
                        Write-Host "ErrorMessage: $($catchResult.error.message)"
                        Write-Host "There is nothing we can do about this right now. Please run AzGovViz with the following parameter: '-NoPolicyComplianceStates'." -ForegroundColor Yellow
                        Write-Host "Impact using parameter '-NoPolicyComplianceStates': only policy compliance states will not be available in the various AzGovViz outputs - all other output remains." -ForegroundColor Yellow
                        break # Break Script
                    }
                    if ($catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems weÂ´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }
                    if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.code -like "*InternalServerError*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*UnknownError*" -or $catchResult.error.code -eq "500") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }
                    if ($catchResult.error.code -like "*AuthorizationFailed*") {
                        if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - investigate that error!/exit"
                            Throw "Error - check the last console output for details"
                        }
                        else {
                            if ($retryAuthorizationFailedCounter -gt 2) {
                                Start-Sleep -Seconds 5
                            }
                            if ($retryAuthorizationFailedCounter -gt 3) {
                                Start-Sleep -Seconds 10
                            }
                            Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - not reasonable, retry #$retryAuthorizationFailedCounter of $retryAuthorizationFailed"
                            $retryAuthorizationFailedCounter ++
                        }
                    }
                    if ($catchResult.error.code -like "*ExpiredAuthenticationToken*" -or $catchResult.error.code -like "*Authentication_ExpiredToken*" -or $catchResult.error.code -like "*InvalidAuthenticationToken*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        createBearerToken -targetEndPoint $targetEndpoint
                    }
                    if ($catchResult.error.code -like "*throttled*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again"
                        Write-Output "Waiting for Azure API Throttling Limits"
                        Start-Sleep -Seconds 11 #MOST APIÂ´s had counters Around 10 Secounds for next API Call without Throttling.
                    }
                }
                elseif ($catchResult.StatusCode.value__ -like "404") {
                    Throw "Information - Ressource didnt exist"
                }
                else {
                    if (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and -not $catchResult -and $tryCounter -lt 6){
                        $sleepSec = @(3, 7, 12, 20, 30, 45)[$tryCounter]
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) try again in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec

                    }
                    else{
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) investigate that error!/exit"
                        Throw "Error - check the last console output for details"
                    }

                }
            }
            else {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" -ForegroundColor $debugForeGroundColor }
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq "StatusCode") {
                    $apiCallResultsCollection.Add("Azure Resource exist!") | Out-Null
                }
                if ($listenOn -eq "CSV") {
                    $azAPIRequestConvertedFromCSV = ($azAPIRequest.Content | ConvertFrom-csv)
                    $apiCallResultsCollection.Add($azAPIRequestConvertedFromCSV.Content)
                }
                if ($listenOn -eq "Content") {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson) | Measure-Object).count))" -ForegroundColor $debugForeGroundColor }
                    $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                }
                elseif ($listenOn -eq "ContentProperties") {
                    if (($azAPIRequestConvertedFromJson.properties.rows | Measure-Object).Count -gt 0) {
                        foreach ($consumptionline in $azAPIRequestConvertedFromJson.properties.rows) {
                            $null = $apiCallResultsCollection.Add([PSCustomObject]@{
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[0])" = $consumptionline[0]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[1])" = $consumptionline[1]
                                    SubscriptionMgPath                                             = $htSubscriptionsMgPath.($consumptionline[1]).ParentNameChain
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[2])" = $consumptionline[2]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[3])" = $consumptionline[3]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[4])" = $consumptionline[4]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[5])" = $consumptionline[5]
                                    "$($azAPIRequestConvertedFromJson.properties.columns.name[6])" = $consumptionline[6]
                                })
                        }
                    }
                }
                else {
                    if (($azAPIRequestConvertedFromJson).value) {
                        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value | Measure-Object).count))" -ForegroundColor $debugForeGroundColor }
                        $null = $apiCallResultsCollection.AddRange($azAPIRequestConvertedFromJson.value)
                    }
                    else {
                        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value not exists; return empty array" -ForegroundColor $debugForeGroundColor }
                    }
                }

                $isMore = $false
                if ($azAPIRequestConvertedFromJson.nextLink) {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson.nextLink) {
                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                            Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            Throw "Error - check the last console output for details"
                        }
                        else {
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.nextLink)"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = [System.Collections.ArrayList]@()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        $uri = $azAPIRequestConvertedFromJson.nextLink
                    }
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                }
                elseIf ($azAPIRequestConvertedFromJson."@oData.nextLink") {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson."@odata.nextLink") {
                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                            Write-Host " $currentTask restartDueToDuplicate@odataNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            Throw "Error - check the last console output for details"
                        }
                        else {
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to @odata.nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: @odata.nextLinkUri: $($azAPIRequestConvertedFromJson."@odata.nextLink")"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = [System.Collections.ArrayList]@()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        $uri = $azAPIRequestConvertedFromJson."@odata.nextLink"
                    }
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: @oData.nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                }
                elseif ($azAPIRequestConvertedFromJson.properties.nextLink) {
                    $isMore = $true
                    if ($uri -eq $azAPIRequestConvertedFromJson.properties.nextLink) {
                        if ($restartDueToDuplicateNextlinkCounter -gt 3) {
                            Write-Host " $currentTask restartDueToDuplicateNextlinkCounter: #$($restartDueToDuplicateNextlinkCounter) - Please report this error/exit"
                            Throw "Error - check the last console output for details"
                        }
                        else {
                            $restartDueToDuplicateNextlinkCounter++
                            Write-Host "nextLinkLog: uri is equal to nextLinkUri"
                            Write-Host "nextLinkLog: uri: $uri"
                            Write-Host "nextLinkLog: nextLinkUri: $($azAPIRequestConvertedFromJson.properties.nextLink)"
                            Write-Host "nextLinkLog: re-starting (#$($restartDueToDuplicateNextlinkCounter)) '$currentTask'"
                            $apiCallResultsCollection = [System.Collections.ArrayList]@()
                            $uri = $initialUri
                            Start-Sleep -Seconds 1
                            createBearerToken -targetEndPoint $targetEndpoint
                            Start-Sleep -Seconds 1
                        }
                    }
                    else {
                        $uri = $azAPIRequestConvertedFromJson.properties.nextLink
                    }
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                }
                else {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: NextLink: none" -ForegroundColor $debugForeGroundColor }
                }
            }
        }
        else {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: notFalse" -ForegroundColor $debugForeGroundColor }
            if ($tryCounterUnexpectedError -lt 13) {
                $sleepSec = @(1, 2, 3, 5, 7, 10, 13, 17, 20, 30, 40, 50, 60)[$tryCounterUnexpectedError]
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (trying 10 times); sleep $sleepSec seconds"
                Write-Host $catchResult
                Start-Sleep -Seconds $sleepSec
            }
            else {
                Write-Host " $currentTask #$tryCounterUnexpectedError 'Unexpected Error' occurred (tried 5 times)/exit"
                Throw "Error - check the last console output for details"
            }
        }
    }
    until(($azAPIRequest.StatusCode -in 200..204 -and -not $isMore ) -or ($Method -eq "HEAD" -and $azAPIRequest.StatusCode -eq 404))
    return $apiCallResultsCollection
}
