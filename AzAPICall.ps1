[CmdletBinding()]
Param
(
    [switch]$DebugAzAPICall,
    [string]$SubscriptionId4AzContext = "undefined"
)

$ErrorActionPreference = "Stop"

#region htParameters (all switch params used in foreach-object -parallel)
$htParameters = @{ }
if ($DebugAzAPICall) {
    $htParameters.DebugAzAPICall = $true
}
else {
    $htParameters.DebugAzAPICall = $false
}
#endregion htParameters

#region PowerShellEditionAnVersionCheck
Write-Host "Checking powershell edition and version"
$requiredPSVersion = "7.0.3"
$splitRequiredPSVersion = $requiredPSVersion.split('.')
$splitRequiredPSVersionMajor = $splitRequiredPSVersion[0]
$splitRequiredPSVersionMinor = $splitRequiredPSVersion[1]
$splitRequiredPSVersionPatch = $splitRequiredPSVersion[2]

$thisPSVersion = ($PSVersionTable.PSVersion)
$thisPSVersionMajor = ($thisPSVersion).Major
$thisPSVersionMinor = ($thisPSVersion).Minor
$thisPSVersionPatch = ($thisPSVersion).Patch

$psVersionCheckResult = "letsCheck"

if ($PSVersionTable.PSEdition -eq "Core" -and $thisPSVersionMajor -eq $splitRequiredPSVersionMajor) {
    if ($thisPSVersionMinor -gt $splitRequiredPSVersionMinor) {
        $psVersionCheckResult = "passed"
        $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$thisPSVersionMinor] gt $($splitRequiredPSVersionMinor))"
    }
    else {
        if ($thisPSVersionPatch -ge $splitRequiredPSVersionPatch) {
            $psVersionCheckResult = "passed"
            $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$splitRequiredPSVersionMinor]; Patch[$thisPSVersionPatch] gt $($splitRequiredPSVersionPatch))"
        }
        else {
            $psVersionCheckResult = "failed"
            $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$splitRequiredPSVersionMinor]; Patch[$thisPSVersionPatch] lt $($splitRequiredPSVersionPatch))"
        }
    }
}
else {
    $psVersionCheckResult = "failed"
    $psVersionCheck = "(Major[$splitRequiredPSVersionMajor] ne $($splitRequiredPSVersionMajor))"
}

if ($psVersionCheckResult -eq "passed") {
    Write-Host " PS check $psVersionCheckResult : $($psVersionCheck); (minimum supported version '$requiredPSVersion')"
    Write-Host " PS Edition: $($PSVersionTable.PSEdition)"
    Write-Host " PS Version: $($PSVersionTable.PSVersion)"
}
else {
    Write-Host " PS check $psVersionCheckResult : $($psVersionCheck)"
    Write-Host " PS Edition: $($PSVersionTable.PSEdition)"
    Write-Host " PS Version: $($PSVersionTable.PSVersion)"
    Write-Host " This script version only supports Powershell 'Core' version '$($requiredPSVersion)' or higher"
    Throw "Error - check the last console output for details"
}
#endregion PowerShellEditionAnVersionCheck

if ($htParameters.DebugAzAPICall -eq $false) {
    write-host "AzAPICall debug disabled" -ForegroundColor Cyan
}
else {
    write-host "AzAPICall debug enabled" -ForegroundColor Cyan
}

#shutuppoluters
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"

#JWTDetails https://www.powershellgallery.com/packages/JWTDetails/1.0.2
#region jwtdetails
function getJWTDetails {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$token
    )

    if (!$token -contains (".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

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
    Write-Verbose "JWT Token:"
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
    Write-Verbose "JWT Signature:"
    Write-Verbose $sig
    $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig

    #Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,
    
    $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
    
    #Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry

    return $decodedToken
}
$funcGetJWTDetails = $function:getJWTDetails.ToString()
#endregion jwtdetails

#Bearer Token
#region createbearertoken
function createBearerToken($targetEndPoint) {
    #$checkContext = Get-AzContext -ErrorAction Stop
    Write-Host "+Processing new bearer token request ($targetEndPoint)"
    if ($targetEndPoint -eq "ManagementAPI") {
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
        $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = ($profileClient.AcquireAccessToken($checkContext.Subscription.TenantId))
        }
        catch {
            $catchResult = $_
        }
    }
    if ($targetEndPoint -eq "MSGraphAPI") {
        $contextForMSGraphToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForMSGraphToken.Account, $contextForMSGraphToken.Environment, $contextForMSGraphToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MSGraphUrl)")
        }
        catch {
            $catchResult = $_
        }
    }
    if ($catchResult -ne "letscheck") {
        Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
        Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount' to set up your Azure credentials."
        Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount'."
        Throw "Error - check the last console output for details"
    }
    $dateTimeTokenCreated = (get-date -format "MM/dd/yyyy HH:mm:ss")
    if ($targetEndPoint -eq "ManagementAPI") {
        $script:htBearerAccessToken.AccessTokenManagement = $newBearerAccessTokenRequest.AccessToken
    }
    if ($targetEndPoint -eq "MSGraphAPI") {
        $script:htBearerAccessToken.AccessTokenMSGraph = $newBearerAccessTokenRequest.AccessToken
    }
    $bearerDetails = GetJWTDetails -token $newBearerAccessTokenRequest.AccessToken
    $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
    $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
    Write-Host "+Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']"
}
$funcCreateBearerToken = $function:createBearerToken.ToString()
$htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#endregion createbearertoken

#API
#region azapicall
function AzAPICall($uri, $method, $currentTask, $body, $listenOn, $getConsumption, $getGroup, $getApp, $getSp, $getGuests, $caller) {
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

    do {
        if ($arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "ManagementAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenManagement
        }
        else {
            $targetEndpoint = "MSGraphAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenMSGraph
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

        $unexpectedError = $false
        $tryCounter++
        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "  DEBUGTASK: attempt#$($tryCounter) processing: $($currenttask)" -ForegroundColor $debugForeGroundColor }
        try {
            if ($body) {
                #write-host "has BODY"
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -ContentType "application/json" -UseBasicParsing
            }
            else {
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers @{"Content-Type" = "application/json"; "Authorization" = "Bearer $bearerToUse" } -UseBasicParsing
            }
        }
        catch {
            try {
                $catchResultPlain = $_.ErrorDetails.Message
                $catchResult = ($catchResultPlain | ConvertFrom-Json -ErrorAction SilentlyContinue) 
            }
            catch {
                $catchResult = $catchResultPlain
                $tryCounterUnexpectedError++
                $unexpectedError = $true
            }
        }
        
        if ($unexpectedError -eq $false) {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: false" -ForegroundColor $debugForeGroundColor }
            if ($azAPIRequest.StatusCode -ne 200) {
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
                    ($getConsumption -and $catchResult.error.code -eq 404) -or 
                    ($getSp -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or 
                    ($getSp -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or
                    ($getApp -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or 
                    ($getApp -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or 
                    ($getGroup -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or 
                    ($getGuests -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or 
                    $catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*" -or
                    $catchResult.error.code -like "*UnknownError*" -or
                    $catchResult.error.code -eq "500") {
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
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
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
                    if ($getConsumption -and $catchResult.error.code -eq 404) {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
                        return $apiCallResultsCollection
                    }
                    if (($getGroup) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain Group status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }
                    if (($getApp -or $getSp) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain ServicePrincipal status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }
                    if ((($getApp -or $getSp) -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or ($getGuests -and $catchResult.error.code -like "*Authorization_RequestDenied*")) {
                        if ($userType -eq "Guest") {
                            Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult)"
                            Write-Host " AzGovViz says: You are a 'Guest' User in the tenant therefore not enough permissions. You have the following options: [1. request membership to AAD Role 'Directory readers'.] [2. Use parameters '-NoAADGuestUsers' and '-NoAADServicePrincipalResolve'.] [3. Grant explicit Microsoft Graph API permission. Permissions reference Users: https://docs.microsoft.com/en-us/graph/api/user-list | Applications: https://docs.microsoft.com/en-us/graph/api/application-list]" -ForegroundColor Yellow
                            Throw "Authorization_RequestDenied"
                        }
                        else {
                            Write-Host " $currentTask - try #$tryCounter; returned: <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) investigate that error!/exit"
                            Throw "Authorization_RequestDenied"
                        }
                    }                    
                }
                else {
                    if ($catchResult.code -eq '' -and $catchResult.error.code -eq '' -and $catchResult.message -eq '' -and $catchResult.error.message -eq '' -and $catchResult -eq '' -and $tryCounter -lt 6){
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
    until($azAPIRequest.StatusCode -eq 200 -and -not $isMore)
    return $apiCallResultsCollection
}
$funcAzAPICall = $function:AzAPICall.ToString()
#endregion azapicall

#test required Az modules cmdlets
#region testAzModules
$testCommands = @('Get-AzContext')
$azModules = @('Az.Accounts')

Write-Host "Testing required Az modules cmdlets"
foreach ($testCommand in $testCommands) {
    if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
        Write-Host " AzModule test failed: cmdlet $testCommand not available - make sure the modules $($azModules -join ", ") are installed" -ForegroundColor Red
        Throw "Error - check the last console output for details"
    }
    else {
        Write-Host " AzModule test passed: Az ps module supporting cmdlet $testCommand installed" -ForegroundColor Green
    }
}

Write-Host "Collecting Az modules versions"
foreach ($azModule in $azModules) {
    $azModuleVersion = (Get-InstalledModule -name "$azModule" -ErrorAction Ignore).Version
    if ($azModuleVersion) {
        Write-Host " Az Module $azModule Version: $azModuleVersion"
    }
    else {
        Write-Host " Az Module $azModule Version: could not be assessed"
    }
}
#endregion testAzModules

#check AzContext
#region checkAzContext
$checkContext = Get-AzContext -ErrorAction Stop
Write-Host "Checking Az Context"
if (-not $checkContext) {
    Write-Host " Context test failed: No context found. Please connect to Azure (run: Connect-AzAccount) and re-run AzGovViz" -ForegroundColor Red
    Throw "Error - check the last console output for details"
}
else {
    $accountType = $checkContext.Account.Type
    $accountId = $checkContext.Account.id
    Write-Host " Context AccountId: '$($accountId)'" -ForegroundColor Yellow
    Write-Host " Context AccountType: '$($accountType)'" -ForegroundColor Yellow

    if ($SubscriptionId4AzContext -ne "undefined") {
        Write-Host " Setting AzContext to SubscriptionId: '$SubscriptionId4AzContext'" -ForegroundColor Yellow
        try {
            Set-AzContext -SubscriptionId $SubscriptionId4AzContext
        }
        catch {
            Throw "Error - check the last console output for details"
        }
        $checkContext = Get-AzContext -ErrorAction Stop
    }
    
    #else{
    if (-not $checkContext.Subscription) {
        $checkContext
        Write-Host " Context test failed: Context is not set to any Subscription. Set your context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run script" -ForegroundColor Red
        Throw "Error - check the last console output for details"
    }
    else {
        Write-Host " Context test passed: Context OK" -ForegroundColor Green
    }
    #}

}
#endregion checkAzContext

#environment check
#region environmentcheck
$checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop

#FutureUse
#Graph Endpoints https://docs.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
#AzureCloud https://graph.microsoft.com
#AzureUSGovernment L4 https://graph.microsoft.us
#AzureUSGovernment L5 (DOD) https://dod-graph.microsoft.us
#AzureChinaCloud https://microsoftgraph.chinacloudapi.cn
#AzureGermanCloud https://graph.microsoft.de

#AzureEnvironmentRelatedUrls
$htAzureEnvironmentRelatedUrls = @{ }
$arrayAzureManagementEndPointUrls = @()
foreach ($checkAzEnvironment in $checkAzEnvironments) {
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ResourceManagerUrl = $checkAzEnvironment.ResourceManagerUrl
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ServiceManagementUrl = $checkAzEnvironment.ServiceManagementUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ActiveDirectoryAuthority = $checkAzEnvironment.ActiveDirectoryAuthority
    if ($checkAzEnvironment.Name -eq "AzureCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.com"
    }
    if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://microsoftgraph.chinacloudapi.cn"
    }
    if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.us"
    }
    if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.de"
    }
}
#endregion environmentcheck

#create bearer token
createBearerToken -targetEndPoint "ManagementAPI"
#MSGraphToken only required for certain scenarios
if (-not $NoAADGroupsResolveMembers -or -not $NoAADServicePrincipalResolve) {
    createBearerToken -targetEndPoint "MSGraphAPI"
}


#EXAMPLE MGMT API
$startGetSubscriptions = get-date
$currentTask = "Getting all Subscriptions"
Write-Host "$currentTask"
#https://management.azure.com/subscriptions?api-version=2020-01-01
$uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions?api-version=2019-10-01"
#$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
$method = "GET"

$requestAllSubscriptionsAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
$requestAllSubscriptionsAPICount = $requestAllSubscriptionsAPI.Count

$endGetSubscriptions = get-date
Write-Host "Getting all $($requestAllSubscriptionsAPICount) Subscriptions duration: $((NEW-TIMESPAN -Start $startGetSubscriptions -End $endGetSubscriptions).TotalSeconds) seconds" 
