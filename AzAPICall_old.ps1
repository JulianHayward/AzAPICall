# https://github.com/JulianHayward/AzAPICall

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$False)][switch]$DebugAzAPICall = $true,
    [Parameter(Mandatory=$False)][string]$SubscriptionId4AzContext = "undefined",
    [Parameter(Mandatory=$False)][switch]$PsParallelization = $true,
    [Parameter(Mandatory=$True)][string]$TenantId,
    [Parameter(Mandatory=$False)][int]$ThrottleLimitMicrosoftGraph = 20,
    [Parameter(Mandatory=$False)][int]$ThrottleLimitARM = 10
)

#Region Prerequisites
$ErrorActionPreference = "Stop"

#region htParameters (all switch params used in foreach-object -parallel)

if ($env:GITHUB_SERVER_URL -and $env:CODESPACES) {
    #GitHub Codespaces
    Write-Host "CheckCodeRunPlatform: running in GitHub Codespaces"
    $checkCodeRunPlatform = "GitHubCodespaces"
}
elseif ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
    #Azure DevOps
    Write-Host "CheckCodeRunPlatform: running in Azure DevOps"
    $checkCodeRunPlatform = "AzureDevOps"
}
elseif ($PSPrivateMetadata) {
    #Azure Automation
    Write-Output "CheckCodeRunPlatform: running in Azure Automation"
    $checkCodeRunPlatform = "AzureAutomation"
}
else {
    #Other Console
    Write-Host "CheckCodeRunPlatform: not Codespaces, not Azure DevOps, not Azure Automation - likely local console"
    $checkCodeRunPlatform = "Console"
}

$htParameters = @{}
$htParameters.DebugAzAPICall = $DebugAzAPICall
write-host "AzAPICall debug enabled" -ForegroundColor Cyan
#endregion htParameters

#Region PowerShellEditionAnVersionCheck
if($PsParallelization) {
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
}
#EndRegion PowerShellEditionAnVersionCheck

if ($htParameters.DebugAzAPICall -eq $false) {
    write-host "AzAPICall debug disabled" -ForegroundColor Cyan
}
else {
    write-host "AzAPICall debug enabled" -ForegroundColor Cyan
}

#Region DisableBreakingChangeWarningMessages
# https://docs.microsoft.com/de-de/powershell/azure/faq?view=azps-7.1.0#how-do-i-disable-breaking-change-warning-messages-in-azure-powershell-
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
#EndRegion DisableBreakingChangeWarningMessages
#EndRegion Prerequisites

#Region AzAPICall
function AzAPICall {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)][string]$uri,
        [Parameter(Mandatory=$True)][string]$method,
        [Parameter(Mandatory=$True)][string]$currentTask,
        [Parameter(Mandatory=$False)][string]$body,
        [Parameter(Mandatory=$False)][string]$listenOn,
        [Parameter(Mandatory=$False)][string]$getConsumption,
        [Parameter(Mandatory=$False)][string]$caller,
        [Parameter(Mandatory=$False)][string]$consistencyLevel,
        [Parameter(Mandatory=$False)][bool]$getGroup,
        [Parameter(Mandatory=$False)][bool]$getGroupMembersCount,
        [Parameter(Mandatory=$False)][bool]$getApp,
        [Parameter(Mandatory=$False)][bool]$getCount,
        [Parameter(Mandatory=$False)][bool]$getPolicyCompliance,
        [Parameter(Mandatory=$False)][bool]$getMgAscSecureScore,
        [Parameter(Mandatory=$False)][bool]$getRoleAssignmentSchedules,
        [Parameter(Mandatory=$False)][bool]$getDiagnosticSettingsMg,
        [Parameter(Mandatory=$False)][bool]$validateAccess,
        [Parameter(Mandatory=$False)][bool]$getMDfC,
        [Parameter(Mandatory=$False)][bool]$noPaging
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

    do {
        if ($arrayAzureManagementEndPointUrls | Where-Object { $uri -match $_ }) {
            $targetEndpoint = "ManagementAPI"
            $bearerToUse = $htBearerAccessToken.AccessTokenManagement
        }
        else {
            $targetEndpoint = "MicrosoftGraph"
            $bearerToUse = $htBearerAccessToken.AccessTokenMSGraph
        }

        #
        $unexpectedError = $false

        $Header = @{
            "Content-Type"  = "application/json";
            "Authorization" = "Bearer $bearerToUse"
        }
        if ($consistencyLevel) {
            $Header = @{
                "Content-Type"     = "application/json";
                "Authorization"    = "Bearer $bearerToUse";
                "ConsistencyLevel" = "$consistencyLevel"
            }
        }

        $startAPICall = Get-Date
        try {
            if ($body) {
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -body $body -Headers $Header -ContentType "application/json" -UseBasicParsing
            }
            else {
                $azAPIRequest = Invoke-WebRequest -Uri $uri -Method $method -Headers $Header -UseBasicParsing
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

        #API Call Tracking
        $tstmp = (Get-Date -Format "yyyyMMddHHmmssms")
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
                Duration                             = $durationAPICall.TotalSeconds
            })

        $tryCounter++
        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "  DEBUGTASK: attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'" -ForegroundColor $debugForeGroundColor }
            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "  Forced DEBUG: attempt#$($tryCounter) processing: $($currenttask) uri: '$($uri)'" }
        }

        if ($unexpectedError -eq $false) {
            if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: false" -ForegroundColor $debugForeGroundColor }
                if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: unexpectedError: false" }
            }
            if ($azAPIRequest.StatusCode -ne 200) {
                if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" -ForegroundColor $debugForeGroundColor }
                    if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                }
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
                    ($getPolicyCompliance -and $catchResult.error.code -like "*ResponseTooLarge*") -or
                    ($getPolicyCompliance -and -not $catchResult.error.code) -or
                    $catchResult.error.code -like "*InvalidAuthenticationToken*" -or
                    (
                        ($getConsumption -and $catchResult.error.code -eq 404) -or
                        ($getConsumption -and $catchResult.error.code -eq "AccountCostDisabled") -or
                        ($getConsumption -and $catchResult.error.message -like "*does not have any valid subscriptions*") -or
                        ($getConsumption -and $catchResult.error.code -eq "Unauthorized") -or
                        ($getConsumption -and $catchResult.error.code -eq "BadRequest" -and $catchResult.error.message -like "*The offer*is not supported*" -and $catchResult.error.message -notlike "*The offer MS-AZR-0110P is not supported*") -or
                        ($getConsumption -and $catchResult.error.code -eq "BadRequest" -and $catchResult.error.message -like "Invalid query definition*") -or
                        ($getConsumption -and $catchResult.error.code -eq "NotFound" -and $catchResult.error.message -like "*have valid WebDirect/AIRS offer type*") -or
                        ($getConsumption -and $catchResult.error.code -eq "NotFound" -and $catchResult.error.message -like "Cost management data is not supported for subscription(s)*") -or
                        ($getConsumption -and $catchResult.error.code -eq "IndirectCostDisabled")
                    ) -or
                    $catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*" -or
                    (($getSP -or $getApp -or $getGroup -or $getGroupMembersCount) -and $catchResult.error.code -like "*Request_ResourceNotFound*") -or
                    (($getSP -or $getApp) -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or
                    ($getGroupMembersCount -and $catchResult.error.message -like "*count is not currently supported*") -or
                    $catchResult.error.code -like "*UnknownError*" -or
                    $catchResult.error.code -like "*BlueprintNotFound*" -or
                    $catchResult.error.code -eq "500" -or
                    $catchResult.error.code -eq "ResourceRequestsThrottled" -or
                    $catchResult.error.code -eq "429" -or
                    ($getMgAscSecureScore -and $catchResult.error.code -eq "BadRequest") -or
                    ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "ResourceNotOnboarded") -or
                    ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "TenantNotOnboarded") -or
                    ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "InvalidResourceType") -or
                    ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "InvalidResource") -or
                    ($getRoleAssignmentScheduledInstances -and $catchResult.error.code -eq "InvalidResource") -or
                    ($getDiagnosticSettingsMg -and $catchResult.error.code -eq "InvalidResourceType") -or
                    ($catchResult.error.code -eq "InsufficientPermissions") -or
                    $catchResult.error.code -eq "ClientCertificateValidationFailure" -or
                    ($validateAccess -and $catchResult.error.code -eq "Authorization_RequestDenied") -or
                    $catchResult.error.code -eq "GatewayAuthenticationFailed" -or
                    $catchResult.message -eq "An error has occurred." -or
                    $catchResult.error.code -eq "Request_UnsupportedQuery" -or
                    ($getMDfC -and $catchResult.error.code -eq "Subscription Not Registered") -or
                    $catchResult.error.code -eq "GeneralError"
                ) {
                    if (($getPolicyCompliance -and $catchResult.error.code -like "*ResponseTooLarge*") -or ($getPolicyCompliance -and -not $catchResult.error.code)) {
                        if ($getPolicyCompliance -and $catchResult.error.code -like "*ResponseTooLarge*") {
                            Write-Host "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response too large, skipping this scope."
                            return "ResponseTooLarge"
                        }
                        if ($getPolicyCompliance -and -not $catchResult.error.code) {
                            #seems API now returns null instead of 'ResponseTooLarge'
                            Write-Host "Info: $currentTask - (StatusCode: '$($azAPIRequest.StatusCode)') Response empty - handle like 'Response too large', skipping this scope."
                            return "ResponseTooLarge"
                        }
                    }

                    if ($catchResult.error.message -like "*The offer MS-AZR-0110P is not supported*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - seems we´re hitting a malicious endpoint .. try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }

                    if ($catchResult.error.code -like "*GatewayTimeout*" -or $catchResult.error.code -like "*BadGatewayConnection*" -or $catchResult.error.code -like "*InvalidGatewayHost*" -or $catchResult.error.code -like "*ServerTimeout*" -or $catchResult.error.code -like "*ServiceUnavailable*" -or $catchResult.code -like "*ServiceUnavailable*" -or $catchResult.error.code -like "*MultipleErrorsOccurred*" -or $catchResult.code -like "*InternalServerError*" -or $catchResult.error.code -like "*InternalServerError*" -or $catchResult.error.code -like "*RequestTimeout*" -or $catchResult.error.code -like "*UnknownError*" -or $catchResult.error.code -eq "500") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again in $tryCounter second(s)"
                        Start-Sleep -Seconds $tryCounter
                    }

                    if ($catchResult.error.code -like "*AuthorizationFailed*") {
                        if ($validateAccess) {
                            #Write-Host "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -ForegroundColor DarkRed
                            return "failed"
                        }
                        else {
                            if ($retryAuthorizationFailedCounter -gt $retryAuthorizationFailed) {
                                Write-Host "- - - - - - - - - - - - - - - - - - - - "
                                Write-Host "!Please report at $($htParameters.GithubRepository) and provide the following dump" -ForegroundColor Yellow
                                Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - $retryAuthorizationFailed retries failed - EXIT"
                                Write-Host ""
                                Write-Host "Parameters:"
                                foreach ($htParameter in ($htParameters.Keys | Sort-Object)) {
                                    Write-Host "$($htParameter):$($htParameters.($htParameter))"
                                }
                                Throw "Error: check the last console output for details"
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

                    if ($catchResult.error.code -like "*ExpiredAuthenticationToken*" -or $catchResult.error.code -like "*Authentication_ExpiredToken*" -or $catchResult.error.code -like "*InvalidAuthenticationToken*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - requesting new bearer token ($targetEndpoint)"
                        CreateBearerToken -targetEndPoint $targetEndpoint
                    }

                    if (
                        ($getConsumption -and $catchResult.error.code -eq 404) -or
                        ($getConsumption -and $catchResult.error.code -eq "AccountCostDisabled") -or
                        ($getConsumption -and $catchResult.error.message -like "*does not have any valid subscriptions*") -or
                        ($getConsumption -and $catchResult.error.code -eq "Unauthorized") -or
                        ($getConsumption -and $catchResult.error.code -eq "BadRequest" -and $catchResult.error.message -like "*The offer*is not supported*" -and $catchResult.error.message -notlike "*The offer MS-AZR-0110P is not supported*") -or
                        ($getConsumption -and $catchResult.error.code -eq "BadRequest" -and $catchResult.error.message -like "Invalid query definition*")
                    ) {
                        if ($getConsumption -and $catchResult.error.code -eq 404) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Subscriptions was created only recently - skipping"
                            return $apiCallResultsCollection
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "AccountCostDisabled") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Access to cost data has been disabled for this Account - skipping CostManagement"
                            return "AccountCostDisabled"
                        }

                        if ($getConsumption -and $catchResult.error.message -like "*does not have any valid subscriptions*") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems there are no valid Subscriptions present - skipping CostManagement"
                            return "NoValidSubscriptions"
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "Unauthorized") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return "Unauthorized"
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "BadRequest" -and $catchResult.error.message -like "*The offer*is not supported*" -and $catchResult.error.message -notlike "*The offer MS-AZR-0110P is not supported*") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return "OfferNotSupported"
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "BadRequest" -and $catchResult.error.message -like "Invalid query definition*") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return "InvalidQueryDefinition"
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "NotFound" -and $catchResult.error.message -like "*have valid WebDirect/AIRS offer type*") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) Unauthorized - handling as exception"
                            return "NonValidWebDirectAIRSOfferType"
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "NotFound" -and $catchResult.error.message -like "Cost management data is not supported for subscription(s)*") {
                            return "NotFoundNotSupported"
                        }

                        if ($getConsumption -and $catchResult.error.code -eq "IndirectCostDisabled") {
                            return "IndirectCostDisabled"
                        }
                    }

                    if (($getGroup) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain Group status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }

                    if (($getGroupMembersCount) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain Group status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }

                    if ($getGroupMembersCount -and $catchResult.error.message -like "*count is not currently supported*") {
                        $maxTries = 7
                        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                            Throw "Error - check the last console output for details"
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
                        start-sleep -Seconds $sleepSec
                    }

                    if (($getApp -or $getSP) -and $catchResult.error.code -like "*Request_ResourceNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) uncertain ServicePrincipal status - skipping for now :)"
                        return "Request_ResourceNotFound"
                    }

                    if ($currentTask -eq "Checking AAD UserType" -and $catchResult.error.code -like "*Authorization_RequestDenied*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) cannot get the executing user´s userType information (member/guest) - proceeding as 'unknown'"
                        return "unknown"
                    }

                    if ((($getApp -or $getSP) -and $catchResult.error.code -like "*Authorization_RequestDenied*") -or ($getGuests -and $catchResult.error.code -like "*Authorization_RequestDenied*")) {
                        if ($htParameters.userType -eq "Guest") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - skip Application (Secrets & Certificates)"
                            return "skipApplications"
                        }
                        if ($userType -eq "Guest" -or $userType -eq "unknown") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult)"
                            if ($userType -eq "Guest") {
                                Write-Host " Your UserType is 'Guest' (member/guest/unknown) in the tenant therefore not enough permissions. You have the following options: [1. request membership to AAD Role 'Directory readers'.] Grant explicit Microsoft Graph API permission." -ForegroundColor Yellow
                            }
                            if ($userType -eq "unknown") {
                                Write-Host " Your UserType is 'unknown' (member/guest/unknown) in the tenant. Seems you do not have enough permissions geeting AAD related data. You have the following options: [1. request membership to AAD Role 'Directory readers'.]" -ForegroundColor Yellow
                            }
                            Throw "Authorization_RequestDenied"
                        }
                        else {
                            Write-Host "- - - - - - - - - - - - - - - - - - - - "
                            Write-Host "!Please report at $($htParameters.GithubRepository) and provide the following dump" -ForegroundColor Yellow
                            Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
                            Write-Host ""
                            Write-Host "Parameters:"
                            foreach ($htParameter in ($htParameters.Keys | Sort-Object)) {
                                Write-Host "$($htParameter):$($htParameters.($htParameter))"
                            }
                            Throw "Authorization_RequestDenied"
                        }
                    }

                    if ($catchResult.error.code -like "*BlueprintNotFound*") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) seems Blueprint definition is gone - skipping for now :)"
                        return "BlueprintNotFound"
                    }
                    if ($catchResult.error.code -eq "ResourceRequestsThrottled" -or $catchResult.error.code -eq "429") {
                        $sleepSeconds = 11
                        if ($catchResult.error.code -eq "ResourceRequestsThrottled") {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
                            start-sleep -Seconds $sleepSeconds
                        }
                        if ($catchResult.error.code -eq "429") {
                            if ($catchResult.error.message -like "*60 seconds*") {
                                $sleepSeconds = 60
                            }
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - throttled! sleeping $sleepSeconds seconds"
                            start-sleep -Seconds $sleepSeconds
                        }

                    }

                    if ($getMgAscSecureScore -and $catchResult.error.code -eq "BadRequest") {
                        $sleepSec = @(1, 1, 2, 3, 5, 7, 9, 10, 13, 15, 20, 25, 30, 45, 60, 60, 60, 60)[$tryCounter]
                        $maxTries = 15
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - capitulation after $maxTries attempts"
                            return "capitulation"
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }

                    if (($getRoleAssignmentSchedules -and $catchResult.error.code -eq "ResourceNotOnboarded") -or ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "TenantNotOnboarded") -or ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "InvalidResourceType") -or ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "InvalidResource") -or ($getRoleAssignmentScheduledInstances -and $catchResult.error.code -eq "InvalidResource")) {
                        if ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "ResourceNotOnboarded") {
                            return "ResourceNotOnboarded"
                        }
                        if ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "TenantNotOnboarded") {
                            return "TenantNotOnboarded"
                        }
                        if ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "InvalidResourceType") {
                            return "InvalidResourceType"
                        }
                        if ($getRoleAssignmentSchedules -and $catchResult.error.code -eq "InvalidResource") {
                            return "InvalidResource"
                        }
                        if ($getRoleAssignmentScheduledInstances -and $catchResult.error.code -eq "InvalidResource") {
                            return "InvalidResource"
                        }
                    }

                    if ($getDiagnosticSettingsMg -and $catchResult.error.code -eq "InvalidResourceType") {
                        return "InvalidResourceType"
                    }

                    if ($catchResult.error.code -eq "InsufficientPermissions" -or $catchResult.error.code -eq "ClientCertificateValidationFailure" -or $catchResult.error.code -eq "GatewayAuthenticationFailed" -or $catchResult.message -eq "An error has occurred." -or $catchResult.error.code -eq "GeneralError") {
                        $maxTries = 7
                        $sleepSec = @(1, 3, 5, 7, 10, 12, 20, 30, 40, 45)[$tryCounter]
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                            Throw "Error - check the last console output for details"
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' sleeping $($sleepSec) seconds"
                        start-sleep -Seconds $sleepSec
                    }

                    if ($validateAccess -and $catchResult.error.code -eq "Authorization_RequestDenied") {
                        #Write-Host "$currentTask failed ('$($catchResult.error.code)' | '$($catchResult.error.message)')" -ForegroundColor DarkRed
                        return "failed"
                    }


                    if ($htParameters.userType -eq "Guest" -and $catchResult.error.code -eq "Authorization_RequestDenied") {
                        #https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' - exit"
                        Write-Host "Tenant seems hardened (AAD External Identities / Guest user access = most restrictive) -> https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/users-restrict-guest-permissions"
                        Write-Host "AAD Role 'Directory readers' is required for your Guest User Account!"
                        Throw "Error - check the last console output for details"
                    }

                    if ($getMDfC -and $catchResult.error.code -eq "Subscription Not Registered") {
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') '$($catchResult.error.code)' | '$($catchResult.error.message)' skipping Subscription"
                        return "SubScriptionNotRegistered"
                    }

                    if ($catchResult.error.code -eq "Request_UnsupportedQuery") {
                        $sleepSec = @(1, 3, 7, 10, 15, 20, 30)[$tryCounter]
                        $maxTries = 5
                        if ($tryCounter -gt $maxTries) {
                            Write-Host " $currentTask - capitulation after $maxTries attempts"
                            return "Request_UnsupportedQuery"
                        }
                        Write-Host " $currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - try again (trying $maxTries times) in $sleepSec second(s)"
                        Start-Sleep -Seconds $sleepSec
                    }

                }
                else {
                    if (-not $catchResult.code -and -not $catchResult.error.code -and -not $catchResult.message -and -not $catchResult.error.message -and -not $catchResult -and $tryCounter -lt 6) {
                        if ($azAPIRequest.StatusCode -eq 204 -and $getConsumption) {
                            return $apiCallResultsCollection
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
                        Write-Host "- - - - - - - - - - - - - - - - - - - - "
                        Write-Host "!Please report at $($htParameters.GithubRepository) and provide the following dump" -ForegroundColor Yellow
                        Write-Host "$currentTask - try #$tryCounter; returned: (StatusCode: '$($azAPIRequest.StatusCode)') <.code: '$($catchResult.code)'> <.error.code: '$($catchResult.error.code)'> | <.message: '$($catchResult.message)'> <.error.message: '$($catchResult.error.message)'> - (plain : $catchResult) - EXIT"
                        Write-Host ""
                        Write-Host "Parameters:"
                        foreach ($htParameter in ($htParameters.Keys | Sort-Object)) {
                            Write-Host "$($htParameter):$($htParameters.($htParameter))"
                        }
                        if ($getConsumption) {
                            Write-Host "If Consumption data is not that important for you, do not use parameter: -DoAzureConsumption (however, please still report the issue - thank you)"
                        }
                        Throw "Error - check the last console output for details"
                    }
                }
            }
            else {
                if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                    if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" -ForegroundColor $debugForeGroundColor }
                    if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: apiStatusCode: $($azAPIRequest.StatusCode)" }
                }
                $azAPIRequestConvertedFromJson = ($azAPIRequest.Content | ConvertFrom-Json)
                if ($listenOn -eq "Content") {
                    if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                        if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson)).count))" -ForegroundColor $debugForeGroundColor }
                        if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: listenOn=content ($((($azAPIRequestConvertedFromJson)).count))" }
                    }
                    $null = $apiCallResultsCollection.Add($azAPIRequestConvertedFromJson)
                }
                elseif ($listenOn -eq "ContentProperties") {
                    if (($azAPIRequestConvertedFromJson.properties.rows).Count -gt 0) {
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
                    }
                }
                else {
                    if (($azAPIRequestConvertedFromJson).value) {
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value).count))" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: listenOn=default(value) value exists ($((($azAPIRequestConvertedFromJson).value).count))" }
                        }
                        foreach ($entry in $azAPIRequestConvertedFromJson.value) {
                            $null = $apiCallResultsCollection.Add($entry)
                        }

                        if ($getGuests) {
                            $guestAccountsCount = ($apiCallResultsCollection).Count
                            if ($guestAccountsCount % 1000 -eq 0) {
                                write-host " $guestAccountsCount processed"
                            }
                        }
                    }
                    else {
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: listenOn=default(value) value not exists; return empty array" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: listenOn=default(value) value not exists; return empty array" }
                        }
                    }
                }

                $isMore = $false
                if (-not $noPaging) {
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
                                Start-Sleep -Seconds 10
                                CreateBearerToken -targetEndPoint $targetEndpoint
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.nextLink
                        }
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: nextLink: $Uri" }
                        }
                    }
                    elseif ($azAPIRequestConvertedFromJson."@oData.nextLink") {
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
                                Start-Sleep -Seconds 10
                                CreateBearerToken -targetEndPoint $targetEndpoint
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson."@odata.nextLink"
                        }
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: @oData.nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: @oData.nextLink: $Uri" }
                        }
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
                                Start-Sleep -Seconds 10
                                CreateBearerToken -targetEndPoint $targetEndpoint
                                Start-Sleep -Seconds 10
                            }
                        }
                        else {
                            $uri = $azAPIRequestConvertedFromJson.properties.nextLink
                        }
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: nextLink: $Uri" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: nextLink: $Uri" }
                        }
                    }
                    else {
                        if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                            if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: NextLink: none" -ForegroundColor $debugForeGroundColor }
                            if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: NextLink: none" }
                        }
                    }
                }
            }
        }
        else {
            if ($htParameters.DebugAzAPICall -eq $true -or $tryCounter -gt 3) {
                if ($htParameters.DebugAzAPICall -eq $true) { Write-Host "   DEBUG: unexpectedError: notFalse" -ForegroundColor $debugForeGroundColor }
                if ($htParameters.DebugAzAPICall -eq $false -and $tryCounter -gt 3) { Write-Host "   Forced DEBUG: unexpectedError: notFalse" }
            }
            if ($tryCounterUnexpectedError -lt 13) {
                $sleepSec = @(1, 2, 3, 5, 7, 10, 13, 17, 20, 30, 40, 50, , 55, 60)[$tryCounterUnexpectedError]
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
$funcAzAPICall = $function:AzAPICall.ToString()
#EndRegion AzAPICall

#JWTDetails https://www.powershellgallery.com/packages/JWTDetails/1.0.2
#Region getJWTDetails
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
#EndRegion getJWTDetails

#Bearer Token
#Region createBearerToken
function createBearerToken($targetEndPoint) {
    $checkContext = Get-AzContext -ErrorAction Stop
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
    if ($targetEndPoint -eq "MicrosoftGraph") {
        $contextForMSGraphToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForMSGraphToken.Account, $contextForMSGraphToken.Environment, $contextForMSGraphToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)")
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
    if ($targetEndPoint -eq "MicrosoftGraph") {
        $script:htBearerAccessToken.AccessTokenMSGraph = $newBearerAccessTokenRequest.AccessToken
    }
    $bearerDetails = GetJWTDetails -token $newBearerAccessTokenRequest.AccessToken
    $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
    $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
    Write-Host "+Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']"
}
$funcCreateBearerToken = $function:createBearerToken.ToString()
$htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#EndRegion createbearertoken

#test required Az modules cmdlets
#Region testAzModules
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
#EndRegion testAzModules

#Region Main
# Clear-AzContext -Force
# Connect-AzAccount -TenantId $TenantId

#check AzContext
Test-PSMDAzContext
#Region checkAzContext (FUNCTION)
# $checkContext = Get-AzContext -ErrorAction Stop
# Write-Host "Checking Az Context"
# if (-not $checkContext) {
#     Write-Host " Context test failed: No context found. Please connect to Azure (run: Connect-AzAccount) and re-run the script" -ForegroundColor Red
#     Throw "Error - check the last console output for details"
# }
# else {
#     $accountType = $checkContext.Account.Type
#     $accountId = $checkContext.Account.Id
#     Write-Host " Context AccountId: '$($accountId)'" -ForegroundColor Yellow
#     Write-Host " Context AccountType: '$($accountType)'" -ForegroundColor Yellow

#     if ($SubscriptionId4AzContext -ne "undefined") {
#         if ($checkContext.Subscription.Id -ne $SubscriptionId4AzContext) {
#             Write-Host " Setting AzContext to SubscriptionId: '$SubscriptionId4AzContext'" -ForegroundColor Yellow
#             try {
#                 $null = Set-AzContext -SubscriptionId $SubscriptionId4AzContext -ErrorAction Stop
#             }
#             catch {
#                 Throw "Error - check the last console output for details"
#             }
#             $checkContext = Get-AzContext -ErrorAction Stop
#             Write-Host " AzContext: $($checkContext.Subscription.Name) ($($checkContext.Subscription.Id))" -ForegroundColor Green
#         }
#         else {
#             Write-Host " AzContext: $($checkContext.Subscription.Name) ($($checkContext.Subscription.Id))" -ForegroundColor Green
#         }
#     }

#     if (-not $checkContext.Subscription) {
#         $checkContext
#         Write-Host " Context test failed: Context is not set to any Subscription. Set your context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run the script" -ForegroundColor Red
#         Throw "Error - check the last console output for details"
#     }
#     else {
#         Write-Host " Context test passed: Context OK" -ForegroundColor Green
#     }
# }
#EndRegion checkAzContext

#environment check
Test-PSMDEnvironment
#Region environmentcheck (FUNCTION)
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
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ARM = $checkAzEnvironment.ResourceManagerUrl
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).KeyVault = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).LogAnalytics = $checkAzEnvironment.AzureOperationalInsightsEndpoint
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.AzureOperationalInsightsEndpoint
    if ($checkAzEnvironment.Name -eq "AzureCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.com"
    }
    if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://microsoftgraph.chinacloudapi.cn"
    }
    if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.us"
    }
    if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.de"
    }
}

$uriMicrosoftGraph = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)"
$uriARM = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM)"
$uriKeyVault = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).KeyVault)"
$uriLogAnalytics = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).LogAnalytics)"
#EndRegion environmentcheck

#init variables
if($PsParallelization) {
    $arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
} else {
    $arrayAPICallTracking = [System.Collections.ArrayList]@()
}

#create bearer token
createBearerToken -targetEndPoint "MicrosoftGraph"
# createBearerToken -targetEndPoint "ARM"
# createBearerToken -targetEndPoint "KeyVault"
# createBearerToken -targetEndPoint "LogAnalytics"

# Example calls
# https://graph.microsoft.com/v1.0/groups
$uri = $uriMicrosoftGraph + "/v1.0/groups?`$top=999&`$filter=(mailEnabled eq false and securityEnabled eq true)&`$select=id,createdDateTime,displayName,description&`$orderby=displayName asc&`$count=true" #https://docs.microsoft.com/en-us/graph/paging
$listenOn = "Value" #Default
$currentTask = "Microsoft Graph API: Get - Groups"
$method = "GET"
$aadgroups = AzAPICall -uri $uri `
                       -method $method `
                       -currentTask $currentTask `
                       -listenOn $listenOn `
                       -consistencyLevel "eventual" `
                       -noPaging $true #$top in url + paging = $true will iterate further https://docs.microsoft.com/en-us/graph/paging

$htAzureAdGroupDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
$arrayGroupMembers = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

$startTime = get-date

$aadgroups | ForEach-Object -Parallel {
    $htAzureAdGroupDetails = $using:htAzureAdGroupDetails
    $uriMicrosoftGraph = $using:uriMicrosoftGraph
    $arrayGroupMembers = $using:arrayGroupMembers
    $htParameters = $using:htParameters
    $htBearerAccessToken = $using:htBearerAccessToken
    $arrayAPICallTracking = $using:arrayAPICallTracking

    $function:AzAPICall = $using:funcAzAPICall
    $function:createBearerToken = $using:funcCreateBearerToken
    $function:GetJWTDetails = $using:funcGetJWTDetails

    $group = $_

    # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
    $uri = $uriMicrosoftGraph + "/v1.0/groups/$($group.id)/members"
    $listenOn = "Value" #Default
    $currentTask = "Microsoft Graph API: Get - Group List Members"
    $method = "GET"
    $AzApiCallResult = AzAPICall -uri $uri `
                                 -method $method `
                                 -currentTask $currentTask `
                                 -listenOn $listenOn `
                                 -caller "CustomDataCollection" `
                                 -noPaging $true #https://docs.microsoft.com/en-us/graph/paging

    $htAzureAdGroupDetails.($group.id) = @()
    $htAzureAdGroupDetails.($group.id) = $AzApiCallResult
} -ThrottleLimit $ThrottleLimitMicrosoftGraph

$parallelElapsedTime = "elapsed time (parallel foreach loop): " + ((get-date) - $startTime).TotalSeconds + " seconds"
Write-Host $parallelElapsedTime

($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)

$aadgroups.Count
$htAzureAdGroupDetails.Keys.Count
$htAzureAdGroupDetails.Values.Id.Count
#EndRegion Main