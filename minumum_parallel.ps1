# https://github.com/JulianHayward/AzAPICall

[CmdletBinding()]
Param
(
    [Parameter(Mandatory = $False)][switch]$DebugAzAPICall,
    [Parameter(Mandatory = $False)][string]$SubscriptionId4AzContext = "undefined",
    [Parameter(Mandatory = $False)][switch]$PsParallelization,
    [Parameter(Mandatory = $False)][int]$ThrottleLimitMicrosoftGraph = 20,
    [Parameter(Mandatory = $False)][int]$ThrottleLimitARM = 10
)

#Region Prerequisites
#Region ErrorActionPreference
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.2#erroractionpreference
$ErrorActionPreference = "Stop"
#EndRegion ErrorActionPreference

#Region DisableBreakingChangeWarningMessages
# https://docs.microsoft.com/de-de/powershell/azure/faq?view=azps-7.1.0#how-do-i-disable-breaking-change-warning-messages-in-azure-powershell-
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings "true"
#EndRegion DisableBreakingChangeWarningMessages

#Region Functions
#Region getJWTDetails
. .\functions\getJWTDetails.ps1
$funcGetJWTDetails = $function:getJWTDetails.ToString()
#EndRegion getJWTDetails

#Region createBearerToken
. .\functions\createBearerToken.ps1
$funcCreateBearerToken = $function:createBearerToken.ToString()
#EndRegion createBearerToken

#Region AzAPICall
. .\functions\AzAPICall.ps1
$funcAzAPICall = $function:AzAPICall.ToString()
#EndRegion AzAPICall
#EndRegion Functions

#Region Variables
if ($PsParallelization) {
    $arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
}
else {
    $arrayAPICallTracking = [System.Collections.ArrayList]@()
    $htBearerAccessToken = @{}
}
#EndRegion Variables

. .\prerequisites\Test-HashtableParameter.ps1
. .\prerequisites\Test-PowerShellVersion.ps1
. .\prerequisites\Test-AzModules.ps1
. .\prerequisites\Test-AzContext.ps1
. .\prerequisites\Test-Environment.ps1
. .\prerequisites\Test-UserType.ps1
#EndRegion Prerequisites

#Region Main
# Example calls
#Region MicrosoftGraphGroupList
# https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
# GET /groups
Write-Host "----------------------------------------------------------"
Write-Host "Processing example call: Microsoft Graph API: Get - Groups"
$uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph + "/v1.0/groups?`$top=999&`$filter=(mailEnabled eq false and securityEnabled eq true)&`$select=id,createdDateTime,displayName,description&`$orderby=displayName asc&`$count=true" # https://graph.microsoft.com/v1.0/groups
$listenOn = "Value" #Default
$currentTask = " 'Microsoft Graph API: Get - Groups'"
Write-Host $currentTask
$method = "GET"
$aadgroups = AzAPICall -uri $uri `
                       -method $method `
                       -currentTask $currentTask `
                       -listenOn $listenOn `
                       -consistencyLevel "eventual" `
                       -noPaging $true #$top in url + paging = $true will iterate further https://docs.microsoft.com/en-us/graph/paging

Write-Host " $currentTask returned results:" $aadgroups.Count
#EndRegion MicrosoftGraphGroupList

#Region MicrosoftGraphGroupMemberList
if ($PsParallelization) {
    Write-Host "----------------------------------------------------------"
    Write-Host "Processing example call: Getting all members for $($aadgroups.Count) AAD Groups (going parallel)"
    $htAzureAdGroupDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayGroupMembers = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $startTime = get-date

    $aadgroups | ForEach-Object -Parallel {
        #general hashTables and arrays
        $checkContext = $using:checkContext
        $htAzureEnvironmentRelatedUrls = $using:htAzureEnvironmentRelatedUrls
        $htAzureEnvironmentRelatedTargetEndpoints = $using:htAzureEnvironmentRelatedTargetEndpoints
        $htParameters = $using:htParameters
        $htBearerAccessToken = $using:htBearerAccessToken
        $arrayAPICallTracking = $using:arrayAPICallTracking
        #general functions
        $function:AzAPICall = $using:funcAzAPICall
        $function:createBearerToken = $using:funcCreateBearerToken
        $function:GetJWTDetails = $using:funcGetJWTDetails
        #specific for this operation
        $htAzureAdGroupDetails = $using:htAzureAdGroupDetails
        $arrayGroupMembers = $using:arrayGroupMembers

        $group = $_

        # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
        # GET /groups/{id}/members
        $uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph + "/v1.0/groups/$($group.id)/members" # https://graph.microsoft.com/v1.0/groups/<GroupId>/members
        $listenOn = "Value" #Default
        $currentTask = " 'Microsoft Graph API: Get - Group List Members (id: $($group.id))'"
        Write-Host $currentTask
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
    Write-Host "returned members:" $htAzureAdGroupDetails.Values.Id.Count

    Write-Host "statistics:"
    ($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)
}
else {
    Write-Host "----------------------------------------------------------"
    Write-Host "Processing example call: Getting all members for $($aadgroups.Count) AAD Groups (going parallel)"
    $htAzureAdGroupDetails = @{}
    $arrayGroupMembers = [System.Collections.ArrayList]@()
    $startTime = get-date

    $aadgroups | ForEach-Object {
        $group = $_

        # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
        # GET /groups/{id}/members
        $uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph + "/v1.0/groups/$($group.id)/members" # https://graph.microsoft.com/v1.0/groups/<GroupId>/members
        $listenOn = "Value" #Default
        $currentTask = " 'Microsoft Graph API: Get - Group List Members (id: $($group.id))'"
        Write-Host $currentTask
        $method = "GET"
        $AzApiCallResult = AzAPICall -uri $uri `
                                     -method $method `
                                     -currentTask $currentTask `
                                     -listenOn $listenOn `
                                     -caller "CustomDataCollection" `
                                     -noPaging $true #https://docs.microsoft.com/en-us/graph/paging

        $htAzureAdGroupDetails.($group.id) = @()
        $htAzureAdGroupDetails.($group.id) = $AzApiCallResult
    }

    $elapsedTime = "elapsed time: " + ((get-date) - $startTime).TotalSeconds + " seconds"
    Write-Host $elapsedTime
    Write-Host "returned members:" $htAzureAdGroupDetails.Values.Id.Count

    Write-Host "statistics:"
    ($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum)
    Write-Host "Use switch parameter -PsParallelization to collect all members for the collected Groups leveraging parallelization!" -ForegroundColor Magenta
}
#EndRegion MicrosoftGraphGroupMemberList

#Region MicrosoftResourceManagerSubscriptions
# https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
# GET https://management.azure.com/subscriptions?api-version=2020-01-01
Write-Host "----------------------------------------------------------"
Write-Host "Processing example call: Microsoft Resource Manager API: List - Subscriptions"
Write-Host " 'ARM API: List - Subscriptions'"
$uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM + "subscriptions?api-version=2020-01-01"
$subscriptions = AzAPICall -uri $uri `
                           -method "GET" `
                           -currentTask "ARM API: List - Subscriptions"

Write-Host " 'ARM API: List - Subscriptions' returned results:" $aadgroups.Count
Write-Host " 'ARM API: List - Subscriptions' first result:" $subscriptions[0].displayName $subscriptions[0].subscriptionId
#EndRegion MicrosoftResourceManagerSubscriptions
#EndRegion Main