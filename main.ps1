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
        .\functions\getJWTDetails.ps1
        $funcGetJWTDetails = $function:getJWTDetails.ToString()
        #EndRegion getJWTDetails

        #Region createBearerToken
        .\functions\createBearerToken.ps1
        $funcCreateBearerToken = $function:createBearerToken.ToString()
        $htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
        #EndRegion createBearerToken

        #Region AzAPICall
        .\functions\AzAPICall.ps1
        $funcAzAPICall = $function:AzAPICall.ToString()
        #EndRegionAzAPICall
    #EndRegion Functions

    #Region Variables
    if($PsParallelization) {
        $arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    } else {
        $arrayAPICallTracking = [System.Collections.ArrayList]@()
    }
    #EndRegion Variables

    .\prerequisites\Test-HashtableParameter.ps1
    .\prerequisites\Test-PowerShellVersion.ps1
    .\prerequisites\Test-AzModules.ps1
    .\prerequisites\Test-AzContext.ps1
    .\prerequisites\Test-Environment.ps1
#EndRegion Prerequisites

#Region Main
Clear-AzContext -Force
Connect-AzAccount -TenantId $TenantId

#Region BearerToken
#create bearer token
createBearerToken -targetEndPoint "MicrosoftGraph"
# createBearerToken -targetEndPoint "ARM"
# createBearerToken -targetEndPoint "KeyVault"
# createBearerToken -targetEndPoint "LogAnalytics"
#EndRegion BearerToken

# Example calls
#Region MicrosoftGraphGroupList
# https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
$uri = $uriMicrosoftGraph + "/v1.0/groups?`$top=999&`$filter=(mailEnabled eq false and securityEnabled eq true)&`$select=id,createdDateTime,displayName,description&`$orderby=displayName asc&`$count=true" # https://graph.microsoft.com/v1.0/groups
$listenOn = "Value" #Default
$currentTask = "Microsoft Graph API: Get - Groups"
$method = "GET"
$aadgroups = AzAPICall -uri $uri `
                       -method $method `
                       -currentTask $currentTask `
                       -listenOn $listenOn `
                       -consistencyLevel "eventual" `
                       -noPaging $true #$top in url + paging = $true will iterate further https://docs.microsoft.com/en-us/graph/paging

$aadgroups.Count
#EndRegion MicrosoftGraphGroupList

#Region MicrosoftGraphGroupMemberList
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
    $uri = $uriMicrosoftGraph + "/v1.0/groups/$($group.id)/members" # https://graph.microsoft.com/v1.0/groups/<GroupId>/members
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

$htAzureAdGroupDetails.Keys.Count
$htAzureAdGroupDetails.Values.Id.Count
#EndRegion MicrosoftGraphGroupMemberList
#EndRegion Main