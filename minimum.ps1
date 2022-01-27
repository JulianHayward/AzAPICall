[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$False)][string]$SubscriptionId4AzContext = "undefined",
    [switch]$DebugAzAPICall
)

#Region Functions

#Region getJWTDetails
. .\functions\getJWTDetails.ps1
#EndRegion getJWTDetails

#Region createBearerToken
$htBearerAccessToken = @{}
. .\functions\createBearerToken.ps1
#EndRegion createBearerToken

#Region AzAPICall
. .\functions\AzAPICall.ps1
#EndRegion AzAPICall

#EndRegion Functions

#Region Variables
$arrayAPICallTracking = [System.Collections.ArrayList]@()
#EndRegion Variables

. .\prerequisites\Test-HashtableParameter.ps1
. .\prerequisites\Test-AzContext.ps1
. .\prerequisites\Test-Environment.ps1
. .\prerequisites\Test-UserType.ps1

# Example calls
# https://graph.microsoft.com/v1.0/groups
Write-Host "----------------------------------------------------------"
Write-Host "Processing example call: Microsoft Graph API: Get - Groups"
$uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph + "/v1.0/groups?`$top=10"
$aadgroups = AzAPICall -uri $uri `
                       -method "GET" `
                       -currentTask "Microsoft Graph API: Get - Groups" `
                       -noPaging $true

Write-Host "Groups First result:" $aadgroups[0].displayName $aadgroups[0].id
Write-Host "Groups Total results:"$aadgroups.Count

# https://management.azure.com/subscriptions?api-version=2020-01-01
Write-Host "------------------------------------------------------"
Write-Host "Processing example call: ARM API: List - Subscriptions"
$uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM + "subscriptions?api-version=2020-01-01"
$subscriptions = AzAPICall -uri $uri `
                       -method "GET" `
                       -currentTask "ARM API: List - Subscriptions" `

Write-Host "Subscriptions First result:" $subscriptions[0].displayName $subscriptions[0].subscriptionId
Write-Host "Subscriptions Total results:"$subscriptions.Count