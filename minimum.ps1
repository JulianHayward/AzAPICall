[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$False)][string]$SubscriptionId4AzContext = "undefined",
    [switch]$DebugAzAPICall
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
#EndRegion Prerequisites

#Region Main
# Example calls
# https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
# GET /groups
Write-Host "----------------------------------------------------------"
Write-Host "Processing example call: Microsoft Graph API: Get - Groups"
$uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph + "/v1.0/groups?`$top=10"
$aadgroups = AzAPICall -uri $uri `
                       -method "GET" `
                       -currentTask "Microsoft Graph API: Get - Groups" `
                       -noPaging $true

Write-Host "Groups First result:" $aadgroups[0].displayName $aadgroups[0].id
Write-Host "Groups Total results:"$aadgroups.Count

# https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
# GET https://management.azure.com/subscriptions?api-version=2020-01-01
Write-Host "------------------------------------------------------"
Write-Host "Processing example call: ARM API: List - Subscriptions"
$uri = ($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM + "subscriptions?api-version=2020-01-01"
$subscriptions = AzAPICall -uri $uri `
                       -method "GET" `
                       -currentTask "ARM API: List - Subscriptions" `

Write-Host "Subscriptions First result:" $subscriptions[0].displayName $subscriptions[0].subscriptionId
Write-Host "Subscriptions Total results:"$subscriptions.Count
#EndRegion Main