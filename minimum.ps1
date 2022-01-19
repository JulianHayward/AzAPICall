[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$False)][string]$SubscriptionId4AzContext = "undefined"
)

#Region Functions

#Region getJWTDetails
. .\functions\getJWTDetails.ps1
#EndRegion getJWTDetails

#Region createBearerToken
. .\functions\createBearerToken.ps1
$htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#EndRegion createBearerToken

#Region AzAPICall
. .\functions\AzAPICall.ps1
#EndRegion AzAPICall

#EndRegion Functions

#Region Variables
$arrayAPICallTracking = [System.Collections.ArrayList]@()
$htParameters = @{}
$htParameters.DebugAzAPICall = $true
#EndRegion Variables

#Connect-AzAccount -Tenant "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -SubscriptionId "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

. .\prerequisites\Test-AzContext.ps1
. .\prerequisites\Test-Environment.ps1

#create bearer token
createBearerToken -targetEndPoint "MicrosoftGraph"

# Example calls
# https://graph.microsoft.com/v1.0/groups
$uri = $uriMicrosoftGraph + "/v1.0/groups?`$top=10"
$aadgroups = AzAPICall -uri $uri `
                       -method "GET" `
                       -currentTask "Microsoft Graph API: Get - Groups" `
                       -noPaging $true

$aadgroups[0]
$aadgroups.Count