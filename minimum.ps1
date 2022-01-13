#Region Functions
#Region getJWTDetails
. .\functions\getJWTDetails.ps1
$funcGetJWTDetails = $function:getJWTDetails.ToString()
#EndRegion getJWTDetails

#Region createBearerToken
. .\functions\createBearerToken.ps1
$funcCreateBearerToken = $function:createBearerToken.ToString()
$htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#EndRegion createBearerToken

#Region AzAPICall
. .\functions\AzAPICall.ps1
$funcAzAPICall = $function:AzAPICall.ToString()
#EndRegion AzAPICall
#EndRegion Functions

#Region Variables
$arrayAPICallTracking = [System.Collections.ArrayList]@()
$htParameters = @{}
$htParameters.DebugAzAPICall = $true
#EndRegion Variables

Connect-AzAccount -Tenant "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" `
                  -SubscriptionId "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"

. .\prerequisites\Test-Environment.ps1

#create bearer token
createBearerToken -targetEndPoint "MicrosoftGraph"

# Example calls
# https://graph.microsoft.com/v1.0/groups
$aadgroups = AzAPICall -uri "https://graph.microsoft.com/v1.0/groups?`$top=10" `
                       -method "GET" `
                       -currentTask "Microsoft Graph API: Get - Groups" `
                       -noPaging $true

$aadgroups[0]
$aadgroups.Count