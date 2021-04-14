function createBearerToken
{
    <#
    .SYNOPSIS
        get token for specific Api Endpoint
    
    .DESCRIPTION
        get token for specific Api Endpoint
    
    .PARAMETER targetEndPoint
        Api Endpoint like 'MsGraphApi'

    .EXAMPLE
        PS C:\> createBearerToken -targetEndpoint "MsGraphApi"

        get token
    #>
	[CmdletBinding()]
	param (
		$targetEndPoint
	)
    Set-AzApiCallContext
    Set-AzApiCallEnvironment

    Write-Output "+Processing new bearer token request ($targetEndPoint)"
    if ($targetEndPoint -eq "AzManagementAPI") {
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile;
        $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile);
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = ($profileClient.AcquireAccessToken($script:checkContext.Subscription.TenantId))
        }
        catch {
            $catchResult = $_
        }
    }
    if ($targetEndPoint -eq "MsGraphAPI") {
        $contextForMSGraphToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForMSGraphToken.Account, $contextForMSGraphToken.Environment, $contextForMSGraphToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($script:htAzureEnvironmentRelatedUrls).(checkContext).Environment.Name).MSGraphUrl)")
        }
        catch {
            $catchResult = $_
        }
    }
    if ($targetEndPoint -eq "AzDevOps") {
        $contextForADOToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForADOToken.Account, $contextForADOToken.Environment, $contextForADOToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://app.vssps.visualstudio.com/")
        }
        catch {
            $catchResult = $_
        }
    }
    if ($targetEndPoint -eq "MsPowerBi") {
        $contextForPowerBIToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForPowerBIToken.Account, $contextForPowerBIToken.Environment, $contextForPowerBIToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com")
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

    if ($targetEndPoint -eq "AzManagementAPI") {
        $script:htBearerAccessToken.AzManagementAPI = [PSCustomObject]@{
            AccessToken = $newBearerAccessTokenRequest.AccessToken
            expire = $newBearerAccessTokenRequest.ExpiresOn
        }
    }
    if ($targetEndPoint -eq "MsGraphAPI") {
        $script:htBearerAccessToken.MsGraphAPI = [PSCustomObject]@{
            AccessToken = $newBearerAccessTokenRequest.AccessToken
            expire = $newBearerAccessTokenRequest.ExpiresOn
        }
    }
    if ($targetEndPoint -eq "AzDevOps") {
        $script:htBearerAccessToken.AzDevOps = [PSCustomObject]@{
            AccessToken = $newBearerAccessTokenRequest.AccessToken
            expire = $newBearerAccessTokenRequest.ExpiresOn
        }
    }
    if ($targetEndPoint -eq "MsPowerBi") {
        $script:htBearerAccessToken.MsPowerBi = [PSCustomObject]@{
            AccessToken = $newBearerAccessTokenRequest.AccessToken
            expire = $newBearerAccessTokenRequest.ExpiresOn
        }
    }

    $bearerDetails = GetJWTDetails -token $newBearerAccessTokenRequest.AccessToken
    $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
    $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
    Write-Host "+Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']"
}