function createBearerToken {

    param (
        [Parameter(Mandatory)]
        [string]
        $targetEndPoint,

        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )

    Logging -logMessage " +Processing new bearer token request '$targetEndPoint' ($($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint))"

    if (($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint) {

        $azContext = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint)")
        }
        catch {
            Logging -logMessage "-ERROR processing new bearer token request ($targetEndPoint): $_" -logMessageWriteMethod 'Error'
            Logging -logMessage "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount -tenantId <tenantId>' to set up your Azure credentials."
            Logging -logMessage "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount -tenantId <tenantId>'."
            Throw 'Error - check the last console output for details'
        }

        $dateTimeTokenCreated = (Get-Date -Format 'MM/dd/yyyy HH:mm:ss')

        ($AzApiCallConfiguration['htBearerAccessToken']).$targetEndPoint = $newBearerAccessTokenRequest.AccessToken

        $bearerDetails = getJWTDetails -token $newBearerAccessTokenRequest.AccessToken
        $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
        $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
        Logging -logMessage " +Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
    }
    else {
        Logging -logMessage "targetEndPoint: '$targetEndPoint' unknown" -logMessageWriteMethod 'Error'
        throw
    }
}