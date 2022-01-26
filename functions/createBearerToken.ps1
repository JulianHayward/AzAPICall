function createBearerToken {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER targetEndPoint
    MicrosoftGraph, ARM, KeyVault, LogAnalytics

    .EXAMPLE
    PS C:\> createBearerToken -targetEndPoint "MicrosoftGraph"

    .NOTES
    General notes
    #>
    param (
        [Parameter(Mandatory = $true)][string]$targetEndPoint
    )
    #Region createBearerToken
    $checkContext = Get-AzContext -ErrorAction Stop
    Write-Host "+Processing new bearer token request ($targetEndPoint)"
    if ($targetEndPoint -eq "ARM") {
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
    elseif ($targetEndPoint -eq "MicrosoftGraph") {
        $contextForMSGraphToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForMSGraphToken.Account, $contextForMSGraphToken.Environment, $contextForMSGraphToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "KeyVault") {
        $contextForKeyVaultToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForKeyVaultToken.Account, $contextForKeyVaultToken.Environment, $contextForKeyVaultToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "LogAnalytics") {
        $contextForLogAnalyticsToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForLogAnalyticsToken.Account, $contextForLogAnalyticsToken.Environment, $contextForLogAnalyticsToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "PowerBI") {
        $contextForPowerBIToken = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForPowerBIToken.Account, $contextForPowerBIToken.Environment, $contextForPowerBIToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://graph.microsoft.com")
        }
        catch {
            $catchResult = $_
        }
    }
    else {
        Throw "Error - Unknown targetEndPoint '$targetEndPoint'"
    }

    if ($catchResult -ne "letscheck") {
        Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
        Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount' to set up your Azure credentials."
        Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount'."
        Throw "Error - check the last console output for details"
    }

    $dateTimeTokenCreated = (get-date -format "MM/dd/yyyy HH:mm:ss")

    $script:htBearerAccessToken.$targetEndPoint = $newBearerAccessTokenRequest.AccessToken

    $bearerDetails = GetJWTDetails -token $newBearerAccessTokenRequest.AccessToken
    $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
    $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
    Write-Host "+Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']"
    #EndRegion createBearerToken
}