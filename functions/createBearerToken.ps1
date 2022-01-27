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
    Write-Host " +Processing new bearer token request ($targetEndPoint)" -ForegroundColor Cyan
    $contextForToken =  [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
    if ($targetEndPoint -eq "ARM") {
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM)")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "MicrosoftGraph") {
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "KeyVault") {
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).KeyVault)")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "LogAnalytics") {
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).LogAnalytics)")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "PowerBI") {
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).PowerBI)")
        }
        catch {
            $catchResult = $_
        }
    }
    elseif ($targetEndPoint -eq "AzDevOps") {
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.Id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "https://app.vssps.visualstudio.com/")
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
    Write-Host " +Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -ForegroundColor Cyan
    #EndRegion createBearerToken
}