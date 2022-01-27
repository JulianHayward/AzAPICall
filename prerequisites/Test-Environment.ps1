#Region Test-Environment
$checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop

$htAzureEnvironmentRelatedUrls = @{}

foreach ($checkAzEnvironment in $checkAzEnvironments) {
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ARM = $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).KeyVault = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).LogAnalytics = $checkAzEnvironment.AzureOperationalInsightsEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = $checkAzEnvironment.ExtendedProperties.MicrosoftGraphUrl

    #if ($checkAzEnvironment.Name -eq "AzureCloud") {
    #    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).PowerBI = "https://graph.microsoft.com"
    #}
}

#$uriMicrosoftGraph = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)"
#$uriARM = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM)"
#$uriKeyVault = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).KeyVault)"
#$uriLogAnalytics = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).LogAnalytics)"
#$uriPowerBI = "https://api.powerbi.com/v1.0/"
#$uriAzDevops = "<uri>"
#EndRegion Test-Environment