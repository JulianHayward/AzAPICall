#Region Test-Environment
$checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop

$htAzureEnvironmentRelatedUrls = @{}
$htAzureEnvironmentRelatedTargetEndpoints = @{}

foreach ($checkAzEnvironment in $checkAzEnvironments) {
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ARM = $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).KeyVault = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).LogAnalytics = $checkAzEnvironment.AzureOperationalInsightsEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = $checkAzEnvironment.ExtendedProperties.MicrosoftGraphUrl

    ($htAzureEnvironmentRelatedTargetEndpoints).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedTargetEndpoints).($checkAzEnvironment.Name).((($checkAzEnvironment.ResourceManagerUrl) -split "/")[2]) = "ARM"
    ($htAzureEnvironmentRelatedTargetEndpoints).($checkAzEnvironment.Name).((($checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId) -split "/")[2]) = "KeyVault"
    ($htAzureEnvironmentRelatedTargetEndpoints).($checkAzEnvironment.Name).((($checkAzEnvironment.AzureOperationalInsightsEndpointResourceId) -split "/")[2]) = "LogAnalytics"
    ($htAzureEnvironmentRelatedTargetEndpoints).($checkAzEnvironment.Name).((($checkAzEnvironment.ExtendedProperties.MicrosoftGraphUrl) -split "/")[2]) = "MicrosoftGraph"
}
#EndRegion Test-Environment