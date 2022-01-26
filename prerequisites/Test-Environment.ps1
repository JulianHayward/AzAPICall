#Region Test-Environment
$checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop

#FutureUse
#Graph Endpoints https://docs.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
#AzureCloud https://graph.microsoft.com
#AzureUSGovernment L4 https://graph.microsoft.us
#AzureUSGovernment L5 (DOD) https://dod-graph.microsoft.us
#AzureChinaCloud https://microsoftgraph.chinacloudapi.cn
#AzureGermanCloud https://graph.microsoft.de

#AzureEnvironmentRelatedUrls
$htAzureEnvironmentRelatedUrls = @{ }
$arrayAzureManagementEndPointUrls = @()
foreach ($checkAzEnvironment in $checkAzEnvironments) {
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ARM = $checkAzEnvironment.ResourceManagerUrl
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).KeyVault = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).LogAnalytics = $checkAzEnvironment.AzureOperationalInsightsEndpoint
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.AzureOperationalInsightsEndpoint
    if ($checkAzEnvironment.Name -eq "AzureCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.com"
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).PowerBI = "https://api.powerbi.com/v1.0/"
    }
    if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://microsoftgraph.chinacloudapi.cn"
    }
    if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.us"
    }
    if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.de"
    }
}

$uriMicrosoftGraph = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)"
$uriARM = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM)"
$uriKeyVault = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).KeyVault)"
$uriLogAnalytics = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).LogAnalytics)"
#EndRegion Test-Environment