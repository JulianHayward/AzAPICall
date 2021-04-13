function Set-AzApiCallEnvironment {
    [CmdletBinding()]
    param (
        
    )
    #region environmentcheck
    $checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop


    foreach ($checkAzEnvironment in $checkAzEnvironments) {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ResourceManagerUrl = $checkAzEnvironment.ResourceManagerUrl
        $arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).AzureKeyVaultUrl = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
        if ($checkAzEnvironment.Name -eq "AzureCloud") {
            ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.com"
        }
        if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
            ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://microsoftgraph.chinacloudapi.cn"
        }
        if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
            ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.us"
        }
        if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
            ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.de"
        }
    }
    #endregion environmentcheck
}