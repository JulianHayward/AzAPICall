function Set-AzApiCallEnvironment
{
    <#
    .SYNOPSIS
        Set-AzApiCallEnvironment
    
    .DESCRIPTION
        Set-AzApiCallEnvironment
    
    .EXAMPLE
        PS C:\> Set-AzApiCallEnvironment

        Set Envirement for different Cloud (Global, GCC, China)
    #>
    [CmdletBinding()]
    param (
        
    )
    #region environmentcheck
    $checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop


    foreach ($checkAzEnvironment in $checkAzEnvironments) {
        ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
        ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ResourceManagerUrl = $checkAzEnvironment.ResourceManagerUrl
        $script:arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
        ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).AzureKeyVaultUrl = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
        if ($checkAzEnvironment.Name -eq "AzureCloud") {
            ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.com"
        }
        if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
            ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://microsoftgraph.chinacloudapi.cn"
        }
        if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
            ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.us"
        }
        if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
            ($script:htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MSGraphUrl = "https://graph.microsoft.de"
        }
    }
    #endregion environmentcheck
}