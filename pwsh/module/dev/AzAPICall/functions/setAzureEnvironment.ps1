function setAzureEnvironment {
    param(
        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration
    )
    #Region Test-Environment
    Logging -preventWriteOutput $true -logMessage ' Set environment endPoint url mapping'

    function testAvailable {
        [CmdletBinding()]Param(
            [string]$EndpointUrl,
            [string]$Endpoint,
            [string]$EnvironmentKey
        )
        Logging -preventWriteOutput $true -logMessage "  Check endpoint: '$($Endpoint)'; endpoint url: '$($EndpointUrl)'"
        if ([string]::IsNullOrWhiteSpace($EndpointUrl)) {
            if ($Endpoint -eq 'MicrosoftGraph') {
                Logging -preventWriteOutput $true -logMessage "  Older Az.Accounts version in use (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey) not existing). AzureEnvironmentRelatedUrls -> Setting static Microsoft Graph Url '$($legacyAzAccountsEnvironmentMicrosoftGraphUrls.($AzApiCallConfiguration['checkContext'].Environment.Name))'"
                return $legacyAzAccountsEnvironmentMicrosoftGraphUrls.($AzApiCallConfiguration['checkContext'].Environment.Name)
            }
            else {
                Logging -preventWriteOutput $true -logMessage "  Cannot read '$($Endpoint)' endpoint from current context (`$AzApiCallConfiguration.checkContext.Environment.$($EnvironmentKey))"
                Logging -preventWriteOutput $true -logMessage "  Please check current context (Subscription criteria: quotaId notLike 'AAD*'; state = enabled); Install latest Az.Accounts version"
                Logging -preventWriteOutput $true -logMessage ($checkContext | Format-List | Out-String)
                Throw 'Error - check the last console output for details'
            }
        }
        else {
            return [string]($EndpointUrl -replace '\/$')
        }
    }

    #MicrosoftGraph Urls for older Az.Accounts version
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls = @{}
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureCloud'] = 'https://graph.microsoft.com'
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureUSGovernment'] = 'https://graph.microsoft.us'
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureChinaCloud'] = 'https://microsoftgraph.chinacloudapi.cn'
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls['AzureGermanCloud'] = 'https://graph.microsoft.de'

    #AzureEnvironmentRelatedUrls
    $AzAPICallConfiguration['azAPIEndpointUrls'] = @{ }
    $AzAPICallConfiguration['azAPIEndpointUrls'].ARM = (testAvailable -Endpoint 'ARM' -EnvironmentKey 'ResourceManagerUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ResourceManagerUrl)
    $AzAPICallConfiguration['azAPIEndpointUrls'].KeyVault = (testAvailable -Endpoint 'KeyVault' -EnvironmentKey 'AzureKeyVaultServiceEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureKeyVaultServiceEndpointResourceId)
    $AzAPICallConfiguration['azAPIEndpointUrls'].LogAnalytics = (testAvailable -Endpoint 'LogAnalytics' -EnvironmentKey 'AzureOperationalInsightsEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureOperationalInsightsEndpointResourceId)
    $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph = (testAvailable -Endpoint 'MicrosoftGraph' -EnvironmentKey 'ExtendedProperties.MicrosoftGraphUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ExtendedProperties.MicrosoftGraphUrl)
    $AzAPICallConfiguration['azAPIEndpointUrls'].StorageAuth = 'https://storage.azure.com'
    $AzAPICallConfiguration['azAPIEndpointUrls'].Storage = 'core.windows.net'
    $AzAPICallConfiguration['azAPIEndpointUrls'].Login = (testAvailable -Endpoint 'Login' -EnvironmentKey 'ActiveDirectoryAuthority' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ActiveDirectoryAuthority)

    #AzureEnvironmentRelatedTargetEndpoints
    $AzAPICallConfiguration['azAPIEndpoints'] = @{ }
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM -split '/')[2]) = 'ARM'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].KeyVault -split '/')[2]) = 'KeyVault'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].LogAnalytics -split '/')[2]) = 'LogAnalytics'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph -split '/')[2]) = 'MicrosoftGraph'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].StorageAuth)) = 'StorageAuth'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].Storage)) = 'Storage'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].Login -split '/')[2]) = 'Login'

    Logging -preventWriteOutput $true -logMessage '  Set environment endPoint url mapping succeeded' -logMessageForegroundColor 'Green'
    return $AzApiCallConfiguration
}