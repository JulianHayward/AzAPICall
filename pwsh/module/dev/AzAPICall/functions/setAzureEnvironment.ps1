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

        if ($Endpoint -eq 'Storage') {
            Logging -preventWriteOutput $true -logMessage "  Check endpoint: '$($Endpoint)'; endpoint url: '.$($EndpointUrl)'"
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Check endpoint: '$($Endpoint)'; endpoint url: '$($EndpointUrl)'"
        }
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
            if ($Endpoint -eq 'Storage') {
                return [string](".$($EndpointUrl -replace '\/$')")
            }
            else {
                return [string]($EndpointUrl -replace '\/$')
            }
        }
    }

    #MicrosoftGraph Urls for older Az.Accounts version
    $legacyAzAccountsEnvironmentMicrosoftGraphUrls = @{
        AzureCloud        = 'https://graph.microsoft.com'
        AzureUSGovernment = 'https://graph.microsoft.us'
        AzureChinaCloud   = 'https://microsoftgraph.chinacloudapi.cn'
        AzureGermanCloud  = 'https://graph.microsoft.de'
    }

    #AzureEnvironmentRelatedUrls
    $AzAPICallConfiguration['azAPIEndpointUrls'] = @{ }
    #ARM
    $AzAPICallConfiguration['azAPIEndpointUrls'].ARM = (testAvailable -Endpoint 'ARM' -EnvironmentKey 'ResourceManagerUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ResourceManagerUrl)
    #KeyVault
    $AzAPICallConfiguration['azAPIEndpointUrls'].KeyVault = (testAvailable -Endpoint 'KeyVault' -EnvironmentKey 'AzureKeyVaultServiceEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureKeyVaultServiceEndpointResourceId)
    #LogAnalytics
    $AzAPICallConfiguration['azAPIEndpointUrls'].LogAnalytics = (testAvailable -Endpoint 'LogAnalytics' -EnvironmentKey 'AzureOperationalInsightsEndpointResourceId' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.AzureOperationalInsightsEndpointResourceId)
    #MicrosoftGraph
    $AzAPICallConfiguration['azAPIEndpointUrls'].MicrosoftGraph = (testAvailable -Endpoint 'MicrosoftGraph' -EnvironmentKey 'ExtendedProperties.MicrosoftGraphUrl' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ExtendedProperties.MicrosoftGraphUrl)
    #Login
    $AzAPICallConfiguration['azAPIEndpointUrls'].Login = (testAvailable -Endpoint 'Login' -EnvironmentKey 'ActiveDirectoryAuthority' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.ActiveDirectoryAuthority)
    #Storage
    $AzAPICallConfiguration['azAPIEndpointUrls'].Storage = [System.Collections.ArrayList]@()
    $null = $AzAPICallConfiguration['azAPIEndpointUrls'].Storage.Add((testAvailable -Endpoint 'Storage' -EnvironmentKey 'StorageEndpointSuffix' -EndpointUrl $AzApiCallConfiguration['checkContext'].Environment.StorageEndpointSuffix))
    $null = $AzAPICallConfiguration['azAPIEndpointUrls'].Storage.Add('.storage.azure.net')
    Logging -preventWriteOutput $true -logMessage "  Add to endpoint: 'Storage'; endpoint url: '.storage.azure.net'"
    $AzAPICallConfiguration['azAPIEndpointUrls'].StorageAuth = 'https://storage.azure.com'
    Logging -preventWriteOutput $true -logMessage "  Auth endpoint for 'Storage': '$($AzAPICallConfiguration['azAPIEndpointUrls'].StorageAuth)'"
    #IssuerUri
    if ($AzApiCallConfiguration['checkContext'].Environment.Name -eq 'AzureChinaCloud') {
        $AzAPICallConfiguration['azAPIEndpointUrls'].IssuerUri = 'https://sts.chinacloudapi.cn'
    }
    else {
        $AzAPICallConfiguration['azAPIEndpointUrls'].IssuerUri = 'https://sts.windows.net'
    }
    #Kusto
    $AzAPICallConfiguration['azAPIEndpointUrls'].Kusto = '.kusto.windows.net'
    Logging -preventWriteOutput $true -logMessage "  Set endpoint: 'Kusto'; endpoint url: '.kusto.windows.net'"
    #MonitorIngest https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview
    $ingestMonitorAuthUrls = @{
        AzureCloud        = 'https://monitor.azure.com'
        AzureUSGovernment = 'https://monitor.azure.us'
        AzureChinaCloud   = 'https://monitor.azure.cn'
    }
    $AzAPICallConfiguration['azAPIEndpointUrls'].MonitorIngest = ".ingest.$($ingestMonitorAuthUrls.($AzApiCallConfiguration['checkContext'].Environment.Name) -replace 'https://')"
    Logging -preventWriteOutput $true -logMessage "  Set endpoint: 'MonitorIngest'; endpoint url: '$($AzAPICallConfiguration['azAPIEndpointUrls'].MonitorIngest)'"
    $AzAPICallConfiguration['azAPIEndpointUrls'].MonitorIngestAuth = $ingestMonitorAuthUrls.($AzApiCallConfiguration['checkContext'].Environment.Name)
    Logging -preventWriteOutput $true -logMessage "  Auth endpoint for 'MonitorIngest': '$($AzAPICallConfiguration['azAPIEndpointUrls'].MonitorIngestAuth)'"

    #AzureEnvironmentRelatedTargetEndpoints
    $AzAPICallConfiguration['azAPIEndpoints'] = @{ }
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].ARM -split '/')[2]) = 'ARM'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].KeyVault -split '/')[2]) = 'KeyVault'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].LogAnalytics -split '/')[2]) = 'LogAnalytics'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].MicrosoftGraph -split '/')[2]) = 'MicrosoftGraph'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].Login -split '/')[2]) = 'Login'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].Storage)) = 'Storage'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].StorageAuth)) = 'StorageAuth'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].MonitorIngest)) = 'MonitorIngest'
    $AzAPICallConfiguration['azAPIEndpoints'].(($AzApiCallConfiguration['azAPIEndpointUrls'].MonitorIngestAuth)) = 'MonitorIngestAuth'

    Logging -preventWriteOutput $true -logMessage '  Set environment endPoint url mapping succeeded' -logMessageForegroundColor 'Green'
    return $AzApiCallConfiguration
}