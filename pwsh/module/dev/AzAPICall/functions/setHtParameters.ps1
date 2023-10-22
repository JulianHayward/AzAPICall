function setHtParameters {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [string]
        $AzAccountsVersion,

        [Parameter(Mandatory)]
        [string]
        $GitHubRepository,

        [Parameter(Mandatory)]
        [bool]
        $DebugAzAPICall,

        [Parameter(Mandatory = $false)]
        [string]
        $SubscriptionId4AzContext,

        [Parameter(Mandatory = $false)]
        [string]
        $TenantId4AzContext,

        [Parameter(Mandatory)]
        [bool]
        $SkipAzContextSubscriptionValidation
    )

    Logging -preventWriteOutput $true -logMessage ' Create htParameters'
    #region codeRunPlatform
    $onAzureDevOps = $false
    $onAzureDevOpsOrGitHubActions = $false
    if ($env:GITHUB_SERVER_URL -and $env:CODESPACES) {
        $codeRunPlatform = 'GitHubCodespaces'
    }
    elseif ($env:REMOTE_CONTAINERS) {
        $codeRunPlatform = 'RemoteContainers'
    }
    elseif ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
        $codeRunPlatform = 'AzureDevOps'
        $onAzureDevOps = $true
        $onAzureDevOpsOrGitHubActions = $true
    }
    elseif ($PSPrivateMetadata) {
        $codeRunPlatform = 'AzureAutomation'
    }
    elseif ($env:GITHUB_ACTIONS) {
        $codeRunPlatform = 'GitHubActions'
        $onGitHubActions = $true
        $onAzureDevOpsOrGitHubActions = $true
    }
    elseif ($env:ACC_IDLE_TIME_LIMIT -and $env:AZURE_HTTP_USER_AGENT -and $env:AZUREPS_HOST_ENVIRONMENT) {
        $codeRunPlatform = 'CloudShell'
    }
    else {
        $codeRunPlatform = 'Console'
    }
    Logging -preventWriteOutput $true -logMessage "  codeRunPlatform: $codeRunPlatform"
    #endregion codeRunPlatform


    if ($DebugAzAPICall) {
        Logging -preventWriteOutput $true -logMessage '  AzAPICall debug enabled' -logMessageForegroundColor 'Cyan'
    }
    else {
        Logging -preventWriteOutput $true -logMessage '  AzAPICall debug disabled' -logMessageForegroundColor 'Cyan'
    }

    # if ($DebugAzAPICall) {
    #     Logging -preventWriteOutput $true -logMessage '  <_______________________________________' -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage '  AzAPICall preparing ht for return' -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     debugAzAPICall                      = $DebugAzAPICall" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     gitHubRepository                    = $GitHubRepository" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     psVersion                           = $($PSVersionTable.PSVersion)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     azAccountsVersion                   = $AzAccountsVersion" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     azAPICallModuleVersion              = $AzAPICallVersion" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     codeRunPlatform                     = $codeRunPlatform" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     onAzureDevOpsOrGitHubActions        = $([bool]$onAzureDevOpsOrGitHubActions)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     onAzureDevOps                       = $([bool]$onAzureDevOps)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     onGitHubActions                     = $([bool]$onGitHubActions)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     subscriptionId4AzContext            = $($SubscriptionId4AzContext)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     tenantId4AzContext                  = $($TenantId4AzContext)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage "     skipAzContextSubscriptionValidation = $([bool]$SkipAzContextSubscriptionValidation)" -logMessageForegroundColor 'Cyan'
    #     Logging -preventWriteOutput $true -logMessage '  _______________________________________>' -logMessageForegroundColor 'Cyan'
    # }

    #Region Test-HashtableParameter
    $htParameters = [ordered]@{
        debugAzAPICall                      = $DebugAzAPICall
        gitHubRepository                    = $GitHubRepository
        psVersion                           = $PSVersionTable.PSVersion
        azAccountsVersion                   = $AzAccountsVersion
        azAPICallModuleVersion              = $AzAPICallVersion
        codeRunPlatform                     = $codeRunPlatform
        onAzureDevOpsOrGitHubActions        = [bool]$onAzureDevOpsOrGitHubActions
        onAzureDevOps                       = [bool]$onAzureDevOps
        onGitHubActions                     = [bool]$onGitHubActions
        subscriptionId4AzContext            = $subscriptionId4AzContext
        tenantId4AzContext                  = $tenantId4AzContext
        skipAzContextSubscriptionValidation = [bool]$skipAzContextSubscriptionValidation
    }

    return $htParameters
    #EndRegion Test-HashtableParameter
}