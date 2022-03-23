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

        [Parameter(Mandatory)]
        [string]
        $writeMethod,

        [Parameter(Mandatory)]
        [string]
        $debugWriteMethod
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
        switch ($debugWriteMethod) {
            'Debug' { Write-Debug '  AzAPICall debug enabled' }
            'Error' { Write-Error '  AzAPICall debug enabled' }
            'Host' { Write-Host '  AzAPICall debug enabled' -ForegroundColor 'Cyan' }
            'Information' { Write-Information '  AzAPICall debug enabled' }
            #'Output' { Write-Output '  AzAPICall debug enabled' } #Not working with a return in a function
            'Output' { Write-Host '  AzAPICall debug enabled' -ForegroundColor 'Cyan' }
            'Progress' { Write-Progress '  AzAPICall debug enabled' }
            'Verbose' { Write-Verbose '  AzAPICall debug enabled' -verbose }
            'Warning' { Write-Warning '  AzAPICall debug enabled' }
            Default { Write-Host '  AzAPICall debug enabled' -ForegroundColor 'Cyan' }
        }
    }
    else {
        Logging -preventWriteOutput $true -logMessage '  AzAPICall debug disabled' -logMessageForegroundColor 'Cyan'
    }

    #Region Test-HashtableParameter
    return [ordered]@{
        debugAzAPICall               = $DebugAzAPICall
        writeMethod                  = $writeMethod
        debugWriteMethod             = $debugWriteMethod
        gitHubRepository             = $GitHubRepository
        psVersion                    = $PSVersionTable.PSVersion
        azAccountsVersion            = $AzAccountsVersion
        azAPICallModuleVersion       = ((Get-Module -Name AzAPICall).Version).ToString()
        codeRunPlatform              = $codeRunPlatform
        onAzureDevOpsOrGitHubActions = [bool]$onAzureDevOpsOrGitHubActions
        onAzureDevOps                = [bool]$onAzureDevOps
        onGitHubActions              = [bool]$onGitHubActions
    }
    #EndRegion Test-HashtableParameter
}