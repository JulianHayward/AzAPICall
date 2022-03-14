﻿function setHtParameters {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)][string]$AzAccountsVersion,
        [Parameter(Mandatory)][string]$GithubRepository,
        [Parameter(Mandatory)][bool]$DebugAzAPICall
    )

    Write-Host ' Create htParameters'
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
    Write-Host '  CodeRunPlatform:' $codeRunPlatform
    #endregion codeRunPlatform


    if ($DebugAzAPICall) {
        write-host '  AzAPICall debug enabled' -ForegroundColor Cyan
    }
    else {
        write-host '  AzAPICall debug disabled' -ForegroundColor Cyan
    }

    #Region Test-HashtableParameter
    return [ordered]@{
        DebugAzAPICall               = $DebugAzAPICall
        GithubRepository             = $GithubRepository
        PSVersion                    = $PSVersionTable.PSVersion
        AzAccountsVersion            = $AzAccountsVersion
        AzAPICallModuleVersion       = ((Get-Module -Name AzAPICall).Version).ToString()
        CodeRunPlatform              = $codeRunPlatform
        onAzureDevOpsOrGitHubActions = [bool]$onAzureDevOpsOrGitHubActions
        onAzureDevOps                = [bool]$onAzureDevOps
        onGitHubActions              = [bool]$onGitHubActions
    }
    #EndRegion Test-HashtableParameter
}