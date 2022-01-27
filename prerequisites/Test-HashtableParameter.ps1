#region CheckCodeRunPlatform
if ($env:GITHUB_SERVER_URL -and $env:CODESPACES) {
    #GitHub Codespaces
    $checkCodeRunPlatform = "GitHubCodespaces"
}
elseif ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
    #Azure DevOps
    $checkCodeRunPlatform = "AzureDevOps"
}
elseif ($PSPrivateMetadata) {
    #Azure Automation
    $checkCodeRunPlatform = "AzureAutomation"
}
elseif ($env:GITHUB_ACTIONS) {
    #GitHub Actions
    $checkCodeRunPlatform = "GitHubActions"
}
elseif ($env:ACC_IDLE_TIME_LIMIT -and $env:AZURE_HTTP_USER_AGENT -and $env:AZUREPS_HOST_ENVIRONMENT) {
    #Azure Cloud Shell
    $checkCodeRunPlatform = "CloudShell"
}
else {
    #Other Console
    $checkCodeRunPlatform = "Console"
}
Write-Host "CheckCodeRunPlatform:" $checkCodeRunPlatform
#endregion CheckCodeRunPlatform

if ($DebugAzAPICall){
    write-host "AzAPICall debug enabled" -ForegroundColor Cyan
}

#Region Test-HashtableParameter
$htParameters = @{
    DebugAzAPICall  = [bool]$DebugAzAPICall
    CodeRunPlatform = $checkCodeRunPlatform
    GitHubRepository = "https://github.com/JulianHayward/AzAPICall"
}
#EndRegion Test-HashtableParameter