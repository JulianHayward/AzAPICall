#Region Test-HashtableParameter
if ($env:GITHUB_SERVER_URL -and $env:CODESPACES) {
    #GitHub Codespaces
    Write-Host "CheckCodeRunPlatform: running in GitHub Codespaces"
    $checkCodeRunPlatform = "GitHubCodespaces"
}
elseif ($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) {
    #Azure DevOps
    Write-Host "CheckCodeRunPlatform: running in Azure DevOps"
    $checkCodeRunPlatform = "AzureDevOps"
}
elseif ($PSPrivateMetadata) {
    #Azure Automation
    Write-Output "CheckCodeRunPlatform: running in Azure Automation"
    $checkCodeRunPlatform = "AzureAutomation"
}
else {
    #Other Console
    Write-Host "CheckCodeRunPlatform: not Codespaces, not Azure DevOps, not Azure Automation - likely local console"
    $checkCodeRunPlatform = "Console"
}

$htParameters = @{}

if ($DebugAzAPICall) {
    $htParameters.DebugAzAPICall = $true
    write-host "AzAPICall debug enabled" -ForegroundColor Cyan
}
else {
    $htParameters.DebugAzAPICall = $false
    write-host "AzAPICall debug disabled" -ForegroundColor Cyan
}
#EndRegion Test-HashtableParameter