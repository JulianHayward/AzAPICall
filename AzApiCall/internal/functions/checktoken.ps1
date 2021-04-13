function checkToken {
    [CmdletBinding()]
    param (
        $targetEndpoint
    )
    
    Write-Host "Check token"
    if ($script:htBearerAccessToken.$targetEndpoint.expire.LocalDateTime -lt $(Get-Date).AddMinutes(-5) -or ($null -eq $script:htBearerAccessToken.$targetEndpoint.expire)) 
    {
        Write-Host "Generate new token for Endpoint $($TargetEndpoint)"
        createBearerToken -targetEndPoint $targetEndpoint
    }
}