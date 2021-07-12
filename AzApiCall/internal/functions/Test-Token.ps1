function Test-Token
{
    <#
    .SYNOPSIS
        check if a valid token exist
    
    .DESCRIPTION
        check if a valid token exist
    
    .PARAMETER targetEndPoint
        Api Endpoint like 'MsGraphApi'

    .EXAMPLE
        PS C:\> Test-Token -targetEndpoint "MsGraphApi"

        check Token
    #>
    [CmdletBinding()]
    param (
        $targetEndpoint
    )
    Write-Verbose "Check token"
    if ($script:htBearerAccessToken.$targetEndpoint.expire.LocalDateTime -lt $(Get-Date).AddMinutes(-5) -or ($null -eq $script:htBearerAccessToken.$targetEndpoint.expire))
    {
        Write-Output "Generate new token for Endpoint $($TargetEndpoint)"
        New-BearerToken -targetEndPoint $targetEndpoint
    }
}
