function Set-AzApiCallContext
{
    <#
    .SYNOPSIS
        Set-Context for Auth

    .DESCRIPTION
        Set-Context for Auth

    .EXAMPLE
        PS C:\> Set-AzApiCallContext

        Set Context
    #>

    [CmdletBinding()]
    param (
        
    )
    
#region checkAzContext
    $script:checkContext = Get-AzContext -ErrorAction Stop
    Write-Host "Checking Az Context"
    if (-not $checkContext) {
        Write-Host " Context test failed: No context found. Please connect to Azure (run: Connect-AzAccount) and re-run AzApiCall" -ForegroundColor Red
        Throw "Error - check the last console output for details"
    }
    else {
        $accountType = $script:checkContext.Account.Type
        $accountId = $script:checkContext.Account.id
        Write-Host " Context AccountId: '$($accountId)'" -ForegroundColor Yellow
        Write-Host " Context AccountType: '$($accountType)'" -ForegroundColor Yellow

        <#if ($SubscriptionId4AzContext -ne "undefined") {
            Write-Host " Setting AzContext to SubscriptionId: '$SubscriptionId4AzContext'" -ForegroundColor Yellow
            try {
                Set-AzContext -SubscriptionId $SubscriptionId4AzContext
            }
            catch {
                Throw "Error - check the last console output for details"
            }
            $checkContext = Get-AzContext -ErrorAction Stop
        }#>
        
        #else{
        if (-not $script:checkContext.Subscription) { #Maybe delete
            $checkContext
            Write-Host " Context test failed: Context is not set to any Subscription. Set your context to a subscription by running: Set-AzContext -subscription <subscriptionId> (run Get-AzSubscription to get the list of available Subscriptions). When done re-run script" -ForegroundColor Red
            Throw "Error - check the last console output for details"
        }
        else {
            Write-Host " Context test passed: Context OK" -ForegroundColor Green
        }
        #}
    }
}