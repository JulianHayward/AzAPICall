# https://github.com/JulianHayward/AzAPICall

Param
(
    [Parameter(Mandatory = $False)][bool]$DebugAzAPICall,
    [Parameter(Mandatory = $False)][string]$SubscriptionId4AzContext = 'undefined'
)

#region parallelization
$NoPsParallelization = $false
if (-not $NoPsParallelization) {
    function testPowerShellVersion {

        Write-Host ' Checking PowerShell edition and version'
        $requiredPSVersion = '7.0.3'
        $splitRequiredPSVersion = $requiredPSVersion.split('.')
        $splitRequiredPSVersionMajor = $splitRequiredPSVersion[0]
        $splitRequiredPSVersionMinor = $splitRequiredPSVersion[1]
        $splitRequiredPSVersionPatch = $splitRequiredPSVersion[2]

        $thisPSVersion = ($PSVersionTable.PSVersion)
        $thisPSVersionMajor = ($thisPSVersion).Major
        $thisPSVersionMinor = ($thisPSVersion).Minor
        $thisPSVersionPatch = ($thisPSVersion).Patch

        $psVersionCheckResult = 'letsCheck'

        if ($PSVersionTable.PSEdition -eq 'Core' -and $thisPSVersionMajor -eq $splitRequiredPSVersionMajor) {
            if ($thisPSVersionMinor -gt $splitRequiredPSVersionMinor) {
                $psVersionCheckResult = 'passed'
                $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$thisPSVersionMinor] gt $($splitRequiredPSVersionMinor))"
            }
            else {
                if ($thisPSVersionPatch -ge $splitRequiredPSVersionPatch) {
                    $psVersionCheckResult = 'passed'
                    $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$splitRequiredPSVersionMinor]; Patch[$thisPSVersionPatch] gt $($splitRequiredPSVersionPatch))"
                }
                else {
                    $psVersionCheckResult = 'failed'
                    $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$splitRequiredPSVersionMinor]; Patch[$thisPSVersionPatch] lt $($splitRequiredPSVersionPatch))"
                }
            }
        }
        else {
            $psVersionCheckResult = 'failed'
            $psVersionCheck = "(Major[$splitRequiredPSVersionMajor] ne $($splitRequiredPSVersionMajor))"
        }

        if ($psVersionCheckResult -eq 'passed') {
            Write-Host "  PS check $psVersionCheckResult : $($psVersionCheck); (minimum supported version '$requiredPSVersion')"
            Write-Host "  PS Edition: $($PSVersionTable.PSEdition); PS Version: $($PSVersionTable.PSVersion)"
            Write-Host '  PS Version check succeeded' -ForegroundColor Green
        }
        else {
            Write-Host "  PS check $psVersionCheckResult : $($psVersionCheck)"
            Write-Host "  PS Edition: $($PSVersionTable.PSEdition); PS Version: $($PSVersionTable.PSVersion)"
            Write-Host "  Parallelization requires Powershell 'Core' version '$($requiredPSVersion)' or higher"
            Throw 'Error - check the last console output for details'
        }
    }
    testPowerShellVersion
    $ThrottleLimitMicrosoftGraph = 20
    $ThrottleLimitARM = 10
}
#endregion parallelization

#region preferences
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.2#erroractionpreference
$ErrorActionPreference = 'Stop'
# https://docs.microsoft.com/de-de/powershell/azure/faq?view=azps-7.1.0#how-do-i-disable-breaking-change-warning-messages-in-azure-powershell-
$ProgressPreference = 'SilentlyContinue'
Set-Item Env:\SuppressAzurePowerShellBreakingChangeWarnings 'true'
#endregion preferences

#Connect | at this stage you should be connected to Azure
#connect-azaccount

#region verifyAZAPICall
Write-Host " Verify 'AzAPICall'"
do {
    try {
        Import-Module -Name AzAPICall
        $importAzAPICallModuleSuccess = $true
    }
    catch {
        Write-Host '  AzAPICall module not found'
        do {
            $installAzAPICallModuleUserChoice = Read-Host '  Do you want to install module AzAPICall from the PowerShell Gallery? (y/n)'
            if ($installAzAPICallModuleUserChoice -eq 'y') {
                try {
                    Install-Module -Name AzAPICall
                }
                catch {
                    Write-Host '  Install-Module -Name AzAPICall Failed'
                    throw
                }
            }
            elseif ($installAzAPICallModuleUserChoice -eq 'n') {
                Write-Host '  AzAPICall module is required, please visit https://aka.ms/AZAPICall or https://www.powershellgallery.com/packages/AzAPICall'
                throw
            }
            else {
                Write-Host "  Accepted input 'y' or 'n'; start over.."
            }
        }
        until ($installAzAPICallModuleUserChoice -eq 'y')
    }
}
until ($importAzAPICallModuleSuccess)
$AzAPICallModuleVersion = (Get-Module -Name AzAPICall).Version
Write-Host "  Import PS module 'AzAPICall' succeeded" -ForegroundColor Green
#endregion verifyAZAPICall

#region initAZAPICall
Write-Host "Initialize 'AzAPICall'"
$parameters4AzAPICallModule = @{
    DebugAzAPICall           = $DebugAzAPICall
    SubscriptionId4AzContext = $SubscriptionId4AzContext
    AzAPICallModuleVersion   = "$($AzAPICallModuleVersion.Major).$($AzAPICallModuleVersion.Minor).$($AzAPICallModuleVersion.Build)"
}
$Configuration = initAzAPICall @parameters4AzAPICallModule
Write-Host "Initialize 'AzAPICall' ($($parameters4AzAPICallModule.AzAPICallModuleVersion)) succeeded" -ForegroundColor Green
#endregion initAZAPICall

$AzAPICallFunctions = getAzAPICallFunctions

#region Main
# Example calls

#region ValidateAccess
$apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
$apiEndPointVersion = '/v1.0'
$api = '/groups'
$optionalQueryParameters = '?$count=true&$top=1'

#$uri = 'https://graph.microsoft.com/v1.0/groups?$count=true&$top=1'
$uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

$azAPICallPayload = @{
    uri                    = $uri
    method                 = 'GET'
    currentTask            = "$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Validate Access for Groups Read permission"
    consistencyLevel       = 'eventual'
    validateAccess         = $true
    noPaging               = $true
    AzApiCallConfiguration = $Configuration
}
Write-Host $azAPICallPayload.currentTask

$res = AzAPICall @azAPICallPayload

if ($res -eq 'failed') {
    Write-Host " $($azAPICallPayload.currentTask) - check FAILED"
    throw
}
else {
    Write-Host " $($azAPICallPayload.currentTask) - check PASSED"
}
#endregion ValidateAccess

#region MicrosoftGraphGroupList
# https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http
# GET /groups
Write-Host '----------------------------------------------------------'
Write-Host 'Processing example call: Microsoft Graph API: Get - Groups'

$apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
$apiEndPointVersion = '/v1.0'
$api = '/groups'
$optionalQueryParameters = '?$top=888&$filter=(mailEnabled eq false and securityEnabled eq true)&$select=id,createdDateTime,displayName,description&$orderby=displayName asc&$count=true'

#$uri = 'https://graph.microsoft.com/v1.0/groups?$top=888&$filter=(mailEnabled eq false and securityEnabled eq true)&$select=id,createdDateTime,displayName,description&$orderby=displayName asc&$count=true'
$uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

$azAPICallPayload = @{
    uri                    = $uri
    method                 = 'GET'
    currentTask            = "'$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Groups'"
    consistencyLevel       = 'eventual'
    noPaging               = $true #$top in $uri + parameter 'noPaging=$false' (not using 'noPaging' in the splat) will iterate further https://docs.microsoft.com/en-us/graph/paging
    AzAPICallConfiguration = $Configuration
}
Write-Host $azAPICallPayload.currentTask

$aadgroups = AzAPICall @azAPICallPayload

Write-Host " $($azAPICallPayload.currentTask) returned results:" $aadgroups.Count
#endregion MicrosoftGraphGroupList

#region MicrosoftGraphGroupMemberList
Write-Host '----------------------------------------------------------'
Write-Host "Processing example call: Getting all members for $($aadgroups.Count) AAD Groups (NoPsParallelization:$($NoPsParallelization))"
if (-not $NoPsParallelization) {
    $htAzureAdGroupDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayGroupMembers = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $startTime = get-date
    $aadgroups | ForEach-Object -Parallel {
        #general hashTables and arrays
        $Configuration = $using:Configuration
        #general functions
        $function:AzAPICall = $using:AzAPICallFunctions.funcAzAPICall
        $function:createBearerToken = $using:AzAPICallFunctions.funcCreateBearerToken
        $function:GetJWTDetails = $using:AzAPICallFunctions.funcGetJWTDetails
        #Import-Module .\pwsh\module\AzAPICall\AzAPICall.psd1 -Force -ErrorAction Stop
        #specific for this operation
        $htAzureAdGroupDetails = $using:htAzureAdGroupDetails
        $arrayGroupMembers = $using:arrayGroupMembers

        $group = $_

        # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
        # GET /groups/{id}/members
        $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
        $apiEndPointVersion = '/v1.0'
        $api = "/groups/$($group.id)/members"
        $optionalQueryParameters = ''

        #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
        $uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

        $azAPICallPayload = @{
            uri                    = $uri
            method                 = 'GET'
            currentTask            = " '$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Group List Members (id: $($group.id))'"
            AzAPICallConfiguration = $Configuration
        }
        Write-Host $azAPICallPayload.currentTask

        $AzApiCallResult = AzAPICall @azAPICallPayload

        #collect results in synchronized hashTable
        $script:htAzureAdGroupDetails.($group.id) = $AzApiCallResult

        #collect results in syncronized arrayList
        foreach ($result in $AzApiCallResult) {
            $null = $script:arrayGroupMembers.Add($result)
        }

    } -ThrottleLimit $ThrottleLimitMicrosoftGraph

    $parallelElapsedTime = "elapsed time (foreach-parallel loop with ThrottleLimit:$($ThrottleLimitMicrosoftGraph)): " + ((get-date) - $startTime).TotalSeconds + ' seconds'
    Write-Host $parallelElapsedTime
    Write-Host 'returned members hashTable:' $htAzureAdGroupDetails.Values.Id.Count
    Write-Host 'returned members arrayList:' $arrayGroupMembers.Count

    Write-Host 'API call statistics::'
    ($Configuration['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum)
}
else {
    $htAzureAdGroupDetails = @{}
    $arrayGroupMembers = [System.Collections.ArrayList]@()
    $startTime = get-date

    $aadgroups | ForEach-Object {
        $group = $_

        # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
        # GET /groups/{id}/members
        $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].MicrosoftGraph
        $apiEndPointVersion = '/v1.0'
        $api = "/groups/$($group.id)/members"
        $optionalQueryParameters = ''

        #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
        $uri = $apiEndPoint + $apiEndPointVersion + $api + $optionalQueryParameters

        $azAPICallPayload = @{
            uri                    = $uri
            method                 = 'GET'
            currentTask            = "'$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Group List Members (id: $($group.id))'"
            AzAPICallConfiguration = $Configuration
        }
        Write-Host $azAPICallPayload.currentTask

        $AzApiCallResult = AzAPICall @azAPICallPayload

        #collect results in hashTable
        $htAzureAdGroupDetails.($group.id) = $AzApiCallResult

        #collect results in arrayList
        foreach ($result in $AzApiCallResult) {
            $null = $arrayGroupMembers.Add($result)
        }
    }

    $elapsedTime = 'elapsed time: ' + ((get-date) - $startTime).TotalSeconds + ' seconds'
    Write-Host $elapsedTime
    Write-Host 'returned members:' $htAzureAdGroupDetails.Values.Id.Count
    Write-Host 'returned members arrayList:' $arrayGroupMembers.Count

    Write-Host 'API call statistics:'
    ($Configuration['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum)
}
#endregion MicrosoftGraphGroupMemberList

#region MicrosoftResourceManagerSubscriptions
# https://docs.microsoft.com/en-us/rest/api/resources/subscriptions/list
# GET https://management.azure.com/subscriptions?api-version=2020-01-01
Write-Host '----------------------------------------------------------'
Write-Host 'Processing example call: Microsoft Resource Manager (ARM) API: List - Subscriptions'

$apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].ARM
$apiVersion = '?api-version=2020-01-01'
$api = '/subscriptions'
$uriParameter = ''

#$uri = https://management.azure.com/subscriptions?api-version=2020-01-01
$uri = $apiEndPoint + $api + $apiVersion + $uriParameter

$azAPICallPayload = @{
    uri                    = $uri
    method                 = 'GET'
    currentTask            = " '$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: List - Subscriptions'"
    AzAPICallConfiguration = $Configuration
}
Write-Host $azAPICallPayload.currentTask

$subscriptions = AzAPICall @azAPICallPayload

Write-Host " 'Subscriptions' returned results:" $subscriptions.Count
Write-Host " 'List - Subscriptions' first result:" $subscriptions[0].displayName $subscriptions[0].subscriptionId
#endregion MicrosoftResourceManagerSubscriptions

#region MicrosoftResourceManagerResources
$subsToProcess = 20
Write-Host '----------------------------------------------------------'
Write-Host "Processing example call: Getting resources (VNets and VMs) for the first $($subsToProcess) Subscriptions (NoPsParallelization:$($NoPsParallelization))"
if (-not $NoPsParallelization) {
    $htAzureResources = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
    $arrayAzureResources = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $startTime = get-date

    $subscriptions.where( { $_.state -eq 'enabled' -and $_.subscriptionPolicies.quotaId -notlike 'AAD*' } )[0..($subsToProcess - 1)] | ForEach-Object -Parallel {
        #general hashTables and arrays
        $Configuration = $using:Configuration
        #general functions
        $function:AzAPICall = $using:AzAPICallFunctions.funcAzAPICall
        $function:createBearerToken = $using:AzAPICallFunctions.funcCreateBearerToken
        $function:GetJWTDetails = $using:AzAPICallFunctions.funcGetJWTDetails
        #Import-Module .\pwsh\module\AzAPICall\AzAPICall.psd1 -Force -ErrorAction Stop
        #specific for this operation
        $htAzureResources = $using:htAzureResources
        $arrayAzureResources = $using:arrayAzureResources

        $subscription = $_

        # https://docs.microsoft.com/en-us/rest/api/resources/resources/list
        # GET https://management.azure.com/subscriptions/{subscriptionId}/resources?$filter={$filter}&$expand={$expand}&$top={$top}&api-version=2021-04-01
        $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].ARM
        $apiVersion = '?api-version=2021-04-01'
        $api = "/subscriptions/$($subscription.subscriptionId)/resources"
        $uriParameter = "&`$filter=resourceType eq 'Microsoft.Network/virtualNetworks' or resourceType eq 'Microsoft.Compute/virtualMachines'"

        #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
        $uri = $apiEndPoint + $api + $apiVersion + $uriParameter

        $azAPICallPayload = @{
            uri                    = $uri
            method                 = 'GET'
            currentTask            = " '$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Resources for Subscription (name: $($subscription.displayName); id: $($subscription.subscriptionId))'"
            AzAPICallConfiguration = $Configuration
        }
        Write-Host $azAPICallPayload.currentTask

        $AzApiCallResult = AzAPICall @azAPICallPayload

        #collect results in synchronized hashTable
        $script:htAzureResources.($subscription.subscriptionId) = $AzApiCallResult

        #collect results in syncronized arrayList
        foreach ($result in $AzApiCallResult) {
            $null = $script:arrayAzureResources.Add($result)
        }

    } -ThrottleLimit $ThrottleLimitARM

    $parallelElapsedTime = "elapsed time (foreach-parallel loop with ThrottleLimit:$($ThrottleLimitARM)): " + ((get-date) - $startTime).TotalSeconds + ' seconds'
    Write-Host $parallelElapsedTime
    Write-Host 'returned resources hashTable:' $htAzureResources.Values.Id.Count
    Write-Host 'returned resources arrayList:' $arrayAzureResources.Count

    Write-Host 'API call statistics::'
    ($Configuration['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum)
}
else {
    $htAzureResources = @{}
    $arrayAzureResources = [System.Collections.ArrayList]@()
    $startTime = get-date

    ($subscriptions.where( { $_.state -eq 'enabled' -and $_.subscriptionPolicies.quotaId -notlike 'AAD*' } ))[0..($subsToProcess - 1)] | ForEach-Object {
        $subscription = $_

        # https://docs.microsoft.com/en-us/rest/api/resources/resources/list
        # GET https://management.azure.com/subscriptions/{subscriptionId}/resources?$filter={$filter}&$expand={$expand}&$top={$top}&api-version=2021-04-01
        $apiEndPoint = $Configuration['htAzureEnvironmentRelatedUrls'].ARM
        $apiVersion = '?api-version=2021-04-01'
        $api = "/subscriptions/$($subscription.subscriptionId)/resources"
        $uriParameter = "&`$filter=resourceType eq 'Microsoft.Network/virtualNetworks' or resourceType eq 'Microsoft.Compute/virtualMachines'"

        #$uri = 'https://graph.microsoft.com/v1.0/groups/<GUID>/members'
        $uri = $apiEndPoint + $api + $apiVersion + $uriParameter

        $azAPICallPayload = @{
            uri                    = $uri
            method                 = 'GET'
            currentTask            = " '$($Configuration['htAzureEnvironmentRelatedTargetEndpoints'].($apiEndPoint.split('/')[2])) API: Get - Resources for Subscription (name: $($subscription.displayName); id: $($subscription.subscriptionId))'"
            AzAPICallConfiguration = $Configuration
        }
        Write-Host $azAPICallPayload.currentTask

        $AzApiCallResult = AzAPICall @azAPICallPayload

        #collect results in hashTable
        $htAzureResources.($subscription.subscriptionId) = $AzApiCallResult

        #collect results in arrayList
        foreach ($result in $AzApiCallResult) {
            $null = $script:arrayAzureResources.Add($result)
        }
    }

    $elapsedTime = 'elapsed time: ' + ((get-date) - $startTime).TotalSeconds + ' seconds'
    Write-Host $elapsedTime
    Write-Host 'returned resources hashTable:' $htAzureResources.Values.Id.Count
    Write-Host 'returned resources arrayList:' $arrayAzureResources.Count

    Write-Host 'API call statistics:'
    ($Configuration['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum)
}
#endregion MicrosoftResourceManagerResources
#endregion Main