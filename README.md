# AzAPICall
You want to have easy way to sent requests to the Microsoft endpoints without getting headache of taking care of valid bearer token and error handling?

Right.. we also! 

Here is **THE SOLUTION**!

## Table of content
- [AzAPICall](#AzAPICall)
    - [Table of content](#Table-of-content)
    - [Current supported endpoints](#Current-supported-endpoints)
    - [AzAPICall Parameter](#AzAPICall-Parameter)
    - [AzAPICall Function](#AzAPICall-Function)
    - [AzAPICall Tracking](#AzAPICall-Tracking)
- [Prerequisites](#Prerequisites)
    - [Powershell](#Powershell)
        - [Versions](#Versions)
        - [Modules](#Modules)
        - [Files](#Files)
        - [General Parameter (main.ps1)](#General-Parameter-(main.ps1))

## Current supported endpoints
- [Microsoft Graph](https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0)
- [Azure Resource Management](https://docs.microsoft.com/en-us/rest/api/resources/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/)
- [Log Analytics](https://docs.microsoft.com/en-us/rest/api/loganalytics/)
- [Power BI](https://docs.microsoft.com/en-us/rest/api/power-bi/)
## AzAPICall Parameter
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| uri				    	    | `string`	| URI of the API request                                                                | ✅		  |
| method					    | `string`	| Method for the API request *(e.g. GET, POST, ..)*                                     | ✅		  |
| currentTask		            | `string`	| Free text field for further output details		                                    | ✅		  |
| body	                        | `string`	| Request Body for the API request - [Example](https://docs.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http#request-body)	| 		   |
| caller                        | `string`  | Set the value to `CustomDataCollection` for parallelization to have different font colors for the debug output |          |
| consistencyLevel              | `string`  | For several [OData query parameters](https://docs.microsoft.com/en-us/graph/query-parameters) the `consistencyLevel`-header need to be set to `eventual` |          |
| listenOn                      | `string`  | Default is `Value`. Depending to the expacted result of the API call the following values are accepted: `Content`, `ContentProperties`, `Value` |          |
| noPaging                      | `switch`    | If value is `true` paging will be deactivated and you will only get the defined number of `$top` results or [Resource Graph limits any query to returning only `100` records](https://docs.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data). Otherwise, you can use `$top` to increase the result batches from default `100` up to `999` for the `AzAPICall`. `$top`-value must be between 1 and 999 inclusive. |          |
| getConsumption                | `switch`    | special error handing endpoint '/providers/Microsoft.CostManagement/query'                                                                                |          |
| getGroup                      | `switch`    | group may have been deleted meanwhile / returns 'Request_ResourceNotFound' instead of error out                                                                                  |          |
| getGroupMembersCount          | `switch`    | beta endpoint (users, groups, servicePrincipals) '*count is not currently supported*' may be returned, however a retry may be successful                                                                                |          |
| getApp                        | `switch`    | app may have been deleted meanwhile / returns 'Request_ResourceNotFound' instead of error out                                                                                |          |
| getPolicyCompliance           | `switch`    | endpoint '/providers/Microsoft.PolicyInsights/policyStates/latest/summarize' returns 'ResponseTooLarge' if a certain amount of compliance data is reached - AzAPICall returns 'ResponseTooLarge' instead of error out                                                                                |          |
| getMgAscSecureScore           | `switch`    | endpoint 'providers/Microsoft.ResourceGraph/resources' may return 'BadRequest' however a retry may be successful - this parameter could be generalized for ARG queries                                                                                 |          |
| getRoleAssignmentSchedules    | `switch`    | endpoint '/providers/Microsoft.Authorization/roleAssignmentSchedules' will return '' if PIM is not enabled - AzAPICall returns 'ResourceNotOnboarded', 'TenantNotOnboarded', 'InvalidResourceType', 'InvalidResource' instead of error out                                                                                 |          |
| getDiagnosticSettingsMg       | `switch`    | endpoint '/providers/microsoft.insights/diagnosticSettings' returns 'InvalidResourceType' in cloud environments where the capaibility is not enabled, yet                                                                                |          |
| validateAccess                | `switch`    | use this parameter if you only want to validate that the requester has permissions to the enpoint, if authorization is denied AzAPICall returns 'failed'                                                                                |          |
| getMDfC                       | `switch`    | if Azure Defender is not activated for the subscription then the endpoint '/providers/Microsoft.Security/pricings' returns 'Subscription Not Registered', AzAPICall will return 'SubScriptionNotRegistered' instead of error out                                                                                |          |

### Examples: 
#### URI
By default, 4 endpoint URI`s are available within the script:

| Endpoint URL		   		     | Variable		        | targetEndPoint |
| ------------------------------ | -------------------- | -------------- |
| https://graph.microsoft.com	 | `$uriMicrosoftGraph` | MicrosoftGraph |
| https://management.azure.com/  | `$uriARM`            | ARM            |
| https://vault.azure.net        | `$uriKeyVault`       | KeyVault       |
| https://api.loganalytics.io/v1 | `$uriLogAnalytics`   | LogAnalytics   |
| https://api.powerbi.com/v1.0   | `$uriPowerBI`        | PowerBI        |

[List groups - HTTP request](https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#http-request)

```POWERSHELL
$uri = $uriMicrosoftGraph + "/v1.0/groups"
```

If you don't feel comfortable using the predfined variables *(e.g: "$uriMicrosoftGraph")* you can directly use the full uri path by yourself:

```POWERSHELL
Write-Output $uri
https://graph.microsoft.com/v1.0/groups

$uri = "https://graph.microsoft.com/v1.0/groups"
```

#### METHOD

The `method` is documented by Microsoft:

[List groups - HTTP request](https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#http-request)

```POWERSHELL
$method = "GET"
```

#### CURRENT TASK

If the script will call multiple times the `AzAPICall`-function and might doing it also in parallel, it is useful to see where the script is.
Regarding to this, the `currentTask` will be included in the output.

```POWERSHELL
$currentTask = "Microsoft Graph API: Get - Group List"
```

## AzAPICall Function

*(main.ps1)*:

Make sure you are authenticated to Azure otherwise implement it to your script:

```POWERSHELL
Clear-AzContext -Force
Connect-AzAccount -Tenant "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" `
                  -SubscriptionId "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" 
```

*(main.ps1)*:

First, you must import the following powershell `functions` and define the `variables` for the parallelization to be able to use them:
```POWERSHELL
#Region Functions
#Region getJWTDetails
.\functions\getJWTDetails.ps1
$funcGetJWTDetails = $function:getJWTDetails.ToString()
#EndRegion getJWTDetails

#Region createBearerToken
.\functions\createBearerToken.ps1
$funcCreateBearerToken = $function:createBearerToken.ToString()
$htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
#EndRegion createBearerToken

#Region AzAPICall
.\functions\AzAPICall.ps1
$funcAzAPICall = $function:AzAPICall.ToString()
#EndRegionAzAPICall
#EndRegion Functions
```
*(main.ps1)*:

Now, depending if you like to use parallelization, you need to define the following variable:
```POWERSHELL
#Region Variables
if($PsParallelization) {
    $arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
} else {
    $arrayAPICallTracking = [System.Collections.ArrayList]@()
}
#EndRegion Variables
```
*(Test-HashtableParameter.ps1)*:

Additionally, the `$htParameters`-hashtable will be created and the `DebugAzAPICall`-value will be set:

```POWERSHELL
$htParameters = @{}
$htParameters.DebugAzAPICall = $DebugAzAPICall #$true or $false
write-host "AzAPICall debug enabled" -ForegroundColor Cyan
```

*(Test-Environment.ps1)*:

For the later usage, we need [the endpoints and store them within a variable](#URI):
```POWERSHELL
#Region Test-Environment
$checkAzEnvironments = Get-AzEnvironment -ErrorAction Stop

#FutureUse
#Graph Endpoints https://docs.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
#AzureCloud https://graph.microsoft.com
#AzureUSGovernment L4 https://graph.microsoft.us
#AzureUSGovernment L5 (DOD) https://dod-graph.microsoft.us
#AzureChinaCloud https://microsoftgraph.chinacloudapi.cn
#AzureGermanCloud https://graph.microsoft.de

#AzureEnvironmentRelatedUrls
$htAzureEnvironmentRelatedUrls = @{ }
$arrayAzureManagementEndPointUrls = @()
foreach ($checkAzEnvironment in $checkAzEnvironments) {
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name) = @{ }
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).ARM = $checkAzEnvironment.ResourceManagerUrl
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.ResourceManagerUrl
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).KeyVault = $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.AzureKeyVaultServiceEndpointResourceId
    ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).LogAnalytics = $checkAzEnvironment.AzureOperationalInsightsEndpoint
    $arrayAzureManagementEndPointUrls += $checkAzEnvironment.AzureOperationalInsightsEndpoint
    if ($checkAzEnvironment.Name -eq "AzureCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.com"
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).PowerBI = "https://api.powerbi.com/v1.0/"
    }
    if ($checkAzEnvironment.Name -eq "AzureChinaCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://microsoftgraph.chinacloudapi.cn"
    }
    if ($checkAzEnvironment.Name -eq "AzureUSGovernment") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.us"
    }
    if ($checkAzEnvironment.Name -eq "AzureGermanCloud") {
        ($htAzureEnvironmentRelatedUrls).($checkAzEnvironment.Name).MicrosoftGraph = "https://graph.microsoft.de"
    }
}

$uriMicrosoftGraph = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).MicrosoftGraph)"
$uriARM = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ARM)"
$uriKeyVault = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).KeyVault)"
$uriLogAnalytics = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).LogAnalytics)"
#EndRegion Test-Environment
```

*(main.ps1)*:

Before we can use the `AzAPICall`-function we need the related bearer-token of the to be [used API](#uri) for the authentication.
You need to call the `createBearerToken`-function and use the `targetEndPoint`-parameter with the value of the to be [used API](#uri).

```POWERSHELL
#create bearer token
createBearerToken -targetEndPoint "MicrosoftGraph"
createBearerToken -targetEndPoint "ARM"
createBearerToken -targetEndPoint "KeyVault"
createBearerToken -targetEndPoint "LogAnalytics"
createBearerToken -targetEndPoint "PowerBI"

```

Let's start with an easy example.

In this case:
- we would like to receive the first 999 the AzureAD groups
`$top=999`
- only get the security enabled  and NOT the mail enabled groups 
`$filter=(mailEnabled eq false and securityEnabled eq true)` 
- get only some properties as result 
`$select=id,createdDateTime,displayName,description`
- order the results by the displayname ascending 
`orderby=displayName asc`

To escape the `$` in the `URI` you need to set a tick \` before the `$`

```POWERSHELL
# Example calls
# https://graph.microsoft.com/v1.0/groups
$uri = $uriMicrosoftGraph + "/v1.0/groups?`$top=999&`$filter=(mailEnabled eq false and securityEnabled eq true)&`$select=id,createdDateTime,displayName,description&`$orderby=displayName asc"
$method = "GET"
$currentTask = "Microsoft Graph API: Get - Groups"
$listenOn = "Value" #Default
$aadgroups = AzAPICall -uri $uri `
                       -method $method `
                       -currentTask $currentTask `
                       -listenOn $listenOn `
                       -consistencyLevel "eventual" `
                       -noPaging $true      
```
All the results will be written to the `$aadgroups`-variable.

Now, you can work further with the results. If you would like to receive all members of the groups in `$aadgroups` you can iterate it and make further API calls sequently or if you are using [PowerShell version >= `7.0.3`](#versions) and the [`PsParallelization`-parameter value is set to `$true`](#general-parameter) then we can use the parallelization of the AzAPICalls.

In this case:
- we need an synchronized hashtable to store the members information 
`$htAzureAdGroupDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))`
- use the previous output in the variable and pipe it to an parallel foreach-object call 
`$aadgroups | ForEach-Object -Parallel {`
- Define how many requests will be handeled in parallel *(The value is set to the ThrottleLimit best-practis)*
`} -ThrottleLimit $ThrottleLimitMicrosoftGraph`
- Declaring all variable which need to be available within the parallel call 
`$using:`
- Get the value of the actual foreach-object 
`$group = $_`
- Call the AzAPICall and temporarilly write the information to a variable 
`$AzApiCallResult`
- Declare an array within the hashtable for this group
`$htAzureAdGroupDetails.($group.id) = @()`
- Write the temporarilly stored information to the synchonized hashtable that they are also available outside of the parallelization
`$htAzureAdGroupDetails.($group.id) = $AzApiCallResult`

```POWERSHELL
$htAzureAdGroupDetails = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))

$aadgroups | ForEach-Object -Parallel {
    $htAzureAdGroupDetails = $using:htAzureAdGroupDetails
    $uriMicrosoftGraph = $using:uriMicrosoftGraph
    $htParameters = $using:htParameters
    $htBearerAccessToken = $using:htBearerAccessToken
    $arrayAPICallTracking = $using:arrayAPICallTracking

    $function:AzAPICall = $using:funcAzAPICall
    $function:createBearerToken = $using:funcCreateBearerToken
    $function:GetJWTDetails = $using:funcGetJWTDetails

    $group = $_

    # https://docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http
    $uri = $uriMicrosoftGraph + "/v1.0/groups/$($group.id)/members"
    $listenOn = "Value" #Default
    $currentTask = "Microsoft Graph API: Get - Group List Members"
    $method = "GET"
    $AzApiCallResult = AzAPICall -uri $uri `
                                 -method $method `
                                 -currentTask $currentTask `
                                 -listenOn $listenOn `
                                 -caller "CustomDataCollection" `
                                 -noPaging $false #https://docs.microsoft.com/en-us/graph/paging

    $htAzureAdGroupDetails.($group.id) = @()
    $htAzureAdGroupDetails.($group.id) = $AzApiCallResult
} -ThrottleLimit $ThrottleLimitMicrosoftGraph
```

Now, your members are stored within the hashtable `$htAzureAdGroupDetails`.

The `Id` of the group from the first call `$aadgroups.Id` will be used as `key` for the hashtable:
```POWERSHELL
$htAzureAdGroupDetails.keys
```

You can address a specific group by the id to see if members are available and who are the members of this group:
```POWERSHELL
$htAzureAdGroupDetails."<GroupId>"
```

### AzAPICall Tracking

To get some insights about all AzAPIcalls you can use the `$arrayAPICallTracking`-ArrayList.

```POWERSHELL
$arrayAPICallTracking[0] | ConvertTo-Json
```
```JSON
{
  "CurrentTask": "Microsoft Graph API: Get - Groups",
  "TargetEndpoint": "MicrosoftGraph",
  "Uri": "https://graph.microsoft.com/v1.0/groups?$top=999&$filter=(mailEnabled eq false and securityEnabled eq true)&$select=id,createdDateTime,displayName,description&$orderby=displayName asc&$count=true",
  "Method": "GET",
  "TryCounter": 0,
  "TryCounterUnexpectedError": 0,
  "RetryAuthorizationFailedCounter": 0,
  "RestartDueToDuplicateNextlinkCounter": 0,
  "TimeStamp": "2022011316040343",
  "Duration": 1.3137266
}
```
As well you can see how fast a AzAPICall was responding:
```POWERSHELL
($arrayAPICallTracking.Duration | Measure-Object -Average -Maximum -Minimum) | ConvertTo-Json
```
```JSON
{
  "Count": 1000,
  "Average": 0.4292551101999999,
  "Sum": null,
  "Maximum": 2.7991866,
  "Minimum": 0.263543,
  "StandardDeviation": null,
  "Property": null
}
```

E.g. the slowest one:
```POWERSHELL
$arrayAPICallTracking | Sort-Object Duration -Descending | Select-Object -First 1 | ConvertTo-Json
```

```JSON
{
  "CurrentTask": "Microsoft Graph API: Get - Group List Members",
  "TargetEndpoint": "MicrosoftGraph",
  "Uri": "https://graph.microsoft.com/v1.0/groups/<GroupId>/members",
  "Method": "GET",
  "TryCounter": 0,
  "TryCounterUnexpectedError": 0,
  "RetryAuthorizationFailedCounter": 0,
  "RestartDueToDuplicateNextlinkCounter": 0,
  "TimeStamp": "20220113160421421",
  "Duration": 2.7991866
}
```

### Good to know
By default, the AzAPICall will have batch results of `100` values. To increase it and to speed up the process you can increase the call also with `$top=999`. Then the batch size of the results will be `999` instead of the default limited `100` returns.
If you would like to do this, you need to use the `consistencyLevel`-paramenter with the value `eventual` and activate the paging with the `noPaging`-parameter value `$false`.

# Prerequisites
## Powershell
### Versions
| PowerShell Version | Description									                                        |
| ------------------ | ------------------------------------------------------------------------------------ |
| 7.0.3 			 | If you would like to use [PowerShell parallelization](https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/), you need to set the parameter `PsParallelization`. |
| 5.x.x			     | If you don't have many data to collect, you can use the `AzAPICall` without parallelization.                    |

### Modules
| PowerShell Module | Version |
| ----------------- | ------- |
| Az.Accounts       | 2.6.1   |

### Files
| PowerShell file | Description |
| --------------- | ------- |
| main.ps1 | Example how to use the `AzAPICall` best. |
| AzAPICall.ps1   | JULIAN |
| createBearerToken.ps1 | JULIAN |
| getJWTDetails.ps1 | JULIAN |
| Test-AzContext.ps1 | JULIAN |
| Test-AzModules.ps1 | Check if predefined command `Get-AzContext` can be executed within the executed PowerShell session. Addtionally, check if the needed module `Az.Accounts` is installed and write the version to the output. |
| Test-Environment.ps1 | Get the environment information of the actual context and predefine the [URI endpoint as variable](#uri). |
| Test-HashtableParameter.ps1 | Check where the code is running *(e.g.: GitHubCodespaces, AzureDevOps, AzureAutomation, Console)*. Set also the `DebugAzAPICall`. |
| Test-PowerShellVersion.ps1 | If `PsParallelization`-parameter is set to `$true`, it need to be verified, that the PowerShell version is >= `7.0.3`. |

## General Parameter (main.ps1)
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| DebugAzAPICall			    | `switch`	| Set to `True` to enable the debugging and get further detailed output.                | 		   |
| SubscriptionId4AzContext		| `string`	| If you would like to use a specific subscription as AzContext. Otherwise, if the `SubscriptionId4AzContext`-parameter value is `undefined`, the standard subscription with the Connect-AzAccount will be used. | 		   |
| PsParallelization			    | `switch`	| `True` or `False` if parallelization should be used. If it should be used PowerShell version >= 7.0.,3 is required. If set to `False` you can use it also with PowerShell verion >= 5.1. | 	 	   |
| TenantId			            | `string`	| ID of your Azure tenant                                                               | ✅ 	  |
| ThrottleLimitMicrosoftGraph	| `int`	    | Only if `PsParallelization` is set to `true`. Set the ThrottelLimit for the Microsoft Graph API call for parallelization. Default and recommended value is `20`. |  		   |
| ThrottleLimitARM			    | `int`	    | Only if `PsParallelization` is set to `true`. Set the ThrottelLimit for the ARM (Azure Resource Manager) API call for parallelization. Default and recommended value is `10`. |  		   |
