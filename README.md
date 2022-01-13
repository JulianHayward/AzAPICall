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

## General Parameter
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| DebugAzAPICall			    | `switch`	| Set to `True` to enable the debugging and get further detailed output.                | 		   |
| SubscriptionId4AzContext		| `string`	| JULIAN                                                                                | 		   |
| PsParallelization			    | `switch`	| `True` or `False` if parellelization should be used. If it should be used PowerShell version >= 7.0.,3 is required. If set to `False` you can use it also with PowerShell verion >= 5.1. | 	 	   |
| TenantId			            | `string`	| ID of your Azure tenant                                                               | ✅ 	  |
| ThrottleLimitMicrosoftGraph	| `int`	    | Only if `PsParallelization` is set to `true`. Set the ThrottelLimit for the Microsoft Graph API call for parallelization. Default and recommended value is `20`. |  		   |
| ThrottleLimitARM			    | `int`	    | Only if `PsParallelization` is set to `true`. Set the ThrottelLimit for the ARM (Azure Resource Manager) API call for parallelization. Default and recommended value is `10`. |  		   |

# AzAPICall

## AzAPICall - Parameter
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| uri				    	    | `string`	| URI of the API request                                                                | ✅		  |
| method					    | `string`	| Method for the API request *(e.g. GET, POST, ..)*                                     | ✅		  |
| currentTask		            | `string`	| Free text field for further output details		                                    | ✅		  |
| body	                        | `string`	| Request Body for the API request - [Example](https://docs.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http#request-body)	| 		   |
| caller                        | `string`  | Set the value to `CustomDataCollection` for parallelization to have different font colors for the debug output |          |
| consistencyLevel              | `string`  | For several [OData query parameters](https://docs.microsoft.com/en-us/graph/query-parameters) the `consistencyLevel`-header need to be set to `eventual` |          |
| listenOn                      | `string`  | Default is `Value`. Depending to the expacted result of the API call the following values are accepted: `Content`, `ContentProperties`, `Value` |          |
| getConsumption                | `bool`    | JULIAN                                                                                |          |
| getGroup                      | `bool`    | JULIAN                                                                                |          |
| getGroupMembersCount          | `bool`    | JULIAN                                                                                |          |
| getApp                        | `bool`    | JULIAN                                                                                |          |
| getCount                      | `bool`    | JULIAN                                                                                |          |
| getPolicyCompliance           | `bool`    | JULIAN                                                                                |          |
| getMgAscSecureScore           | `bool`    | JULIAN                                                                                |          |
| getRoleAssignmentSchedules    | `bool`    | JULIAN                                                                                |          |
| getDiagnosticSettingsMg       | `bool`    | JULIAN                                                                                |          |
| validateAccess                | `bool`    | JULIAN                                                                                |          |
| getMDfC                       | `bool`    | JULIAN                                                                                |          |
| noPaging                      | `bool`    | If value is `true` paging will be deactivated and you will only get the defined number of `$top` results. Otherwise, you can use `$top` to increase the result batches from default `100` up to `999` for the `AzAPICall`. |          |

### Examples: 
#### URI
By default, 4 endpoint URI`s are available within the script:

| Endpoint URL		   		     | Variable		        | targetEndPoint |
| ------------------------------ | -------------------- | -------------- |
| https://graph.microsoft.com	 | `$uriMicrosoftGraph` | MicrosoftGraph |
| https://management.azure.com/  | `$uriARM`            | ARM            |
| https://vault.azure.net        | `$uriKeyVault`       | KeyVault       |
| https://api.loganalytics.io/v1 | `$uriLogAnalytics`   | LogAnalytics   |

[List groups - HTTP request](https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#http-request)

```POWERSHELL
$uri = $uriMicrosoftGraph + "/v1.0/groups"
```

```POWERSHELL
Write-Output $uri
https://graph.microsoft.com/v1.0/groups
```

#### METHOD

The `method` is documented by Microsoft:

[List groups - HTTP request](https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http#http-request)

```POWERSHELL
$method = "GET"
```

#### CURRENT TASK

If the script will call multiple times the `AzAPICall`-function and might doing it also in parellel, it is useful to see where the script is.
Regarding to this, the `currentTtask` will be included in the output.

```POWERSHELL
$currentTask = "Microsoft Graph API: Get - Group List"
```

## AzAPICall - Function

Before we can use the `AzAPICall`-function we need the related bearer-token of the to be [used API](#uri) for the authentication.
You need to call the `createBearerToken`-function and use the `targetEndPoint`-parameter with the value of the to be [used API](#uri).

```POWERSHELL
#create bearer token
createBearerToken -targetEndPoint "MicrosoftGraph"
createBearerToken -targetEndPoint "ARM"
createBearerToken -targetEndPoint "KeyVault"
createBearerToken -targetEndPoint "LogAnalytics"
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
- Define how many requests will be handeled in parallel. These value is set to the ThrottleLimit best-practise. 
`} -ThrottleLimit $ThrottleLimitMicrosoftGraph`
- Defining all variable which need to be re-used within the parellel call by defining it again with 
`$using:`
- Get the value of the actual foreach-object 
`$group = $_`
- Call the AzAPICall and temporarilly write the information to a variable 
`$AzApiCallResult`
- Define an array within the hashtable for this group
`$htAzureAdGroupDetails.($group.id) = @()`
- Write the temporarilly information to the synchonized hashtable that they are also available outside of the parallelization
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
$htAzureAdGroupDetails."<GroupId"
```


### Good to know


By default, the AzAPICall will have batch results of `100` values. To increase it and to speed up the process you can increase the call also with `$top=999`. Then the batch size of the results will be `999` instead of `100`.
If you would like to do this, you need to use the `consistencyLevel`-paramenter with the value `eventual` and activate the paging with the `noPaging`-parameter value `$false`.