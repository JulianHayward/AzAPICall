# AzAPICall

[![GitHub Super-Linter](https://github.com/JulianHayward/AzAPICall/workflows/Lint%20Code%20Base/badge.svg)](https://github.com/marketplace/actions/super-linter)

You want to have easy way to sent requests to the Microsoft endpoints without getting headache of taking care of valid bearer token and error handling?

## Table of content
- [Supported endpoints](#supported-endpoints)
- [AzAPICall Parameter](#azapicall-parameter)
- [AzAPICall Function](#azapicall-function)
- [AzAPICall Tracking](#azapicall-tracking)
- [Prerequisites](#prerequisites)
    - [Powershell](powershell)
        - [Versions](#versions)
        - [Modules](#modules)
        - [Files](#files)
        - [General Parameters](#general-parameters)

## Supported endpoints
- [Microsoft Graph](https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0)
- [Azure Resource Management](https://docs.microsoft.com/en-us/rest/api/resources/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/)
- [Log Analytics](https://docs.microsoft.com/en-us/rest/api/loganalytics/)

Add a new endpoint -> setAzureEnvironment.ps1

## AzAPICall Parameter
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| uri				    	    | `string`	| URI of the API request                                                                | ✅		  |
| method					    | `string`	| Method for the API request *(e.g. GET, POST, ..)*                                     | ✅		  |
| currentTask		            | `string`	| Free text field for further output details		                                    | ✅		  |
| body	                        | `string`	| Request Body for the API request - [Example](https://docs.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http#request-body)	| 		   |
| caller                        | `string`  | Set the value to `CustomDataCollection` for parallelization to have different font colors for the debug output |          |
| consistencyLevel              | `string`  | For several [OData query parameters](https://docs.microsoft.com/en-us/graph/query-parameters) the `consistencyLevel`-header need to be set to `eventual` |          |
| listenOn                      | `string`  | Default is `Value`. Depending to the expacted result of the API call the following values are accepted: `Content`, `ContentProperties` |          |
| noPaging                      | `switch`    | If value is `true` paging will be deactivated and you will only get the defined number of `$top` results or [Resource Graph limits any query to returning only `100` records](https://docs.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data). Otherwise, you can use `$top` to increase the result batches from default `100` up to `999` for the `AzAPICall`. `$top`-value must be between 1 and 999 inclusive. |          |
| getMgAscSecureScore           | `switch`    | endpoint 'providers/Microsoft.ResourceGraph/resources' may return 'BadRequest' however a retry may be successful - this parameter could be generalized for ARG queries                                                                                 |          |
| validateAccess                | `switch`    | use this parameter if you only want to validate that the requester has permissions to the enpoint, if authorization is denied AzAPICall returns 'failed'                                                                                |          |

### Examples: 
#### URI
By default, 4 endpoint URI`s are available within the script:

| Endpoint URL		   		     | Variable		        | targetEndPoint |
| ------------------------------ | -------------------- | -------------- |
| https://graph.microsoft.com	 | `$uriMicrosoftGraph` | MicrosoftGraph |
| https://management.azure.com/  | `$uriARM`            | ARM            |
| https://vault.azure.net        | `$uriKeyVault`       | KeyVault       |
| https://api.loganalytics.io/v1 | `$uriLogAnalytics`   | LogAnalytics   |


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
| 7.0.3| default |
| 5.x.x|[PowerShell parallelization](https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/) requires PS 7.0.3 or higher. If running PS 5.x you need to set the `bool` parameter `NoPsParallelization` to `true`.|

### Modules
| PowerShell Module |
| ----------------- |
| Az.Accounts       |

### Files
| PowerShell file | Description |
| --------------- | ------- |
| example.ps1 | Example how to use the `AzAPICall`|
| AzAPICall.ps1   | Handler for the REST call (handles known return code, handles paging). Optional use parameter `-DebugAzAPICall` to get console output on AzAPICall activity. |
| createBearerToken.ps1 | Creation of the Bearer Token for target API endpoint (Microsoft Graph, Azure Resource Manager, etc.). |
| getJWTDetails.ps1 | Decode a JWT Access Token and convert to a PowerShell Object. JWT Access Token updated to include the JWT Signature (sig), JWT Token Expiry (expiryDateTime) and JWT Token time to expiry (timeToExpiry). for more details check [JWTDetails](https://www.powershellgallery.com/packages/JWTDetails/1.0.2). |
| testAzContext.ps1 | Checks if valid context is given. Sets context to target subscription if parameter `-SubscriptionId4AzContext` is used. |
| testAzModules.ps1 | Check if predefined command `Get-AzContext` can be executed within the executed PowerShell session. Addtionally, check if the needed module `Az.Accounts` is installed and write the version to the output. |
| setAzureEnvironment.ps1 | Get the environment information of the actual context and predefine the [URI endpoint as variable](#uri). |
| createHtParameters.ps1 | Check where the code is running *(e.g.: GitHub Actions, GitHub Codespaces, Azure DevOps, Azure Automation, Azure CloudShell, Console)*. |
| testPowerShellVersion.ps1 | If `bool` parameter `-NoPsParallelization` = `false` is used then PowerShell version must be >= `7.0.3`. ([PowerShell ForEach-Object Parallel Feature](https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/)) |
| testUserType.ps1 | If the executing principal is a user then check if the user is a member of a guest |

## General Parameters
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| DebugAzAPICall			    | `bool`	| Set to `True` to enable the debugging and get further detailed output.                | 		   |
| SubscriptionId4AzContext		| `string`	| If you would like to use a specific subscription as AzContext. Otherwise, if the `SubscriptionId4AzContext`-parameter value is `undefined`, the standard subscription with the Connect-AzAccount will be used. | 		   |
| NoPsParallelization			    | `bool`	| If `bool` parameter `-NoPsParallelization` = `false` is used then PowerShell version must be >= `7.0.3`. ([PowerShell ForEach-Object Parallel Feature](https://devblogs.microsoft.com/powershell/powershell-foreach-object-parallel-feature/)) | 	 	   |
| ThrottleLimitMicrosoftGraph	| `int`	    | Relevant if `NoPsParallelization` is set to `false`. Set the ThrottelLimit for the Microsoft Graph API call for parallelization. Default and recommended value is `20`. |  		   |
| ThrottleLimitARM			    | `int`	    | Relevant if `NoPsParallelization` is set to `false`. Set the ThrottelLimit for the ARM (Azure Resource Manager) API call for parallelization. Default and recommended value is `10`. |  		   |
