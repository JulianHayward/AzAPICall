# AzAPICall

[![GitHub Super-Linter](https://github.com/JulianHayward/AzAPICall/workflows/Lint%20Code%20Base/badge.svg)](https://github.com/marketplace/actions/super-linter)

You want to have easy way to sent requests to the Microsoft endpoints without getting headache of taking care of valid bearer token and error handling?

## Table of content
- [Example](#azapicall-example)
- [Supported endpoints](#supported-endpoints)
- [AzAPICall Parameter](#azapicall-parameter)
- [AzAPICall Tracking](#azapicall-tracking)
- [Prerequisites](#prerequisites)
    - [Powershell](powershell)
        - [Modules](#modules)
        - [Files](#files)
        - [General Parameters](#general-parameters)

## AzAPICall example
[AzAPICallExample.ps1](pwsh/AzAPICallExample.ps1)

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
$Configuration['arrayAPICallTracking'][0] | ConvertTo-Json
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
($Configuration['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum) | ConvertTo-Json
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
$Configuration['arrayAPICallTracking'] | Sort-Object Duration -Descending | Select-Object -First 1 | ConvertTo-Json
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
By default, endPoints return results in batches of e.g. `100`. You can increase the return count defining e.g. `$top=999`.  
`$top` requires use of `consistencyLevel` = `eventual`

# Prerequisites
## Powershell
### Modules
| PowerShell Module |
| ----------------- |
| Az.Accounts       |

## General Parameters
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| DebugAzAPICall			    | `bool`	| Set to `True` to enable the debugging and get further detailed output.                | 		   |
| SubscriptionId4AzContext		| `string`	| If you would like to use a specific subscription as AzContext. Otherwise, if the `SubscriptionId4AzContext`-parameter value is `undefined`, the standard subscription with the Connect-AzAccount will be used. | 		   |
