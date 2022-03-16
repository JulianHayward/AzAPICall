# AzAPICall

[![GitHub Super-Linter](https://github.com/JulianHayward/AzAPICall/workflows/Lint%20Code%20Base/badge.svg)](https://github.com/marketplace/actions/super-linter)

You want to have easy way to sent requests to the Microsoft endpoints without getting headache of taking care of valid bearer token and error handling?

## Table of content
- [AzAPICall example](#azapicall-example)
- [Supported endpoints](#supported-endpoints)
- [AzAPICall Parameters](#azapicall-parameters)
- [General Parameters](#general-parameters)
- [AzAPICall Tracking](#azapicall-tracking)
- [Prerequisites](#prerequisites)
    - [Powershell Modules](powershell-modules)

## AzAPICall example

Get & Set AzAPICall PowerShell module

```POWERSHELL
Install-Module -Name AzAPICall
Import-Module -Name AzAPICall
```

Connect to Azure

```POWERSHELL
Connect-AzAccount
```

Initialize AzAPICall

```POWERSHELL
$parameters4AzAPICallModule = @{
    #SubscriptionId4AzContext = $null #specify Subscription Id
    #DebugAzAPICall = $true
}
$azAPICallConf = initAzAPICall @parameters4AzAPICallModule
```

Use AzAPICall

```POWERSHELL
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups" -AzAPICallConfiguration $azAPICallConf
```
[AzAPICallExample.ps1](pwsh/AzAPICallExample.ps1)

## Supported endpoints

| Endpoint | Endpoint URL		   		     | Variable		        |
| ------------------------------ | -------------------- | -------------- |
| [Microsoft Graph](https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0) | https://graph.microsoft.com	 | `$azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph` |
| [ARM (Azure Resource Management)](https://docs.microsoft.com/en-us/rest/api/resources/) | https://management.azure.com  | `$azAPICallConf['azAPIEndpointUrls'].ARM`            |
| [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/) | https://vault.azure.net        | `$azAPICallConf['azAPIEndpointUrls'].KeyVault`       |
| [Log Analytics](https://docs.microsoft.com/en-us/rest/api/loganalytics/) | https://api.loganalytics.io/v1 | `$azAPICallConf['azAPIEndpointUrls'].LogAnalytics`   |

Add a new endpoint -> setAzureEnvironment.ps1

## AzAPICall Parameters
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| uri				    	    | `string`	| `$azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups` which translates to: `https://graph.microsoft.com/v1.0/groups`                                                             | ✅		  |
| AzAPICallConfiguration				    	    | `object`	| Set of prebuilt (`$azAPICallConf = initAzAPICall`) variables required for AzAPICall operations (`-AzAPICallConfiguration $azAPICallConf`)                                                                | ✅		  |
| method					    | `string`	| Method for the API request *(e.g. GET, POST, ..)*                                     | default is 'GET', else define it	  |
| currentTask		            | `string`	| Free text field; in case of error or enabled `-DebugAzAPICall` currentTask will be output to console		                                    | 		  |
| body	                        | `string`	| Request Body for the API request - [Example](https://docs.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http#request-body)	| 		   |
| caller                        | `string`  | Set the value to `CustomDataCollection` for parallelization to have different font colors for the debug output |          |
| consistencyLevel              | `string`  | For several [OData query parameters](https://docs.microsoft.com/en-us/graph/query-parameters) the `consistencyLevel`-header need to be set to `eventual` |          |
| listenOn                      | `string`  | Default is `Value`. Depending to the expected response of the API call the following values are accepted: `Content`, `ContentProperties` |          |
| noPaging                      | `switch`    | If value is `true` paging will be deactivated and you will only get the defined number of `$top` results or [Resource Graph limits any query to returning only `100` records](https://docs.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data). Otherwise, you can use `$top` to increase the result batches from default `100` up to `999` for the `AzAPICall`. Value for `$top` must range from 1 to 999 |          |
| validateAccess                | `switch`    | Use this parameter if you only want to validate that the requester has permissions to the enpoint, if authorization is denied AzAPICall returns 'failed'. (Using `-validateAccess` will set `noPaging` to `true`)                                                                                |          |

### Good to know
By default, endPoints return results in batches of e.g. `100`. You can increase the return count defining e.g. `$top=999` (`$top` requires use of `consistencyLevel` = `eventual`)

## General Parameters
| Field					   		| Type		| Description									                                        | Required |
| ----------------------------- | :-------: | ------------------------------------------------------------------------------------- | :------: |
| DebugAzAPICall			    | `bool`	| Set to `true` to enable debug output                | 		   |
| SubscriptionId4AzContext		| `string`	| Specify if specific subscription should be used for the AzContext (Subscription Id / GUID) | 		   |

### AzAPICall Tracking

To get some insights on all API calls you can check the `$azAPICallConf['arrayAPICallTracking']` object (synchronized ArrayList)

```POWERSHELL
$azAPICallConf['arrayAPICallTracking'][0] | ConvertTo-Json
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
($azAPICallConf['arrayAPICallTracking'].Duration | Measure-Object -Average -Maximum -Minimum) | ConvertTo-Json
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

## Prerequisites
### Powershell Modules
| PowerShell Module |
| ----------------- |
| Az.Accounts       |