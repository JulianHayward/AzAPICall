# AzAPICall

[![PowerShell Gallery Version (including pre-releases)](https://img.shields.io/powershellgallery/v/AzAPICall?include_prereleases&label=PowerShell%20Gallery)](https://www.powershellgallery.com/packages/AzAPICall)

You want to have an easy way to interact with the Microsoft Azure API endpoints without getting headache of taking care of valid bearer token and error handling?

## Table of content
- [AzAPICall](#azapicall)
  - [Table of content](#table-of-content)
  - [AzAPICall example](#azapicall-example)
    - [Get \& Set AzAPICall PowerShell module](#get--set-azapicall-powershell-module)
    - [Initialize AzAPICall](#initialize-azapicall)
    - [How to use AzAPICall ?!](#how-to-use-azapicall-)
      - [Example for Microsoft Graph](#example-for-microsoft-graph)
      - [Example for Azure Resource Manager](#example-for-azure-resource-manager)
  - [Public functions](#public-functions)
  - [Supported endpoints](#supported-endpoints)
  - [General Parameters](#general-parameters)
  - [AzAPICall Parameters](#azapicall-parameters)
  - [Good to know](#good-to-know)
    - [Don´t accept the defaults](#dont-accept-the-defaults)
    - [AzAPICall Tracking](#azapicall-tracking)
  - [Prerequisites](#prerequisites)
    - [Powershell Modules](#powershell-modules)
  - [Contribute](#contribute)

## AzAPICall example

### Get & Set AzAPICall PowerShell module

```POWERSHELL
Install-Module -Name AzAPICall
#Import-Module -Name AzAPICall
```

Connect to Azure

```POWERSHELL
Connect-AzAccount
```

### Initialize AzAPICall

```POWERSHELL
$parameters4AzAPICallModule = @{
    #SubscriptionId4AzContext = $null #specify Subscription Id #[string]
    #TenantId4AzContext = $null #specify Tenant Id #[string]
    #DebugAzAPICall = $true #[bool]
    #WriteMethod = 'Output' #Debug, Error, Host, Information, Output, Progress, Verbose, Warning (default: host) #[string]
    #DebugWriteMethod = 'Warning' #Debug, Error, Host, Information, Output, Progress, Verbose, Warning (default: host) #[string]
    #SkipAzContextSubscriptionValidation = $true #Only use in case you do not have any valid (quotaId != AAD_* & state != disabled) subscriptions in your tenant OR you do not have any permissions on Azure Resources (Management Groups, Subscriptions, Resource Groups, Resources) and but want to connect non-ARM API endpoints such as Microsoft Graph etc. #[bool]
    #AzAPICallCustomRuleSet = $object #wip #[object]
}
$azAPICallConf = initAzAPICall @parameters4AzAPICallModule
```

### How to use AzAPICall ?!  

#### Example for Microsoft Graph
Get AAD Groups:  
```POWERSHELL
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups" -AzAPICallConfiguration $azAPICallConf
```
_confused by_ '`$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)`'_? It´s basically a reference to the correct endpoint (think public cloud, sovereign clouds). You can of course also hardcode the endpoint URI:_

```POWERSHELL
AzAPICall -uri "https://graph.microsoft.com/v1.0/groups" -AzAPICallConfiguration $azAPICallConf
```

#### Example for Azure Resource Manager
List Azure Subscriptions (expect multiple results):  
```POWERSHELL
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions?api-version=2020-01-01" -AzAPICallConfiguration $azAPICallConf
```
Get Azure Subscription (expect one result):  
```POWERSHELL
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($subscriptionId)?api-version=2020-01-01" -AzAPICallConfiguration $azAPICallConf -listenOn Content
```
[AzAPICallExample.ps1](pwsh/AzAPICallExample.ps1)

## Public functions
* initAzAPICall
* AzAPICall
* getAzAPICallFunctions
* getAzAPICallRuleSet
* createBearerToken

createBearerToken example: 
```POWERSHELL
$azAPICallConf = initAzAPICall
createBearerToken -AzAPICallConfiguration $azapicallconf -targetEndPoint 'Storage'
Write-Host 'here is the token:' $azAPICallConf['htBearerAccessToken'].Storage
```

## Supported endpoints

| Endpoint                                                                                   | Endpoint URL (AzureCloud)                                                                                    | Variable                                                                                                  |
| ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| [Microsoft Graph](https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0) | `https://graph.microsoft.com`                                                                                | `$azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph`                                                      |
| [ARM (Azure Resource Management)](https://docs.microsoft.com/en-us/rest/api/resources/)    | `https://management.azure.com` (or regional: `https://westus.management.azure.com`)                          | `$azAPICallConf['azAPIEndpointUrls'].ARM`                                                                 |
| [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/)                     | `https://vault.azure.net`                                                                                    | `$azAPICallConf['azAPIEndpointUrls'].KeyVault`                                                            |
| [Log Analytics](https://docs.microsoft.com/en-us/rest/api/loganalytics/)                   | `https://api.loganalytics.io/v1`                                                                             | `$azAPICallConf['azAPIEndpointUrls'].LogAnalytics`                                                        |
| [Storage (blob)](https://learn.microsoft.com/en-us/rest/api/storageservices/)              | `https://<storageAccountName>.blob.core.windows.net` / `https://<storageAccountName>.blob.storage.azure.net` | https://_storageAccountName_.blob.core.windows.net /  https://_storageAccountName_.blob.storage.azure.net |

Add a new endpoint -> setAzureEnvironment.ps1

## General Parameters

Parameters that can be used with the initAzAPICall cmdlet 

Example: [Initialize AzAPICall](#initialize-azapicall)

| Field                               |   Type   | Description                                                                                                                                                                                                                                                                                                                                                                                                                  | Required |
| ----------------------------------- | :------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------: |
| DebugAzAPICall                      |  `bool`  | Set to `true` to enable debug output                                                                                                                                                                                                                                                                                                                                                                                         |          |
| SubscriptionId4AzContext            | `string` | Specify if specific subscription should be used for the AzContext (Subscription Id / GUID)                                                                                                                                                                                                                                                                                                                                   |          |
| TenantId4AzContext                  | `string` | Specify Tenant be used for the AzContext (Tenant Id / GUID)                                                                                                                                                                                                                                                                                                                                                                  |          |
| WriteMethod                         | `string` | Write method. Debug, Error, Host, Information, Output, Progress, Verbose, Warning (default: host)                                                                                                                                                                                                                                                                                                                            |          |
| DebugWriteMethod                    | `string` | Write method in case of wanted or enforced debug. Debug, Error, Host, Information, Output, Progress, Verbose, Warning (default: host)                                                                                                                                                                                                                                                                                        |          |
| AzAPICallCustomRuleSet              | `object` | wip                                                                                                                                                                                                                                                                                                                                                                                                                          |          |
| SkipAzContextSubscriptionValidation |  `bool`  | Only use in case you do not have any valid (quotaId != AAD_* & state != disabled) subscriptions in your tenant OR you do not have any permissions on Azure Resources (Management Groups, Subscriptions, Resource Groups, Resources) and but want to connect non-ARM API endpoints such as Microsoft Graph etc. (Per default a subscription is expected to be present in the Az context, if not then AzAPICall will throw..). |          |


## AzAPICall Parameters

Parameters that can be used with the AzAPICall cmdlet

Example: `AzAPICall -uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -AzAPICallConfiguration $azAPICallConf`

| Field                  |   Type    | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |                          Info                           |
| ---------------------- | :-------: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------------------------------------------------: |
| uri                    | `string`  | `$azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups` which translates to: `https://graph.microsoft.com/v1.0/groups`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |                  mandatory parameter ✅                  |
| AzAPICallConfiguration | `object`  | Set of prebuilt (`$azAPICallConf = initAzAPICall`) variables required for AzAPICall operations (`-AzAPICallConfiguration $azAPICallConf`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |                  mandatory parameter ✅                  |
| method                 | `string`  | Method for the API request (e.g. `GET`, `POST`, ..)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |                    default is `GET`                     |
| currentTask            | `string`  | Free text field; in case of error or enabled `-DebugAzAPICall` currentTask will be output to console                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |                                                         |
| body                   | `string`  | Request Body for the API request - [Example](https://docs.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http#request-body)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |                                                         |
| caller                 | `string`  | Set the value to `CustomDataCollection` for parallelization to have different font colors for the debug output                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |                                                         |
| consistencyLevel       | `string`  | For several [OData query parameters](https://docs.microsoft.com/en-us/graph/query-parameters) the `consistencyLevel`-header need to be set to `eventual`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |                                                         |
| listenOn               | `string`  | Depending to the expected response of the API call the following values are accepted: `Value`, `Content`, `ContentProperties`, `Headers` or `StatusCode`. &#128161; An example for the ARM Subscriptions API: To get _one_ defined subscription you would use `-listenOn Content`, for get/list _all_ subscriptions you would use `-listenOn Value` (which is the default). Think [singular/plural](#example-for-azure-resource-manager)                                                                                                                                                                                                                                               |                   default is `Value`                    |
| noPaging               | `switch`  | If value is `true` paging will be deactivated and you will only get the defined number of `$top` results or [Resource Graph limits any query to returning only `100` records](https://docs.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data). Otherwise, you can use `$top` to increase the result batches from default `100` up to `999` for the `AzAPICall`. Value for `$top` must range from 1 to 999                                                                                                                                                                                                                                                    |                                                         |
| validateAccess         | `switch`  | Use this parameter if you only want to validate that the requester has permissions to the enpoint, if authorization is denied AzAPICall returns 'failed'. (Using `-validateAccess` will set `noPaging` to `true`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |                                                         |
| skipOnErrorCode        | `int32[]` | In some cases _(e.g. trying to add a user to a group were the user is already a member of)_ the API responde with an http status code 400. This is an expected error. To not throw an error and exit the script, you can use this parameter and set an expected error status code like `400`. You can also pass multiple errorcodes e.g. `-skipOnErrorCode 400,409`                                                                                                                                                                                                                                                                                                                    |                                                         |
| unhandledErrorAction   | `string`  | When a call to an API returns an Error, that error is processed by AzAPICallErrorHandler. If that error is unhandled, AzAPICallErrorHandler will log the error and Throw a message which terminates the script. This happens when parameter -unhandledErrorAction is set to `Stop` (which is also the default if not configured). When -unhandledErrorAction is set to `Continue`, AzAPICallErrorHandler logs the error including full details to raise an issue at the repo and continues processing. When -unhandledErrorAction is set to `ContinueQuiet`, AzAPICallErrorHandler only logs the error (excluding full details to raise an issue at the repo) and continues processing | default is `Stop`, options: `Continue`, `ContinueQuiet` |

## Good to know
### Don´t accept the defaults

By default, endPoints return results in batches of e.g. `100`. You can increase the return count defining e.g. `$top=999` (`$top` requires use of `consistencyLevel` = `eventual`)

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
  "Duration": 1.3137266,
  "StatusCode": 404,
  "StatusCodePhrase": "NotFound",
  "rawException": "{
                    "Exception": {
                      "Response": {
                        "Version": "1.1",
                        "Content": "System.Net.Http.HttpConnectionResponseContent",
                        "StatusCode": 404,
                        "ReasonPhrase": "Not Found",
                        [..]
                      },
                      [..]
                    },
                    [..]
                  }"
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

## Contribute

Your contribution is welcome.

Thanks to the awesome contributors:
* Brooks Vaugn
* Kai Schulz
* Simon Wahlin
* Tim Stock
* Tim Wanierke