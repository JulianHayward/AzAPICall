# AzAPICall

[![PowerShell Gallery Version (including pre-releases)](https://img.shields.io/powershellgallery/v/AzAPICall?include_prereleases&label=PowerShell%20Gallery)](https://www.powershellgallery.com/packages/AzAPICall)

AzAPICall simplifies calls to Microsoft Azure API endpoints by managing bearer tokens, handling common API errors, and following supported pagination formats.

## Table of contents

- [AzAPICall](#azapicall)
  - [Table of contents](#table-of-contents)
  - [AzAPICall example](#azapicall-example)
    - [Get \& Set AzAPICall PowerShell module](#get--set-azapicall-powershell-module)
    - [Initialize AzAPICall](#initialize-azapicall)
    - [How to use AzAPICall](#how-to-use-azapicall)
      - [Example for Microsoft Graph](#example-for-microsoft-graph)
      - [Example for Azure Resource Manager](#example-for-azure-resource-manager)
  - [Public functions](#public-functions)
  - [Supported endpoints](#supported-endpoints)
  - [General Parameters](#general-parameters)
  - [AzAPICall Parameters](#azapicall-parameters)
  - [Good to know](#good-to-know)
    - [Page sizes and pagination](#page-sizes-and-pagination)
    - [Partial results on errors](#partial-results-on-errors)
    - [AzAPICall Tracking](#azapicall-tracking)
  - [Runtime environment](#runtime-environment)
    - [Azure DevOps](#azure-devops)
  - [Prerequisites](#prerequisites)
    - [PowerShell runtime](#powershell-runtime)
    - [PowerShell modules](#powershell-modules)
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

### How to use AzAPICall

#### Example for Microsoft Graph

Get Microsoft Entra ID groups:

```POWERSHELL
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups" -AzAPICallConfiguration $azAPICallConf
```

`$azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph` contains the Microsoft Graph endpoint for the Azure environment in your context, including supported sovereign clouds. You can also hardcode the public-cloud endpoint:

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
$subscriptionId = $azAPICallConf['checkContext'].Subscription.Id # Or specify another subscription GUID
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].ARM)/subscriptions/$($subscriptionId)?api-version=2020-01-01" -AzAPICallConfiguration $azAPICallConf -listenOn Content
```

[AzAPICallExample.ps1](pwsh/AzAPICallExample.ps1)

## Public functions

- initAzAPICall

- AzAPICall
- getAzAPICallFunctions
- getAzAPICallRuleSet
- createBearerToken

createBearerToken example:

```POWERSHELL
$azAPICallConf = initAzAPICall
createBearerToken -AzAPICallConfiguration $azapicallconf -targetEndPoint 'Storage'
Write-Host 'here is the token:' $azAPICallConf['htBearerAccessToken'].Storage
```

## Supported endpoints

| Endpoint                                                                                                                 | Endpoint URL (AzureCloud)                                                                                    | Variable                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| [Microsoft Graph](https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0)                               | `https://graph.microsoft.com`                                                                                | `$azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph`                                                        |
| [ARM (Azure Resource Management)](https://docs.microsoft.com/en-us/rest/api/resources/)                                  | `https://management.azure.com`<br>(or regional: `https://westus.management.azure.com`)                       | `$azAPICallConf['azAPIEndpointUrls'].ARM`<br>(or regional: `$azAPICallConf['azAPIEndpointUrls'].ARMwestus`) |
| [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/)                                                   | `https://vault.azure.net`                                                                                    | `$azAPICallConf['azAPIEndpointUrls'].KeyVault`                                                              |
| [Log Analytics](https://docs.microsoft.com/en-us/rest/api/loganalytics/)                                                 | `https://api.loganalytics.io/v1`                                                                             | `$azAPICallConf['azAPIEndpointUrls'].LogAnalytics`                                                          |
| [Storage (blob)](https://learn.microsoft.com/en-us/rest/api/storageservices/)                                            | `https://<storageAccountName>.blob.core.windows.net` / `https://<storageAccountName>.blob.storage.azure.net` | https://_storageAccountName_.blob.core.windows.net /  https://_storageAccountName_.blob.storage.azure.net   |
| [Monitor (ingest)](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview#rest-api-call) | `https://<dce-endpoint>.ingest.monitor.azure.com` | Suffix: `$azAPICallConf['azAPIEndpointUrls'].MonitorIngest` |
| [Kusto (Azure Data Explorer)](https://learn.microsoft.com/en-us/kusto/api/rest/) | `https://<cluster>.<region>.kusto.windows.net` | Suffix: `$azAPICallConf['azAPIEndpointUrls'].Kusto`; use the full cluster URL for requests. |

**Endpoint capabilities and limitations (1.4.2):**

- **Key Vault:** The table's `https://vault.azure.net` value is the authentication audience, not a vault-specific request URL. Data-plane requests use `https://<vault-name>.vault.azure.net/...`. The current module does not recognize those vault-specific hosts, so Key Vault data-plane routing is not currently supported despite the configured audience.
- **Storage:** Use `-listenOn Content` for XML response text or `-listenOn Raw` for the web response. The default `Value` mode does not extract Storage XML entries. XML listing responses containing `NextMarker` are currently logged but not followed; only the first page is returned. Callers must handle continuation explicitly.
- **Kusto (Azure Data Explorer):** Requests to `https://<cluster>.<region>.kusto.windows.net/...` are recognized. The module derives the token audience from the cluster URL. When calling `createBearerToken` directly, supply `-targetEndPoint Kusto -TargetCluster 'https://<cluster>.<region>.kusto.windows.net'`. Host matching is currently hardcoded to `.kusto.windows.net`; other cloud suffixes are not supported automatically. The generic authentication-error refresh path also currently omits the required cluster argument.
- **Monitor ingestion:** Use the full ingestion endpoint supplied by Azure, with the configured `.MonitorIngest` suffix for the current cloud. Endpoint configuration does not imply that every service supports the same pagination or response format.

To add an endpoint, review [setAzureEnvironment.ps1](pwsh/module/dev/AzAPICall/functions/setAzureEnvironment.ps1) and the host matching in [AzAPICall.ps1](pwsh/module/dev/AzAPICall/functions/AzAPICall.ps1).

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
| uri | `string` | Full HTTPS request URI, for example `"$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups"`. | mandatory parameter ✅ |
| AzAPICallConfiguration | `object`  | Set of prebuilt (`$azAPICallConf = initAzAPICall`) variables required for AzAPICall operations (`-AzAPICallConfiguration $azAPICallConf`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |                  mandatory parameter ✅                  |
| method                 | `string`  | Method for the API request (e.g. `GET`, `POST`, ..)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |                    default is `GET`                     |
| currentTask            | `string`  | Free text field; in case of error or enabled `-DebugAzAPICall` currentTask will be output to console                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |                                                         |
| body                   | `string`  | Request Body for the API request - [Example](https://docs.microsoft.com/en-us/graph/api/group-post-owners?view=graph-rest-1.0&tabs=http#request-body)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |                                                         |
| caller | `string` | Reserved/currently inactive. The former `CustomDataCollection` debug-color behavior is commented out. | |
| consistencyLevel       | `string`  | For several [OData query parameters](https://docs.microsoft.com/en-us/graph/query-parameters) the `consistencyLevel`-header need to be set to `eventual`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |                                                         |
| listenOn               | `string`  | Depending to the expected response of the API call the following values are accepted: `Value`, `Content`, `ContentProperties`, `Headers`, `StatusCode` or `Raw`. &#128161; An example for the ARM Subscriptions API: To get _one_ defined subscription you would use `-listenOn Content`, for get/list _all_ subscriptions you would use no `-listenOn`-parameter as the default `listenOn`-value would be `Value`. Think [singular/plural](#example-for-azure-resource-manager)                                                                                                                                                                                                       |                   default is `Value`                    |
| noPaging | `switch` | Use `-noPaging` to disable automatic continuation and return only the first response page. Page size and limits are API-specific; AzAPICall does not impose a universal `$top` range. See [Page sizes and pagination](#page-sizes-and-pagination). | default is off |
| validateAccess         | `switch`  | Use this parameter if you only want to validate that the requester has permissions to the enpoint, if authorization is denied AzAPICall returns 'failed'. (Using `-validateAccess` will set `noPaging` to `true`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |                                                         |
| skipOnErrorCode        | `int32[]` | In some cases _(e.g. trying to add a user to a group were the user is already a member of)_ the API responde with an http status code 400. This is an expected error. To not throw an error and exit the script, you can use this parameter and set an expected error status code like `400`. You can also pass multiple errorcodes e.g. `-skipOnErrorCode 400,409`                                                                                                                                                                                                                                                                                                                    |                                                         |
| unhandledErrorAction | `string` | For unhandled errors in the standard handler, `Stop` throws. `Continue` logs diagnostic details, stops the current request loop, and returns already collected results. `ContinueQuiet` does the same without the parameter dump. The caller can continue, but results may be partial; later pages are not fetched. See [Partial results on errors](#partial-results-on-errors). | default is `Stop`, options: `Continue`, `ContinueQuiet` |

## Good to know

### Page sizes and pagination

Page sizes are defined by each API, not by AzAPICall. `-noPaging` disables automatic continuation and returns only the first response page; it does not set the page size. Without this switch, the module follows supported `nextLink` and Resource Graph `$skipToken` responses. See the Storage limitation under [Supported endpoints](#supported-endpoints).

**Microsoft Graph:** For the [list groups API](https://learn.microsoft.com/en-us/graph/api/group-list), request up to 999 groups per page using `$top`. Escape the dollar sign in a double-quoted PowerShell URI:

```POWERSHELL
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].MicrosoftGraph)/v1.0/groups?`$top=999" -AzAPICallConfiguration $azAPICallConf
```

`$top` alone does not require `-consistencyLevel eventual`. Certain [advanced directory queries](https://learn.microsoft.com/en-us/graph/aad-advanced-queries) require that header and, in many cases, `$count=true`. Check the specific API and query combination.

**Azure Resource Graph:** The default page size is 100 records and the maximum is 1,000. Set `options.$top` in the JSON request body, not a universal AzAPICall parameter:

```POWERSHELL
$body = @{
  query = 'Resources | project id, name, type | order by id asc'
  options = @{ '$top' = 1000; resultFormat = 'objectArray' }
} | ConvertTo-Json -Depth 10
AzAPICall -uri "$($azAPICallConf['azAPIEndpointUrls'].ARM)/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" -method POST -body $body -listenOn Content -AzAPICallConfiguration $azAPICallConf
```

Automatic continuation depends on the API returning a usable token. Some Resource Graph queries cannot return a `$skipToken`; see [working with large data sets](https://learn.microsoft.com/en-us/azure/governance/resource-graph/concepts/work-with-data).

### Partial results on errors

For errors handled by the standard error handler, `-unhandledErrorAction Stop` throws when the error cannot be handled or its applicable retry budget is exhausted. `Continue` and `ContinueQuiet` stop the current request loop and return any previously collected results, allowing the calling script to proceed. They do **not** skip the failed page and continue fetching later pages.

**Returned results may therefore be incomplete.** Inspect logs and API-call tracking before treating them as a complete inventory. `Continue` includes diagnostic details; `ContinueQuiet` omits the parameter dump but still logs the error. Some failures outside the standard handler can still throw regardless of this setting.

### AzAPICall Tracking

To get some insights on all API calls you can check the `$azAPICallConf['arrayAPICallTracking']` object (synchronized ArrayList)

```POWERSHELL
$azAPICallConf['arrayAPICallTracking'][0] | ConvertTo-Json -Depth 10
```

Example of a successful first request (the first attempt is tracked as `TryCounter: 1`):

```JSON
{
  "CurrentTask": "Microsoft Graph API: Get - Groups",
  "TargetEndpoint": "MicrosoftGraph",
  "Uri": "https://graph.microsoft.com/v1.0/groups?$top=999&$filter=(mailEnabled eq false and securityEnabled eq true)&$select=id,createdDateTime,displayName,description&$orderby=displayName asc&$count=true",
  "Method": "GET",
  "TryCounter": 1,
  "TryCounterUnexpectedError": 0,
  "TryCounterConnectionRelatedError": 0,
  "RetryAuthorizationFailedCounter": null,
  "RestartDueToDuplicateNextlinkCounter": 0,
  "TimeStamp": "2022011316040343",
  "Duration": 1.3137266,
  "StatusCode": 200,
  "StatusCodePhrase": "OK",
  "RawException": null
}
```

On failure, `RawException` contains the PowerShell error record, not a pre-serialized JSON string. Its JSON representation depends on the error and serialization depth.

You can also inspect request durations:

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

## Runtime environment

### Azure DevOps

If you are using a PowerShell script within a pipeline and an `OIDC` service connection, you need to set the [`SYSTEM_ACCESSTOKEN` environment variable](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#systemaccesstoken) in the task of your pipeline. This allows the AzAPICall module to use it for token renewal:

```YML
  - task: AzurePowerShell@5
    displayName: 'OIDC testing with AzurePowerShell@5'
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
    inputs:
      azureSubscription: '$(ServiceConnection)'
      azurePowerShellVersion: LatestVersion
      ScriptType: 'InlineScript'
      Inline: |
        try {
            Install-Module -Name 'AzAPICall' -RequiredVersion '1.4.2' -ErrorAction Stop
        }
        catch {
            Write-Warning '33596ac3-5aab-4704-aef2-e1de6ac71f05'
            Throw $_
        }

        # [..]
```

Otherwise, you will encounter an error message during your pipeline execution:

```text
Logging: /home/vsts/work/1/s/AzAPICall/functions/AzAPICallFunctions.ps1:1672
Line |
1672 |  …             Logging -logMessage "-ERROR: OIDC ADO - Could not find ac …
     |                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | -ERROR: OIDC ADO - Could not find access token, check if the environment
     | variable 'SYSTEM_ACCESSTOKEN' exists and has valid data.
     | https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops&tabs=yaml#systemaccesstoken

##[error]PowerShell exited with code '1'.
```

## Prerequisites

### PowerShell runtime

Use a currently supported PowerShell 7 release. Selected offline regression checks for this review were run on PowerShell 7.6.5; this is not a full live-Azure compatibility certification.

The module manifest does not declare a minimum PowerShell version. Some code paths use PowerShell 7 features such as `ConvertFrom-Json -AsHashtable`, so Windows PowerShell 5.1 compatibility should not be assumed. The separate [parallel example](pwsh/AzAPICallExample.ps1) checks for PowerShell Core 7 with a minimum version of 7.0.3; that historical minimum is not a recommendation to use an unsupported release.

### PowerShell modules

| PowerShell Module |
| ----------------- |
| Az.Accounts       |

Authenticate with `Connect-AzAccount` (or the hosting pipeline's Azure login task) before initialization. The identity needs permissions for each target API and network access to its endpoint; an Azure management-plane role does not automatically grant Microsoft Graph or Storage data-plane permissions.

## Contribute

Your contribution is welcome.

See the [contribution guide](CONTRIBUTING.md) for the development layout, how stable and beta builds work, validation steps, and pull-request guidance.

Thanks to the awesome contributors:

- Brooks Vaugn
- Kai Schulz
- Simon Wahlin
- Tim Stock
- Tim Wanierke
