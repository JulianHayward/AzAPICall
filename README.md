# AzApiCall
This function will support your Work with Microsoft Graph. It will provide you easily handle your token issurance and will automate a lot of functionalities what normaly you need to code yourself, like paging or error handling.
For information on how to get started, additional dokumentation or examples, check out the [Wiki](https://github.com/JulianHayward/AzAPICall/wiki)
## Current supported endpoints
- Microsoft Graph
- Azure Management
- Azure DevOps
- Microsoft PowerBi
## How to install
```powershell
    Todo  Build up a module and bring it to PSGallery
```
## Example
### Microsoft Graph
```powershell
AzAPICall -uri 'https://graph.microsoft.com/beta/directoryRoles' -Method Get -currentTask "Collecting AADDirectoryRoles"
```
### Azure Management
```powershell
AzApiCall -uri 'https://management.azure.com/subscriptions/**subscriptionId**/resourceGroups/**resourceGroupName**/providers/Microsoft.ApiManagement/service/**serviceName**/groups/**groupId**?api-version=2019-12-01' -Method Get
```

#### Check Ressource avability
```powershell
azapicall -uri "https://management.azure.com/subscriptions/**subscriptionId**/resourcegroups/**resourcegrouname**?api-version=2020-10-01" -method HEAD -listenOn StatusCode
```
### PowerBi
```powershell
AzAPICall -uri 'https://api.powerbi.com/v1.0/myorg/groups/**GroupID**/datasets/**DataSetId**/refreshes' -Method Post -body { "notifyOption": "MailOnFailure" }
```

### Full Code Example
```powershell
$startGetSubscriptions = get-date
$currentTask = "Getting all Subscriptions"
Write-Host "$currentTask"
#https://management.azure.com/subscriptions?api-version=2020-01-01
$uri = "$(($htAzureEnvironmentRelatedUrls).($checkContext.Environment.Name).ResourceManagerUrl)subscriptions?api-version=2019-10-01"
#$path = "/providers/Microsoft.Authorization/policyDefinitions?api-version=2019-09-01"
$method = "GET"

$requestAllSubscriptionsAPI = ((AzAPICall -uri $uri -method $method -currentTask $currentTask))
$requestAllSubscriptionsAPICount = $requestAllSubscriptionsAPI.Count

$endGetSubscriptions = get-date
Write-Host "Getting all $($requestAllSubscriptionsAPICount) Subscriptions duration: $((NEW-TIMESPAN -Start $startGetSubscriptions -End $endGetSubscriptions).TotalSeconds) seconds" 
```

### Parallel Code Example
