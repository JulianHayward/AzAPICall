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
### PowerBi
```powershell
AzAPICall -uri 'https://api.powerbi.com/v1.0/myorg/groups/**GroupID**/datasets/**DataSetId**/refreshes' -Method Post -body { "notifyOption": "MailOnFailure" }
```
### Azure DevOps
```powershell
AzAPICall -uri 'https://vsaex.dev.azure.com/**contoso**/_apis/userentitlements?&api-version=5.0-preview.2' -Method Get -currentTask "Collecting Az DevOps User Data"
```
➡️ [more examples...][CodeSamples]

## Supported Plattforms
AzApiCall is builded to run inside of Powershell 5 and Powershell 7. If you wanna implement AzApiCall inside of Posh 7, you need to handle data store while using **foreach -Parallel**


[CodeSamples]: https://github.com/JulianHayward/AzAPICall/blob/main/examples/CodeSamples.txt