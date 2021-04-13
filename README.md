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