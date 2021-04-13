# ht for BearerToken
$script:htBearerAccessToken = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
$script:htAzureEnvironmentRelatedUrls = [System.Collections.Hashtable]::Synchronized((New-Object System.Collections.Hashtable))
$script:arrayAzureManagementEndPointUrls = @()
$script:arrayAPICallTracking = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$script:arrayAPICallTrackingCustomDataCollection = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$script:checkContext