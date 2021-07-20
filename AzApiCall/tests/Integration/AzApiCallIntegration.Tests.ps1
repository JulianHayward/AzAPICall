param
(
    [Parameter()][System.String]$User,

    [Parameter()][System.String]$UserPassword

)

# Azure Management Integration Test
    Write-Verbose 'Azure Management Integration Test'
    try { 
        AzApiCall -uri 'https://management.azure.com/subscriptions?api-version=2020-01-01' -method Get
    }
    catch { 
        throw "Azure Management Integration isnt successfull"
    }

# Ms Graph Integration Test
    Write-Verbose 'Ms Graph Integration'
    try { 
        AzAPICall -uri 'https://graph.microsoft.com/beta/directoryRoles' -method Get
    }
    catch { 
        throw "Ms Graph Integration isnt successfull"
    }