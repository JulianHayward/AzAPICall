function createBearerToken {

    param (
        [Parameter(Mandatory)]
        [string]
        $targetEndPoint,

        [Parameter(Mandatory)]
        [object]
        $AzAPICallConfiguration,

        [Parameter()]
        [string]
        $TargetCluster
    )

    if ($targetEndPoint -eq 'Storage') {
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' `"$($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)`" ($(($AzApiCallConfiguration['azAPIEndpointUrls']).StorageAuth))"
    }
    elseif ($targetEndPoint -eq 'MonitorIngest') {
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' `"$($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)`" ($(($AzApiCallConfiguration['azAPIEndpointUrls']).MonitorIngestAuth))"
    }
    elseif ($targetEndPoint -eq 'Kusto') {
        if (-not $TargetCluster) {
            Logging -logMessage " -targetEndPoint: '$targetEndPoint'; -targetCluster undefined: '$TargetCluster'"
            throw " -targetEndPoint: '$targetEndPoint'; -targetCluster undefined: '$TargetCluster'"
        }
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' cluster '$TargetCluster'"
    }
    else {
        Logging -logMessage " +Processing new bearer token request '$targetEndPoint' `"$($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)`""
    }

    if (($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint -or $targetEndPoint -eq 'Kusto') {
        function setBearerAccessToken {
            param (
                [Parameter(Mandatory)]
                [string]
                $createdBearerToken,

                [Parameter(Mandatory)]
                [string]
                $targetEndPoint,

                [Parameter(Mandatory)]
                [object]
                $AzAPICallConfiguration,

                [Parameter()]
                [string]
                $TargetCluster
            )

            if ($targetEndPoint -eq 'Kusto') {
                $AzApiCallConfiguration['htBearerAccessToken'].$TargetCluster = $createdBearerToken
            }
            else {
                $AzApiCallConfiguration['htBearerAccessToken'].$targetEndPoint = $createdBearerToken
            }

            $dateTimeTokenCreated = (Get-Date -Format 'MM/dd/yyyy HH:mm:ss')
            $bearerDetails = getJWTDetails -token $createdBearerToken
            $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
            $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry

            if ($targetEndPoint -eq 'Storage') {
                Logging -logMessage " +Bearer token '$targetEndPoint' ($(($AzApiCallConfiguration['azAPIEndpointUrls']).StorageAuth)): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
            elseif ($targetEndPoint -eq 'MonitorIngest') {
                Logging -logMessage " +Bearer token '$targetEndPoint' ($(($AzApiCallConfiguration['azAPIEndpointUrls']).MonitorIngestAuth)): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
            elseif ($targetEndPoint -eq 'Kusto') {
                Logging -logMessage " +Bearer token '$targetEndPoint' ($TargetCluster): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
            else {
                Logging -logMessage " +Bearer token '$targetEndPoint': [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -logMessageForegroundColor 'DarkGray'
            }
        }

        $azContext = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        try {
            if ($targetEndPoint -eq 'Storage') {
                $tokenRequestEndPoint = ($AzApiCallConfiguration['azAPIEndpointUrls']).StorageAuth
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
            }
            elseif ($targetEndPoint -eq 'MonitorIngest') {
                $tokenRequestEndPoint = ($AzApiCallConfiguration['azAPIEndpointUrls']).MonitorIngestAuth
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
            }
            elseif ($targetEndPoint -eq 'Kusto') {
                $tokenRequestEndPoint = $TargetCluster
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -targetCluster $TargetCluster -AzAPICallConfiguration $AzAPICallConfiguration
            }
            else {
                $tokenRequestEndPoint = ($AzApiCallConfiguration['azAPIEndpointUrls']).$targetEndPoint
                $createdBearerToken = ([Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$tokenRequestEndPoint")).AccessToken
                setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
            }
        }
        catch {
            if (($AzApiCallConfiguration['htParameters']).codeRunPlatform -eq 'GitHubActions') {
                if (($AzApiCallConfiguration['htParameters']).GitHubActionsOIDC) {
                    if (($AzApiCallConfiguration['htParameters']).GitHubActionsOIDC -eq $true) {
                        if ($_ -like '*AADSTS700024*') {
                            Logging -logMessage " Running on '$(($AzApiCallConfiguration['htParameters']).codeRunPlatform)' OIDC: '$(($AzApiCallConfiguration['htParameters']).GitHubActionsOIDC)' - Getting Bearer Token from Login endpoint '$(($AzApiCallConfiguration['azAPIEndpointUrls']).Login)'"

                            $audience = 'api://AzureADTokenExchange'
                            $url = '{0}&audience={1}' -f $ENV:ACTIONS_ID_TOKEN_REQUEST_URL, $audience
                            $gitHubJWT = Invoke-RestMethod $url -Headers @{Authorization = ('bearer {0}' -f $ENV:ACTIONS_ID_TOKEN_REQUEST_TOKEN) }

                            function createBearerTokenFromLoginEndPoint {
                                param (
                                    [Parameter(Mandatory)]
                                    [string]
                                    $tokenRequestEndPoint,

                                    [Parameter(Mandatory)]
                                    $gitHubJWT,

                                    [Parameter(Mandatory)]
                                    [object]
                                    $AzAPICallConfiguration
                                )

                                $loginUri = "$(($AzApiCallConfiguration['azAPIEndpointUrls']).Login)/{0}/oauth2/v2.0/token" -f "$(($AzApiCallConfiguration['checkContext']).Tenant.Id)"
                                $body = "scope=$($tokenRequestEndPoint)/.default&client_id=$(($AzApiCallConfiguration['checkContext']).Account.Id)&grant_type=client_credentials&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion={0}" -f [System.Net.WebUtility]::UrlEncode($gitHubJWT.Value)
                                $bearerToken = Invoke-RestMethod $loginUri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction SilentlyContinue

                                <# Output the token
                                $payloadBearerToken = ($bearerToken.access_token -split '\.')[1]
                                if (($payloadBearerToken.Length % 4) -ne 0) {
                                    $payloadBearerToken = $payloadBearerToken.PadRight($payloadBearerToken.Length + 4 - ($payloadBearerToken.Length % 4), '=')
                                }
                                [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payloadBearerToken)) | ConvertFrom-Json | ConvertTo-Json
                                #>

                                return $bearerToken
                            }

                            $createdBearerToken = (createBearerTokenFromLoginEndPoint -tokenRequestEndPoint $tokenRequestEndPoint -AzAPICallConfiguration $AzAPICallConfiguration -gitHubJWT $gitHubJWT).access_token
                            setBearerAccessToken -createdBearerToken $createdBearerToken -targetEndPoint $targetEndPoint -AzAPICallConfiguration $AzAPICallConfiguration
                        }
                        else {
                            $dumpErrorProcessingNewBearerToken = $true
                        }
                    }
                    else {
                        $dumpErrorProcessingNewBearerToken = $true
                    }
                }
                else {
                    $dumpErrorProcessingNewBearerToken = $true
                }
            }
            else {
                $dumpErrorProcessingNewBearerToken = $true
            }

            if ($dumpErrorProcessingNewBearerToken) {
                Logging -logMessage "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount -tenantId <tenantId>'" -logMessageForegroundColor 'DarkRed'
                #Logging -logMessage "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount -tenantId <tenantId>'." -logMessageForegroundColor 'DarkRed'
                Logging -logMessage "-ERROR processing new bearer token request ($(($AzApiCallConfiguration['htParameters']).codeRunPlatform)) for targetEndPoint '$targetEndPoint' ($($AzApiCallConfiguration['azAPIEndpointUrls'].$targetEndPoint)): $_" -logMessageWriteMethod 'Error'
                Throw 'Error - check the last console output for details'
            }
        }
    }
    else {
        Logging -logMessage "targetEndPoint: '$targetEndPoint' unknown" -logMessageWriteMethod 'Error'
        throw "targetEndPoint: '$targetEndPoint' unknown"
    }
}