# Change summary: AzAPICall 1.4.1 → 1.4.2

## Fixes

- **Storage error handling:** Groups the Storage-specific authorization and hostname error conditions so that all require the target endpoint to be `Storage`. Previously, some conditions could match other endpoints.
- **Resource Graph pagination:** Clears accumulated results before restarting after a duplicate `$skipToken`, preventing abandoned pages from being included in the final results.
- **OIDC Authentication error propagation:** Replaces GUID-only exceptions with diagnostic logging followed by `throw $_`. This preserves the underlying error for the outer handler, including the authentication error text used to select OIDC fallback. 
Related issue: https://github.com/JulianHayward/AzAPICall/issues/53

## Enhancements

- **Cost Management:** Handles `NotFound` responses containing “returns null or empty list for id” by returning `NotFoundNotSupported`, rather than treating them as unhandled failures. The diagnostic identifies a potentially new or parked subscription.
- **Cloud-specific federation audiences:** Adds `TokenExchangeAudience` configuration for Azure public, US Government, and China clouds. Unknown environments fall back to the public-cloud audience. GitHub Actions uses this setting instead of a hardcoded audience.

| Azure environment | Token exchange audience |
| --- | --- |
| AzureCloud | `api://AzureADTokenExchange` |
| AzureUSGovernment | `api://AzureADTokenExchangeUSGov` |
| AzureChinaCloud | `api://AzureADTokenExchangeChina` |

## OIDC refactoring

- Consolidates the GitHub Actions and Azure DevOps token-exchange helpers into one platform-aware function.
- Returns the access-token string directly.
- Changes token-exchange requests from `-ErrorAction SilentlyContinue` to `Stop`, with explicit failure logging.
- Ensures Azure DevOps failures with a non-`ClientAssertion` account type reach the common error-reporting path.

## Other changes

- Updates the reported version from **1.4.1 to 1.4.2**.
- Comments out the `Logging` switch’s `Throw` branch. Although `initAzAPICall` already disallows that write method, direct internal calls specifying it now fall through to `Write-Host` rather than throwing.
- Normalizes some `Param` and `Throw` capitalization and adds a final newline. These changes have no functional effect.

## Backlog

### Bounded token-refresh retries (review finding 3)

**Current behavior:** The generic authentication-error branch in `AzAPICallErrorHandler` requests a new bearer token and returns `action = 'retry'` for errors such as `ExpiredAuthenticationToken`, `Authentication_ExpiredToken`, and `InvalidAuthenticationToken`. It does not enforce a refresh limit. The dedicated Kusto 401 branch has its own limit, but matching generic token errors are handled earlier and bypass it.

**Impact:** If token acquisition succeeds but the API continues rejecting the token, the request can loop indefinitely, repeatedly refreshing credentials and sleeping.

**Suggested fix:**

- Let the handler return a distinct `refreshToken` action; let `AzAPICall` own the refresh operation and its budget.
- Initialize a local refresh counter for each `AzAPICall` invocation and allow, for example, two refresh attempts after authentication failures.
- Reset the counter after a successful HTTP response so a later page can recover independently from token expiry.
- When the budget is exhausted, log the failure and respect `unhandledErrorAction`: throw for `Stop`, or stop retrying and retain already collected results for `Continue` and `ContinueQuiet`.
- Preserve wrong-tenant handling, `skipOnErrorCode` precedence, and compatibility with custom handlers returning the existing actions.

**Related Kusto issue (review finding 9):** The generic refresh path omits `TargetCluster`. Forward the cluster URL when refreshing Kusto credentials; retain the base ARM token audience for regional ARM endpoints.

**Regression checks:** Persistent token rejection terminates after the configured refresh budget; an expired token can recover; a successful page resets the budget; separate invocations do not share counters; both Kusto authentication branches receive the cluster; all three error-action modes behave as intended.

### Per-call authorization retry state (review finding 8)

**Current behavior:** The `AuthorizationFailed` handler increments `$script:retryAuthorizationFailedCounter`. The counter is cleared on exhaustion but not after a call recovers successfully. Its initialization inside `AzAPICall` is commented out.

**Impact:** An invocation can inherit failures from an earlier invocation and receive fewer than its intended five retries. For example, if the first call succeeds after three authorization failures, a subsequent call starts with those three failures already counted.

**Suggested fix:**

- Initialize a local mutable state object in `AzAPICall`, such as `$authorizationRetryState = @{ Count = 0 }`.
- Have the child-scope error handler increment and read `$authorizationRetryState.Count` for comparisons and diagnostic messages.
- Update request tracking to read the same state object and remove the script-scoped reset on exhaustion.
- Preserve the existing five-retry limit and delay schedule. Retain the budget across pages within one invocation; each new invocation starts at zero.

**Scope consideration:** Simply removing `script:` from an integer increment is insufficient: assignment in the handler creates a child-local value rather than updating the calling function's counter. Mutating a shared hashtable avoids that problem without module-wide state.

**Regression checks:** A call that retries and succeeds does not reduce the next call's budget; persistent failure allows five retries and exits on the sixth failure; paging retains the invocation's count; tracking records the local count; `Stop`, `Continue`, and `ContinueQuiet` retain their existing exit behavior.

### Storage `NextMarker` pagination (review finding 5)

**Current behavior:** Storage XML responses are inspected for `EnumerationResults.NextMarker`, but the pagination branch only logs the marker. It neither updates the request URI nor sets `$isMore = $true`, so the loop exits after the first successful page.

**Impact:** Blob or container listings can appear successful while returning only their first page. A small `maxresults` value makes this easy to reproduce, provided the listing contains more entries than the requested page size.

**Suggested fix:**

- Clear `$storageResponseXML` before parsing each response to avoid reusing an earlier page's XML.
- For Storage XML listing responses with a nonempty `NextMarker`, add or replace the URI's `marker` query parameter.
- Treat the marker as opaque and URL-encode it once, preserving other parameters such as `comp`, `restype`, `prefix`, and `maxresults`.
- Set `$isMore = $true` and `$notTryCounter = $true`, as in the other pagination paths.
- Continue until the marker is empty, even if an intermediate page contains no entries.
- Detect repeated markers and report a pagination failure rather than looping indefinitely or silently claiming a complete result.
- Preserve `-noPaging` and the existing output contract: `Content` collects XML text per page and `Raw` collects web responses. The default `Value` mode does not extract entries from Storage XML; that is a separate output-shape limitation.

**Regression checks:** Multiple pages are collected; an empty page with a marker continues; reserved characters in markers survive encoding; an existing marker is replaced; other query parameters are preserved; repeated markers terminate; `-noPaging` requests only one page.

**Scope:** This proposal covers XML listing APIs using `NextMarker`, not every Azure Storage continuation mechanism.

### Explicit POST for OIDC token exchange (review finding 1)

**Current behavior:** The shared `createBearerTokenFromLoginEndPoint` helper calls `Invoke-RestMethod` with a form body and content type but no `-Method POST`. Providing a body does not select POST; the earlier offline request-construction check on PowerShell 7.6.5 confirmed GET.

**Impact:** The fallback request does not use the HTTP method required by the Microsoft Entra token endpoint and can fail instead of exchanging the federated assertion for an access token. This affects the shared GitHub Actions and Azure DevOps fallback helper, not the separate Azure DevOps request that obtains the OIDC assertion and already specifies POST.

**Suggested fix:** Add `-Method POST` to the token-endpoint request, retaining the form-encoded payload, `application/x-www-form-urlencoded` content type, and terminating error handling.

**Regression checks:** Mock both platform paths and assert that the token-endpoint request uses POST, targets the configured tenant and login endpoint, sends the expected form fields, returns the access-token string on success, and propagates failure without logging credentials.