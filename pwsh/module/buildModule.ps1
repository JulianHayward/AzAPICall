param(
    [Parameter()]
    [switch]
    $test,

    [Parameter()]
    [switch]
    $beta
)

$ErrorActionPreference = 'Stop'


if ($beta) {
    Write-Host 'Building final beta module (one file containing all functions)'

    $latestAzAPICallVersionInDev = (Import-PowerShellDataFile -Path .\pwsh\module\dev\AzAPICall\AzAPICallBeta.psd1 -Verbose -ErrorAction Stop).ModuleVersion
    if (-not $test) {
        $latestAzAPICallBetaVersionInGallery = (Find-Module -Name AzAPICallBeta -ErrorAction Stop).Version
        if ($latestAzAPICallBetaVersionInGallery -eq $latestAzAPICallVersionInDev) {
            Write-Host "Version conflict (Gallery/Dev):  $latestAzAPICallBetaVersionInGallery = $latestAzAPICallVersionInDev"
            Write-Host 'For testing use switch parameter -test'
            Throw 'Please use switch parameter -test, update AzAPICallBeta version or import the new module'
        }
    }

    if (Test-Path .\pwsh\module\build\AzAPICallBeta.zip) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICallBeta.zip -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build for AzAPICallBeta.zip failed'
            throw
        }
    }

    Write-Host ' Cleaning build\functions'

    if (Test-Path .\pwsh\module\build\AzAPICallBeta\functions\AzAPICallFunctions.ps1) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICallBeta\functions\AzAPICallFunctions.ps1 -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build/functions for AzAPICallFunctions.ps1 failed'
            throw
        }
    }

    if (Test-Path .\pwsh\module\build\AzAPICallBeta\AzAPICallBeta.psd1) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICallBeta\AzAPICallBeta.psd1 -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build for AzAPICallBeta.psd1 failed'
            throw
        }
    }

    if (Test-Path .\pwsh\module\build\AzAPICallBeta\AzAPICallBeta.psm1) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICallBeta\AzAPICallBeta.psm1 -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build for AzAPICallBeta.psm1 failed'
            throw
        }
    }

    try {
        "function getAzAPICallVersion { return '$latestAzAPICallVersionInDev' }" | Set-Content -Path .\pwsh\module\dev\AzAPICall\functions\getAzAPICallVersion.ps1 -Verbose
    }
    catch {
        Write-Host ' building AzAPICallVersion.ps1 failed'
        Throw
    }

    Get-ChildItem -Path .\pwsh\module\dev\AzAPICall\functions | ForEach-Object -Process {
        Write-Host ' processing:' $PSItem.Name
        $fileContent = Get-Content -Path .\pwsh\module\dev\AzAPICall\functions\$($PSItem.Name) -Raw -Verbose
        $fileContent | Add-Content -Path .\pwsh\module\build\AzAPICallBeta\functions\AzAPICallFunctions.ps1 -Verbose
    }

    try {
        Copy-Item -Path .\pwsh\module\dev\AzAPICall\AzAPICallBeta.psd1 -Destination .\pwsh\module\build\AzAPICallBeta -Verbose -ErrorAction Stop
    }
    catch {
        Write-Host ' Copy AzAPICallBeta.psd1 failed'
        Throw
    }

    try {
        Copy-Item -Path .\pwsh\module\dev\AzAPICall\AzAPICallBeta.psm1 -Destination .\pwsh\module\build\AzAPICallBeta -Verbos -ErrorAction Stop
    }
    catch {
        Write-Host ' Copy AzAPICallBeta.psm1 failed'
        Throw
    }

    try {
        Compress-Archive -Path .\pwsh\module\build\AzAPICallBeta -DestinationPath .\pwsh\module\build\AzAPICallBeta.zip
    }
    catch {
        Write-Host ' Compress-Archive of build\AzAPICallBeta failed'
        Throw
    }

    Write-Host "Building one file containing all functions done (module version: $latestAzAPICallVersionInDev)"
}
else {
    Write-Host 'Building final module (one file containing all functions)'

    $latestAzAPICallVersionInDev = (Import-PowerShellDataFile -Path .\pwsh\module\dev\AzAPICall\AzAPICall.psd1 -Verbose -ErrorAction Stop).ModuleVersion
    if (-not $test) {
        $latestAzAPICallVersionInGallery = (Find-Module -Name AzAPICall -ErrorAction Stop).Version
        if ($latestAzAPICallVersionInGallery -eq $latestAzAPICallVersionInDev) {
            Write-Host "Version conflict (Gallery/Dev):  $latestAzAPICallVersionInGallery = $latestAzAPICallVersionInDev"
            Write-Host 'For testing use switch parameter -test'
            throw
        }
    }

    if (Test-Path .\pwsh\module\build\AzAPICall.zip) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICall.zip -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build for AzAPICall.zip failed'
            throw
        }
    }

    Write-Host ' Cleaning build\functions'

    if (Test-Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1 -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build/functions for AzAPICallFunctions.ps1 failed'
            throw
        }
    }

    if (Test-Path .\pwsh\module\build\AzAPICall\AzAPICall.psd1) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICall\AzAPICall.psd1 -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build for AzAPICall.psd1 failed'
            throw
        }
    }

    if (Test-Path .\pwsh\module\build\AzAPICall\AzAPICall.psm1) {
        try {
            Remove-Item -Path .\pwsh\module\build\AzAPICall\AzAPICall.psm1 -Verbose -ErrorAction Stop
        }
        catch {
            Write-Host ' Cleaning build for AzAPICall.psm1 failed'
            throw
        }
    }

    try {
        "function getAzAPICallVersion { return '$latestAzAPICallVersionInDev' }" | Set-Content -Path .\pwsh\module\dev\AzAPICall\functions\getAzAPICallVersion.ps1 -Verbose
    }
    catch {
        Write-Host ' building AzAPICallVersion.ps1 failed'
        Throw
    }

    Get-ChildItem -Path .\pwsh\module\dev\AzAPICall\functions | ForEach-Object -Process {
        Write-Host ' processing:' $PSItem.Name
        $fileContent = Get-Content -Path .\pwsh\module\dev\AzAPICall\functions\$($PSItem.Name) -Raw -Verbose
        $fileContent | Add-Content -Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1 -Verbose
    }

    try {
        Copy-Item -Path .\pwsh\module\dev\AzAPICall\AzAPICall.psd1 -Destination .\pwsh\module\build\AzAPICall -Verbose -ErrorAction Stop
    }
    catch {
        Write-Host ' Copy AzAPICall.psd1 failed'
        Throw
    }

    try {
        Copy-Item -Path .\pwsh\module\dev\AzAPICall\AzAPICall.psm1 -Destination .\pwsh\module\build\AzAPICall -Verbos -ErrorAction Stop
    }
    catch {
        Write-Host ' Copy AzAPICall.psm1 failed'
        Throw
    }

    try {
        Compress-Archive -Path .\pwsh\module\build\AzAPICall -DestinationPath .\pwsh\module\build\AzAPICall.zip
    }
    catch {
        Write-Host ' Compress-Archive of build\AzAPICall failed'
        Throw
    }

    Write-Host "Building one file containing all functions done (module version: $latestAzAPICallVersionInDev)"
}