Write-Host 'Building one file containing all functions'
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

Get-ChildItem -path .\pwsh\module\dev\AzAPICall\functions | ForEach-Object -Process {
    Write-Host ' processing:' $PSItem.Name
    $fileContent = Get-Content -Path .\pwsh\module\dev\AzAPICall\functions\$($PSItem.Name) -Raw
    $fileContent | Add-Content -Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1
}

try {
    Copy-Item -Path .\pwsh\module\dev\AzAPICall\AzAPICall.psd1 -Destination .\pwsh\module\build\AzAPICall -Verbose -ErrorAction Stop
}
catch {
    Write-Host ' Copy AzAPICall.psd1 not possible'
    Throw
}

try {
    Copy-Item -Path .\pwsh\module\dev\AzAPICall\AzAPICall.psm1 -Destination .\pwsh\module\build\AzAPICall -Verbos -ErrorAction Stop
}
catch {
    Write-Host ' Copy AzAPICall.psm1 not possible'
    Throw
}

Write-Host 'Building one file containing all functions done'