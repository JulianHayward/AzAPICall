Write-Host 'Building one file containing all functions'
Write-Host ' Cleaning build\functions'

if (Test-Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1) {
    try {
        Remove-Item -Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1 -Verbose -ErrorAction Stop
    }
    catch {
        Write-Host ' Cleaning build/functions failed'
        throw
    }
}

Get-ChildItem -path .\pwsh\module\dev\AzAPICall\functions | ForEach-Object -Process {
    Write-Host ' processing:' $PSItem.Name
    $fileContent = Get-Content -Path .\pwsh\module\dev\AzAPICall\functions\$($PSItem.Name) -Raw
    $fileContent | Add-Content -Path .\pwsh\module\build\AzAPICall\functions\AzAPICallFunctions.ps1
}
Write-Host 'Building one file containing all functions done'