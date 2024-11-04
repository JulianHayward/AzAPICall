Get-ChildItem -Path $PSScriptRoot\functions | ForEach-Object -Process {
    . $PSItem.FullName
}