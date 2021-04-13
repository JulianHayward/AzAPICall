<#
Add all things you want to run after importing the main function code

WARNING: ONLY provide paths to files!

After building the module, this file will be completely ignored, adding anything but paths to files ...
- Will not work after publishing
- Could break the build process
#>

$moduleRoot = Split-Path (Split-Path $PSScriptRoot)

# Load Configurations
(Get-ChildItem "$moduleRoot\internal\configurations\*.ps1" -ErrorAction Ignore).FullName
