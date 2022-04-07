function testAzModules {
    $testCommands = @('Get-AzContext')
    $azModules = @('Az.Accounts')

    Logging -preventWriteOutput $true -logMessage ' Check required Az modules cmdlets'
    foreach ($testCommand in $testCommands) {
        if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
            Logging -preventWriteOutput $true -logMessage "  AzModule test failed: cmdlet '$testCommand' not available - install module(s): '$($azModules -join ', ')'" -logMessageForegroundColor 'Red'
            Throw 'Error - check the last console output for details'
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Az PS module supporting cmdlet '$testCommand' installed"
        }
    }

    #Logging -preventWriteOutput $true -logMessage " Collecting Az modules versions"
    foreach ($azModule in $azModules) {
        $azModuleVersion = (Get-InstalledModule -Name "$azModule" -ErrorAction Ignore).Version
        if ($azModuleVersion) {
            Logging -preventWriteOutput $true -logMessage "  Az Module $azModule Version: $azModuleVersion"
            Logging -preventWriteOutput $true -logMessage '  Required Az modules cmdlets check succeeded' -logMessageForegroundColor 'Green'
            return $azModuleVersion
        }
        else {
            Logging -preventWriteOutput $true -logMessage "  Az Module $azModule Version: could not be assessed"
            Logging -preventWriteOutput $true -logMessage '  Required Az modules cmdlets check succeeded' -logMessageForegroundColor 'Green'
            return 'n/a'
        }
    }
}