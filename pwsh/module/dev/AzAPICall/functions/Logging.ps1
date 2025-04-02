function Logging {
    param (
        [Parameter(Mandatory)]
        [string]
        $logMessage,

        [Parameter()]
        [string]
        $logMessageForegroundColor = $debugForeGroundColor,

        [Parameter()]
        [string]
        $logMessageWriteMethod = $AzAPICallConfiguration['htParameters'].writeMethod,

        [Parameter()]
        [bool]
        $preventWriteOutput
    )

    if (-not $logMessageForegroundColor) {
        $logMessageForegroundColor = 'Cyan'
    }

    if (-not $logMessageWriteMethod -or ($preventWriteOutput -and $logMessageWriteMethod -eq 'Output')) {
        $logMessageWriteMethod = 'Warning'
    }

    switch ($logMessageWriteMethod) {
        'Debug' { Write-Debug $logMessage }
        'Error' { Write-Error $logMessage }
        'Host' { Write-Host $logMessage -ForegroundColor $logMessageForegroundColor }
        'Information' { Write-Information $logMessage }
        'Output' { Write-Output $logMessage }
        'Progress' { Write-Progress $logMessage }
        'Verbose' { Write-Verbose $logMessage -Verbose }
        'Warning' { Write-Warning $logMessage }
        'Throw' { throw $logMessage }
        Default { Write-Host $logMessage -ForegroundColor $logMessageForegroundColor }
    }
}