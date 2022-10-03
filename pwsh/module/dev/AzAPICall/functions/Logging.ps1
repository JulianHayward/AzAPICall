function Logging {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $logMessage,

        [Parameter(Mandatory = $false)]
        [string]
        $logMessageForegroundColor = $debugForeGroundColor,

        [Parameter(Mandatory = $false)]
        [string]
        $logMessageWriteMethod = $AzAPICallConfiguration['htParameters'].writeMethod,

        [Parameter(Mandatory = $false)]
        [bool]
        $preventWriteOutput
    )

    if (-not $logMessageForegroundColor) {
        $logMessageForegroundColor = 'Cyan'
    }

    if (-not $logMessageWriteMethod -or $preventWriteOutput) {
        if (-not $logMessageWriteMethod -and $logMessageWriteMethod -ne 'Output' ) {
            $logMessageWriteMethod = 'Warning'
        }
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
        Default { Write-Host $logMessage -ForegroundColor $logMessageForegroundColor }
    }
}