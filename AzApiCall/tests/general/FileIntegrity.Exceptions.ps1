# List of forbidden commands
$global:BannedCommands = @(
	#'Write-Host'
	#'Write-Verbose'
	#'Write-Warning'
	#'Write-Error'
	#'Write-Output'
	'Write-Information'
	'Write-Debug'
	
	# Use CIM instead where possible
	'Get-WmiObject'
	'Invoke-WmiMethod'
	'Register-WmiEvent'
	'Remove-WmiObject'
	'Set-WmiInstance'

	# Use Get-WinEvent instead
	'Get-EventLog'
)


$global:MayContainCommand = @{
#	"Write-Host"  = @()
#	"Write-Verbose" = @()
#	"Write-Warning" = @()
#	"Write-Error"  = @()
#	"Write-Output" = @()
#	"Write-Information" = @()
#	"Write-Debug" = @()
}