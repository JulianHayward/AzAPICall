@{
	# Script module or binary module file associated with this manifest
	RootModule = 'AzApiCall.psm1'
	
	# Version number of this module.
	ModuleVersion = '1.0.1'
	
	# ID used to uniquely identify this module
	GUID = '06c8b02a-f5a8-4c1a-8380-f86ab7be973f'
	
	# Author of this module
	Author = 'Julian Hayward'
	
	# Company or vendor of this module
	CompanyName = 'Microsoft'
	
	# Copyright statement for this module
	Copyright = 'Copyright (c) 2021 Julian Hayward'
	
	# Description of the functionality provided by this module
	Description = 'This function will support your Work with Microsoft Graph. It will provide you easily handle your token issurance and will automate a lot of functionalities what normaly you need to code yourself, like paging or error handling.'
	
	# Minimum version of the Windows PowerShell engine required by this module
	PowerShellVersion = '7.0.3'
	
	# Modules that must be imported into the global environment prior to importing
	# this module
	RequiredModules = @(
		@{ ModuleName='Az.Accounts'; ModuleVersion='2.0.0'},
		@{ ModuleName='PSFramework'; ModuleVersion='1.6.197' }
	)
	
	# Assemblies that must be loaded prior to importing this module
	# RequiredAssemblies = @('bin\AzApiCall.dll')
	
	# Type files (.ps1xml) to be loaded when importing this module
	# TypesToProcess = @('xml\AzApiCall.Types.ps1xml')
	
	# Format files (.ps1xml) to be loaded when importing this module
	# FormatsToProcess = @('xml\AzApiCall.Format.ps1xml')
	
	# Functions to export from this module
	FunctionsToExport = @(
		'AzAPICall'
	)
	
	# Cmdlets to export from this module
	CmdletsToExport = ''
	
	# Variables to export from this module
	VariablesToExport = ''
	
	# Aliases to export from this module
	AliasesToExport = ''
	
	# List of all modules packaged with this module
	ModuleList = @()
	
	# List of all files packaged with this module
	FileList = @()
	
	# Private data to pass to the module specified in ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
	PrivateData = @{
		
		#Support for PowerShellGet galleries.
		PSData = @{
			
			# Tags applied to this module. These help with module discovery in online galleries.
			# Tags = @()
			
			# A URL to the license for this module.
			# LicenseUri = ''
			
			# A URL to the main website for this project.
			# ProjectUri = ''
			
			# A URL to an icon representing this module.
			# IconUri = ''
			
			# ReleaseNotes of this module
			# ReleaseNotes = ''
			
		} # End of PSData hashtable
		
	} # End of PrivateData hashtable
}