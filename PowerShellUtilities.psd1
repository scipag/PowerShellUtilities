<#
    PowerShellUtilities provides various utility commandlets.

    Author: Eleanore Young, Michael Schneider, scip AG
    License: MIT
    Copyright: 2017 Eleanore Young, Michael Schneider, scip AG
    Required Dependencies: None
    Optional Dependencies: None
#>

@{

# Script module or binary module file associated with this manifest.
RootModule = '.\PowerShellUtilities.psm1'

# Version number of this module.
ModuleVersion = '0.4.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'a80cfdb5-a30b-4504-8c9e-f0517b241e3c'

# Author of this module
Author = 'Eleanore Young, Michael Schneider'

# Company or vendor of this module
CompanyName = 'scip AG'

# Copyright statement for this module
Copyright = 'MIT License, 2019 (c) E. Young, M. Schneider, scip AG'

# Description of the functionality provided by this module
Description = 'Provides various utility commandlets.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.0'

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    "Select-MimikatzDomainAccounts",
    "Select-MimikatzLocalAccounts",
    "Invoke-MimikatzNetwork"
)

# List of all files packaged with this module
FileList = @(
    "PowerShellUtilities.psm1",
    "PowerShellUtilities.psd1",
    "Invoke-MimikatzNetwork.ps1",
    "Select-MimikatzDomainAccounts.ps1",
    "Select-MimikatzLocalAccounts.ps1"    
)
}
