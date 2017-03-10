<#
    PowerShellUtilities provides various utility commandlets.

    Author: Eleanore Young, Michael Schneider, scip AG
    License: MIT
    Copyright: 2017 Eleanore Young, Michael Schneider, scip AG
    Required Dependencies: None
    Optional Dependencies: None
#>
Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | % { . $_.FullName}