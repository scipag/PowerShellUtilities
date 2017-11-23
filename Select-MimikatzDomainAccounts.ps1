<#
    ScipUtilities provides various utility commandlets.

    Author: Eleanore Young, Michael Schneider, scip AG
    License: MIT
    Copyright: 2017 Eleanore Young, Michael Schneider, scip AG
    Required Dependencies: None
    Optional Dependencies: None
#>

#Requires -Version 5
Set-StrictMode -Version 5

function New-DomainAccountEntry {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [String]
        $Username,

        [AllowEmptyString()]
        [String]
        $Password,

        [AllowEmptyString()]
        [String]
        $NtlmHash,

        [AllowEmptyString()]
        [String]
        $Sha1Hash
    )

    New-Object -TypeName PSObject -Prop @{
        'Domain' = $Domain.ToUpper();
        'Username' = $Username;
        'Password' = $Password;
        'NTLM' = $NtlmHash;
        'SHA1' = $Sha1Hash;
    }
}


function Select-MimikatzDomainAccounts {
<#
    .SYNOPSIS
    Extract passwords or password hashes from Mimikatz log files. Developed for Mimikatz version 2.0 alpha.

    .PARAMETER Path
    Choose the path or GLOB pattern that tells the function which files to search.

    .PARAMETER HashcatSelect
    Choose to look for either passwords or hashes (ntlm and sha1).

    .PARAMETER OutputTo
    Output the results either to the console, to a format parseable in hashcat, or to CSV.
#>
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Path = "*.log",

        [ValidateSet("console", "hashcat", "csv")]
        [String]
        $OutputTo = "console",

        [ValidateSet("ntlm", "sha1")]
        [String]
        $HashcatSelect = "ntlm"
    )

    $DomainPasswordRegex = "\s+\*\s+Username\s+:\s+(?<username>[-_a-zA-Z0-9]+)[\r\n]+\s+\*\s+Domain\s+:\s+(?<domain>[a-zA-Z0-9]+)[\r\n]+\s+\*\s+Password\s+:\s+(?<password>(?!\(null\)).*)[\r\n]+"
    $DomainHashRegex = "\s+\*\s+Username\s+:\s+(?<username>[-_a-zA-Z0-9]+)[\r\n]+\s+\*\s+Domain\s+:\s+(?<domain>[a-zA-Z0-9]+)[\r\n]+(\s+\*\sFlags\s+:\s+.*[\r\n]+)?\s+\*\s+NTLM\s+:\s+(?<ntlm>[0-9a-fA-F]+)[\r\n]+\s+\*\sSHA1\s+:\s+(?<sha1>[0-9a-fA-F]+)[\r\n]+"

    $DomainAccounts = @{}
    Foreach ($LogFile in Get-ChildItem -Recurse $Path) {
        $Content = Get-Content -Raw -Path $LogFile

        $DomainPasswordMatches = Select-String -InputObject $Content -AllMatches -Pattern $DomainPasswordRegex
        if ($DomainPasswordMatches -ne $null) {
            Foreach ($Match in $DomainPasswordMatches.Matches) {
                $g = $Match.Groups
                $Username = $g["username"].Value
                if (!$DomainAccounts.ContainsKey($Username)) {
                    $SearchEntry = New-DomainAccountEntry -Domain $g["domain"].Value -Username $Username -Password $g["password"].Value
                    $DomainAccounts.Add($Username, $SearchEntry)
                } else {
                    $SearchEntry = $DomainAccounts.Get_Item($Username)
                    $SearchEntry.Password = $g["password"].Value
                    $DomainAccounts.Set_Item($Username, $SearchEntry)
                }
            }
        } 

        $DomainHashMatches = Select-String -InputObject $Content -AllMatches -Pattern $DomainHashRegex
        if ($DomainHashMatches -ne $null) {
            Foreach ($Match in $DomainHashMatches.Matches) {
                $g = $Match.Groups
                $Username = $g["username"].Value
                if (!$DomainAccounts.ContainsKey($Username)) {
                    $SearchEntry = New-DomainAccountEntry -Domain $g["domain"].Value -Username $Username -NtlmHash $g["ntlm"].Value -Sha1Hash $g["sha1"].Value
                    $DomainAccounts.Add($Username, $SearchEntry)
                } else {
                    $SearchEntry = $DomainAccounts.Get_Item($Username)
                    $SearchEntry.NTLM = $g["ntlm"].Value
                    $SearchEntry.SHA1 = $g["sha1"].Value
                    $DomainAccounts.Set_Item($Username, $SearchEntry)
                }
            }
        }
    }
    
    if ($DomainAccounts.Count -eq 0) {
        Write-Warning "Could not find any domain accounts."
    } else {
        $DomainAccounts = ($DomainAccounts.Values | Sort-Object -Property Username)
    }

    if ($OutputTo -eq "csv") {
        $DomainAccounts | ConvertTo-Csv -NoTypeInformation
    } elseif ($OutputTo -eq "hashcat") {
        if ($HashcatSelect -eq "ntlm") {
            Foreach ($Entry in $DomainAccounts) {
                $Entry.Username + ":" + $Entry.NTLM
            }
        } elseif ($HashcatSelect -eq "sha1") {
            Foreach ($Entry in $DomainAccounts) {
                $Entry.Username + ":" + $Entry.SHA1
            }
        } else {
            throw "Format '$HashcatSelect' doesn't make sense for hashcat output."
        }
    } else {
        $DomainAccounts | Format-Table
    }
}
