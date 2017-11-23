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

function New-LocalAccountEntry {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Hostname,

        [ValidateNotNullOrEmpty()]
        [String]
        $Username,

        [AllowEmptyString()]
        [String]
        $LmHash,

        [AllowEmptyString()]
        [String]
        $NtlmHash
    )

    New-Object -TypeName PSObject -Prop @{
        'Hostname' = $Hostname;
        'Username' = $Username;
        'LM' = $LmHash;
        'NTLM' = $NtlmHash;
    }
}

function Select-MimikatzLocalAccounts {
<#
    .SYNOPSIS
    Extract passwords or password hashes from Mimikatz log files. Developed for Mimikatz version 2.0 alpha.

    .PARAMETER Path
    Choose the path or GLOB pattern that tells the function which files to search.

    .PARAMETER OutputTo
    Output the results either to the console, to a format parseable in hashcat, or to CSV.

    .PARAMETER HashcatSelect
    Choose to look for either passwords or hashes (ntlm and lm).
#>
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Path = "*.log",

        [ValidateSet("console", "hashcat", "csv")]
        [String]
        $OutputTo = "console",

        [ValidateSet("ntlm", "lm")]
        [String]
        $HashcatSelect = "ntlm"
    )

    $LocalHashRegex = "lsadump::sam[\r\n]+Domain\s+:\s+(?<host>[-_a-zA-Z0-9]+)[\r\n]+SysKey.*[\r\n]+Local\sSID.*[\r\n]+SAMKey.*[\r\n]+(?:RID.*[\r\n]*User\s+:\s+(?<username>[-_a-zA-Z0-9]+)[\r\n]+LM\s+:\s+(?<lm>[0-9a-fA-F]*)[\r\n]+NTLM\s+:\s+(?<ntlm>[0-9a-fA-F]*)[\r\n]+)+"

    $LocalAccounts = New-Object System.Collections.Generic.List[System.Object]
    Foreach ($LogFile in Get-ChildItem -Recurse $Path) {
        $Content = Get-Content -Raw -Path $LogFile

        $LocalHashMatches = Select-String -InputObject $Content -AllMatches -Pattern $LocalHashRegex
        if ($LocalHashMatches -ne $null) {
            Foreach ($Match in $LocalHashMatches.Matches) {
                $Hostname = $Match.Groups["host"].Value
                For ($i=0; $i -lt $Match.Groups["username"].Captures.Count; $i++) {
                    $Username = $Match.Groups["username"].Captures[$i].Value
                    $LmHash = $Match.Groups["lm"].Captures[$i].Value
                    $NtlmHash = $Match.Groups["ntlm"].Captures[$i].Value
                    $SearchEntry = New-LocalAccountEntry -Hostname $Hostname -Username $Username -LmHash $LmHash -NtlmHash $NtlmHash
                    $LocalAccounts.Add($SearchEntry)
                }
            }
        }
    }
    
    if ($LocalAccounts.Count -eq 0) {
        Write-Warning "Could not find any local accounts with password hashes."
    }

    if ($OutputTo -eq "csv") {
        $LocalAccounts | ConvertTo-Csv -NoTypeInformation
    } elseif ($OutputTo -eq "hashcat") {
        if ($HashcatSelect -eq "ntlm") {
            Foreach ($Entry in $LocalAccounts) {
                $Entry.Username + ":" + $Entry.NTLM
            }
        } elseif ($HashcatSelect -eq "lm") {
            Foreach ($Entry in $LocalAccounts) {
                $Entry.Username + ":" + $Entry.LM
            }
        } else {
            throw "Format '$HashcatSelect' doesn't make sense for hashcat output."
        }
    } else {
        $LocalAccounts | Format-Table
    }
}
