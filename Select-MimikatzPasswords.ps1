<#
    ScipUtilities provides various utility commandlets.

    Author: Eleanore Young, Michael Schneider, scip AG
    License: MIT
    Copyright: 2017 Eleanore Young, Michael Schneider, scip AG
    Required Dependencies: None
    Optional Dependencies: None
#>

#Requires -Version 2
Set-StrictMode -Version 2

function Select-MimikatzPasswords {
<#
    .SYNOPSIS
    Extract passwords or password hashes from Mimikatz log files. Developed for Mimikatz version 2.0 alpha.

    .PARAMETER Path
    Choose the path or GLOB pattern that tells the function which files to search.

    .PARAMETER FindData
    Choose to look for either passwords or hashes (ntlm and sha1).

    .PARAMETER OutputTo
    Output the results either to the console, to a format parseable in hashcat, or to CSV.
#>
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Path = "*.log",

        [ValidateSet("passwords", "ntlm", "sha1")]
        [String]
        $FindData = "passwords",

        [ValidateSet("console", "hashcat", "csv")]
        [String]
        $OutputTo = "console"
    )

    $PasswordRegex = "\s+\*\sUsername\s+:\s(?<username>[a-zA-Z0-9]+)[\r\n]+\s+\*\sDomain\s+:\s(?<domain>[a-zA-Z0-9]+)[\r\n]+\s+\*\sPassword\s+:\s(?<password>(?!\(null\)).*)[\r\n]+"
    $HashRegex = "\s+\*\sUsername\s+:\s(?<username>[a-zA-Z0-9]+)[\r\n]+\s+\*\sDomain\s+:\s(?<domain>[a-zA-Z0-9]+)[\r\n]+\s+\*\sFlags\s+:\s.*[\r\n]+\s+\*\sNTLM\s+:\s(?<ntlm>[0-9a-fA-F]+)[\r\n]+\s+\*\sSHA1\s+:\s(?<sha1>[0-9a-fA-F]+)[\r\n]+"

    $PasswordOutput = New-Object System.Collections.Generic.List[System.Object]
    $HashOutput = New-Object System.Collections.Generic.List[System.Object]
    Foreach ($LogFile in Get-ChildItem -Recurse $Path) {
        $Content = Get-Content -Raw -Path $LogFile
        $PasswordMatches = Select-String -InputObject $Content -AllMatches -Pattern $PasswordRegex

        Foreach ($Match in $PasswordMatches.Matches) {
            $SearchEntry = New-Object System.Object
            $SearchEntry | Add-Member -NotePropertyName "Username" -NotePropertyValue $Match.Groups["username"].Value
            $SearchEntry | Add-Member -NotePropertyName "Domain" -NotePropertyValue $Match.Groups["domain"].Value
            $SearchEntry | Add-Member -NotePropertyName "Password" -NotePropertyValue $Match.Groups["password"].Value
            $PasswordOutput.Add($SearchEntry)
        }

        $HashMatches = Select-String -InputObject $Content -AllMatches -Pattern $HashRegex
        Foreach ($Match in $HashMatches.Matches) {
            $SearchEntry = New-Object System.Object
            $SearchEntry | Add-Member -NotePropertyName "Username" -NotePropertyValue $Match.Groups["username"].Value
            $SearchEntry | Add-Member -NotePropertyName "Domain" -NotePropertyValue $Match.Groups["domain"].Value
            $SearchEntry | Add-Member -NotePropertyName "NTLM" -NotePropertyValue $Match.Groups["ntlm"].Value
            $SearchEntry | Add-Member -NotePropertyName "SHA1" -NotePropertyValue $Match.Groups["sha1"].Value
            $HashOutput.Add($SearchEntry)
        }
    }

    $PasswordOutput = ($PasswordOutput | Sort-Object -Property Username -Unique)
    $HashOutput = ($HashOutput | Sort-Object -Property Username -Unique)

    if ($OutputTo -eq "csv") {
        
        if ($FindData -in ("ntlm", "sha1")) {
            $HashOutput | ConvertTo-Csv -NoTypeInformation
        } elseif ($FindData -eq "passwords") {
            $PasswordOutput | ConvertTo-Csv -NoTypeInformation
        } else {
            throw "Format '$FindData' doesn't make sense for CSV output."
        }
    } elseif ($OutputTo -eq "hashcat") {
        if ($FindData -eq "ntlm") {
            Foreach ($Entry in $HashOutput) {
                $Entry.Username + ":" + $Entry.NTLM
            }
        } elseif ($FindData -eq "sha1") {
            Foreach ($Entry in $HashOutput) {
                $Entry.Username + ":" + $Entry.SHA1
            }
        } else {
            throw "Format '$FindData' doesn't make sense for hashcat output."
        }
    } else {
        if ($FindData -eq "passwords") {
            $PasswordOutput
        } else {
            $HashOutput
        }
    }
}