<#PSScriptInfo

.VERSION 1.0

.GUID 3121f2fd-ff6f-4ddb-93cc-da97938b71c7

.AUTHOR Brian McMahon

.COPYRIGHT
Copyright = '(c) Brian McMahon 2023
This PowerShell script is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or 
(at your option) any later version.
This PowerShell script is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this PowerShell script. If not, see <https://www.gnu.org/licenses/>.'

.LICENSEURI
https://github.com/bmcmcm/Test-PingPortThreaded/blob/master/LICENSE.md

.PROJECTURI
https://github.com/bmcmcm/Test-PingPortThreaded

.EXTERNALMODULEDEPENDENCIES 
@('Invoke-Threaded')

.RELEASENOTES
Initial Release

#>

<# 
.SYNOPSIS
Using threading via the "Invoke-Threaded" module, Test-PingPortThreaded pings a group of supplied targets, and port scans targets that are successfully pinged.

.DESCRIPTION
Test-PingPortThreaded is a demonstration script for the Invoke-Threaded module. The script will ping IP Addresses or computer hostnames, and scan for open TCP ports. None of the parameters are manditory, but arrays of targets and ports can be supplied instead of using the defaults. 

.PARAMETER Targets
String[] (defaults to local class C of the localhost's IP Address), IP Addresses or computer hostnames or a combination of each.

.PARAMETER PortsToScan
Int[] (defaults to the top well known ports between 1 and 1000), TCP port numbers to scan if a ping is successful

.PARAMETER TimeoutInSeconds
Int (default is 2), Number of seconds (not milliseconds) to wait before a ping or TCP port scan times out.

.PARAMETER ThreadCount
Int (default is 200), Maximum number of threads that will be started

.INPUTS
You cannot pipe objects to Test-PingPortThreaded.ps1.

.OUTPUTS
Test-PingPortThreaded.ps1 outputs a PSCustomObject array which contains all successful ping and any successful TCP port scans.

.EXAMPLE
The following example uses all defaults and exports the results to Out-GridView

PS> .\Test-PingPortThreaded.ps1 | Out-GridView

.EXAMPLE
The following example gets targets all of the computer found in the local Active Directory Domain, scans specified ports and exports the results to a CSV file.

PS> .\Test-PingPortThreaded.ps1 -Targets (Get-ADComputer -Filter *).Name -PortsToScan @(80,135,137,138,139,443) | Export-CSV -Path C:\Temp\PingPortResults.csv -NoTypeInformation
#> 


[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,Position=0)]
    [string[]]$Targets = (1..254 | ForEach-Object {((Get-NetIPAddress -AddressFamily IPV4).IPAddress.Split('.')[0..2] -join '.') + '.' + $_ }),

    [Parameter(Mandatory=$false,Position=1)]
    [int[]]$PortsToScan = @(7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88, 102, 110, 113,
        119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179, 194, 201, 264, 318, 381, 383, 389, 411, 412, 427,
        443, 445, 464, 465, 497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 546, 547, 560, 563, 587, 591,
        593, 596, 631, 636, 639, 646, 691, 860, 873, 902, 989, 990, 993, 995),
    
    [Parameter(Mandatory=$false,Position=2)]
    [int]$TimeoutInSeconds = 2,

    [Parameter(Mandatory=$false,Position=3)]
    [int]$ThreadCount = 200
)

Import-Module Invoke-Threaded
try 
{
    if (!(Get-Command Invoke-Threaded)) 
    {
        Write-Error "Invoke-Threaded command not found, check for missing module or the installation"
        return
    }
}
catch 
{
    Write-Error "Invoke-Threaded command not found, check for missing module or the installation"
}

function Test-ICMP
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string]$PingTarget,

        [Parameter(Mandatory=$false,Position=1)]
        [int]$TimeoutInSeconds = 2    
    )
    $TargetName = $null
    $regx = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    $r = Test-Connection -TargetName $PingTarget -TimeoutSeconds $TimeoutInSeconds -Count 1 -IPv4
    if ($r.Status -eq "Success")
    {
        if ($PingTarget -match $regx)
        {
            $TargetName = [System.Net.DNS]::GetHostEntry($PingTarget).HostName
        } else {
    
        }
        if (!$TargetName) {$TargetName = $PingTarget}
    }
    return [PSCustomObject]@{
        Source = $r.Source
        PingTarget = $r.DisplayAddress
        TargetName = $TargetName
        Latency = $r.Latency
        Status = $r.Status
    }
}

function Test-TCPPort
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [int]$Port,

        [Parameter(Position=1)]
        [string]$Target,
        
        [Parameter(Position=2)]
        [int]$TimeoutInMS = 2000
    )
    $portCheck = (New-Object System.Net.Sockets.TcpClient).ConnectAsync($Target, $Port).Wait($TimeoutInMS)
    if ($portCheck)
    {
        return [PSCustomObject]@{
            Target = $Target
            Port = $Port
        }
    } else { return $null }
}

$param = [System.Collections.Generic.Dictionary[string,object]]::new()
$param.Add("TimeoutInSeconds", $TimeoutInSeconds)
$pings = Invoke-Threaded -ScriptBlock (Get-Command Test-ICMP).ScriptBlock -TargetList $Targets -ParametersToPass $param -MaxThreads $ThreadCount -ThreadWaitSleepTimerMs 100 -MaxThreadWaitTimeSec 30

$tcpChecks = $pings | Where-Object {$_.Status -eq "Success"}
$report = @()
$index = 0
foreach ($target in $tcpChecks)
{
    $report += [PSCustomObject]@{
        Source = $target.Source
        IPAddress = $target.PingTarget
        Hostname = $target.TargetName
        Latency = $target.Latency
        Status = $target.Status
        OpenPorts = ""
        OpenPortArray = @()
    }
    $param = [System.Collections.Generic.Dictionary[string,object]]::new()
    $param.Add("Target", $target.PingTarget)
    $param.Add("TimeoutInMS", $TimeoutInSeconds * 1000)
    $portret = Invoke-Threaded -ScriptBlock (Get-Command Test-TCPPort).ScriptBlock -TargetList $PortsToScan -ParametersToPass $param -MaxThreads $ThreadCount -ThreadWaitSleepTimerMs 100 -MaxThreadWaitTimeSec 30

    foreach ($portresult in $portret)
    {
        $report[$index].OpenPortArray += $portresult.Port
    }
    $report[$index].OpenPortArray = $report[$index].OpenPortArray | Sort-Object
    try {
        $report[$index].OpenPorts = [System.String]::Join(",",$report[$index].OpenPortArray)
    }
    catch {
        #Empty array error, don't care, ha
    }
    $index++
}
$report