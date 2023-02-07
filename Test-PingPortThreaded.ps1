[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,Position=1)]
    [string[]]$Targets = (1..254 | ForEach-Object {((Get-NetIPAddress -AddressFamily IPV4).IPAddress.Split('.')[0..2] -join '.') + '.' + $_ }),

    [Parameter(Mandatory=$false,Position=2)]
    [int[]]$PortsToScan = @(7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88, 102, 110, 113,
        119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179, 194, 201, 264, 318, 381, 383, 389, 411, 412, 427,
        443, 445, 464, 465, 497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 546, 547, 560, 563, 587, 591,
        593, 596, 631, 636, 639, 646, 691, 860, 873, 902, 989, 990, 993, 995),
    
    [Parameter(Mandatory=$false,Position=3)]
    [int]$TimeoutInSeconds = 2
)

Import-Module D:\Powershell\Invoke-Threaded-1\Invoke-Threaded.psd1

function Test-ICMP
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string]$PingTarget,

        [Parameter(Mandatory=$false,Position=1)]
        [int]$TimeoutInSeconds = 1    
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
        [int]$TimeoutInMS = 1000
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
$pings = Invoke-Threaded -ScriptBlock (Get-Command Test-ICMP).ScriptBlock -TargetList $Targets -ParametersToPass $param -MaxThreads 200 -ThreadWaitSleepTimerMs 100 -MaxThreadWaitTimeSec 20

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
        OpenPorts = @()
    }
    $param = [System.Collections.Generic.Dictionary[string,object]]::new()
    $param.Add("Target", $target.PingTarget)
    $portset = Invoke-Threaded -ScriptBlock (Get-Command Test-TCPPort).ScriptBlock -TargetList $PortsToScan -ParametersToPass $param -MaxThreads 80 -ThreadWaitSleepTimerMs 100 -MaxThreadWaitTimeSec 20
    foreach ($portresult in $portset)
    {
        $report[$index].OpenPorts += $portresult.Port
    }
    $report[$index].OpenPorts = $report[$index].OpenPorts | Sort-Object
    $index++
}
$report