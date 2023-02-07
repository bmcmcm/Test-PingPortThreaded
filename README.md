# Test-PingPortThreaded

### Overview
Test-PingPortThreaded is a demonstration script for the Invoke-Threaded module project (see https://github.com/bmcmcm/Invoke-Threaded), which is available on https://www.powershellgallery.com/. The script can be used without providing any parameters, whereupon it will:

* Ping the Class C address range 1..254 that the localhost is on using 200 threads.
* Test for open TCP ports out of the most commonly used ports found from 1 to 1000.
* Output a PSCustomObject that can be output to a CSV file, Out-Gridview, or used for further processing by another script.

The non-manditory input parameters that can be supplied are:

* __Targets__ String[] (defaults to local class C of the localhost's IP Address), IP Addresses or computer hostnames or a combination of each.
* __PortsToScan__ Int[] (defaults to the top well known ports between 1 and 1000), TCP port numbers to scan if a ping is successful.
* __TimeoutInSeconds__ Int (default is 2), Number of seconds (not milliseconds) to wait before a ping or TCP port scan times out.
* __ThreadCount__ Int (default is 200), Maximum number of threads that will be started.
