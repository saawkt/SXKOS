Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }
Get-Process @("svchost", "audiodg") -ErrorAction SilentlyContinue | ForEach-Object {$_.ProcessorAffinity=0x8}
