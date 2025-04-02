
Disable-MMAgent -PageCombining
Disable-MMAgent -MemoryCompression

Get-PnpDevice -FriendlyName 'AMD PSP' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'AMD SMBus' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Base System Device' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Composite Bus Enumerator' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'High precision event timer' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Intel SMBus' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Legacy device' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Microsoft GS Wavetable Synth' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Microsoft Kernel Debug Network Adapter' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Microsoft Virtual Drive Enumerator' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'NDIS Virtual Network Adapter Enumerator' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Numeric data processor' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'PCI Data Acquisition and Signal Processing Controller' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'PCI Encryption/Decryption Controller' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'PCI Memory Controller' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'PCI Simple Communications Controller' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'Realtek USB 2.0 Card Reader' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'SM Bus Controller' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'System Speaker' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'System Timer' | Disable-PnpDevice -confirm:$false
Get-PnpDevice -FriendlyName 'UMBus Root Bus Enumerator' | Disable-PnpDevice -confirm:$false

Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force
