# Define the registry path
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Get all registry entries under the path
$regEntries = Get-ItemProperty -Path $regPath

# Loop through the entries and delete those that start with "MicrosoftEdgeAutoLaunch_"
foreach ($entry in $regEntries.PSObject.Properties) {
    if ($entry.Name -like "MicrosoftEdgeAutoLaunch_*") {
        Remove-ItemProperty -Path $regPath -Name $entry.Name
    }
}
