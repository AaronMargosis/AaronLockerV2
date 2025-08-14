<#
.SYNOPSIS
Basic one-time single-computer configuration changes for AppLocker.
Requires administrative rights.

.DESCRIPTION
Configures the Application Identity service (AppIDSvc) for automatic start
Starts the Application Identity service
Sets the maximum log size for each of the AppLocker event logs to 1GB.

#>

# Configure AppIDSvc for Automatic start
Set-Service -Name AppIDSvc -StartupType Automatic

# Start the service if not already running
Start-Service -Name AppIDSvc

# Set the primary AppLocker event log sizes to 1GB

$logName = 'Microsoft-Windows-AppLocker/EXE and DLL'
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.MaximumSizeInBytes = 1GB
$log.SaveChanges()

$logName = 'Microsoft-Windows-AppLocker/MSI and Script'
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.MaximumSizeInBytes = 1GB
$log.SaveChanges()

#These event logs don't exist on Windows 7: ignore any errors.
try
{
    $logName = 'Microsoft-Windows-AppLocker/Packaged app-Deployment'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.MaximumSizeInBytes = 1GB
    $log.SaveChanges()

    $logName = 'Microsoft-Windows-AppLocker/Packaged app-Execution'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.MaximumSizeInBytes = 1GB
    $log.SaveChanges()
}
catch {}
