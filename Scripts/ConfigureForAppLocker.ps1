<#
.SYNOPSIS
Basic one-time single-computer configuration changes for AppLocker.
Requires administrative rights.

.DESCRIPTION
Configures the Application Identity service (AppIDSvc) for automatic start
Starts the Application Identity service
Sets the maximum log size for each of the AppLocker event logs to 1GB.

#>

# Check for admin rights first
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Error "This script requires administrative rights."
    exit
}

# Configure AppIDSvc for Automatic start if not already configured that way
if ((Get-Service AppIDSvc).StartType -ne 'Automatic')
{
    # There's a bug in PS v5.1 through at least v7.5.2 where setting the start type reports an error,
    # even though it succeeds, so set the error action to suppress that error and then verify
    # success afterward.
    Set-Service -Name AppIDSvc -StartupType 'Automatic' -ErrorAction SilentlyContinue
    if ((Get-Service AppIDSvc).StartType -ne 'Automatic')
    {
        Write-Warning ("Failed to set service start type to Automatic. Currently " + (Get-Service AppIDSvc).StartType)
    }
}

# Start the service if not already running
if ((Get-Service AppIDSvc).Status -ne 'Running')
{
    Start-Service -Name AppIDSvc
}

# Set the primary AppLocker event log sizes to 1GB each.

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
