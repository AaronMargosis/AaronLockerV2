<#
.SYNOPSIS
Retrieve information about ACB (*) events controlled by AaronLocker.

(*) ACB = App Control for Business, formerly Windows Defender Application Control (WDAC).

.DESCRIPTION
AaronLocker implements audits or blocks against AppLocker bypasses that rely on certain Windows executables
loading certain Windows DLLs in combinations for which there is never any legitimate need.

This script returns information about any such events that have occurred on the system.
#>

<#
Research findings:

* Event ID 3076 is for audited events, and 3077 for blocked events. These two events are sufficient for what we need.

* The versions are not backward compatible, as the index of a given property does not remain constant across all versions with that property.

* The versions of 3076 and 3077 change together. That is, the properties for a given version of event 3076 are identical with those of the corresponding 3077 version.

Known property names associated with one or more versions of events 3076 and 3077 on Windows 11 24H2, with "+" marking the properties this script collects:

+   File Name
    FileDescription
    FileDescriptionLength
    FileNameLength
    FileVersion
    InternalName
    InternalNameLength
    OriginalFileName
    OriginalFileNameLength
    PackageFamilyName
    PackageFamilyNameLength
+   PolicyGUID
    PolicyHash
    PolicyHashSize
+   PolicyID
    PolicyIDLength
+   PolicyName
    PolicyNameLength
+   Process Name
    ProcessNameLength
    ProductName
    ProductNameLength
    Requested Signing Level
    SHA1 Flat Hash
    SHA1 Flat Hash Size
    SHA1 Hash
    SHA1 Hash Size
    SHA256 Flat Hash
    SHA256 Flat Hash Size
    SHA256 Hash
    SHA256 Hash Size
    SI Signing Scenario
    Status
    UserWriteable
    USN
    Validated Signing Level
#>

# Build a lookup for the array indices of the property names for each version of events 3076 and 3077, so
# we can get the "PolicyName" property (if present) in an event, regardless of the event version.
# Note that the property arrays are the same for corresponding versions of events 3076 and 3077.
# For $ev3077Info, the event version number is the lookup key; the value is a lookup for that event version.
# In that lookup, the property name is the lookup key; the value is the array index for that property.
$ev3077Info = @{}
(Get-WinEvent -ListProvider "Microsoft-Windows-CodeIntegrity").Events | Where-Object { $_.Id -eq 3077 } | %{ 

    $arrData = @(([xml]$_.Template).template.data)
    $propDictionary = @{}
    0 .. ($arrData.Count - 1) | %{ $propDictionary.Add( $arrData[$_].name, $_ ) }
    $ev3077Info.Add($_.Version.ToString(), $propDictionary)
}

# Given an event, a lookup dictionary for that event version, and a property name,
# returns the data associated with that property if it exists in the event.
function GetPropertyValue($event, $dict, $propname)
{
    if ($null -ne $dict)
    {
        $ixProperty = $dict[$propname]
        if ($null -ne $ixProperty)
        {
            Write-Output $event.Properties[$ixProperty].Value
        }
    }
}

# Retrieve all the 3076 and 3077 events
foreach ($event in @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -FilterXPath '*[System[(EventID=3076 or EventID=3077)]]' -ErrorAction SilentlyContinue))
{
    # Get the lookup dictionary associated with the event version
    $ver = $event.Version.ToString()
    $dict = $ev3077Info[$ver]

    Write-Output ([pscustomobject]@{
        TimeCreated = $event.TimeCreated;       # [datetime]
        Message     = $event.Message;           # [string]
        UserId      = $event.UserId;            # [System.Security.Principal.SecurityIdentifier]
        Computer    = $event.MachineName;       # [string]
        Level       = $event.LevelDisplayName;  # [string]
        ProcessName = GetPropertyValue -ev $event -dict $dict -propname "Process Name"; # [string]
        FileName    = GetPropertyValue -ev $event -dict $dict -propname "File Name";    # [string]
        PolicyID    = GetPropertyValue -ev $event -dict $dict -propname "PolicyID";     # [string]
        PolicyName  = GetPropertyValue -ev $event -dict $dict -propname "PolicyName";   # [string]
        PolicyGUID  = GetPropertyValue -ev $event -dict $dict -propname "PolicyGUID";   # [string]
    })
}
