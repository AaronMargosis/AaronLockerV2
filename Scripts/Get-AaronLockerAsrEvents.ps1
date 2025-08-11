<#
.SYNOPSIS
Get event information for the Exploit Guard Attack Surface Reduction (ASR) events relevant to AaronLocker.

Retrieve events with IDs 1121, 1122, and 1129 from "Microsoft-Windows-Windows Defender/Operational"

Returns the Get-WinEvent results, with the corresponding ASR rule name added to each event object.
#>

#
# Map ASR rule GUIDs to corresponding rule names.
# (Currently mapping only those associated with AaronLocker macro-control rules.)
#
function MapAsrRuleGuidToName([string] $guid)
{
    switch($guid.ToUpper())
    {
    '26190899-1602-49E8-8B27-EB1D0A1CE869' {'Block Office communication application from creating child processes' }

    '3B576869-A4EC-4529-8536-B80A7769E899' {'Block Office applications from creating executable content' }

    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84' {'Block Office applications from injecting code into other processes' }

    '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B' {'Block Win32 API calls from Office macro' }

    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A' {'Block all Office applications from creating child processes' }
    }
}

# Retrieve events with IDs 1121, 1122, and 1129...

$events = @(Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath '*[System[(EventID=1121 or EventID=1122 or EventID=1129)]]' -ErrorAction SilentlyContinue)

if ($events.Count -gt 0)
{
    # Add the ASR rule name to each returned object.
    # Note that in the current definitions, the rule GUID is the fourth property for the three events we're tracking.
    $events | %{ Add-Member -InputObject $_ -Name "AsrRule" -MemberType NoteProperty -Value (MapAsrRuleGuidToName -guid $_.Properties[3].Value) -PassThru }
}
else
{
    "No ASR events"
}

<#
Event info:

    (Get-WinEvent -ListProvider "Microsoft-Windows-Windows Defender").Events | ?{
        $_.Id -in @(1121, 1122, 1129)
    } | %{
        [pscustomobject]@{
            Id = $_.Id;
            Level = $_.Level.DisplayName;
            LogName = $_.LogLink.LogName;
            Version = $_.Version;
            Description = $_.Description;
            Template = $_.Template;
        }
    }

Results (note that the template is the same for events 1121 and 1122 (block event and audited event), and that the ASR rule GUID is the fourth property in each template.

    Id          : 1121
    Level       : Warning
    LogName     : Microsoft-Windows-Windows Defender/Operational
    Version     : 0
    Description : Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.
                   For more information please contact your IT administrator.
                    ID: %4
                    Detection time: %5
                    User: %6
                    Path: %7
                    Process Name: %8
                    Target Commandline: %12
                    Parent Commandline: %13
                    Involved File: %14
                    Inheritance Flags: %15
                    Security intelligence Version: %9
                    Engine Version: %10
                    Product Version: %2

    Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                    <data name="Product Name" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Product Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Unused" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="ID" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Detection Time" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="User" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Path" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Process Name" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Security intelligence Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Engine Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="RuleType" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Target Commandline" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Parent Commandline" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Involved File" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Inhertiance Flags" inType="win:UnicodeString" outType="xs:string"/>
                  </template>


    Id          : 1122
    Level       : Information
    LogName     : Microsoft-Windows-Windows Defender/Operational
    Version     : 0
    Description : Microsoft Defender Exploit Guard audited an operation that is not allowed by your IT administrator.
                   For more information please contact your IT administrator.
                    ID: %4
                    Detection time: %5
                    User: %6
                    Path: %7
                    Process Name: %8
                    Target Commandline: %12
                    Parent Commandline: %13
                    Involved File: %14
                    Inheritance Flags: %15
                    Security intelligence Version: %9
                    Engine Version: %10
                    Product Version: %2

    Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                    <data name="Product Name" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Product Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Unused" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="ID" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Detection Time" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="User" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Path" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Process Name" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Security intelligence Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Engine Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="RuleType" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Target Commandline" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Parent Commandline" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Involved File" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Inhertiance Flags" inType="win:UnicodeString" outType="xs:string"/>
                  </template>


    Id          : 1129
    Level       : Information
    LogName     : Microsoft-Windows-Windows Defender/Operational
    Version     : 0
    Description : A user has allowed a blocked Microsoft Defender Exploit Guard operation.
                    ID: %4
                    User: %5
                    Path: %6
                    Process Name: %7
                    Involved File: %8

    Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                    <data name="Product Name" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Product Version" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Unused" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="ID" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="User" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Path" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Process Name" inType="win:UnicodeString" outType="xs:string"/>
                    <data name="Involved File" inType="win:UnicodeString" outType="xs:string"/>
                  </template>
#>