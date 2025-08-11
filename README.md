# AaronLockerV2

## "What it is" overview

[TODO: Explain "AaronLocker," goals, history, ...]

## "How-To" overview

Gather information about one or more endpoints using AaronLocker_EndpointTool.exe into scan files. (The Parse-ScanFile.ps1 script can be useful
for inspecting those results.)

AaronLocker_RuleBuilder.exe consumes these files to propose sets of rules and then to create AppLocker policy XML files (corresponding audit and enforce policies).

Apply the policy using GPO, AppLocker PowerShell cmdlets, or SysNocturnals AppLockerPolicyTool.exe.

Use AppLocker_WDAC_EnhanceTool.exe to apply some WDAC rules to close some AppLocker gaps, and OfficeMacroControlTool.exe to apply local GPO policies to close gaps exposed by Office apps.

The Get-AppLockerEvents.ps1, Get-AaronLockerAsrEvents.ps1, and Get-AaronLockerWdacEvents.ps1 scripts are useful for retrieving relevant events triggered by AaronLocker rules.

More details about The Tools and The Scripts follow.

## The Tools

### AaronLocker_EndpointTool.exe

Command-line utility to perform full endpoint scans or single-directory scans on Windows endpoints to gather information from which to build AaronLocker/AppLocker rules. Writes output to UTF-8 encoded text file.

Command-line syntax:

```
  Full endpoint scan:
    AaronLocker_EndpointTool.exe -full [-out filename]

  One-directory scan:
    AaronLocker_EndpointTool.exe -dir dirname [-label appname] [-out filename]

  Shortcuts/links scan:
    AaronLocker_EndpointTool.exe -links [-out filename]

  -out   : specifies output filename. If not specified, writes to stdout.
  -dir   : "dirname" specifies directory to scan.
  -label : optional app name to associate with files under the directory.
```
### AaronLocker_RuleBuilder.exe

Command-line utility to review and configure AppLocker rule sets from one or more scans plus additional configuration options, then to build AppLocker XML rule sets. 
Creates two XML documents, representing the rules in Enforce mode and a corresponding set in Audit mode.

Command-line syntax:
```
  AaronLocker_RuleBuilder.exe +s scanFilePath... [+o appRuleOption...] [+w windowsExeOption...] [-r ruleSetToRemove...] [-rr ruleSetsToRemove...] [+x XmlOutputDirectory]

    +s:  import a serialized endpoint scan file (full scan or one-directory scan).
         You can specify "+s scanFilePath" multiple times on the command line.
         You must specify at least one full scan file.

    +o:  apply predefined per-app rules. appRuleOption must be one of:
           ChromeM - For machine-wide install of Google Chrome (enables its user-profile binaries)
           ChromeU - Enables per-user install of Google Chrome and everything signed by Google
           Firefox - Allows users to install and run Mozilla Firefox from unsafe directories
           Teams   - Allows users to install and run Microsoft Teams from unsafe directories
           Zoom    - Allows users to install and run Zoom from unsafe directories
           WebEx   - Allows users to install and run WebEx from unsafe directories
           Slack   - Allows users to install and run Slack from unsafe directories
           Flash   - Allows Flash player in Chromium-based browsers
           Intuit  - Allows Intuit products to run per-user data updaters, such as for TurboTax
           StoreAll - Allows users to download and run all apps from the Microsoft Store app
           StoreMS - Allows users to download and run Microsoft-signed apps from the Microsoft Store app
           MSDLLs  - Allows users to load any Microsoft-signed DLLs (DISCOURAGED, only as last resort)
         You can specify "+o appRuleOption" multiple times on the command line.

    +w:  don't exclude built-in Windows executable that will otherwise be blocked by default:
           Cipher  - Allow non-admin execution of Cipher.exe (File Encryption Utility)
           Runas   - Allow non-admin execution of Runas.exe (Run As Utility)
           Mshta   - Allow non-admin execution of Mshta.exe (Microsoft (R) HTML Application host)
           WMIC    - Allow non-admin execution of WMIC.exe (WMI Commandline Utility)
         You can specify "+w windowsExeOption" multiple times on the command line.

    +winTemp:  create rules for files found under the \Windows\Temp directory.
         By default these files are ignored for rule-building.

    -r:  remove a proposed rule set by name prior to export.
         You can specify "-r ruleSetToRemove" multiple times.

    -rr: remove all proposed rule sets with names beginning with the specified name prior to export.
         (Unlike with the -r option, the -rr specification is case-insensitive.)
         For example, "-rr Symbol" will remove all proposed rule sets with names beginning with "Symbol".
         You can specify "-rr ruleSetsToRemove" multiple times.

    +x:  Export XML policy files to XmlOutputDirectory.

    If you do not specify +x to export XML files, AaronLocker_RuleBuilder.exe lists rule set names and the
    proposed rules associated with each.

Examples:

  AaronLocker_RuleBuilder.exe +o ChromeM +o Zoom +s fullscan.txt +s JoesApp.txt
    Enables predefined rules for two apps, imports two scans; outputs proposed rules to stdout.

  AaronLocker_RuleBuilder.exe +o ChromeM +o Zoom +s fullscan.txt +s JoesApp.txt -r "Utils (Non-default root directory)"
    Enables predefined rules for two apps, imports two scans; outputs proposed rules (after removing one rule set) to stdout.

  AaronLocker_RuleBuilder.exe +o ChromeM +o Zoom +s fullscan.txt +s JoesApp.txt -rr Utils +x C:\AaronLocker
    Enables predefined rules for two apps, imports two scans; writes AppLocker Enforce and Audit policy XML files to the
    C:\AaronLocker directory after removing all rule sets that have names beginning with "Utils".
```

### AppLockerPolicyTool.exe

AppLockerPolicyTool.exe is a command-line tool to manage AppLocker policy on the local Windows endpoint: listing, replacing, or deleting AppLocker policy either through local GPO, or CSP/MDM interfaces (without an MDM server). It can also retrieve effective GPO policy, which can incorporate AppLocker policies from Active Directory GPO. Finally, it provides an emergency interface directly into the AppLocker policy cache.

Already published here: https://github.com/AaronMargosis/AppLockerPolicyTool/

### AppLocker_WDAC_EnhanceTool.exe

Command-line tool to manage WDAC-policy enhancements to close some AppLocker gaps.

Command-line syntax:
```
  AppLocker_WDAC_EnhanceTool.exe [-audit | -block | -remove | -files directory]

  -audit:  deploy Audit policy to appropriate file location, and
           remove any existing Block policy file.
  -block:  deploy Block policy to appropriate file location, and
           remove any existing Audit policy file.
  -remove: delete policy file(s) from target location.
  -files directory: export all embedded CI policy files to the
           named directory (absolute or relative path).

To test whether policy is in effect, run the following command:
    regsvr32.exe scrobj.dll

```

### GetAaronLockerFileInformation.exe

Command-line utility for diagnostic and testing purposes. Gathers information about one or more files on a Windows endpoint and reports it in list (default) or tabular form. Can write to console or to a UTF-8-encoded file. Accepts wildcard characters.

Command-line syntax:

```
    GetAaronLockerFileInformation.exe -file filepath... [-table] [-out outputFilename]
 or
    GetAaronLockerFileInformation.exe -link filepath... [-table] [-out outputFilename]

You can specify multiple filepaths; each must be preceded by "-file" or "-link".
"filepath" can include wildcard characters.
```

Example output:

```
> GetAaronLockerFileInformation.exe -file C:\Temp\Newtonsoft.Json.Bson.dll
FilePath           C:\Temp\Newtonsoft.Json.Bson.dll
FileType           DLL
VerProductName     Json.NET BSON
VerFileDescription Json.NET BSON .NET Standard 2.0
X500CertSigner     CN=Json.NET (.NET Foundation), O=Json.NET (.NET Foundation), L=Redmond, S=wa, C=US, SERIALNUMBER=603 389 068
ALPublisherName    O=JSON.NET (.NET FOUNDATION), L=REDMOND, S=WA, C=US
ALProductName      JSON.NET BSON
ALBinaryName       NEWTONSOFT.JSON.BSON.DLL
ALBinaryVersion    1.0.2.22727
ALHash             0xADD5C49A220AD27F6C97B5D9D55B42E62D151C512CE074F28CD73D0C829E58C9
SHA256             0xF3C56166D7F90296BBE6B03F64335623C3165ED25948288F1F316FA74DD8327F
FileSize           97720
PEMachineType      I386
SigningTimestamp   2018-11-27 23:10:19
PEFileLinkDate
CreateTime         2024-08-31 04:00:06
LastWriteTime      2018-11-28 04:10:18
```

### OfficeMacroControlTool.exe

Command-line utility for configuring Office macro control policies.

Command-line syntax:

```
Usage:

    OfficeMacroControlTool.exe [options...]

Options include:

  -ASR         : Set Attack Surface Reduction rules to Not Configured
  +ASR:block   : Set Attack Surface Reduction rules to BLOCK mode
  +ASR:audit   : Set Attack Surface Reduction rules to AUDIT mode
  +ASR:warn    : Set Attack Surface Reduction rules to WARN mode
  -DUM         : Set "Disable All Unsigned Macros" to Not Configured
  +DUM:basic   : Set "Disable All Unsigned Macros" to basic restrictions
                 Configures "VBA Macro Notification Settings" to "Disable all except digitally signed macros"
  +DUM:trusted : +DUM:basic plus "Require macros to be signed by a trusted publisher"
  +DUM:strict  : +DUM:trusted plus "Block certificates from trusted publishers that are only installed in the current
                 user certificate store" and "Require Extended Key Usage (EKU) for certificates from trusted publishers"
  +BM, -BM     : Configure/unconfigure "Block macros from running in Office files from the internet"
  +VAdd, -VAdd : Configure/unconfigure "Disable unsigned VBA addins"
                 For Excel and PowerPoint: "Require that application add-ins are signed by Trusted Publisher"
  +DTL, -DTL   : Configure/unconfigure "Disable all trusted locations"
  +LFB, -LFB   : Configure/unconfigure "Legacy File Block"
  +SEM, -SEM   : Configure/unconfigure "Scan encrypted macros"
  +DVBA, -DVBA : Configure/unconfigure "Disable all VBA"

  +LHF         : Configure all the low-hanging fruit; equivalent to
                     +ASR:audit +BM +VAdd +DTL +SEM
  +MHF         : Configure all the medium-hanging fruit; equivalent to
                     +ASR:block +BM +VAdd +DTL +LFB +SEM
  +Max         : Configure strict settings (all but "Disable all VBA"); equivalent to
                     +ASR:block +DUM:strict +BM +VAdd +DTL +LFB +SEM

  +NC          : Explicitly revert all unspecified options to Not Configured
                 (If used without any other options, reverts all the above options to Not Configured.)
  -WhatIf      : List what would be changed without making changes
  -Verify      : Verify selected settings against current local policy

If options conflict, the last one specified takes precedence.
```

### PathToAppNameTool.exe

Command-line utility to map file paths to localized application display names based on desktop and start menu shortcuts.

Command-line syntax:

```
Usage:

    PathToAppNameTool.exe itemToTranslate [...] [-out filename]

  Each "itemToTranslate" can be a full path to a directory or file to be mapped.
  If "itemToTranslate" begins with "@" it is a text file containing one or more file paths to map,
  one per line.

  If -out is specified, output is written to UTF8-encoded filename, one result per line. Otherwise,
  output is written to stdout.
```

### WinrtFunctionalityDll.dll

Windows DLL that encapsulates Windows Runtime functionality, to be loaded on demand on systems that support WinRT.

Primary purpose is to gather information about all installed packaged apps (a.k.a., Store apps, AppX)

## The Scripts

### Parse-ScanFile.ps1

Simplifies the inspection of the scan files produced by AaronLocker_EndpointTool.exe.
It outputs a hash table from the contents of the named AaronLocker scan file.
Attributes include:
```
    ScanType
    ComputerName
    ScanStarted
    ScanEnded
    ScanDuration
    WindowsDirectories
    ErrorInfo
    UnsafeDirsUnderWindows
    UnsafeDirsUnderPF
    SafePaths
    FileDetails
    AppLabels
    PackagedApps
    ShellLinks
```
Example:
```
    $scan = Parse-ScanFile.ps1 .\fullscan.txt
    # List the generated app labels
    $scan.AppLabels
```

### ConfigureForAppLocker.ps1

Performs basic one-time single-computer configuration changes for AppLocker.
Requires administrative rights.
* Configures the Application Identity service (AppIDSvc) for automatic start
* Starts the Application Identity service
* Sets the maximum log size for each of the AppLocker event logs to 1GB.

### ClearApplockerLogs.ps1

Clears events from local AppLocker event logs.
Requires administrative rights.

### Get-AppLockerEvents.ps1

Retrieves and sorts relevant event data from AppLocker logs, filters out noise, synthesizes data, and reports as 
tab-delimited CSV output, PSCustomObjects, or as a PowerShell GridView.

Run `help Get-AppLockerEvents.ps1` for much more information.

### Get-AaronLockerAsrEvents.ps1

Get event information for the Exploit Guard Attack Surface Reduction (ASR) events relevant to AaronLocker.

Returns the Get-WinEvent results, with the corresponding ASR rule name added to each event object.

### Get-AaronLockerWdacEvents.ps1

Retrieve information about ACB (*) events controlled by AaronLocker.

AaronLocker implements audits or blocks against AppLocker bypasses that rely on certain Windows executables
loading certain Windows DLLs in combinations for which there is never any legitimate need.

This script returns information about any such events that have occurred on the system.

(*) ACB = App Control for Business, formerly Windows Defender Application Control (WDAC).
