# AaronLockerV2

## "What it is" overview

[Explain "AaronLocker," goals, history, ...]

## "How-To" overview

Gather information about one or more endpoints using AaronLocker_EndpointTool.exe into scan files.

AaronLocker_RuleBuilder.exe consumes these files to propose sets of rules and then to create AppLocker policy XML files (corresponding audit and enforce policies).

Apply the policy using GPO, AppLocker PowerShell cmdlets, or SysNocturnals AppLockerPolicyTool.exe.

Use AppLocker_WDAC_EnhanceTool.exe to apply some WDAC rules to close some AppLocker gaps, and OfficeMacroControlTool.exe to apply local GPO policies to close gaps exposed by Office apps.

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
           MSDLLs  - Allows users to load any Microsoft-signed DLLs (DISCOURAGED, only as last resort)
         You can specify "+o appRuleOption" multiple times on the command line.

    +w:  don't exclude built-in Windows executable that will otherwise be blocked by default:
           Cipher  - Allow non-admin execution of Cipher.exe (File Encryption Utility)
           Runas   - Allow non-admin execution of Runas.exe (Run As Utility)
           Mshta   - Allow non-admin execution of Mshta.exe (Microsoft (R) HTML Application host)
           WMIC    - Allow non-admin execution of WMIC.exe (WMI Commandline Utility)
         You can specify "+w windowsExeOption" multiple times on the command line.

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

Command-line tool to manage WDAC-policy enhancements to AppLocker rules.

Command-line syntax:
```
Usage:

  AppLocker_WDAC_EnhanceTool.exe [-deploy | -remove | -info] [-reboot]

-deploy: deploy policy file to appropriate location.
-remove: delete policy from target location.
-info:   report information about WDAC status.
-reboot: reboot if -deploy or -remove make changes successfully.

Exit code is:
  0 if no error (*);
  Windows error code on error deploying or removing policy file;
  -1 for syntax or other major error.
(*) The following are NOT error conditions:
  Running this program on a system that does not support the WDAC policy enhancements;
  Specifying -remove when the target file to delete doesn't exist;
```

### GetAaronLockerFileInformation.exe

Command-line utility for diagnostic and testing purposes. Gathers information about one or more files on a Windows endpoint and reports it in list (default) or tabular form. Can write to console or to a UTF-8-encoded file. Accepts wildcard characters.

Command-line syntax:

```
    GetAaronLockerFileInformation.exe -file filepath... [-table] [-out outputFilename]

You can specify multiple filepaths; each must be preceded by "-file".
"filepath" can include wildcard characters.
```

Example output:

```
> GetAaronLockerFileInformation.exe -file C:\Python39\DLLs\select.pyd
FilePath           C:\Python39\DLLs\select.pyd
FileType           DLL
VerProductName     Python
VerFileDescription Python Core
X500CertSigner     CN=Python Software Foundation, O=Python Software Foundation, L=Wolfeboro, S=New Hampshire, C=US
ALPublisherName    O=PYTHON SOFTWARE FOUNDATION, L=WOLFEBORO, S=NEW HAMPSHIRE, C=US
ALProductName      PYTHON
ALBinaryName       SELECT.PYD
ALBinaryVersion    3.9.1150.1013
ALHash             0x49773DB698DAC457E634A7400E2877AC7C9F1E4EFE6C3C157422D7E0731D71EE
FileSize           28216
SigningTimestamp   2020-12-07 17:24:13
PEFileLinkDate     2020-12-07 17:12:43
CreateTime         2020-12-07 23:12:26
LastWriteTime      2020-12-07 23:12:26
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

