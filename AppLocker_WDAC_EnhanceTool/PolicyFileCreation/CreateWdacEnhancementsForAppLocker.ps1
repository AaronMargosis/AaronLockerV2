<#
.SYNOPSIS
Implement WDAC rules to enhance AppLocker allowlisting for supported Windows versions, by disallowing a handful of EXE/DLL 
combinations that have been shown to allow arbitrary code execution. These WDAC rules are designed to be used in combination
with AppLocker rules that include DLL rule enforcement.

.DESCRIPTION
Numerous web pages that describe bypass of allowlisting rules (particularly AppLocker) describe techniques that use existing 
Windows binaries in specific combinations to download and execute arbitrary script. AppLocker's script rules enforcement is
performed by the Windows Script Host only at certain expected entry points (particularly cscript.exe and wscript.exe).
Execution paths that manage to avoid those entry points can run arbitrary, adversary-supplied VBscript and JScript, including
script downloaded from a remote server. 

The combinations involved include mshtml.dll ("Microsoft (R) HTML Viewer") being loaded by rundll32.exe, and scrobj.dll 
("Windows ® Script Component Runtime") loaded directly or indirectly by one of rundll32.exe, regsvr32.exe, or cmstp.exe. None 
of these EXE or DLL files can safely be blocked entirely, but there are no known legitimate purposes for which those executables
ever need to load those specific DLLs, certainl not after Windows setup has completed.

AaronLocker's design intent is to provide comprehensive protection against unauthorized code execution, including through
common "lolbins" ("living off the land binaries" - leveraging files already present on the target system). 

Beginning in Windows 10 v1703 and Windows Server 2019, Windows Defender Application Control (WDAC) supports the ability to
block specific DLLs from being loaded from specific processes, such as the combinations described above.

This script creates WDAC policy files tailored to those needs. It produces four easily-deployable WDAC binary policy files,
each of which supports one of these needs:
* Audit policy for deployment on Windows 10 v1709-v1809 or Windows Server 2019 (which support only one WDAC policy at a time);
* Block policy for deployment on Windows 10 v1709-v1809 or Windows Server 2019 (which support only one WDAC policy at a time);
* Audit policy for deployment on Windows versions that support multiple WDAC policies (Win10 v1903+, Win11, WS2022);
* Block policy for deployment on Windows versions that support multiple WDAC policies (Win10 v1903+, Win11, WS2022);

Windows versions earlier than Win10 v1709 are not supported, for reasons explained in the "More details" section below.
Windows versions v1709-v1809 and Windows Server 2019 must be fully patched at least through October 2019 for the policies 
to work correctly.

This script must be executed on Windows 10 v1903 or later, Windows 11, or Windows Server 2022 or later.

Deployment:

On Windows 10 v1709-v1809 (including Windows Server 2019) the policy file must be copied to:
    %windir%\System32\CodeIntegrity\SiPolicy.p7b
On Windows 10 v1903 and later, the policy file must be copied to:
    %windir%\System32\CodeIntegrity\CiPolicies\Active\{496a5746-5600-4cdd-b22e-333fd5614d00}.cip
Note that the target computer must be rebooted for the changes to WDAC policy to take effect. To remove the enforcement, delete 
the policy file and reboot.
(Note that as of this writing (Jan 2022) Windows v1709, v1803, and v1809 are out of support, except for Windows 10 LTSC v1809
and Windows Server 2019.)

AaronLocker's AppLocker_WDAC_EnhanceTool.exe is designed to deploy the correct file to the correct location depending on operating
system version.

Testing:

To test whether the policies are working after reboot, run these commands from a Cmd.exe command prompt:

regsvr32.exe scrobj.dll
  * If policy working: "The module 'scrobj.dll' failed to load." and "Your organization used Device Guard to block this app."
  * If not working: "DllRegisterServer in scrobj.dll succeeded."

rundll32.exe mshtml.dll,NonExistent
  * If policy working: "There was a problem starting mshtml.dll. Your organization used Device Guard to block this app."
  * If not working: "Error in mshtml.dll" and "Missing entry: NonExistent"


More details:

Windows Defender Application Control (WDAC), a.k.a. "Configurable Code Integrity" (CCI) and originally branded as "Device Guard," 
was introduced in the first version of Windows 10. Windows 10 v1703 introduced improvements that enable the creation of WDAC rules 
to disallow specific processes from loading specific DLLs. However, until Windows 10 v1903, enforcement of *any* WDAC rules causes 
all PowerShell instances to run in Constrained Language (CL) mode, which is undesirable. Windows 10 v1903 introduced a WDAC policy-
creation option not to enforce script controls. AaronLocker relies on AppLocker to enforce script controls, with which we can be
more selective about when PowerShell should run in CL mode. Although this script must be executed on Windows 10 v1903 or later, the 
rules it creates can be applied to fully-patched Windows 10 v1709 or later (including Windows 11). Based on testing, Windows 10 LTSB 
v1607 and Windows Server 2016 appear to support per-app rules, but not the script enforcement option, so these rules should not 
be applied to those older systems.

Testing on Win10 LTSC 2019 indicates that the internal policy GUID must be the predefined "allow-all" GUID, {A244370E-44C9-4C06-B551-F6016E563076}.
For Windows versions that support multiple WDAC policies, we want to have our own unique but constant GUID.

Coexistence with other WDAC policies:
This script creates a WDAC policy with a unique but constant GUID and can coexist with other WDAC policies on Windows systems that
support multiple WDAC policies (Win10 v1903 and later).
Windows 10 v1709-v1809 and Windows Server 2019 support only a single WDAC policy, represented in System32\CodeIntegrity\SiPolicy.p7b.


TODO: determine how to manage situations on v1709-v1809 where a target system has a preexisting WDAC policy. (Note that as of this 
writing (Jan 2022) Windows v1709, v1803, and v1809 are out of support, except for Windows 10 LTSC v1809 and Windows Server 2019.) 
Initial tests with the WldpGetLockdownPolicy suggest that it returns different results on different Windows versions with the same
WDAC policy. E.g., on 19H2 it says that lockdown is off even when these rules are in place.

TODO: Come up with a reliable way to determine whether a binary policy file is ours. E.g., find "AaronLocker" in its name/ID. (How? Just string search in a binary?)
TODO: Need to be able to identify and handle situations in which a customer is using signed WDAC policies.

Can also deploy via CSP: https://docs.microsoft.com/en-us/windows/client-management/mdm/applicationcontrol-csp

Note that Mshta.exe ("Microsoft (R) HTML Application host") can also run arbitrary script. AaronLocker's AppLocker rules disallow
its execution by non-administrative users. Mshta.exe runs .hta files, which are essentially local HTML files that can include script.
Mshta.exe was never updated to enforce AppLocker or WDAC rules and does not verify its input files. To date, the Windows security
team has no intention of updating Mshta.exe to enforce allowlisting rules, and by default WDAC disallows Mshta.exe entirely.

See comment block at the end of this script file for details about Windows events to monitor to track when policy is applied and when
rules are enforced.


References:

Some public documentation of AppLocker/WDAC bypasses:

  https://github.com/api0cradle/UltimateAppLockerByPassList
  https://github.com/milkdevil/UltimateAppLockerByPassList
  https://lolbas-project.github.io/
  https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/

WDAC "per-app rules" that make it possible to keep specific processes from loading specific DLLs:
  https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/feature-availability
  https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-windows-defender-application-control-policy-to-control-specific-plug-ins-add-ins-and-modules

WDAC option not to enforce script rules:

  https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create#:~:text=11%20Disabled%3AScript%20Enforcement,have%20unintended%20results.
  https://www.microsoft.com/security/blog/2019/07/01/delivering-major-enhancements-in-windows-defender-application-control-with-the-windows-10-may-2019-update/#:~:text=Disabled%3A%20Script%20Enforcement%20rule%20option%20support

WDAC multiple-policy support (Windows 10 v1903 and newer):
  https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deploy-multiple-windows-defender-application-control-policies
  https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/deployment/deploy-wdac-policies-with-script

Major WDAC blog post:
  DEPLOYING WINDOWS 10 APPLICATION CONTROL POLICY
  https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/deploying-windows-10-application-control-policy/ba-p/2486267

#>

param(
)

# This script must be run on Win10 v1903 or later. Important features missing otherwise.
$osver = [System.Environment]::OSVersion.Version
if ($osver.Major -lt 10 -or $osver.Build -lt 18362)
{
    Write-Error "`nThis script cannot be executed on Windows versions earlier than Windows 10 v1903."
    return
}

# Put files in the same directory with this script.
$workingDir = [System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)

# Define GUIDs that we need.
$PredefAllowAllGuid  = '{A244370E-44C9-4C06-B551-F6016E563076}'
$AaronLockerGuid     = '{0f78c0e5-cb41-47b7-96f7-fedf43fafcb3}'
# Define target files - policy XML and corresponding binary files.
$xmlAuditLegacy      = [System.IO.Path]::Combine($workingDir, "WDAC-audit-policy-for-AppLocker-enhancement-legacy.xml")
$xmlBlockLegacy      = [System.IO.Path]::Combine($workingDir, "WDAC-block-policy-for-AppLocker-enhancement-legacy.xml")
$xmlAudit1903Plus    = [System.IO.Path]::Combine($workingDir, "WDAC-audit-policy-for-AppLocker-enhancement-1903plus.xml")
$xmlBlock1903Plus    = [System.IO.Path]::Combine($workingDir, "WDAC-block-policy-for-AppLocker-enhancement-1903plus.xml")
# For pre v1903 systems, binary file must be "SiPolicy.p7b"
$binAuditLegacy      = [System.IO.Path]::Combine($workingDir, "SiPolicy-Audit.p7b")
$binBlockLegacy      = [System.IO.Path]::Combine($workingDir, "SiPolicy-Block.p7b")
# For v1903+ systems (with multiple policy support), the file name must be the policy ID GUID + ".cip"
$binAudit1903Plus    = [System.IO.Path]::Combine($workingDir, $AaronLockerGuid + "-Audit.cip")
$binBlock1903Plus    = [System.IO.Path]::Combine($workingDir, $AaronLockerGuid + "-Block.cip")

# Temporary XML files - keep them in the working dir.
$fnameTemp1 = [System.IO.Path]::Combine($workingDir, [System.Guid]::NewGuid().Guid + ".xml")
$fnameTemp2 = [System.IO.Path]::Combine($workingDir, [System.Guid]::NewGuid().Guid + ".xml")
$fnameTemp3 = [System.IO.Path]::Combine($workingDir, [System.Guid]::NewGuid().Guid + ".xml")

# Build an "allow" rule from a standard Windows file, then modify the resulting rules to allow all files:
$rule = New-CIPolicyRule -DriverFilePath $env:windir\System32\ci.dll -Level FileName
# -MultiplePolicyFormat ensures that the policy gets a unique policy ID.
# But then we're overriding, forcing a specific GUID so that we always have the same file name.
New-CIPolicy -MultiplePolicyFormat -Rules $rule -UserPEs -FilePath $fnameTemp1
# Read the new policy XML file in, change its file rules to allow all files, and save to a separate temp file
$xmlTemp = [xml](gc $fnameTemp1)
$xmlTemp.SiPolicy.FileRules.Allow | ForEach-Object { $_.FileName = "*"; $_.FriendlyName = "Allow all"; $_.RemoveAttribute("MinimumFileVersion"); }
$xmlTemp.Save($fnameTemp2)

# The rules we want to add: don't allow regsvr32.exe, cmstp.exe, or rundll32.exe to load scrobj.dll, or rundll32.exe to load mshtml.dll.
# Note that the "FileName" level leads to rule enforcement based on PE files' OriginalFileName version resource attribute. When the 
# New-CIPolicyRule cmdlets are executed, rules are created using the values of the OriginalFileName version resource attributes of the 
# EXE and DLL files referenced by the -AppID and -DriverFilePath parameters. (Turns out that the OriginalFileName values in these cases
# turn out to be the same as the corresponding file names in the file system.) When these rules are applied to a system, no EXE - whether
# signed or unsigned - with an OriginalFileName attribute of "CMSTP.EXE" can load any DLL with an OriginalFileName attribute of 
# "scrobj.dll".
# TODO: might it be worth it to keep flash.ocx from being loaded by Acrord32.exe or other Acrobat Reader processes? Or is this entirely OBE now? (Need samples of those files to do that.)
$rules =
    (New-CIPolicyRule -DriverFilePath $env:windir\System32\scrobj.dll -Level FileName -Deny -AppID $env:windir\System32\cmstp.exe) +
    (New-CIPolicyRule -DriverFilePath $env:windir\System32\scrobj.dll -Level FileName -Deny -AppID $env:windir\System32\regsvr32.exe) +
    (New-CIPolicyRule -DriverFilePath $env:windir\System32\scrobj.dll -Level FileName -Deny -AppID $env:windir\System32\rundll32.exe) +
    (New-CIPolicyRule -DriverFilePath $env:windir\System32\mshtml.dll -Level FileName -Deny -AppID $env:windir\System32\rundll32.exe)

# Merge the deny rules and the "allow all" policy into a new policy XML file.
Merge-CIPolicy -OutputFilePath $fnameTemp3 -PolicyPaths $fnameTemp2 -Rules $rules | Out-Null

#                                                           Make sure that user-mode code integrity is enabled
Set-RuleOption -Option  0         -FilePath $fnameTemp3 	# Enabled:UMCI
#                                                           Not requiring that these policies be signed
Set-RuleOption -Option  6         -FilePath $fnameTemp3 	# Enabled:Unsigned System Integrity Policy
#                                                           Allow the F8 advanced boot menu to continue to work
Set-RuleOption -Option  9         -FilePath $fnameTemp3 	# Enabled:Advanced Boot Options Menu
#                                                           Disable script enforcement so that PowerShell is not always required to run in ConstrainedLanguage mode.
#                                                           Use AppLocker rules instead so that CL is enforced only for interactive non-admin PowerShell sessions.
Set-RuleOption -Option 11         -FilePath $fnameTemp3 	# Disabled:Script Enforcement
#                                                           Make it possible for future policy updates to be able to take effect without reboot
Set-RuleOption -Option 16         -FilePath $fnameTemp3 	# Enabled:Update Policy No Reboot
#                                                           Do not enforce Store App rules through WDAC (use AppLocker instead)
Set-RuleOption -Option 12 -Delete -FilePath $fnameTemp3 	# REMOVE Required:Enforce Store Applications

# Create the XMLs for the Audit policies
# Assign and name and ID to the policy. This text will appear in logged CodeIntegrity events, and is also embedded in the binary policy file.
Set-CIPolicyIdInfo -FilePath $fnameTemp3 -PolicyId 'AaronLocker WDAC AUDIT policy' -PolicyName 'AaronLocker AppLocker enhancement - audit specific EXE/DLL combinations' 
# Explicitly enable Audit for creation of the audit policies:
Set-RuleOption -Option  3         -FilePath $fnameTemp3 	# Enabled:Audit Mode
# Set policy ID GUIDs, save to target policy XML names for Audit policies
$xmlTemp = [xml](gc $fnameTemp3)
$xmlTemp.SiPolicy.PolicyID = $xmlTemp.SiPolicy.BasePolicyID = $PredefAllowAllGuid
$xmlTemp.Save($xmlAuditLegacy)
$xmlTemp.SiPolicy.PolicyID = $xmlTemp.SiPolicy.BasePolicyID = $AaronLockerGuid
$xmlTemp.Save($xmlAudit1903Plus)

# Create the XMLs for the Block policies
# Assign and name and ID to the policy. This text will appear in logged CodeIntegrity events, and is also embedded in the binary policy file.
Set-CIPolicyIdInfo -FilePath $fnameTemp3 -PolicyId 'AaronLocker WDAC BLOCK policy' -PolicyName 'AaronLocker AppLocker enhancement - block specific EXE/DLL combinations' 
Set-RuleOption -Option  3 -Delete -FilePath $fnameTemp3 	# REMOVE Enabled:Audit Mode
# Set policy ID GUIDs, save to target policy XML names for Audit policies
$xmlTemp = [xml](gc $fnameTemp3)
$xmlTemp.SiPolicy.PolicyID = $xmlTemp.SiPolicy.BasePolicyID = $PredefAllowAllGuid
$xmlTemp.Save($xmlBlockLegacy)
$xmlTemp.SiPolicy.PolicyID = $xmlTemp.SiPolicy.BasePolicyID = $AaronLockerGuid
$xmlTemp.Save($xmlBlock1903Plus)

# Convert the policy XMLs to binary form:
ConvertFrom-CIPolicy -XmlFilePath $xmlAuditLegacy   -BinaryFilePath $binAuditLegacy
ConvertFrom-CIPolicy -XmlFilePath $xmlBlockLegacy   -BinaryFilePath $binBlockLegacy
ConvertFrom-CIPolicy -XmlFilePath $xmlAudit1903Plus -BinaryFilePath $binAudit1903Plus
ConvertFrom-CIPolicy -XmlFilePath $xmlBlock1903Plus -BinaryFilePath $binBlock1903Plus

# Delete the temp files:
Remove-Item $fnameTemp1, $fnameTemp2, $fnameTemp3


<#
CodeIntegrity events to monitor when these WDAC rules are enforced to block unauthorized DLL loads.

https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/event-id-explanations

Each violation reports error event IDs 3077 and 3033 in "Microsoft-Windows-CodeIntegrity/Operational" as shown in the examples below.
In addition, information event ID 3089 is logged with additional information about the violation events. These events can be connected
via correlation IDs (GUIDs) in the event data.
3077 has more detail about the failure than 3033; the data in the 3089 events is needed to get the full data about the event including
the signers of the binaries. Note that there are at least 6 different versions of 3077.

When audit mode is applied instead of block mode, event ID 3076 is logged instead of 3077.

Event 3099 is an information event that is logged at system start when a WDAC policy is applied. It logs, among other things,
the policy's ID and name. It can be useful to monitor that the AaronLocker WDAC policy has been applied.

----------------------------------------------------------------------------------------------------

Example data from a single execution of "regsvr32.exe scrobj.dll" on Windows 10 v21H2:

    Id               : 3033
    Version          : 0
    LevelDisplayName : Error
    Message          : Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\regsvr32.exe) attempted 
                       to load \Device\HarddiskVolume3\Windows\System32\scrobj.dll that did not meet the Enterprise signing level 
                       requirements.
    UserId           : S-1-5-21-352879197-4051354371-3799005610-1001

    Id               : 3089
    Version          : 2
    LevelDisplayName : Information
    Message          : Signature information for another event. Match using the Correlation Id.
    UserId           : S-1-5-21-352879197-4051354371-3799005610-1001

    Id               : 3077
    Version          : 5
    LevelDisplayName : Error
    Message          : Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\System32\regsvr32.exe) attempted 
                       to load \Device\HarddiskVolume3\Windows\System32\scrobj.dll that did not meet the Enterprise signing level 
                       requirements or violated code integrity policy (Policy ID:{496a5746-5600-4cdd-b22e-333fd5614d00}).
    UserId           : S-1-5-21-352879197-4051354371-3799005610-1001

    Id               : 3089
    Version          : 2
    LevelDisplayName : Information
    Message          : Signature information for another event. Match using the Correlation Id.
    UserId           : S-1-5-21-352879197-4051354371-3799005610-1001

And the corresponding XML from those four events. Note that event 3077 includes Policy ID = "AaronLocker WDAC policy."

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /> 
        <EventID>3033</EventID> 
        <Version>0</Version> 
        <Level>2</Level> 
        <Task>1</Task> 
        <Opcode>111</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2021-12-27T19:58:05.0166515Z" /> 
        <EventRecordID>191</EventRecordID> 
        <Correlation ActivityID="{06dc59e1-fb5b-0001-7580-dc065bfbd701}" /> 
        <Execution ProcessID="1800" ThreadID="1784" /> 
        <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel> 
        <Computer>DESKTOP-7E3E45C</Computer> 
        <Security UserID="S-1-5-21-352879197-4051354371-3799005610-1001" /> 
      </System>
      <EventData>
        <Data Name="FileNameLength">51</Data> 
        <Data Name="FileNameBuffer">\Device\HarddiskVolume3\Windows\System32\scrobj.dll</Data> 
        <Data Name="ProcessNameLength">53</Data> 
        <Data Name="ProcessNameBuffer">\Device\HarddiskVolume3\Windows\System32\regsvr32.exe</Data> 
        <Data Name="RequestedPolicy">2</Data> 
        <Data Name="ValidatedPolicy">1</Data> 
        <Data Name="Status">3236495362</Data> 
      </EventData>
    </Event>

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /> 
        <EventID>3089</EventID> 
        <Version>2</Version> 
        <Level>4</Level> 
        <Task>1</Task> 
        <Opcode>130</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2021-12-27T19:58:05.0166525Z" /> 
        <EventRecordID>192</EventRecordID> 
        <Correlation ActivityID="{06dc59e1-fb5b-0001-7580-dc065bfbd701}" /> 
        <Execution ProcessID="1800" ThreadID="1784" /> 
        <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel> 
        <Computer>DESKTOP-7E3E45C</Computer> 
        <Security UserID="S-1-5-21-352879197-4051354371-3799005610-1001" /> 
      </System>
      <EventData>
        <Data Name="TotalSignatureCount">1</Data> 
        <Data Name="Signature">0</Data> 
        <Data Name="CacheState">22</Data> 
        <Data Name="Hash Size">20</Data> 
        <Data Name="Hash">15CDD7ED37A78CE09017B11C7252E925E4A3313E</Data> 
        <Data Name="PageHash">false</Data> 
        <Data Name="SignatureType">4</Data> 
        <Data Name="ValidatedSigningLevel">12</Data> 
        <Data Name="VerificationError">26</Data> 
        <Data Name="Flags">0</Data> 
        <Data Name="PolicyBits">2050</Data> 
        <Data Name="NotValidBefore">2021-09-02T18:23:41.0000000Z</Data> 
        <Data Name="NotValidAfter">2022-09-01T18:23:41.0000000Z</Data> 
        <Data Name="PublisherNameLength">17</Data> 
        <Data Name="PublisherName">Microsoft Windows</Data> 
        <Data Name="IssuerNameLength">37</Data> 
        <Data Name="IssuerName">Microsoft Windows Production PCA 2011</Data> 
        <Data Name="PublisherTBSHashSize">32</Data> 
        <Data Name="PublisherTBSHash">74F1449A56F47618DDFB01D1ED45CC791F30F9FAADC25036E8B806EFCB6CD7B2</Data> 
        <Data Name="IssuerTBSHashSize">32</Data> 
        <Data Name="IssuerTBSHash">4E80BE107C860DE896384B3EFF50504DC2D76AC7151DF3102A4450637A032146</Data> 
      </EventData>
    </Event>

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /> 
        <EventID>3077</EventID> 
        <Version>5</Version> 
        <Level>2</Level> 
        <Task>18</Task> 
        <Opcode>111</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2021-12-27T19:58:05.0190333Z" /> 
        <EventRecordID>193</EventRecordID> 
        <Correlation ActivityID="{06dc59e1-fb5b-0001-7580-dc065bfbd701}" /> 
        <Execution ProcessID="1800" ThreadID="1784" /> 
        <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel> 
        <Computer>DESKTOP-7E3E45C</Computer> 
        <Security UserID="S-1-5-21-352879197-4051354371-3799005610-1001" /> 
      </System>
      <EventData>
        <Data Name="FileNameLength">51</Data> 
        <Data Name="File Name">\Device\HarddiskVolume3\Windows\System32\scrobj.dll</Data> 
        <Data Name="ProcessNameLength">53</Data> 
        <Data Name="Process Name">\Device\HarddiskVolume3\Windows\System32\regsvr32.exe</Data> 
        <Data Name="Requested Signing Level">2</Data> 
        <Data Name="Validated Signing Level">1</Data> 
        <Data Name="Status">0xc0e90002</Data> 
        <Data Name="SHA1 Hash Size">20</Data> 
        <Data Name="SHA1 Hash">15CDD7ED37A78CE09017B11C7252E925E4A3313E</Data> 
        <Data Name="SHA256 Hash Size">32</Data> 
        <Data Name="SHA256 Hash">C22C0675B180EFD4656134AFF576860F4086FBFD775A9C0D7BEFDD08C1F80108</Data> 
        <Data Name="SHA1 Flat Hash Size">20</Data> 
        <Data Name="SHA1 Flat Hash">35CACF1ADA899882019C97BBF044E3B011EBA987</Data> 
        <Data Name="SHA256 Flat Hash Size">32</Data> 
        <Data Name="SHA256 Flat Hash">164EA0913EF910084147CAB550C12B8F12C710A3F1BADF4A26C6691517A031C4</Data> 
        <Data Name="USN">33757488</Data> 
        <Data Name="SI Signing Scenario">1</Data> 
        <Data Name="PolicyNameLength">77</Data> 
        <Data Name="PolicyName">AaronLocker AppLocker enhancement - disallow specific EXE/DLL combinations</Data> 
        <Data Name="PolicyIDLength">26</Data> 
        <Data Name="PolicyID">AaronLocker WDAC policy</Data> 
        <Data Name="PolicyHashSize">32</Data> 
        <Data Name="PolicyHash">D712AE632B982E38F464415A17E1B15F28FD01150E19CC707082A4F6C320271D</Data> 
        <Data Name="OriginalFileNameLength">10</Data> 
        <Data Name="OriginalFileName">scrobj.dll</Data> 
        <Data Name="InternalNameLength">10</Data> 
        <Data Name="InternalName">scrobj.dll</Data> 
        <Data Name="FileDescriptionLength">34</Data> 
        <Data Name="FileDescription">Windows ® Script Component Runtime</Data> 
        <Data Name="ProductNameLength">46</Data> 
        <Data Name="ProductName">Microsoft ® Windows ® Script Component Runtime</Data> 
        <Data Name="FileVersion">5.812.10240.16384</Data> 
        <Data Name="PolicyGUID">{496a5746-5600-4cdd-b22e-333fd5614d00}</Data> 
        <Data Name="UserWriteable">false</Data> 
        <Data Name="PackageFamilyNameLength">0</Data> 
        <Data Name="PackageFamilyName" /> 
      </EventData>
    </Event>

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /> 
        <EventID>3089</EventID> 
        <Version>2</Version> 
        <Level>4</Level> 
        <Task>1</Task> 
        <Opcode>130</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2021-12-27T19:58:05.0190352Z" /> 
        <EventRecordID>194</EventRecordID> 
        <Correlation ActivityID="{06dc59e1-fb5b-0001-7580-dc065bfbd701}" /> 
        <Execution ProcessID="1800" ThreadID="1784" /> 
        <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel> 
        <Computer>DESKTOP-7E3E45C</Computer> 
        <Security UserID="S-1-5-21-352879197-4051354371-3799005610-1001" /> 
      </System>
      <EventData>
        <Data Name="TotalSignatureCount">1</Data> 
        <Data Name="Signature">0</Data> 
        <Data Name="CacheState">22</Data> 
        <Data Name="Hash Size">20</Data> 
        <Data Name="Hash">15CDD7ED37A78CE09017B11C7252E925E4A3313E</Data> 
        <Data Name="PageHash">false</Data> 
        <Data Name="SignatureType">4</Data> 
        <Data Name="ValidatedSigningLevel">12</Data> 
        <Data Name="VerificationError">26</Data> 
        <Data Name="Flags">0</Data> 
        <Data Name="PolicyBits">2050</Data> 
        <Data Name="NotValidBefore">2021-09-02T18:23:41.0000000Z</Data> 
        <Data Name="NotValidAfter">2022-09-01T18:23:41.0000000Z</Data> 
        <Data Name="PublisherNameLength">17</Data> 
        <Data Name="PublisherName">Microsoft Windows</Data> 
        <Data Name="IssuerNameLength">37</Data> 
        <Data Name="IssuerName">Microsoft Windows Production PCA 2011</Data> 
        <Data Name="PublisherTBSHashSize">32</Data> 
        <Data Name="PublisherTBSHash">74F1449A56F47618DDFB01D1ED45CC791F30F9FAADC25036E8B806EFCB6CD7B2</Data> 
        <Data Name="IssuerTBSHashSize">32</Data> 
        <Data Name="IssuerTBSHash">4E80BE107C860DE896384B3EFF50504DC2D76AC7151DF3102A4450637A032146</Data> 
      </EventData>
    </Event>

----------------------------------------------------------------------------------------------------
Sample informational data at system start when the AaronLocker WDAC policy is applied:

    Id               : 3099
    Version          : 1
    LevelDisplayName : Information
    Message          : Refreshed and activated Code Integrity policy {496a5746-5600-4cdd-b22e-333fd5614d00} AaronLocker 
                       AppLocker enhancement - disallow specific EXE/DLL combinations. id AaronLocker WDAC policy. Status 
                       0x0
    UserId           : S-1-5-18

And the corresponding XML from the event:

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-CodeIntegrity" Guid="{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /> 
        <EventID>3099</EventID> 
        <Version>1</Version> 
        <Level>4</Level> 
        <Task>21</Task> 
        <Opcode>131</Opcode> 
        <Keywords>0x8000000000000000</Keywords> 
        <TimeCreated SystemTime="2021-12-27T23:02:53.9707587Z" /> 
        <EventRecordID>197</EventRecordID> 
        <Correlation /> 
        <Execution ProcessID="4" ThreadID="8" /> 
        <Channel>Microsoft-Windows-CodeIntegrity/Operational</Channel> 
        <Computer>DESKTOP-7E3E45C</Computer> 
        <Security UserID="S-1-5-18" /> 
      </System>
      <EventData>
        <Data Name="PolicyNameLength">77</Data> 
        <Data Name="PolicyNameBuffer">AaronLocker AppLocker enhancement - disallow specific EXE/DLL combinations</Data> 
        <Data Name="PolicyIdLength">26</Data> 
        <Data Name="PolicyIdBuffer">AaronLocker WDAC policy</Data> 
        <Data Name="PolicyGUID">{496a5746-5600-4cdd-b22e-333fd5614d00}</Data> 
        <Data Name="Status">0x0</Data> 
        <Data Name="Options">0x91880004</Data> 
        <Data Name="PolicyHashSize">32</Data> 
        <Data Name="PolicyHash">D712AE632B982E38F464415A17E1B15F28FD01150E19CC707082A4F6C320271D</Data> 
      </EventData>
    </Event>


----------------------------------------------------------------------------------------------------

Event template data for event 3033:

Microsoft-Windows-CodeIntegrity/Operational, Event Id 3033 (captured on Win10 v1809 LTSC, same on Win11)
Description: Code Integrity determined that a process (%4) attempted to load %2 that did not meet the %5 signing level requirements.
Version  : 0
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="FileNameBuffer" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="ProcessNameBuffer" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="RequestedPolicy" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="ValidatedPolicy" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:UInt32" outType="xs:unsignedInt"/>
           </template>

----------------------------------------------------------------------------------------------------

Event template data for event 3077:

Microsoft-Windows-CodeIntegrity/Operational, Event Id 3077. 
Note that there are multiple versions of this event, and that versions with the same ID are not always the same on all Windows versions.
Versions that include policy name and ID will include the policy name/ID in the policy (incl. "AaronLocker").

Description: Code Integrity determined that a process (%4) attempted to load %2 that did not meet the %5 signing level requirements or violated code integrity policy.
Description: Code Integrity determined that a process (%4) attempted to load %2 that did not meet the %5 signing level requirements or violated code integrity policy (Policy ID:%29).
Description: Code Integrity determined that a process (%4) attempted to load %2 that did not meet the %5 signing level requirements or violated code integrity policy (Policy ID:%33).

Event template for event 3076 is identical to that of 3077, with these changes:
* 3076 is an Information event rather than an error event;
* The Description text for 3076 appends "However, due to code integrity auditing policy, the image was allowed to load." to the Description text of the corresponding 3077 version.
* Opcode is SiPolicyFailureIgnored (value 118) instead of PolicyFailure (value 111).

Versions and schema templates:

Version  : 0
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
           </template>
           

Version  : 1
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyName" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
             <data name="PolicyIDLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyID" inType="win:UnicodeString" outType="xs:string" length="PolicyIDLength"/>
           </template>
           

Version  : 2
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyName" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
             <data name="PolicyIDLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyID" inType="win:UnicodeString" outType="xs:string" length="PolicyIDLength"/>
             <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
           </template>
           

Version  : 3
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyName" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
             <data name="PolicyIDLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyID" inType="win:UnicodeString" outType="xs:string" length="PolicyIDLength"/>
             <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
             <data name="OriginalFileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="OriginalFileName" inType="win:UnicodeString" outType="xs:string" length="OriginalFileNameLength"/>
             <data name="InternalNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="InternalName" inType="win:UnicodeString" outType="xs:string" length="InternalNameLength"/>
             <data name="FileDescriptionLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="FileDescription" inType="win:UnicodeString" outType="xs:string" length="FileDescriptionLength"/>
             <data name="ProductNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="ProductName" inType="win:UnicodeString" outType="xs:string" length="ProductNameLength"/>
             <data name="FileVersion" inType="win:AnsiString" outType="xs:string"/>
           </template>
           

Version  : 4 on Windows v1809 LTSC
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="SHA1 Flat Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Flat Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Flat Hash Size"/>
             <data name="SHA256 Flat Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Flat Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Flat Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyName" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
             <data name="PolicyIDLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyID" inType="win:UnicodeString" outType="xs:string" length="PolicyIDLength"/>
             <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
             <data name="OriginalFileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="OriginalFileName" inType="win:UnicodeString" outType="xs:string" length="OriginalFileNameLength"/>
             <data name="InternalNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="InternalName" inType="win:UnicodeString" outType="xs:string" length="InternalNameLength"/>
             <data name="FileDescriptionLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="FileDescription" inType="win:UnicodeString" outType="xs:string" length="FileDescriptionLength"/>
             <data name="ProductNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="ProductName" inType="win:UnicodeString" outType="xs:string" length="ProductNameLength"/>
             <data name="FileVersion" inType="win:AnsiString" outType="xs:string"/>
           </template>


Version  : 4 on Windows v21H2 and Windows 11
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyName" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
             <data name="PolicyIDLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyID" inType="win:UnicodeString" outType="xs:string" length="PolicyIDLength"/>
             <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
             <data name="OriginalFileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="OriginalFileName" inType="win:UnicodeString" outType="xs:string" length="OriginalFileNameLength"/>
             <data name="InternalNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="InternalName" inType="win:UnicodeString" outType="xs:string" length="InternalNameLength"/>
             <data name="FileDescriptionLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="FileDescription" inType="win:UnicodeString" outType="xs:string" length="FileDescriptionLength"/>
             <data name="ProductNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="ProductName" inType="win:UnicodeString" outType="xs:string" length="ProductNameLength"/>
             <data name="FileVersion" inType="win:AnsiString" outType="xs:string"/>
             <data name="PolicyGUID" inType="win:GUID" outType="xs:GUID"/>
           </template>
           

Version  : 5 (Windows v21H2 and Windows 11)
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="FileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="File Name" inType="win:UnicodeString" outType="xs:string" length="FileNameLength"/>
             <data name="ProcessNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="Process Name" inType="win:UnicodeString" outType="xs:string" length="ProcessNameLength"/>
             <data name="Requested Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Validated Signing Level" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
             <data name="SHA1 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Hash Size"/>
             <data name="SHA256 Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Hash Size"/>
             <data name="SHA1 Flat Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA1 Flat Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA1 Flat Hash Size"/>
             <data name="SHA256 Flat Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="SHA256 Flat Hash" inType="win:Binary" outType="xs:hexBinary" length="SHA256 Flat Hash Size"/>
             <data name="USN" inType="win:UInt64" outType="win:HexInt64"/>
             <data name="SI Signing Scenario" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyName" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
             <data name="PolicyIDLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PolicyID" inType="win:UnicodeString" outType="xs:string" length="PolicyIDLength"/>
             <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
             <data name="OriginalFileNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="OriginalFileName" inType="win:UnicodeString" outType="xs:string" length="OriginalFileNameLength"/>
             <data name="InternalNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="InternalName" inType="win:UnicodeString" outType="xs:string" length="InternalNameLength"/>
             <data name="FileDescriptionLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="FileDescription" inType="win:UnicodeString" outType="xs:string" length="FileDescriptionLength"/>
             <data name="ProductNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="ProductName" inType="win:UnicodeString" outType="xs:string" length="ProductNameLength"/>
             <data name="FileVersion" inType="win:AnsiString" outType="xs:string"/>
             <data name="PolicyGUID" inType="win:GUID" outType="xs:GUID"/>
             <data name="UserWriteable" inType="win:Boolean" outType="xs:boolean"/>
             <data name="PackageFamilyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PackageFamilyName" inType="win:UnicodeString" outType="xs:string" length="PackageFamilyNameLength"/>
           </template>


----------------------------------------------------------------------------------------------------

Event template data for event 3089:

Microsoft-Windows-CodeIntegrity/Operational, Event Id 3089
Description: Signature information for another event. Match using the Correlation Id.
Versions and schema templates:

Version  : 0
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="TotalSignatureCount" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Signature" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Hash" inType="win:Binary" outType="xs:hexBinary" length="Hash Size"/>
             <data name="SignatureType" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="ValidatedSigningLevel" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="VerificationError" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Flags" inType="win:UInt32" outType="win:HexInt32"/>
             <data name="PolicyBits" inType="win:UInt32" outType="win:HexInt32"/>
             <data name="NotValidBefore" inType="win:FILETIME" outType="xs:dateTime"/>
             <data name="NotValidAfter" inType="win:FILETIME" outType="xs:dateTime"/>
             <data name="PublisherNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PublisherName" inType="win:UnicodeString" outType="xs:string" length="PublisherNameLength"/>
             <data name="IssuerNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="IssuerName" inType="win:UnicodeString" outType="xs:string" length="IssuerNameLength"/>
           </template>
           

Version  : 1
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="TotalSignatureCount" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Signature" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Hash" inType="win:Binary" outType="xs:hexBinary" length="Hash Size"/>
             <data name="PageHash" inType="win:Boolean" outType="xs:boolean"/>
             <data name="SignatureType" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="ValidatedSigningLevel" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="VerificationError" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Flags" inType="win:UInt32" outType="win:HexInt32"/>
             <data name="PolicyBits" inType="win:UInt32" outType="win:HexInt32"/>
             <data name="NotValidBefore" inType="win:FILETIME" outType="xs:dateTime"/>
             <data name="NotValidAfter" inType="win:FILETIME" outType="xs:dateTime"/>
             <data name="PublisherNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PublisherName" inType="win:UnicodeString" outType="xs:string" length="PublisherNameLength"/>
             <data name="IssuerNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="IssuerName" inType="win:UnicodeString" outType="xs:string" length="IssuerNameLength"/>
             <data name="PublisherTBSHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PublisherTBSHash" inType="win:Binary" outType="xs:hexBinary" length="PublisherTBSHashSize"/>
             <data name="IssuerTBSHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="IssuerTBSHash" inType="win:Binary" outType="xs:hexBinary" length="IssuerTBSHashSize"/>
           </template>
           

Version  : 2
Template : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
             <data name="TotalSignatureCount" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Signature" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="CacheState" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Hash Size" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="Hash" inType="win:Binary" outType="xs:hexBinary" length="Hash Size"/>
             <data name="PageHash" inType="win:Boolean" outType="xs:boolean"/>
             <data name="SignatureType" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="ValidatedSigningLevel" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="VerificationError" inType="win:UInt8" outType="xs:unsignedByte"/>
             <data name="Flags" inType="win:UInt32" outType="win:HexInt32"/>
             <data name="PolicyBits" inType="win:UInt32" outType="win:HexInt32"/>
             <data name="NotValidBefore" inType="win:FILETIME" outType="xs:dateTime"/>
             <data name="NotValidAfter" inType="win:FILETIME" outType="xs:dateTime"/>
             <data name="PublisherNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="PublisherName" inType="win:UnicodeString" outType="xs:string" length="PublisherNameLength"/>
             <data name="IssuerNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
             <data name="IssuerName" inType="win:UnicodeString" outType="xs:string" length="IssuerNameLength"/>
             <data name="PublisherTBSHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="PublisherTBSHash" inType="win:Binary" outType="xs:hexBinary" length="PublisherTBSHashSize"/>
             <data name="IssuerTBSHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
             <data name="IssuerTBSHash" inType="win:Binary" outType="xs:hexBinary" length="IssuerTBSHashSize"/>
           </template>


----------------------------------------------------------------------------------------------------

Event template data for information event 3099:

Microsoft-Windows-CodeIntegrity/Operational, Event Id 3099
Description: Refreshed and activated Code Integrity policy %5 %2. id %4. Status %6
Versions and schema templates:

Version     : 0
Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
                <data name="PolicyNameBuffer" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
                <data name="PolicyIdLength" inType="win:UInt16" outType="xs:unsignedShort"/>
                <data name="PolicyIdBuffer" inType="win:UnicodeString" outType="xs:string" length="PolicyIdLength"/>
                <data name="TypeOfPolicy" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
                <data name="Options" inType="win:HexInt32" outType="win:HexInt32"/>
                <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
              </template>
              
Version     : 1
Template    : <template xmlns="http://schemas.microsoft.com/win/2004/08/events">
                <data name="PolicyNameLength" inType="win:UInt16" outType="xs:unsignedShort"/>
                <data name="PolicyNameBuffer" inType="win:UnicodeString" outType="xs:string" length="PolicyNameLength"/>
                <data name="PolicyIdLength" inType="win:UInt16" outType="xs:unsignedShort"/>
                <data name="PolicyIdBuffer" inType="win:UnicodeString" outType="xs:string" length="PolicyIdLength"/>
                <data name="PolicyGUID" inType="win:GUID" outType="xs:GUID"/>
                <data name="Status" inType="win:HexInt32" outType="win:HexInt32"/>
                <data name="Options" inType="win:HexInt32" outType="win:HexInt32"/>
                <data name="PolicyHashSize" inType="win:UInt32" outType="xs:unsignedInt"/>
                <data name="PolicyHash" inType="win:Binary" outType="xs:hexBinary" length="PolicyHashSize"/>
              </template>


#>

