// AppLocker_WDAC_EnhanceTool.cpp
//
// Command-line tool to manage WDAC-policy enhancements to AppLocker rules.
// Policy files to deploy are embedded in this executable as resources.
//
//TODO: This needs detailed documentation... See CreateWdacEnhancementsForAppLocker.ps1 
//TODO: These comments need to be cleaned up.
/*TODO:
* Need to be able to support upgrade scenario where a system goes from not supporting multiple policies to supporting them.
  E.g., scenario where policy file was SiPolicy.p7b but now the target file is in the CiPolicies\Active subdir.
* Should report WDAC status information such as WldpGetLockdownPolicy (even though it seems to be inconsistent across Windows versions).
* If there's any way to determine whether a binary policy file is an AaronLocker one, that would be good to report.

* Possible to force a refresh with code like this (NOT compatible with multiple-policy WDAC):
Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = $DestinationBinary}
--> copies target to SiPolicy.p7b, though...


Info can try to obtain information about current policies through WMI bridge to CSP - requires running as SY:
ROOT\CIMV2\mdm\dmmap:MDM_ApplicationControl_Policies01_01
ROOT\CIMV2\mdm\dmmap:MDM_ApplicationControl_PolicyInfo03

Query existing policy state:

*	On Win10 v1903+, can query some information about WDAC policies through the ApplicationControl CSP – look at instances of MDM_ApplicationControl_PolicyInfo03 and MDM_ApplicationControl_Policies01_01. Note that on Win11 (21H2) there is an always-present but not-in-effect policy called WindowsE_Lockdown_Flight_Policy_Supplemental – we should probably ignore it, and anything else that’s not in effect and not ours.

*	On all Windows versions that support WDAC: can try to look at CodeIntegrity event 3099 for latest policy application (e.g., policy name).

*	Citool.exe coming in insider builds to query policies.

*	Acknowledged bug in the definitions of CodeIntegrity event 3077 differing on different Windows versions.

*	Binary file format of the policy files remains undocumented, so they can’t be queried/inspected in a supported way.

*	Bug (*) in v1903+ reported to MS: replace a multi-policy file with another with a different name, different policy, but same policy ID GUID, and no refresh action; query CSP reports new name but says it's in effect when it's not.

	(*) Possible workaround to determine what policy is in place - look at most recent event IDs 3099 matching PolicyGUID, then compare the PolicyHash value reported in that event to the SHA256 hash of the policy file in place.
	If the hash doesn't match, the file in place is not in effect. (Total PITA - over 6 years after the first release of Device Guard / WDAC, and its management story is still shit. "What policies are in effect right now?" "Sorry,
	can't answer that.")

Rebootless policy update:

*	Rebootless policy update is not possible at all prior to Windows v1809 / WS2019.

*	If not using multiple policies (i.e., using just the SiPolicy.p7b), can use a WMI method invocation to refresh policy: ROOT\Microsoft\Windows\CI:PS_UpdateAndCompareCIPolicy
	Note that this method has not been updated to properly handle the new multiple policy format. One side effect is that it copies the target policy file to SiPolicy.p7b.
	The PowerShell implementation of the WMI command is:
		Invoke-CimMethod -Namespace root\Microsoft\Windows\CI -ClassName PS_UpdateAndCompareCIPolicy -MethodName Update -Arguments @{FilePath = $DestinationBinary}

*	There’s a “Refresh CI Policy” tool download from Microsoft that uses an undocumented API (NtSetSystemInformation) to refresh CI policy. The MS security PM says the tool is supported, but IMO it’s not really supported – 
	it’s not part of Windows, has no EULA, no update mechanism, no support expiration, etc. PM says customers can deploy it internally, but there’s nothing stated about whether a vendor can redist it.

*	Citool.exe will be in the next Win11 version and can do rebootless policy update; it will be backported to supported Win10 v1903+ versions, depending on customer demand.

*	Removing a policy always requires a reboot. The closest approximation to removing a policy without reboot is to replace existing policy files with corresponding Allow-All binary files with the same policy ID GUID 
	as the policy being replaced and a supported rebootless refresh, then delete that allow-all policy which remains effective and is removed at next reboot.

WDAC policy items cannot be deleted through the WMI/CSP bridge.

*/

#include <Windows.h>
#include <iostream>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "EmbeddedFiles.h"
#include "CIPolicyPaths.h"

// ------------------------------------------------------------------------------------------

/// <summary>
/// Write command-line syntax to stderr and then exit.
/// </summary>
/// <param name="szError">Caller-supplied error text</param>
/// <param name="argv0">The program's argv[0] value</param>
static void Usage(const wchar_t* szError, const wchar_t* argv0)
{
	std::wstring sExe = GetFileNameFromFilePath(argv0);
	if (szError)
		std::wcerr << std::endl << szError << std::endl;
	std::wcerr
		<< std::endl
		<< L"Manages AaronLocker WDAC policies to close some AppLocker gaps." << std::endl
		<< std::endl
		<< L"Usage:" << std::endl
		<< std::endl
		<< L"  " << sExe << L" [-audit | -block | -remove | -files directory]" << std::endl
		<< std::endl
		<< L"  -audit:  deploy Audit policy to appropriate file location, and" << std::endl
		<< L"           remove any existing Block policy file." << std::endl
		<< L"  -block:  deploy Block policy to appropriate file location, and" << std::endl
		<< L"           remove any existing Audit policy file." << std::endl
		<< L"  -remove: delete policy file(s) from target location." << std::endl
		<< L"  -files directory: export all embedded CI policy files to the" << std::endl
		<< L"           named directory (absolute or relative path)." << std::endl
		<< std::endl
		<< L"To test whether policy is in effect, run the following command:" << std::endl
		<< L"    regsvr32.exe scrobj.dll" << std::endl
		<< std::endl;

	exit(-1);
}

// ------------------------------------------------------------------------------------------
// Helper functions

/// <summary>
/// Verifies that the input name represents an existing directory.
/// Also removes any trailing backslash from the parameter.
/// </summary>
/// <param name="sPolicyFileDirectory">In/out: directory name to verify; value can be altered</param>
/// <returns>true if the name represents and existing directory; false otherwise</returns>
static bool ValidateDirectory(std::wstring& sPolicyFileDirectory)
{
	// Remove trailing path separator if it has one. (PowerShell autocomplete likes to append them, helpfully...)
	while (EndsWith(sPolicyFileDirectory, L'\\') || EndsWith(sPolicyFileDirectory, L'/'))
		sPolicyFileDirectory = sPolicyFileDirectory.substr(0, sPolicyFileDirectory.length() - 1);

	// Verify that it is an existing directory
	DWORD dwFileAttributes = GetFileAttributesW(sPolicyFileDirectory.c_str());
	return (INVALID_FILE_ATTRIBUTES != dwFileAttributes && (0 != (FILE_ATTRIBUTE_DIRECTORY & dwFileAttributes)));
}

/// <summary>
/// If we need to overwrite or delete a file, make sure it's not marked read-only.
/// </summary>
static void MarkFileNormal(const wchar_t* szTargetFile)
{
	// (We don't need support for paths greater than MAX_PATH for these files, so just
	// call the APIs directly.)
	if (szTargetFile)
	{
		Wow64FsRedirection wow64FSRedir(true);
		DWORD dwFileAttrs = GetFileAttributesW(szTargetFile);
		if (INVALID_FILE_ATTRIBUTES != dwFileAttrs)
		{
			SetFileAttributesW(szTargetFile, FILE_ATTRIBUTE_NORMAL);
		}
	}
}

/// <summary>
/// Delete target file, if present.
/// </summary>
/// <param name="szTargetFile">File to delete</param>
/// <returns>true if file deleted or not present; false if file was present and couldn't be deleted</returns>
static bool DeleteTargetFile(const wchar_t* szTargetFile)
{
	// Make sure it's not marked read-only before attempting delete.
	MarkFileNormal(szTargetFile);

	Wow64FsRedirection wow64FSRedir(true);
	BOOL ret = DeleteFileW(szTargetFile);
	if (ret)
	{
		std::wcout << L"Deleted " << szTargetFile << std::endl;
	}
	else
	{
		DWORD dwLastErr = GetLastError();
		// Don't report failure to delete if the file wasn't there.
		if (ERROR_FILE_NOT_FOUND != dwLastErr)
		{
			std::wcerr << L"Unable to delete " << szTargetFile << L":" << std::endl
				<< SysErrorMessageWithCode(dwLastErr);
			return false;
		}
	}
	return true;
}

// ------------------------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv)
{
	// Internal sanity check before trying to use constructed paths:
	CIPolicyPaths::ValidateConstructedPaths();

	int exitCode = 0;
	bool
		bAudit  = false,
		bBlock  = false,
		bRemove = false;
	std::wstring sPolicyFileDirectory;

	// Parse command line options
	int ixArg = 1;
	while (ixArg < argc)
	{
		if (0 == StringCompareCaseInsensitive(L"-audit", argv[ixArg]))
		{
			bAudit = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"-block", argv[ixArg]))
		{
			bBlock = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"-remove", argv[ixArg]))
		{
			bRemove = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"-files", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for -files", argv[0]);
			sPolicyFileDirectory = argv[ixArg];
			if (!ValidateDirectory(sPolicyFileDirectory))
				Usage(L"Invalid directory specified with -files", argv[0]);
		}
		else
		{
			Usage(L"Unrecognized command-line option", argv[0]);
		}
		++ixArg;
	}

	// Validate command line options
	size_t operations = 0;
	if (bAudit) operations++;
	if (bBlock) operations++;
	if (bRemove) operations++;
	if (sPolicyFileDirectory.length() > 0) operations++;
	if (1 != operations)
	{
		Usage(L"Pick one of -audit, -block, -remove, or -files", argv[0]);
	}

	// These WDAC enhancements require fully-patched Win10 v1709 at a minimum:
	// Need both per-app rules (introduced in Win10 v1703) *and* support for the 
	// "Disabled:Script Enforcement" rule option so that not every single PowerShell
	// instance runs in ConstrainedLanguage mode. The Set-RuleOption cmdlet support
	// was introduced in Win10 v1903, but support for the resulting option was
	// backported all the way to v1709 via updates.
	if (!IsWindows10v1709OrGreater())
	{
		std::wcerr << L"AaronLocker WDAC enhancement for AppLocker not supported on this Windows version." << std::endl;
		exit(-2);
	}

	if (bAudit || bBlock || bRemove)
	{
		// Windows 10 v1903 and newer supports multiple WDAC policies.
		if (IsWindows10v1903OrGreater())
		{
			if (bAudit || bBlock)
			{
				// Deploying one file, removing another if present
				EmbeddedFiles::File_t fileId = bAudit ? EmbeddedFiles::File_t::Multi_Policy_Audit : EmbeddedFiles::File_t::Multi_Policy_Blocking;
				const std::wstring& sFileToExtract = bAudit ? CIPolicyPaths::MultiPolicyAuditFilePath() : CIPolicyPaths::MultiPolicyBlockingFilePath();
				const std::wstring& sFileToRemove  = bBlock ? CIPolicyPaths::MultiPolicyAuditFilePath() : CIPolicyPaths::MultiPolicyBlockingFilePath();
				// If target file already present, remove "read-only" on it if set
				MarkFileNormal(sFileToExtract.c_str());
				DeleteTargetFile(sFileToRemove.c_str());
				std::wstring sErrorInfo;
				if (EmbeddedFiles::Extract(fileId, sFileToExtract.c_str(), sErrorInfo))
				{
					std::wcout << L"Deployed " << sFileToExtract << std::endl;
				}
				else
				{
					std::wcerr << sErrorInfo << std::endl;
					exitCode = -3;
				}
			}
			else if (bRemove)
			{
				// Remove file(s)
				bool bDel1 = DeleteTargetFile(CIPolicyPaths::MultiPolicyAuditFilePath().c_str());
				bool bDel2 = DeleteTargetFile(CIPolicyPaths::MultiPolicyBlockingFilePath().c_str());
				if (!bDel1 || !bDel2)
				{
					exitCode = -4;
				}
			}
		}
		else
		{
			// Older Windows versions didn't support multiple WDAC policies.
			const wchar_t* szSinglePolicyFilePath = CIPolicyPaths::SinglePolicyFilePath().c_str();
			if (bAudit || bBlock)
			{
				EmbeddedFiles::File_t fileId = bAudit ? EmbeddedFiles::File_t::Single_Policy_Audit : EmbeddedFiles::File_t::Single_Policy_Block;
				// If the policy file already exists, remove "read-only" if set
				MarkFileNormal(szSinglePolicyFilePath);
				std::wstring sErrorInfo;
				if (EmbeddedFiles::Extract(fileId, szSinglePolicyFilePath, sErrorInfo))
				{
					std::wcout << L"Deployed " << szSinglePolicyFilePath << std::endl;
				}
				else
				{
					std::wcerr << sErrorInfo << std::endl;
					exitCode = -5;
				}
			}
			else if (bRemove)
			{
				if (!DeleteTargetFile(szSinglePolicyFilePath))
				{
					exitCode = -6;
				}
			}
		}
	}
	else if (sPolicyFileDirectory.length() > 0)
	{
		// Extract all the embedded WDAC policy files to the named directory
		struct policyFileInfo_t { EmbeddedFiles::File_t fileId; std::wstring sTargetPath; };
		policyFileInfo_t polFiles[4] = {
			{ EmbeddedFiles::File_t::Single_Policy_Audit, sPolicyFileDirectory + L"\\Audit-" + EmbeddedFiles::SinglePolicyFileName() },
			{ EmbeddedFiles::File_t::Single_Policy_Block, sPolicyFileDirectory + L"\\Block-" + EmbeddedFiles::SinglePolicyFileName() },
			{ EmbeddedFiles::File_t::Multi_Policy_Audit, sPolicyFileDirectory + L"\\" + EmbeddedFiles::MultiPolicyAuditFileName() },
			{ EmbeddedFiles::File_t::Multi_Policy_Blocking, sPolicyFileDirectory + L"\\" + EmbeddedFiles::MultiPolicyBlockingFileName() }
		};
		for (size_t ixPolFiles = 0; ixPolFiles < 4; ++ixPolFiles)
		{
			const policyFileInfo_t& polFile = polFiles[ixPolFiles];
			std::wstring sErrorInfo;
			if (EmbeddedFiles::Extract(polFile.fileId, polFile.sTargetPath.c_str(), sErrorInfo))
			{
				std::wcout << L"Extracted " << EmbeddedFiles::FileIdToName(polFile.fileId) << L" to " << polFile.sTargetPath << std::endl;
			}
			else
			{
				std::wcerr << sErrorInfo << std::endl;
				exitCode = -7;
			}
		}
	}

	return exitCode;
}

