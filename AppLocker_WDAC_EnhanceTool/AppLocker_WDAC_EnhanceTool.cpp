// AppLocker_WDAC_EnhanceTool.cpp
//
// Command-line tool to manage WDAC-policy enhancements to AppLocker rules.
//
//TODO: This needs detailed documentation... See CreateWdacEnhancementsForAppLocker.ps1 
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
#include <fstream>

// For directory listing...
#include <string>
#include <vector>

#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"

// ------------------------------------------------------------------------------------------

/// <summary>
/// Write command-line syntax to stderr and then exit.
/// </summary>
/// <param name="szError">Caller-supplied error text</param>
/// <param name="argv0">The program's argv[0] value</param>
void Usage(const wchar_t* szError, const wchar_t* argv0)
{
	std::wstring sExe = GetFileNameFromFilePath(argv0);
	if (szError)
		std::wcerr << szError << std::endl;
	std::wcerr
		<< std::endl
		<< L"Usage:" << std::endl
		<< std::endl
		<< L"  " << sExe << L" [-audit | -block | -remove | -info]" << std::endl
		<< std::endl
		<< L"-audit:  deploy Audit policy file to appropriate location." << std::endl
		<< L"-block:  deploy Block policy file to appropriate location." << std::endl
		<< L"-remove: delete policy from target location." << std::endl
		<< L"-info:   report information about WDAC status." << std::endl
		<< std::endl
		<< L"Exit code is:" << std::endl
		<< L"  0 if no error (*);" << std::endl
		<< L"  Windows error code on error deploying or removing policy file;" << std::endl
		<< L"  -1 for syntax or other major error." << std::endl
		<< L"(*) The following are NOT error conditions:" << std::endl
		<< L"  Running this program on a system that does not support the WDAC policy enhancements;" << std::endl
		<< L"  Specifying -remove when the target file to delete doesn't exist;" << std::endl
		<< std::endl;

	exit(-1);
}

// ------------------------------------------------------------------------------------------
// File and directory names

/// <summary>
/// For systems that support only a single WDAC policy, the policy file goes in SiPolicy.p7b
/// in the CodeIntegrity root directory.
/// </summary>
static const std::wstring sAuditPolicyFileLegacy  = L"SiPolicy-Audit.p7b";
static const std::wstring sBlockPolicyFileLegacy  = L"SiPolicy-Block.p7b";
static const std::wstring sTargetPolicyFileLegacy = L"SiPolicy.p7b";
/// <summary>
/// For systems that support multiple WDAC policies (Win10 v1903+), the policy file has a
/// GUID name and goes into the CiPolicies\Active subdirectory of the CodeIntegrity directory.
/// The GUID file name must match the policy GUID embedded in the policy file.
/// </summary>
static const std::wstring sAuditPolicyFile1903Plus  = L"{496a5746-5600-4cdd-b22e-333fd5614d00}-Audit.cip";
static const std::wstring sBlockPolicyFile1903Plus  = L"{496a5746-5600-4cdd-b22e-333fd5614d00}-Block.cip";
static const std::wstring sTargetPolicyFile1903Plus = L"{496a5746-5600-4cdd-b22e-333fd5614d00}.cip";

/// <summary>
/// Return the path to the CodeIntegrity root directory.
/// Does not verify that the path exists.
/// </summary>
static const std::wstring& CodeIntegrityRootDir()
{
	// Build the value only on first use
	static std::wstring sCodeIntegrityRootDir;
	if (0 == sCodeIntegrityRootDir.length())
	{
		sCodeIntegrityRootDir = WindowsDirectories::System32Directory() + L"\\CodeIntegrity";
	}
	return sCodeIntegrityRootDir;
}

/// <summary>
/// Return the path to the CodeIntegrity active CI policies directory (for systems with multiple WDAC policy support).
/// Does not verify that the path exists.
/// </summary>
static const std::wstring& ActiveCiPoliciesDir()
{
	// Build the value only on first use
	static std::wstring sActiveCiPoliciesDir;
	if (0 == sActiveCiPoliciesDir.length())
	{
		sActiveCiPoliciesDir = CodeIntegrityRootDir() + L"\\CiPolicies\\Active";
	}
	return sActiveCiPoliciesDir;
}

// ------------------------------------------------------------------------------------------
// Helper function that gets information about a file or directory and adds it to fileInfoCollection.
// TAKEN FROM AppLockerPolicy\EmergencyClean.cpp
//TODO: Figure out what -info should report and do that instead of this.
//TODO: If this is worth keeping, don't have multiple copies here and in EmergencyClean.
/// <summary>
/// File information to report
/// </summary>
struct FileInfo_t
{
	std::wstring sFullPath, sLastWriteTime, sCreateTime;
	LARGE_INTEGER filesize;
	bool bIsDirectory;

	FileInfo_t() : bIsDirectory(false)
	{
		filesize = { 0 };
	}
};
typedef std::vector<FileInfo_t> FileInfoCollection_t;
static void AddFSObjectToCollection(const std::wstring& sObjName, bool bIsDirectory, FileInfoCollection_t& fileInfoCollection);

// ------------------------------------------------------------------------------------------

int wmain(int argc, wchar_t** argv)
{
	int exitCode = 0;
	bool
		bAudit  = false,
		bBlock  = false,
		bRemove = false,
		bInfo   = false;
	std::wstring sThisExeDir, sLocalFile, sTargetFile;

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
		else if (0 == StringCompareCaseInsensitive(L"-info", argv[ixArg]))
		{
			bInfo = true;
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
	if (bInfo) operations++;
	if (1 != operations)
	{
		Usage(L"Pick one of -audit, -block, -remove, or -info", argv[0]);
	}

	// These WDAC enhancements require fully-patched Win10 v1709 at a minimum:
	// Need both per-app rules (introduced in Win10 v1703) *and* support for the 
	// "Disabled:Script Enforcement" rule option so that not every single PowerShell
	// instance runs in ConstrainedLanguage mode. The Set-RuleOption cmdlet support
	// was introduced in Win10 v1903, but support for the resulting option was
	// backported all the way to v1709 via updates.
	if (!IsWindows10v1709OrGreater())
	{
		std::wcout << L"AaronLocker WDAC enhancement for AppLocker not supported on this Windows version." << std::endl;
		return 0;
	}

	// Identify source and target file locations for -deploy and -remove.
	// If needed, the binary policy file to deploy is expected to be in the same directory as this executable.
	sThisExeDir = WindowsDirectories::ThisExeDirectory();
	if (0 == sThisExeDir.length())
	{
		std::wcerr << L"Error getting path of current executable" << std::endl;
		return -1;
	}

	// Windows 10 v1903 and newer supports multiple WDAC policies.
	if (IsWindows10v1903OrGreater())
	{
		sLocalFile = sThisExeDir + L"\\" + (bAudit ? sAuditPolicyFile1903Plus : sBlockPolicyFile1903Plus);
		sTargetFile = ActiveCiPoliciesDir() + L"\\" + sTargetPolicyFile1903Plus;
	}
	else
	{
		sLocalFile = sThisExeDir + L"\\" + (bAudit ? sAuditPolicyFileLegacy : sBlockPolicyFileLegacy);
		sTargetFile = CodeIntegrityRootDir() + L"\\" + sTargetPolicyFileLegacy;
	}

	bool bSuccess = false;
	if (bAudit || bBlock || bRemove)
	{
		// If we need to overwrite or delete a file, make sure it's not marked read-only.
		// (We don't need support for paths greater than MAX_PATH for these files, so just
		// call the APIs directly.)
		Wow64FsRedirection wow64FSRedir(true);
		DWORD dwFileAttrs = GetFileAttributesW(sTargetFile.c_str());
		if (INVALID_FILE_ATTRIBUTES != dwFileAttrs)
		{
			SetFileAttributesW(sTargetFile.c_str(), FILE_ATTRIBUTE_NORMAL);
		}
	}
	if (bAudit || bBlock)
	{
		// Copy the local file to the target location.
		Wow64FsRedirection wow64FSRedir(true);
		BOOL ret = CopyFileW(sLocalFile.c_str(), sTargetFile.c_str(), FALSE);
		if (ret)
		{
			std::wcout << L"Policy file copied to " << sTargetFile << std::endl;
			bSuccess = true;
		}
		else
		{
			DWORD dwLastErr = GetLastError();
			exitCode = (int)dwLastErr;
			std::wcout
				<< L"Policy file not copied: " << SysErrorMessage(dwLastErr) << std::endl
				<< L"Source: " << sLocalFile << std::endl
				<< L"Target: " << sTargetFile << std::endl;
		}
	}
	else if (bRemove)
	{
		// Remove file from the target location.
		Wow64FsRedirection wow64FSRedir(true);
		BOOL ret = DeleteFileW(sTargetFile.c_str());
		if (ret)
		{
			std::wcout << L"Policy file removed from " << sTargetFile << std::endl;
			bSuccess = true;
		}
		else
		{
			// Set the exitCode to 0 if the file to delete already doesn't exist.
			DWORD dwLastErr = GetLastError();
			exitCode = (ERROR_FILE_NOT_FOUND == dwLastErr) ? 0 : (int)dwLastErr;
			std::wcout
				<< L"Policy file not removed: " << SysErrorMessage(dwLastErr) << std::endl
				<< L"Target: " << sTargetFile << std::endl;
		}
	}
	else if (bInfo)
	{
		//TODO: decide what information to report and report that.
		//TODO: if keeping this code, refactor (also in EmergencyClean).
		DirWalker dirWalker;
		std::wstringstream strErrorInfo;
		if (!dirWalker.Initialize(CodeIntegrityRootDir().c_str(), strErrorInfo))
		{
			std::wcerr << strErrorInfo.str() << std::endl;
			exitCode = -1;
		}
		else
		{
			FileInfoCollection_t fileInfoCollection;
			std::wstring sCurrDir;
			while (dirWalker.GetCurrent(sCurrDir))
			{
				// Add the current directory to the collection
				AddFSObjectToCollection(sCurrDir, true, fileInfoCollection);

				// Add all the files in the current directory to the collection
				std::vector<std::wstring> files, subdirectories;
				if (GetFiles(sCurrDir, files, false))
				{
					for (
						std::vector<std::wstring>::const_iterator iterFiles = files.begin();
						iterFiles != files.end();
						++iterFiles
						)
					{
						AddFSObjectToCollection(*iterFiles, false, fileInfoCollection);
					}
				}

				dirWalker.DoneWithCurrent();
			}

			for (
				FileInfoCollection_t::const_iterator iterFI = fileInfoCollection.begin();
				iterFI != fileInfoCollection.end();
				++iterFI
				)
			{
				if (!iterFI->bIsDirectory)
				{
					std::wcout << iterFI->sCreateTime << L"  " << iterFI->sLastWriteTime << L"  " << std::setw(8) << iterFI->filesize.QuadPart << L"  " << iterFI->sFullPath << std::endl;
				}
				else
				{
					std::wcout << iterFI->sCreateTime << L"  " << iterFI->sLastWriteTime << L"  " << std::setw(8) << L"" << L"  " << iterFI->sFullPath << std::endl;
				}
			}

		}
	}

	return exitCode;
}

// Helper function that gets information about a file or directory and adds it to fileInfoCollection.
// TAKEN FROM EmergencyClean.cpp
static void AddFSObjectToCollection(const std::wstring& sObjName, bool bIsDirectory, FileInfoCollection_t& fileInfoCollection)
{
	FileInfo_t fileInfo;
	fileInfo.bIsDirectory = bIsDirectory;
	fileInfo.sFullPath = sObjName;

	DWORD dwFlags = (bIsDirectory ? FILE_FLAG_BACKUP_SEMANTICS : 0);
	Wow64FsRedirection wow64FSRedir(true);
	HANDLE hFile = CreateFileW(sObjName.c_str(), 0, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, dwFlags, NULL);
	wow64FSRedir.Revert();
	if (INVALID_HANDLE_VALUE != hFile)
	{
		FILETIME ftCreateTime, ftLastAccessTime, ftLastWriteTime;
		if (GetFileTime(hFile, &ftCreateTime, &ftLastAccessTime, &ftLastWriteTime))
		{
			fileInfo.sCreateTime = FileTimeToWString(ftCreateTime);
			fileInfo.sLastWriteTime = FileTimeToWString(ftLastWriteTime);
		}
		if (!bIsDirectory)
		{
			GetFileSizeEx(hFile, &fileInfo.filesize);
		}
		CloseHandle(hFile);
	}
	fileInfoCollection.push_back(fileInfo);
}
