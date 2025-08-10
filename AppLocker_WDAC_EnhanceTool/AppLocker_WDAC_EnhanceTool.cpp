// AppLocker_WDAC_EnhanceTool.cpp
//
// Command-line tool to manage WDAC-policy enhancements to AppLocker rules.
// Policy files to deploy are embedded in this executable as resources.
//
// For detailed documentation, see CreateWdacEnhancementsForAppLocker.ps1
//

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
			// Older Windows versions don't support multiple WDAC policies.
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
			{ EmbeddedFiles::File_t::Multi_Policy_Audit, sPolicyFileDirectory + L"\\Audit-" + EmbeddedFiles::MultiPolicyAuditFileName() },
			{ EmbeddedFiles::File_t::Multi_Policy_Blocking, sPolicyFileDirectory + L"\\Block-" + EmbeddedFiles::MultiPolicyBlockingFileName() }
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

