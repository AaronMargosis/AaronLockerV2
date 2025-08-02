// Class to manage extractable files embedded as resources in this executable.

#include <Windows.h>
#include <sstream>
#include "..\AaronLocker_CommonUtils\SysErrorMessage.h"
#include "..\AaronLocker_CommonUtils\Wow64FsRedirection.h"
#include "EmbeddedFiles.h"
#include "resource.h"

const wchar_t* const szResourceType = L"CIPOLICYFILE";

/// <summary>
/// Map file ID to corresponding string form
/// </summary>
const wchar_t* EmbeddedFiles::FileIdToName(File_t fileId)
{
	switch (fileId)
	{
	case File_t::Single_Policy_Audit:
		return L"Single_Policy_Audit";
	case File_t::Single_Policy_Block:
		return L"Single_Policy_Block";
	case File_t::Multi_Policy_Audit:
		return L"Multi_Policy_Audit";
	case File_t::Multi_Policy_Blocking:
		return L"Multi_Policy_Blocking";
	}
	return nullptr;
}

/// <summary>
/// Module-internal helper function to retrieve a string from the executable's string table resource and return it as a std::wstring.
/// </summary>
/// <param name="uID">Input: resource ID</param>
/// <param name="sString">Output: text from string table resource</param>
/// <returns>true if successful, false otherwise</returns>
static bool GetStringResource(UINT uID, std::wstring& sString)
{
	sString.clear();
	const wchar_t* pszString = nullptr;
	int ret = LoadString(GetModuleHandleW(NULL), uID, (LPWSTR)&pszString, 0);
	if (ret > 0)
	{
		sString.assign(pszString, ret);
		return true;
	}
	else
	{
		return false;
	}
}

/// <summary>
/// Name of the policy file for single-policy platforms.
/// </summary>
const std::wstring& EmbeddedFiles::SinglePolicyFileName()
{
	static std::wstring sString;
	if (sString.length() == 0)
	{
		GetStringResource(IDS_SinglePolicyFileName, sString);
	}
	return sString;
}

/// <summary>
/// Name of the audit policy file for multiple-policy platforms.
/// </summary>
const std::wstring& EmbeddedFiles::MultiPolicyAuditFileName()
{
	static std::wstring sString;
	if (sString.length() == 0)
	{
		GetStringResource(IDS_MultiPolicyAuditFileName, sString);
	}
	return sString;
}

/// <summary>
/// Name of the blocking policy file for multiple-policy platforms.
/// </summary>
const std::wstring& EmbeddedFiles::MultiPolicyBlockingFileName()
{
	static std::wstring sString;
	if (sString.length() == 0)
	{
		GetStringResource(IDS_MultiPolicyBlockingFileName, sString);
	}
	return sString;
}

/// <summary>
/// Extract an embedded resource to a target file path.
/// </summary>
/// <param name="fileId">Input: ID for the embedded resource to extract</param>
/// <param name="szTargetFile">Input: file path to which to extract the resource</param>
/// <param name="sErrorInfo">Output: error information on failure</param>
/// <returns>true if successful, false otherwise.</returns>
bool EmbeddedFiles::Extract(File_t fileId, const wchar_t* szTargetFile, std::wstring& sErrorInfo)
{
	sErrorInfo.clear();
	const wchar_t* szFileIdName = FileIdToName(fileId);
	if (!szFileIdName)
	{
		sErrorInfo = L"Invalid file ID";
		return false;
	}

	HRSRC hRsrc = NULL;
	HGLOBAL hLoadedResource = NULL;
	LPBYTE pbResource = NULL;
	DWORD dwResSize = 0;
	DWORD dwLastErr = 0;

	// Find and load the resource into memory.
	hRsrc = FindResourceW(NULL, szFileIdName, szResourceType);
	if (hRsrc)
		hLoadedResource = LoadResource(NULL, hRsrc);
	if (hLoadedResource)
		pbResource = (LPBYTE)LockResource(hLoadedResource);
	if (hRsrc)
		dwResSize = SizeofResource(NULL, hRsrc);
	if (!pbResource || 0 == dwResSize)
	{
		std::wstringstream strErrorInfo;
		strErrorInfo << L"Internal program error; cannot find embedded resource " << szFileIdName;
		sErrorInfo = strErrorInfo.str();
		return false;
	}

	Wow64FsRedirection wow64FSRedir(true);

	bool bRet = false;
	// Extract embedded resource file to target file path.
	HANDLE hFile = CreateFileW(
		szTargetFile,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	dwLastErr = GetLastError();
	if (INVALID_HANDLE_VALUE != hFile)
	{
		DWORD dwNumWritten = 0;
		BOOL wfRet = WriteFile(
			hFile,
			pbResource,
			dwResSize,
			&dwNumWritten,
			NULL);
		dwLastErr = GetLastError();
		CloseHandle(hFile);
		if (wfRet)
			bRet = true;
	}
	if (!bRet)
	{
		std::wstringstream strErrorInfo;
		strErrorInfo << L"Unable to extract to " << szTargetFile << L":" << std::endl << SysErrorMessageWithCode(dwLastErr);
		sErrorInfo = strErrorInfo.str();
	}
	return bRet;
}
