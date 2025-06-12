#include "FileSystemUtils-Windows.h"
#include "../AaronLocker_CommonUtils/StringUtils.h"
#include <sstream>

// --------------------------------------------------------------------------------------------------------------
// Automated handling of extended-support paths for APIs that are otherwise limited to MAX_PATH.

// Extended path specifier - path starts with \\?\ 
static const std::wstring sExtPathSpecifier = L"\\\\?\\";

/// <summary>
/// Returns true if the input path begins with the extended-path specifier: "\\?\"
/// </summary>
/// <param name="szOriginalPath">Input: file path to inspect</param>
/// <returns>true if the path beings with the extended-path specifier; false otherwise</returns>
bool IsExtendedPathSpec(const wchar_t* szOriginalPath)
{
	if (NULL == szOriginalPath)
		return false;

	return StartsWith(szOriginalPath, sExtPathSpecifier, true);
}


/// <summary>
/// Returns an extended-path version of the input file path, primarily for use with APIs that otherwise
/// limit file paths to MAX_PATH.
/// Handles local paths (i.e., beginning with a drive letter) and UNC paths.
///  
/// Ref: Maximum Path Length Limitation, 
/// https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation
/// 
/// Note: this function performs limited validation of the input path, and assumes that the input
/// is a valid, full path specification.
/// </summary>
/// <param name="szOriginalPath">Input: file path to convert to an extended-path spec</param>
/// <returns>Extended-path file specification based on input path.</returns>
std::wstring PathToExtendedPath(const wchar_t* szOriginalPath)
{
	// Extended-path specifier is different for "local" (drive letter) and UNC paths:
	// "Local" path becomes \\?\D:\path...
	// UNC path becomes \\?\UNC\server\share\...

	// Note: minimal validation of input path: check for NULL, and check for leading "\\" for UNC.
	// If it doesn't start with "\\" it's assumed to be a local (drive letter) path.

	// Check for NULL just to avoid crashes.
	if (NULL == szOriginalPath)
		return std::wstring();

	std::wstringstream strRet;
	// Always start with "\\?\"
	strRet << sExtPathSpecifier;
	// Check for UNC - path beginning with two backslashes
	if (StartsWith(szOriginalPath, L"\\\\", true))
	{
		// Append "UNC" and start at the second character of the input path --
		// skip the first of the two leading backslashes
		strRet << L"UNC" << &szOriginalPath[1];
	}
	else
	{
		strRet << szOriginalPath;
	}
	return strRet.str();
}



/// <summary>
/// Wrapper around CreateFileW to open an existing file, automatically handling case where an
/// extended-path specifier is needed to open the file.
/// </summary>
/// <param name="lpFileNameFullPath">Input: full path to file to open</param>
/// <param name="dwDesiredAccess">Input: desired access to pass to CreateFileW</param>
/// <param name="dwShareMode">Input: share mode to pass to CreateFileW</param>
/// <param name="dwLastError">Output: GetLastError() value if file can't be opened.</param>
/// <param name="sAltName">Output: extended-path version of the file path, if needed to open the file. Input value not modified otherwise.</param>
/// <returns>File handle on success; INVALID_HANDLE_VALUE on failure</returns>
HANDLE OpenExistingFile_ExtendedPath(
	LPCWSTR lpFileNameFullPath,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	DWORD& dwLastError,
	std::wstring& sAltName
)
{
	SetLastError(0);
	// Do not modify sAltName parameter unless an extended-path spec is attempted.
	HANDLE hRetVal = CreateFileW(lpFileNameFullPath, dwDesiredAccess, dwShareMode, NULL, OPEN_EXISTING, 0, NULL);
	dwLastError = GetLastError();
	// For some failures, try again with extended path spec (unless already extended path spec)
	if (INVALID_HANDLE_VALUE == hRetVal && 
		(ERROR_PATH_NOT_FOUND == dwLastError || ERROR_INVALID_NAME == dwLastError) && 
		!IsExtendedPathSpec(lpFileNameFullPath))
	{
		sAltName = PathToExtendedPath(lpFileNameFullPath);
		SetLastError(0);
		hRetVal = CreateFileW(sAltName.c_str(), dwDesiredAccess, dwShareMode, NULL, OPEN_EXISTING, 0, NULL);
		dwLastError = GetLastError();
	}
	return hRetVal;
}


/// <summary>
/// Wrapper around GetFileAttributesW that automatically handles case where an extended-path
/// specifier is needed to inspect the file system object.
/// </summary>
/// <param name="lpFileNameFullPath">Input: full path to the file system object to inspect</param>
/// <param name="dwLastError">Output: GetLastError() value if object cannot be inspected.</param>
/// <param name="sAltName">Output: extended-path version of the file system object, if needed to inspect it. Input value not modified otherwise.</param>
/// <returns></returns>
DWORD GetFileAttributes_ExtendedPath(
	LPCWSTR lpFileNameFullPath,
	DWORD& dwLastError,
	std::wstring& sAltName
)
{
	SetLastError(0);
	// Do not modify sAltName parameter unless an extended-path spec is attempted.
	DWORD dwRetVal = GetFileAttributesW(lpFileNameFullPath);
	dwLastError = GetLastError();
	// For some failures, try again with extended path spec (unless already extended path spec)
	if (INVALID_FILE_ATTRIBUTES == dwRetVal && 
		ERROR_PATH_NOT_FOUND == dwLastError && 
		!IsExtendedPathSpec(lpFileNameFullPath))
	{
		sAltName = PathToExtendedPath(lpFileNameFullPath);
		SetLastError(0);
		dwRetVal = GetFileAttributesW(sAltName.c_str());
		dwLastError = GetLastError();
	}

	return dwRetVal;
}


/// <summary>
/// Wrapper around FindFirstFileExW API that automatically handles case where an extended path
/// specifier is needed to succeed.
/// Parameters and return value are identical to those of FindFirstFileExW, minus the unused 
/// lpSearchFilter parameter.
/// </summary>
HANDLE FindFirstFileEx_ExtendedPath(
	_In_ LPCWSTR lpFileName,
	_In_ FINDEX_INFO_LEVELS fInfoLevelId,
	_Out_writes_bytes_(sizeof(WIN32_FIND_DATAW)) LPVOID lpFindFileData,
	_In_ FINDEX_SEARCH_OPS fSearchOp,
	_In_ DWORD dwAdditionalFlags
)
{
	HANDLE hFileSearch = FindFirstFileExW(
		lpFileName,
		fInfoLevelId,
		lpFindFileData,
		fSearchOp,
		NULL, // Unused lpSearchFilter parameter
		dwAdditionalFlags);
	DWORD dwLastError = GetLastError();
	// For certain failures, try again with extended path specifier (if not already in use)
	if (INVALID_HANDLE_VALUE == hFileSearch &&
		ERROR_PATH_NOT_FOUND == dwLastError &&
		!IsExtendedPathSpec(lpFileName))
	{
		hFileSearch = FindFirstFileExW(
			PathToExtendedPath(lpFileName).c_str(),
			fInfoLevelId,
			lpFindFileData,
			fSearchOp,
			NULL, // Unused lpSearchFilter parameter
			dwAdditionalFlags);
	}

	return hFileSearch;
}