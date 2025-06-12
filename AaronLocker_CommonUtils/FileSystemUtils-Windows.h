// Windows file system utility functions

#pragma once
#include <Windows.h>
#include <string>


/// <summary>
/// Indicates whether dwAttributes represent a directory that isn't also a reparse point.
/// dwAttributes is returned by the GetFileAttributes API.
/// </summary>
/// <param name="dwAttributes">Value returned by GetFileAttributes</param>
/// <returns>true if the attributes represent a directory that isn't also a reparse point.</returns>
inline bool IsNonReparseDirectory(DWORD dwAttributes)
{
	if (INVALID_FILE_ATTRIBUTES == dwAttributes)
		return false;

	const DWORD dwAttrNonReparseDir = FILE_ATTRIBUTE_DIRECTORY;
	const DWORD dwAttrNonReparseDirMask = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
	return (dwAttrNonReparseDir == (dwAttributes & dwAttrNonReparseDirMask));
}

/// <summary>
/// Indicates whether the file-find data represents a non-reparse-point directory that also isn't "." or ".."
/// </summary>
/// <param name="findFileData"></param>
/// <returns></returns>
inline bool IsSubdirectory(const WIN32_FIND_DATAW& findFileData)
{
	return
		IsNonReparseDirectory(findFileData.dwFileAttributes) &&
		(0 != wcscmp(L".", findFileData.cFileName)) &&
		(0 != wcscmp(L"..", findFileData.cFileName));
}


// --------------------------------------------------------------------------------------------------------------
// Automated handling of extended-support paths for APIs that are otherwise limited to MAX_PATH.


/// <summary>
/// Returns true if the input path begins with the extended-path specifier: "\\?\"
/// </summary>
/// <param name="szOriginalPath">Input: file path to inspect</param>
/// <returns>true if the path beings with the extended-path specifier; false otherwise</returns>
bool IsExtendedPathSpec(const wchar_t* szOriginalPath);


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
std::wstring PathToExtendedPath(const wchar_t* szOriginalPath);


/// <summary>
/// Wrapper around CreateFileW API to open an existing file, automatically handling case where an
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
);


/// <summary>
/// Wrapper around GetFileAttributesW API that automatically handles case where an extended-path
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
);

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
);
