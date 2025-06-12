// Get the names or full paths to a directory's subdirectories

#include "pch.h"
#include "../AaronLocker_CommonUtils/FileSystemUtils.h"
#include "FileSystemUtils-Windows.h"
#include "Wow64FsRedirection.h"
#include "GetFilesAndSubdirectories.h"

bool GetFiles(const std::wstring& sDirectoryPath, std::vector<std::wstring>& files, bool bNamesOnly)
{
	// Return all files in the directory
	return GetFiles(sDirectoryPath, L"*", files, bNamesOnly);
}

bool GetFiles(const std::wstring& sDirectoryPath, const std::wstring& sSpec, std::vector<std::wstring>& files, bool bNamesOnly)
{
	// Initialize return value and output parameter
	bool retval = false;
	files.clear();

	// Disable WOW64 file system redirection. Reverts to previous state when this variable goes out of scope (function exit).
	Wow64FsRedirection fsredir(true);

	// Identify all files and add them to the collection.
	// Search specification is current directory + "\" + search spec (e.g., "*.exe")
	std::wstring sSearchSpec = sDirectoryPath + L"\\" + sSpec;
	WIN32_FIND_DATAW FindFileData = { 0 };
	HANDLE hFileSearch = FindFirstFileEx_ExtendedPath(
		sSearchSpec.c_str(),
		FINDEX_INFO_LEVELS::FindExInfoBasic, // Optimize - no need to get short names
		&FindFileData,
		FINDEX_SEARCH_OPS::FindExSearchNameMatch,
		FIND_FIRST_EX_LARGE_FETCH); // optimization, according to the documentation
	if (INVALID_HANDLE_VALUE != hFileSearch)
	{
		retval = true;
		do {
			// If the returned name is not a subdirectory, a reparse point (junction, directory symbolic link, file symbolic link),
			// offline, requiring download to access, etc., then add it to the collection.
			const DWORD dwUngoodFileAttributes =
				FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_REPARSE_POINT |
				FILE_ATTRIBUTE_OFFLINE |
				FILE_ATTRIBUTE_RECALL_ON_OPEN |
				FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
			// If any "ungood" attributes, treat it as not a file.
			if (0 == (FindFileData.dwFileAttributes & dwUngoodFileAttributes))
			{
				if (bNamesOnly)
				{
					// file name only
					files.push_back(FindFileData.cFileName);
				}
				else
				{
					// Full path
					files.push_back(
						sDirectoryPath + L"\\" + FindFileData.cFileName
					);
				}
			}
			// Get the next one
		} while (FindNextFileW(hFileSearch, &FindFileData));
		// Search complete, close the handle.
		FindClose(hFileSearch);
	}
	return retval;
}

/// <summary>
/// Get the names or full paths to a directory's non-reparse-point subdirectories.
/// Disables WOW64 file system redirection for the duration of the function.
/// </summary>
/// <param name="sDirectoryPath">Input: the path of the directory to inspect</param>
/// <param name="subdirectories">Output: a collection of names or full paths of the directory's subdirectories</param>
/// <param name="bNamesOnly">Input: if true, returns only the names of the subdirectories; if false (default) returns full paths</param>
/// <returns>true if successful, false on error</returns>
bool GetSubdirectories(const std::wstring& sDirectoryPath, std::vector<std::wstring>& subdirectories, bool bNamesOnly)
{
	// Initialize return value and output parameter
	bool retval = false;
	subdirectories.clear();

	// Disable WOW64 file system redirection. Reverts to previous state when this variable goes out of scope (function exit).
	Wow64FsRedirection fsredir(true);

	// Identify non-junction/non-symbolic-link subdirectories and add them to the collection.
	// Search specification is current directory + "\*"
	std::wstring sSearchSpec = sDirectoryPath + L"\\*";
	WIN32_FIND_DATAW FindFileData = { 0 };
	HANDLE hFileSearch = FindFirstFileEx_ExtendedPath(
		sSearchSpec.c_str(),
		FINDEX_INFO_LEVELS::FindExInfoBasic, // Optimize - no need to get short names
		&FindFileData,
		FINDEX_SEARCH_OPS::FindExSearchLimitToDirectories, // does this do anything?
		FIND_FIRST_EX_LARGE_FETCH); // optimization, according to the documentation
	if (INVALID_HANDLE_VALUE != hFileSearch)
	{
		retval = true;
		do {
			// If the returned name is a real subdirectory (not "." or ".." or a reparse point -- i.e., isn't a junction or directory symbolic link -- add it to the collection.
			if (IsSubdirectory(FindFileData))
			{
				if (bNamesOnly)
				{
					// Subdirectory name only
					subdirectories.push_back(FindFileData.cFileName);
				}
				else
				{
					// Full path
					subdirectories.push_back(
						sDirectoryPath + L"\\" + FindFileData.cFileName
					);
				}
			}
		// Get the next one
		} while (FindNextFileW(hFileSearch, &FindFileData));
		// Search complete, close the handle.
		FindClose(hFileSearch);
	}
	return retval;
}
