// File system utility functions

#pragma once
#include "../AaronLocker_CommonUtils/StringUtils.h"

/// <summary>
/// Returns the parent directory of the input file specification, or an empty string if there is no parent directory.
/// Handles UNC paths correctly (highest-level directory includes server and share name).
/// Forward slash and backslash are both valid path separators.
/// Note that parent directory of "C:\Subdir" will be returned as "C:", not "C:\" with the trailing slash.
/// </summary>
/// <param name="sFilePath">Input file specification (can be a path to a file or a directory)</param>
/// <returns>Parent directory, or empty string if no parent directory</returns>
inline std::wstring GetDirectoryNameFromFilePath(const std::wstring& sFilePath)
{
	// Accept both forward slash or backslash as path separators
	const wchar_t* szPathSepChars = L"/\\";

	// Find last path separator in the input. If none found, return an empty string.
	size_t ixLastPathSep = sFilePath.find_last_of(szPathSepChars);
	if (std::wstring::npos == ixLastPathSep)
	{
		return std::wstring();
	}

	// UNC path if the input starts with \\ or //. For UNC, shortest valid parent directory name includes the server and the share specification;
	// i.e., of the form \\server\share.
	if (StartsWith(sFilePath, L"\\\\") || StartsWith(sFilePath, L"//"))
	{
		// First, find the first path separator after the server name:
		size_t ixPathSep = sFilePath.find_first_of(szPathSepChars, 2);
		// If that's found, then find the first path separator after the share name:
		if (std::wstring::npos != ixPathSep)
			ixPathSep = sFilePath.find_first_of(szPathSepChars, ixPathSep + 1);
		// If there aren't enough path separators, or the last one is the last character in the string, there's no parent directory; return empty
		if (std::wstring::npos == ixPathSep || sFilePath.length() - 1 == ixPathSep)
			return std::wstring();
	}
	else
	{
		// Not a UNC path.
		// If the first path separator is the last character in the string (e.g., "C:\"), there's no parent directory; return empty.
		// (Note that because of the ixLastPathSep check earlier, ixFirstPathSep is guaranteed not to be npos, and sFilePath is not an empty string.)
		size_t ixFirstPathSep = sFilePath.find_first_of(szPathSepChars);
		if (sFilePath.length() - 1 == ixFirstPathSep)
			return std::wstring();
	}

	// All verifications check out. Return the string up to the last path separator.
	return sFilePath.substr(0, ixLastPathSep);
}

/// <summary>
/// Returns the file name by itself without the directory.
/// If the input parameter is a directory path, this function returns the leaf directory name.
/// </summary>
inline std::wstring GetFileNameFromFilePath(const std::wstring& sFilePath)
{
	// Look for last forward slash or backslash
	size_t ixLastPathSep = sFilePath.find_last_of(L"/\\");
	if (std::wstring::npos == ixLastPathSep)
	{
		// No path separators in the path - just return the original string
		return sFilePath;
	}
	else
	{
		// Return the string following the last path separator
		return sFilePath.substr(ixLastPathSep + 1);
	}
}

/// <summary>
/// Returns the file name by itself without the directory.
/// </summary>
inline std::string GetFileNameFromFilePath(const std::string& sFilePath)
{
	// Look for last forward slash or backslash
	size_t ixLastPathSep = sFilePath.find_last_of("/\\");
	if (std::string::npos == ixLastPathSep)
	{
		// No path separators in the path - just return the original string
		return sFilePath;
	}
	else
	{
		// Return the string following the path separator
		return sFilePath.substr(ixLastPathSep + 1);
	}
}

/// <summary>
/// Returns the file extension (if any) without the dot.
/// </summary>
inline std::wstring GetFileNameWithoutExtensionFromFilePath(const std::wstring& sFilePath)
{
	std::wstring sFilename = GetFileNameFromFilePath(sFilePath);
	size_t ixLastDot = sFilename.find_last_of(L'.');
	if (std::wstring::npos == ixLastDot)
		return sFilename; // no dots in filename
	else
		return sFilename.substr(0, ixLastDot);
}

/// <summary>
/// Returns the file extension (if any) without the dot.
/// </summary>
inline std::wstring GetFileExtensionFromFilePath(const std::wstring& sFilePath)
{
	std::wstring sFilename = GetFileNameFromFilePath(sFilePath);
	size_t ixLastDot = sFilename.find_last_of(L'.');
	if (std::wstring::npos == ixLastDot)
		return std::wstring(); // no dots in filename
	else
		return sFilename.substr(ixLastDot + 1); // text after last dot
}

/// <summary>
/// Reports whether the path provided starts with the directory name (case-insensitive).
/// Can require two separate tests - can't just look for StartsWith. E.g., if sFullPath is
/// "C:\Tempest\file.txt" and sDirectoryToMatch is "C:\Temp", StartsWith would return true,
/// which would be inaccurate. Hence, need to test for equality first, and then test
/// StartsWith against the input directory + backslash.
/// 
/// If PathStartsWithDirectory returns true, it guarantees that sFullPath.length() is at least
/// as long as sDirectoryToMatch.length(), even if one or both contain embedded NUL characters.
/// </summary>
/// <param name="sFullPath">Input: the full path to inspect</param>
/// <param name="sDirectoryToMatch">Input: the directory to verify that sFullPath begins with</param>
/// <returns>true if sFullPath is or starts with the directory to match against; false otherwise</returns>
inline bool PathStartsWithDirectory(const std::wstring& sFullPath, const std::wstring& sDirectoryToMatch)
{
	return
		// Additional length check - defense against wstring containing embedded NUL characters, which screws up wchar_t* comparisons
		sFullPath.length() >= sDirectoryToMatch.length() &&
		(EqualCaseInsensitive(sFullPath, sDirectoryToMatch) ||
		StartsWith(sFullPath, sDirectoryToMatch + L"\\", false));
}



