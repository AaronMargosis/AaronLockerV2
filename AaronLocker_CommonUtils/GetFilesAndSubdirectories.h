// Get the names or full paths to a directory's files and subdirectories

#pragma once

#include <vector>
#include <string>


/// <summary>
/// Get the names or full paths to a directory's files.
/// Disables WOW64 file system redirection for the duration of the function.
/// </summary>
/// <param name="sDirectoryPath">Input: the path of the directory to inspect</param>
/// <param name="files">Output: a collection of names or full paths of the directory's files</param>
/// <param name="bNamesOnly">Input: if true, returns only the names of the subdirectories; if false (default) returns full paths</param>
/// <returns>true if successful, false on error</returns>
bool GetFiles(const std::wstring& sDirectoryPath, std::vector<std::wstring>& files, bool bNamesOnly = false);


/// <summary>
/// Get the names or full paths to a directory's files, with limiting search spec (e.g., "*.lnk").
/// Disables WOW64 file system redirection for the duration of the function.
/// </summary>
/// <param name="sDirectoryPath">Input: the path of the directory to inspect</param>
/// <param name="sSpec">Input: specification that can include wildcards; e.g., *.exe</param>
/// <param name="files">Output: a collection of names or full paths of the directory's files</param>
/// <param name="bNamesOnly">Input: if true, returns only the names of the subdirectories; if false (default) returns full paths</param>
/// <returns>true if successful, false on error</returns>
bool GetFiles(const std::wstring& sDirectoryPath, const std::wstring& sSpec, std::vector<std::wstring>& files, bool bNamesOnly = false);


/// <summary>
/// Get the names or full paths to a directory's non-reparse-point subdirectories.
/// Disables WOW64 file system redirection for the duration of the function.
/// </summary>
/// <param name="sDirectoryPath">Input: the path of the directory to inspect</param>
/// <param name="subdirectories">Output: a collection of names or full paths of the directory's subdirectories</param>
/// <param name="bNamesOnly">Input: if true, returns only the names of the subdirectories; if false (default) returns full paths</param>
/// <returns>true if successful, false on error</returns>
bool GetSubdirectories(const std::wstring& sDirectoryPath, std::vector<std::wstring>& subdirectories, bool bNamesOnly = false);
