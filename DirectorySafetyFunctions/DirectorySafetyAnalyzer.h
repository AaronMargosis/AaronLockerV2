#pragma once
#include <sstream>
#include <vector>
#include "SidsToFilter.h"
#include "DirectorySafetyStructs.h"

/// <summary>
/// Class containing static methods for analyzing directory safety.
/// </summary>
class DirectorySafetyAnalyzer
{
public:
	/// <summary>
	/// Inspects a file system object's security descriptor and determines whether any non-admin entities 
	/// are granted write permissions to the object.
	/// Intended primarily for directories but can also be used for files.
	/// Takes special cases into account -- such as root directory of user profile directories
	/// (e.g., "C:\Users") -- treating them as always unsafe.
	/// NOTE: this function does not disable file system redirection if executed in WOW64. (InspectDirectoryHierarchySafety does.)
	/// </summary>
	/// <param name="szFileSystemPath">Input: file system object to inspect</param>
	/// <param name="sidsToFilter">Input: admin/equivalent SIDs in security descriptor to ignore</param>
	/// <param name="bIsNonadminWritable">Output: true if a non-admin entity has write permissions to the object</param>
	/// <param name="bNeedsAltDataStreamExclusion">Output: true if non-admin entity can create an ADS on the directory and execute its content.</param>
	/// <param name="nonadminSids">Output: set of non-admin SIDs granted write access</param>
	/// <param name="sErrorInfo">Output: Provides textual information about error, or about special-casing.</param>
	/// <returns>true if inspection succeeds; false otherwise. (sErrorInfo populated if false.)</returns>
	static bool InspectDirectorySafety(
		const wchar_t* szFileSystemPath,    // input: file system object
		const SidsToFilter& sidsToFilter,   // input: SIDs in security descriptor to ignore
		bool& bIsNonadminWritable,          // output: true if object is nonadmin-writable; false otherwise
		bool& bNeedsAltDataStreamExclusion, // output: true if nonadmin can create and execute content in an alternate data stream on the directory 
		std::vector<CSid>& nonadminSids,    // output: list of nonadmin SIDs granted write access
		std::wstring& sErrorInfo            // output: textual information about any error (if fn returns false)
	);

	/// <summary>
	/// Inspects a directory hierarchy for nonadmin-writable directories.
	/// Note that this function disables 64-bit file system redirection.
	/// </summary>
	/// <param name="szFileSystemPath">Input: file system object to inspect</param>
	/// <param name="bRecurseIntoUnsafeDirectories">Input: true to recurse into unsafe directories, false not to recurse into unsafe directories</param>
	/// <param name="sidsToFilter">Input: admin/equivalent SIDs in security descriptor to ignore</param>
	/// <param name="unsafeDirectoryInfo">Output (appended): collection of UnsafeDirectoryInfo_t objects for any identified unsafe directories. (Appended, not cleared first.)</param>
	/// <param name="strErrorInfo">Output (appended): textual information about any errors encountered. (Appended, not cleared first.)</param>
	/// <returns>true if inspection succeeds; false otherwise.</returns>
	static bool InspectDirectoryHierarchySafety(
		const wchar_t* szFileSystemPath,
		bool bRecurseIntoUnsafeDirectories,
		const SidsToFilter& sidsToFilter,   // input: SIDs in security descriptor to ignore
		UnsafeDirectoryCollection_t& unsafeDirectoryInfo,
		std::wstringstream& strErrorInfo
	);
};

