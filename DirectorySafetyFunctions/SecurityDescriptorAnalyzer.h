#pragma once
#include "SidsToFilter.h"

class SecurityDescriptorAnalyzer
{
public:
	/// <summary>
	/// Inspects a file system object's security descriptor and determines whether any non-admin entities 
	/// are granted write permissions to the object.
	/// Intended primarily for directories but can also be used for files.
	/// </summary>
	/// <param name="szFileSystemPath">Input: file system object to inspect</param>
	/// <param name="sidsToFilter">Input: admin/equivalent SIDs in security descriptor to ignore</param>
	/// <param name="bIsNonadminWritable">Output: true if a non-admin entity has write permissions to the object</param>
	/// <param name="bNeedsAltDataStreamExclusion">Output: true if non-admin entity can create an ADS on the directory and execute its content.</param>
	/// <param name="nonadminSids">Output: set of non-admin SIDs granted write access</param>
	/// <param name="sErrorInfo">Output: if this function fails, provides textual information about the error.</param>
	/// <returns>true if inspection succeeds; false otherwise. (sErrorInfo populated if false.)</returns>
	static bool IsNonadminWritable(
		const wchar_t* szFileSystemPath,    // input: file system object
		const SidsToFilter& sidsToFilter,   // input: SIDs in security descriptor to ignore
		bool& bIsNonadminWritable,          // output: true if object is nonadmin-writable; false otherwise
		bool& bNeedsAltDataStreamExclusion, // output: true if nonadmin can create and execute content in an alternate data stream on the directory 
		std::vector<CSid>& nonadminSids,    // output: list of nonadmin SIDs granted write access
		std::wstring& sErrorInfo            // output: textual information about any error (if fn returns false)
	);
};

