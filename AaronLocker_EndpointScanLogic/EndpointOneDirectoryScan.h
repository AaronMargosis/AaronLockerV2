#pragma once
#include "EndpointScan_Base.h"

/// <summary>
/// Class to scan a directory hierarchy for files to consider creating AppLocker rules for.
/// Designed for use in response to AppLocker warning or error events about blocked files.
/// </summary>
class EndpointOneDirectoryScan : public EndpointScan_Base
{
public:
	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="sidsToFilter">Collection of admin/admin-equivalent SIDs to ignore when inspecting security descriptors</param>
	EndpointOneDirectoryScan(const SidsToFilter& sidsToFilter);
	// Destructor
	virtual ~EndpointOneDirectoryScan();

	/// <summary>
	/// Performs scan of the specified directory hierarchy for information about AppLocker-relevant files.
	/// You can call this function multiple times with different directories and app labels to
	/// accumulate results into a single collection.
	/// See ScanResults_FileDetails() in the base class to retrieve the results.
	/// 
	/// Guidance on the input szFileOrDirectoryPath, the object to scan:
	/// * Can be a directory or a file. If a file, the function scans the file's parent directory (with some exceptions, below).
	/// * Path can begin with "%OSDRIVE% or %WINDIR% (from AppLocker event), but not other pseudo-environment variables.
	/// * Overly-broad root directories are not allowed (e.g., "C:\", "C:\Users", "C:\Program Files"), nor are any paths under 
	///   the Windows directory.
	/// * The provided path cannot be a user's Desktop or Downloads directory (too many unrelated files would be picked up, and
	///   we don't want to create rules for everything a user happened to download). However, the path can be a subdirectory of
	///   those directories.
	/// * The scan reverts to a scan of just one file (not a directory hierarchy) if the input is an MSI file (as these are 
	///   typically self-contained), or an existing file in a user's Desktop or Downloads directory.
	/// </summary>
	/// <param name="szFileOrDirectoryPath">Input: root directory to search. See details in summary above.</param>
	/// <param name="szAppLabel">Input: label to associate with the files that are found.</param>
	/// <returns>true if the scan is performed; false if not performed.</returns>
	bool ScanDirectory(const wchar_t* szFileOrDirectoryPath, const wchar_t* szAppLabel);

	// See ScanResults_FileDetails() in the base class to retrieve the results.
	// Also see ErrorInfo() in the base class to retrieve information about any errors during the scan.

private:
	// Same description as for ScanDirectory, plus a stream for error info. Public entry point performs a little overhead on entry and exit.
	bool ScanDirectory_Impl(const wchar_t* szFileOrDirectoryPath, const wchar_t* szAppLabel, std::wstringstream& strErrorInfo);

private:
	// Not implemented
	EndpointOneDirectoryScan(const EndpointOneDirectoryScan&) = delete;
	EndpointOneDirectoryScan& operator = (const EndpointOneDirectoryScan&) = delete;
};

