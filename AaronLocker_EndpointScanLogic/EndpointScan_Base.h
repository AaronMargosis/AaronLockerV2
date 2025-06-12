#pragma once

#include <string>
#include <vector>
#include "../DirectorySafetyFunctions/DirectorySafetyFunctions.h"
#include "../AppLockerFunctionality/AppLockerFunctionality.h"
#include "EndpointScan_Structs.h"
#include "EndpointScan_Links.h"
#include "PathToAppNameMap.h"


// ------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------

/// <summary>
/// Common code and data for full endpoint scan and single-directory scan.
/// Always a base class, never instantiated directly.
/// </summary>
class EndpointScan_Base
{
public:
	/// <summary>
	/// Retrieve details about AppLocker-relevant files after a scan has completed. 
	/// </summary>
	const FileDetailsCollection_t& ScanResults_FileDetails() const
	{
		return m_FileDetails;
	}

	const ShellLinkDataContextCollection_t& ScanResults_ShellLinks() const
	{
		return m_linkScanner.ScanResults();
	}

	/// <summary>
	/// Reports when a scan was started
	/// </summary>
	const SYSTEMTIME& GetStartTime() const { return m_StartTime; }

	/// <summary>
	/// Reports when a scan completed
	/// </summary>
	const SYSTEMTIME& GetEndTime() const { return m_EndTime; }

	const std::wstring& ErrorInfo() const { return m_sErrorInfo; }

protected:
	// All the rest of this is implementation for derived classes to use

	// Constructor
	EndpointScan_Base(const SidsToFilter& sidsToFilter);
	// Destructor
	virtual ~EndpointScan_Base();

	/// <summary>
	/// Derived class should call ScanStarted when a scan begins
	/// </summary>
	void ScanStarted() { GetSystemTime(&m_StartTime); }
	/// <summary>
	/// Derived class should call ScanEnded when a scan ends.
	/// </summary>
	void ScanEnded() { GetSystemTime(&m_EndTime); }

	/// <summary>
	/// Inspects a directory hierarchy for nonadmin-writable directories.
	/// Note that this function disables 64-bit file system redirection.
	/// </summary>
	/// <param name="szRootDirectory">Input: file system root directory to inspect</param>
	/// <param name="sidsToFilter">Input: admin/equivalent SIDs in security descriptor to ignore</param>
	/// <param name="unsafeDirectoryInfo">Output (appended): collection of UnsafeDirectoryInfo_t objects for any identified unsafe directories. (Appended, not cleared first.)</param>
	/// <param name="strErrorInfo">Output (appended): textual information about any errors encountered. (Appended, not cleared first.)</param>
	/// <returns>true if inspection succeeds; false otherwise.</returns>
	bool ScanDirectoryHierarchyForUnsafeSubdirs(
		const wchar_t* szRootDirectory,
		const SidsToFilter& sidsToFilter,   // input: SIDs in security descriptor to ignore
		UnsafeDirectoryCollection_t& unsafeDirectoryInfo,
		std::wstringstream& strErrorInfo
	);

	/// <summary>
	/// Look for files in and under szRootDirectory for AppLocker-relevant files and add their details to the FileDetails collection.
	/// </summary>
	/// <param name="szRootDirectory">Input: Directory to begin searching in</param>
	/// <param name="szAppLabel">Input: App label to associate with the files</param>
	/// <param name="pvUnsafeDirectoryInfo">Collection of known unsafe subdirectories.
	/// If NULL, assumed that all subdirectories are unsafe.
	/// If empty list, assumed that all subdirectories are safe.</param>
	/// <param name="strErrorInfo">Output (appended): textual information about any errors encountered. (Appended, not cleared first.)</param>
	void ScanDirectoryHierarchyForAppLockerRelevantFiles(
		const wchar_t* szRootDirectory,
		const wchar_t* szAppLabel,
		UnsafeDirectoryCollection_t* pvUnsafeDirectoryInfo,
		std::wstringstream& strErrorInfo);

	/// <summary>
	/// Inspect the input file and add its details to the FileDetails collection if it's AppLocker-relevant.
	/// </summary>
	/// <param name="sFilePath">Input: full path to the file to inspect</param>
	/// <param name="szAppLabel">Input: App label to associate with the files</param>
	/// <param name="bIsSafeDirectory">Input: true if the directory is not user-writable, false otherwise</param>
	/// <param name="strErrorInfo">Output (appended): textual information about any errors encountered. (Appended, not cleared first.)</param>
	void ScanOneFile(
		const std::wstring& sFilePath,
		const wchar_t* szAppLabel,
		bool bIsSafeDirectory,
		std::wstringstream& strErrorInfo);

	/// <summary>
	/// Inspect shortcut files in system-wide and per-user locations.
	/// </summary>
	bool ScanForShellLinks(std::wstringstream& strErrorInfo);
	
	/// <summary>
	/// Initialize the path-to-appname mapper with collected shell link information.
	/// </summary>
	/// <param name="shellLinks"></param>
	void InitializePathToAppMap(const ShellLinkDataContextCollection_t& shellLinks);

protected:
	// Data
	// Set on construction
	const SidsToFilter& m_sidsToFilter;
	// Collection of details about AppLocker-relevant files
	FileDetailsCollection_t m_FileDetails;
	// Object to perform scan for details about start menu / desktop shortcuts
	EndpointScan_Links m_linkScanner;
	// Lookup to map an arbitrary file path to an app display name
	PathToAppMap m_PathToAppMap;
	// Flag to indicate whether a provided app label should be favored over path-to-appname mapping (for one-directory scans).
	bool m_bFavorProvidedAppLabel;
	// Errors accumulated during the scan
	std::wstring m_sErrorInfo;

private:
	// Data managed within this class
	SYSTEMTIME m_StartTime, m_EndTime;

private:
	//Not implemented
	EndpointScan_Base(const EndpointScan_Base&) = delete;
	EndpointScan_Base& operator = (const EndpointScan_Base&) = delete;
};

