#pragma once
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "EndpointScan_Base.h"

// ------------------------------------------------------------------------------------------

// ------------------------------------------------------------------------------------------

/// <summary>
/// Class to perform a full scan of an endpoint for information to create a base set of 
/// AppLocker rules.
/// </summary>
class EndpointFullScan : public EndpointScan_Base
{
public:
	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="sidsToFilter">Collection of admin/admin-equivalent SIDs to ignore when inspecting security descriptors</param>
	EndpointFullScan(const SidsToFilter& sidsToFilter);
	// Destructor
	virtual ~EndpointFullScan();

	/// <summary>
	/// Returns the hardcoded set of files for which this class retrieves information for exclusion rules by default.
	/// </summary>
	/// <param name="defaultProgramsToExclude">Output: the set of explicit file paths of programs to exclude</param>
	/// <param name="defaultDotNetProgramsToExclude">Output: the set of file names of .NET programs to search for under %windir%\Microsoft.NET</param>
	void GetDefaultProgramsToExclude(
		std::vector<std::wstring>& defaultProgramsToExclude,
		std::vector<std::wstring>& defaultDotNetProgramsToExclude) const;

	/// <summary>
	/// Perform the full scan of the endpoint:
	/// * Scans the Windows and Program Files directories for unsafe directories to exclude from allow-execution rules.
	/// * Retrieves information about built-in files under the Windows directory that need to be excluded from allow-execution rules.
	/// * Retrieves informaton about safe paths such as AV directories under ProgramData, and logon server shares.
	/// * Retrieves details about AppLocker-relevant files in common user-writable locations for which allow rules might be considered.
	/// </summary>
	/// <returns>true if no significant errors occurred, false otherwise</returns>
	bool PerformFullScan();

	/// <summary>
	/// Retrieve information about unsafe directories under the Windows directory after the scan has completed.
	/// </summary>
	const UnsafeDirectoryCollection_t& ScanResults_UnsafeWindowsSubdirs() const
	{
		return m_unsafeWindowsSubdirs;
	}

	/// <summary>
	/// Retrieve information about unsafe directories under the Program Files directories after the scan has completed.
	/// </summary>
	const UnsafeDirectoryCollection_t& ScanResults_UnsafeProgFilesSubdirs() const
	{
		return m_unsafeProgFilesSubdirs;
	}

	/// <summary>
	/// Retrieve information to create exclusions for specific files under the Windows directory after the scan has completed.
	/// </summary>
	const PubInfoForExclusionsCollecton_t& ScanResults_PubInfoForWindowsExclusions() const
	{
		return m_PubInfoForWindowsExclusions;
	}

	/// <summary>
	/// Retrieve information about identified safe paths after the scan has completed.
	/// </summary>
	const SafePathInfoCollection_t& ScanResults_PlatformSafePathInfo() const
	{
		return m_PlatformSafePathInfo;
	}

	/// <summary>
	/// Retrieve information about installed packaged apps (a.k.a., AppX)
	/// </summary>
	const PackagedAppInfoCollection_t& ScanResults_InstalledPackagedApps() const
	{
		return m_PackagedAppInfo;
	}

	// Also see ScanResults_FileDetails() in the base class to retrieve details about AppLocker-relevant files after a scan has completed. 
	// Also see ErrorInfo() in the base class to retrieve information about any errors during the scan.

private:
	// Internal implementation. Function purposes should be clear from their names.
	// Documentation in the .cpp file.

	bool ScanWindowsForUnsafeSubdirectories(std::wstringstream& strErrorInfo);
	bool ScanProgramFilesForUnsafeSubdirectories(std::wstringstream& strErrorInfo);
	bool ScanForWindowsExclusionInfo(std::wstringstream& strErrorInfo);
	void ScanForSafeAVPaths(std::wstringstream& strErrorInfo);
	bool AddToSafePathCollectionIfSafeDirectory(const std::wstring& sPath, const std::wstring& sLabel, std::wstringstream& strErrorInfo);
	void ScanForLogonServerPaths(std::wstringstream& strErrorInfo);
	void ScanFileInfoForAppsInCommonLocations(std::wstringstream& strErrorInfo);
	void ScanPortionsOfUserProfile(const std::wstring& sUserProfileDir, std::wstringstream& strErrorInfo);
	void ScanUserProfileSubdirWithExclusions(const std::wstring& sFullAppdataPath, const std::wstring& sRelativeAppdataPath, const CaseInsensitiveStringLookup& exclusions, std::wstringstream& strErrorInfo);
	void ScanInstalledPackagedApps(std::wstringstream& strErrorInfo);

private:
	// Data produced by scan
	UnsafeDirectoryCollection_t
		m_unsafeWindowsSubdirs,
		m_unsafeProgFilesSubdirs;
	PubInfoForExclusionsCollecton_t
		m_PubInfoForWindowsExclusions;
	SafePathInfoCollection_t
		m_PlatformSafePathInfo;
	PackagedAppInfoCollection_t
		m_PackagedAppInfo;

private:
	// Not implemented
	EndpointFullScan(const EndpointFullScan&) = delete;
	EndpointFullScan& operator = (const EndpointFullScan&) = delete;
};

