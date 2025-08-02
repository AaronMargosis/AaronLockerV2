#include "pch.h"
#include <lm.h>
#pragma comment(lib, "netapi32.lib")
#include <NTSecAPI.h>
#pragma comment(lib, "secur32.lib")
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "EndpointFullScan.h"

EndpointFullScan::EndpointFullScan(const SidsToFilter& sidsToFilter)
	: EndpointScan_Base(sidsToFilter)
{
}

EndpointFullScan::~EndpointFullScan()
{
}

// ------------------------------------------------------------------------------------------
// The main interface - invokes all the lower-level operations that make up the full scan.

bool EndpointFullScan::PerformFullScan()
{
	ScanStarted();

	bool retval;
	std::wstringstream strErrorInfo;

	// Scan for shell links so that the path-to-appname map can be initialized prior to scanning files in common locations.
	ScanForShellLinks(strErrorInfo);
	InitializePathToAppMap(ScanResults_ShellLinks());

	retval = ScanWindowsForUnsafeSubdirectories(strErrorInfo);
	retval &= ScanProgramFilesForUnsafeSubdirectories(strErrorInfo);
	//retval &= ScanForWindowsExclusionInfo(strErrorInfo);
	ScanForSafeAVPaths(strErrorInfo);
	ScanForLogonServerPaths(strErrorInfo);
	ScanFileInfoForAppsInCommonLocations(strErrorInfo);
	ScanInstalledPackagedApps(strErrorInfo);

	m_sErrorInfo = strErrorInfo.str();

	ScanEnded();
	
	return retval;
}

// ------------------------------------------------------------------------------------------
// Identify information about unsafe directories under the Windows and Program Files directories.

bool EndpointFullScan::ScanWindowsForUnsafeSubdirectories(std::wstringstream& strErrorInfo)
{
	// Initialize return value
	bool retval = false;

	// Initialize data to capture
	m_unsafeWindowsSubdirs.clear();

	// Look for nonadmin-writable subdirectories of the Windows directory
	retval = ScanDirectoryHierarchyForUnsafeSubdirs(
		WindowsDirectories::WindowsDirectory().c_str(),
		m_sidsToFilter,
		m_unsafeWindowsSubdirs,
		strErrorInfo
	);

	return retval;
}

bool EndpointFullScan::ScanProgramFilesForUnsafeSubdirectories(std::wstringstream& strErrorInfo)
{
	// Initialize return value
	bool retval = false;

	// Initialize data to capture
	m_unsafeProgFilesSubdirs.clear();

	// Scan Program Files for nonadmin-writable subdirectories
	retval = ScanDirectoryHierarchyForUnsafeSubdirs(
		WindowsDirectories::ProgramFiles().c_str(),
		m_sidsToFilter,
		m_unsafeProgFilesSubdirs,
		strErrorInfo
	);

	// Also scan Program Files (x86) if it exists and add its findings to the same collection.
	if (WindowsDirectories::ProgramFilesX86().length() > 0)
	{
		retval &= ScanDirectoryHierarchyForUnsafeSubdirs(
			WindowsDirectories::ProgramFilesX86().c_str(),
			m_sidsToFilter,
			m_unsafeProgFilesSubdirs,
			strErrorInfo
		);
	}
	return retval;
}

// ------------------------------------------------------------------------------------------
// Gather information about built-in Windows files that non-admins shouldn't be allowed to execute.
// This information is used to create publisher exclusions on the Windows allow-execution path rule.

// Default set of known full paths of programs not to allow:
const std::wstring sDefaultProgramsToExclude[] = {
	WindowsDirectories::System32Directory() + L"\\mshta.exe",
	WindowsDirectories::System32Directory() + L"\\PresentationHost.exe",
	WindowsDirectories::System32Directory() + L"\\wbem\\WMIC.exe",
	WindowsDirectories::System32Directory() + L"\\cipher.exe",
	WindowsDirectories::System32Directory() + L"\\runas.exe"
};
const size_t nDefaultProgramsToExclude = sizeof(sDefaultProgramsToExclude) / sizeof(sDefaultProgramsToExclude[0]);

// Names of Microsoft.NET files to search for. There can be more than one instance of each and in multiple Microsoft.NET subdirectories.
// This implementation retrieves information from all of them but not keeping duplicate information.
const wchar_t* szDefaultDotNetProgramsToExclude[] = {
	L"AddInProcess.exe",
	L"AddInProcess32.exe",
	L"AddInUtil.exe",
	L"InstallUtil.exe",
	L"IEExec.exe",
	L"RegAsm.exe",
	L"RegSvcs.exe",
	L"MSBuild.exe",
	L"Microsoft.Workflow.Compiler.exe"
};
const size_t nDefaultDotNetProgramsToExclude = sizeof(szDefaultDotNetProgramsToExclude) / sizeof(szDefaultDotNetProgramsToExclude[0]);

/// <summary>
/// Returns the hardcoded set of files for which this class retrieves information for exclusion rules by default.
/// </summary>
/// <param name="defaultProgramsToExclude">Output: the set of explicit file paths of programs to exclude</param>
/// <param name="defaultDotNetProgramsToExclude">Output: the set of file names of .NET programs to search for under %windir%\Microsoft.NET</param>
void EndpointFullScan::GetDefaultProgramsToExclude(std::vector<std::wstring>& defaultProgramsToExclude, std::vector<std::wstring>& defaultDotNetProgramsToExclude) const
{
	defaultProgramsToExclude.clear();
	defaultDotNetProgramsToExclude.clear();

	for (size_t ix = 0; ix < nDefaultProgramsToExclude; ++ix)
		defaultProgramsToExclude.push_back(sDefaultProgramsToExclude[ix]);
	for (size_t ix = 0; ix < nDefaultDotNetProgramsToExclude; ++ix)
		defaultDotNetProgramsToExclude.push_back(szDefaultDotNetProgramsToExclude[ix]);
}

/// <summary>
/// Internal/local helper function to perform recursive search for the .NET programs of interest.
/// </summary>
/// <param name="sThisDir">Input: the current directory being searched.</param>
/// <param name="sFilesToInspect">Output: collection of file paths of identified files.</param>
static void SearchForDotNetProgramsToExclude(const std::wstring& sThisDir, std::vector<std::wstring>& sFilesToInspect)
{
	// Look in the directory hierarchy under sThisDir for all instances of the files of interest.
	DirWalker dirWalker;
	std::wstringstream strErrorInfo;
	if (!dirWalker.Initialize(sThisDir.c_str(), strErrorInfo))
		return;

	std::wstring sCurrDir;
	while (dirWalker.GetCurrent(sCurrDir))
	{
		// Look for the each of the .NET programs in the current directory; if found, add its full path to the collection.
		for (size_t ix = 0; ix < nDefaultDotNetProgramsToExclude; ++ix)
		{
			// Build full file path
			std::wstring sFile = sCurrDir + L"\\" + szDefaultDotNetProgramsToExclude[ix];
			// Test file existence
			HANDLE hFile = CreateFileW(sFile.c_str(), 0, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
			if (INVALID_HANDLE_VALUE != hFile)
			{
				// Found the file: add its full path to the collection
				sFilesToInspect.push_back(sFile);

				// Visual Studio compiler keeps reporting warning C6001 "Using uninitialized memory '*hFile'" 
				// for the CloseHandle call on the next line. I have no idea why. hFile is *always* assigned 
				// the return value of CreateFileW before it gets here. Reported VS bug to Microsoft Jan 3 2021.
				CloseHandle(hFile);
			}
		}

		dirWalker.DoneWithCurrent();
	}
}

//TODO: Consider moving this functionality to a different place and exposing it in a different tool. Reasons:
// This code is no longer needed in regular endpoint scans, as the exclusion list it returns is now hardcoded.
// The reason it's hardcoded now is because some of the content changes across different Windows versions so no 
// single scan will get them all, and we need to exclude them all.
// The reason for exposing this functionality in a different place and in a different tool is to periodically
// test new Windows versions to determine whether new variants show up that need exclusion.
bool EndpointFullScan::ScanForWindowsExclusionInfo(std::wstringstream& strErrorInfo)
{
	// Initialize return value
	bool retval = true;

	// Initialize collected information.
	m_PubInfoForWindowsExclusions.clear();

	// Build a collection of the full paths of all the files to be inspected
	std::vector<std::wstring> filesToInspect;

	// Add default set of known full paths of programs not to allow
	for (size_t ix = 0; ix < nDefaultProgramsToExclude; ++ix)
	{
		filesToInspect.push_back(sDefaultProgramsToExclude[ix]);
	}
	// Find all instances of the .NET programs to exclude
	std::wstring sMicrosoftNetDir = WindowsDirectories::WindowsDirectory() + L"\\Microsoft.NET";
	SearchForDotNetProgramsToExclude(sMicrosoftNetDir, filesToInspect);

	// keyLookup is a hash-lookup object to quickly determine whether publisher data from a file has 
	// already been added from a previous file.
	CaseInsensitiveStringLookup keyLookup;

	// Get publisher information from each of the files
	for (
		std::vector<std::wstring>::const_iterator iter = filesToInspect.begin();
		iter != filesToInspect.end();
		++iter
		)
	{
		AppLockerFileInformation alfi(iter->c_str());
		std::wstring sPublisher, sProduct, sBinary, sVersion, sX500, sSigningTimestamp;
		DWORD dwApiError = 0;
		if (alfi.GetPublisherInfo(sPublisher, sProduct, sBinary, sVersion, sX500, sSigningTimestamp, dwApiError))
		{
			// The exclusion info will use publisher, product, and binary name.
			// Lookup key uses those (already upper-cased) separated by a tab character.
			const wchar_t chSep = 0x09;
			std::wstring sKeyedName =
				sPublisher + chSep +
				sProduct + chSep +
				sBinary;
			// If it's not already in the lookup object, add the key to the lookup and the data to the result collection.
			// If it's already in the lookup object, ignore it.
			if (keyLookup.Add(sKeyedName))
			{
				m_PubInfoForWindowsExclusions.push_back(
					PubInfoForExclusions_t(sPublisher, sProduct, sBinary)
				);
			}
		}
		else
		{
			// Highly unusual not to be able to retrieve publisher information from one of these files.
			strErrorInfo << L"Can't get publisher information to exclude \"" << *iter << L"\": " << SysErrorMessageWithCode(dwApiError) << std::endl;
			retval = false;
		}
	}
	return retval;
}

// ------------------------------------------------------------------------------------------
// For NO GOOD REASON, some AV products put files that users need to execute under ProgramData,
// albeit in safe directories (not writable by non-admins).
// If the path exists on the endpoint and is a safe directory, add it to the safe-path
// collection. Note: don't want to create a path rule for a path that doesn't exist, as a
// non-admin could potentially create that path and run anything they want.

void EndpointFullScan::ScanForSafeAVPaths(std::wstringstream& strErrorInfo)
{
	// Add these directories to the safe-paths collection if they are present and safe.
	// Windows Defender AV directory under ProgramData.
	// (No need also to include the "Windows Defender Advanced Threat Protection" sibling directory;
	// nothing in there executed by interactive users, as of this writing.)
	AddToSafePathCollectionIfSafeDirectory(
		WindowsDirectories::ProgramData() + L"\\Microsoft\\Windows Defender",
		L"Windows Defender (under ProgramData)",
		strErrorInfo
	);
	// Symantec SEP directory under ProgramData
	AddToSafePathCollectionIfSafeDirectory(
		WindowsDirectories::ProgramData() + L"\\Symantec\\Symantec Endpoint Protection",
		L"Symantec SEP (under ProgramData)",
		strErrorInfo
	);
	AddToSafePathCollectionIfSafeDirectory(
		WindowsDirectories::ProgramData() + L"\\Microsoft\\Windows\\AppRepository",
		L"Microsoft packaged-app files that got installed into ProgramData (!)",
		strErrorInfo
	);
}

// Internal helper function used by ScanForSafeAVPaths.
// If the input path is an existing, safe directory, add it and the label to the m_PlatformSafePathInfo collection.
bool EndpointFullScan::AddToSafePathCollectionIfSafeDirectory(const std::wstring& sPath, const std::wstring& sLabel, std::wstringstream& strErrorInfo)
{
	bool retval = false;

	// Determine whether the directory exists, is a directory, and not also a reparse point (junction or symlink).
	DWORD dwLastError;
	std::wstring sAltName;
	DWORD dwAttributes = GetFileAttributes_ExtendedPath(sPath.c_str(), dwLastError, sAltName);
	if (IsNonReparseDirectory(dwAttributes))
	{
		// Determine whether the directory is safe or unsafe.
		bool bIsNonadminWritable;
		bool bNeedsAltDataStreamExclusion;
		std::vector<CSid> nonadminSids;
		std::wstring sErrorInfo;

		bool ret = SecurityDescriptorAnalyzer::IsNonadminWritable(
			sPath.c_str(),
			m_sidsToFilter,
			bIsNonadminWritable,
			bNeedsAltDataStreamExclusion,
			nonadminSids,
			sErrorInfo
		);

		if (ret)
		{
			// If the directory is not nonadmin-writable, add it to the collection
			// If it is nonadmin-writable, log an error about it.
			if (!bIsNonadminWritable)
			{
				m_PlatformSafePathInfo.push_back(
					SafePathInfo_t(sLabel, sPath + L"\\*")
				);
				retval = true;
			}
			else
			{
				strErrorInfo << L"AV path \"" << sPath << L"\" exists but is nonadmin-writable." << std::endl;
			}
		}
		else
		{
			// Could not determine whether the directory is safe or unsafe. Log an error.
			strErrorInfo << sPath << L": " << sErrorInfo << std::endl;
		}
	}
	return retval;
}

// ------------------------------------------------------------------------------------------
// Scan for logon server paths.

void EndpointFullScan::ScanForLogonServerPaths(std::wstringstream& strErrorInfo)
{
	//TODO: Capture error info in EndpointFullScan::ScanForLogonServerPaths if anything goes wrong.
	UNREFERENCED_PARAMETER(strErrorInfo);

	// Get a set of domain names and known DC names (without hitting the network if possible)
	CaseInsensitiveStringLookup DomainAndDcNames;

	// Get the computer's DNS domain name, if it exists.
	DWORD dwBuffer = 0;
	const COMPUTER_NAME_FORMAT fmt = ComputerNameDnsDomain;
	GetComputerNameExW(fmt, NULL, &dwBuffer);
	if (dwBuffer > 1)
	{
		wchar_t* pszBuffer = new wchar_t[dwBuffer];
		if (GetComputerNameExW(fmt, pszBuffer, &dwBuffer))
		{
			// Domain-joined.
			DomainAndDcNames.Add(pszBuffer);

			// Now get the domain's NetBIOS name and add that.
			// (This API returns a workgroup name if not domain-joined; never want to add that)
			WKSTA_INFO_100* pWkstaInfo100 = NULL;
			NET_API_STATUS status = NetWkstaGetInfo(NULL, 100, (LPBYTE*)&pWkstaInfo100);
			if (NERR_Success == status)
			{
				DomainAndDcNames.Add(pWkstaInfo100->wki100_langroup);
				NetApiBufferFree(pWkstaInfo100);
			}
		}
		delete[] pszBuffer;
	}

	// Next, enumerate LSA sessions and pick up their DnsDomains, and logon server (when DnsDomain not empty).
	// This can pick up logon servers, and possibly also pick up user domains when users are not in the same
	// domain as the machine.
	ULONG LogonSessionCount = 0;
	PLUID pLogonSessionList = NULL;
	NTSTATUS status = LsaEnumerateLogonSessions(&LogonSessionCount, &pLogonSessionList);
	if (0 == status)
	{
		for (ULONG ixSession = 0; ixSession < LogonSessionCount; ++ixSession)
		{
			PLUID pLuid = &pLogonSessionList[LogonSessionCount - 1 - ixSession];
			PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
			status = LsaGetLogonSessionData(pLuid, &pSessionData);
			if (0 == status)
			{
				const wchar_t* pDnsDomain = pSessionData->DnsDomainName.Buffer;
				const wchar_t* pLogonServer = pSessionData->LogonServer.Buffer;
				// If DnsDomainName is not an empty string, add it to the set, and then
				// the logon server (if not null/empty). Add the logon server ONLY if
				// the account has a domain; otherwise we'd add the local machine name.
				if (pDnsDomain && *pDnsDomain)
				{
					DomainAndDcNames.Add(pDnsDomain);
					if (pLogonServer && *pLogonServer)
					{
						DomainAndDcNames.Add(pLogonServer);
					}
				}
				LsaFreeReturnBuffer(pSessionData);
			}
		}
		LsaFreeReturnBuffer(pLogonSessionList);
	}

	// If there are other ways to pick up potential logon servers without enumerating all the DCs from here,
	// add that logic in here at some point.

	// Now, add the names we've got to the safe-path set with both netlogon and sysvol share paths.
	const std::wstring sLabel = L"Logon server shares";
	const std::wstring sUnc = L"\\\\";
	CaseInsensitiveStringLookup::const_iterator iterNames;
	for (
		iterNames = DomainAndDcNames.begin();
		iterNames != DomainAndDcNames.end();
		++iterNames
		)
	{
		m_PlatformSafePathInfo.push_back(
			SafePathInfo_t(sLabel, sUnc + *iterNames + L"\\netlogon\\*")
		);
		m_PlatformSafePathInfo.push_back(
			SafePathInfo_t(sLabel, sUnc + *iterNames + L"\\sysvol\\*")
		);
	}
}

// ------------------------------------------------------------------------------------------
// Scan for information about AppLocker-relevant files in common locations for which we might need to create
// custom rules.

void EndpointFullScan::ScanFileInfoForAppsInCommonLocations(std::wstringstream& strErrorInfo)
{
	// Initialize collection
	m_FileDetails.clear();

	// Look for AppLocker-relevant files in each of the unsafe directories under the Windows directory
	UnsafeDirectoryCollection_t::const_iterator iterUnsafeDirs;
	for (
		iterUnsafeDirs = m_unsafeWindowsSubdirs.begin();
		iterUnsafeDirs != m_unsafeWindowsSubdirs.end();
		++iterUnsafeDirs
		)
	{
		ScanDirectoryHierarchyForAppLockerRelevantFiles(
			iterUnsafeDirs->m_sFileSystemPath.c_str(), 
			L"Writable files under Windows directory",
			NULL,
			strErrorInfo);
	}

	// Look for AppLocker-relevant files in each of the unsafe directories under the Program Files directories
	for (
		iterUnsafeDirs = m_unsafeProgFilesSubdirs.begin();
		iterUnsafeDirs != m_unsafeProgFilesSubdirs.end();
		++iterUnsafeDirs
		)
	{
		ScanDirectoryHierarchyForAppLockerRelevantFiles(
			iterUnsafeDirs->m_sFileSystemPath.c_str(), 
			L"Writable files under Program Files",
			NULL,
			strErrorInfo);
	}

	// Identify non-default root directories, determine whether they are safe or unsafe, and then look
	// for AppLocker-relevant files in each of them.
	// 
	// Root directory usually "C:\"
	std::wstring sRootDir = WindowsDirectories::SystemDriveDirectory() + L"\\";
	std::vector<std::wstring> vRootSubdirNames;
	std::vector<std::wstring>::const_iterator iterNames;
	// Get the names of all the subdirectories under the system drive root directory. Names only, not full paths.
	if (GetSubdirectories(sRootDir, vRootSubdirNames, true))
	{
		// Look at each of them in turn.
		for (
			iterNames = vRootSubdirNames.begin();
			iterNames != vRootSubdirNames.end();
			++iterNames
			)
		{
			// Inspect files in the ones that are non-default subdirectories
			if (!WindowsDirectories::IsDefaultRootDirName(iterNames->c_str()))
			{
				// Directory path to inspect
				std::wstring sPath = sRootDir + *iterNames;
				// App label to associate with any files in the directory hierarchy
				std::wstring sAppLabel = *iterNames + L" (Non-default root directory)";
				// Collection of information about directory hierarchy's safety/non-safety.
				UnsafeDirectoryCollection_t vUnsafeDirectoryInfo;
				// Pointer to that collection (in case we need to clear it - see below)
				UnsafeDirectoryCollection_t* pvUnsafeDirectoryInfo = &vUnsafeDirectoryInfo;

				// Identify safe/unsafe directories in this non-default directory
				// If the inspection fails (unlikely at the moment), treat the directory as unsafe
				// by passing in a NULL pointer for the ScanDirectoryHierarchyForAppLockerRelevantFiles's
				// collection parameter instead of an empty collection.
				if (!DirectorySafetyAnalyzer::InspectDirectoryHierarchySafety(
					sPath.c_str(),
					false,
					m_sidsToFilter,
					vUnsafeDirectoryInfo,
					strErrorInfo))
				{
					pvUnsafeDirectoryInfo = NULL;
				}

				// Scan the directory hierarchy for AppLocker-relevant files.
				ScanDirectoryHierarchyForAppLockerRelevantFiles(sPath.c_str(), sAppLabel.c_str(), pvUnsafeDirectoryInfo, strErrorInfo);
			}
		}
	}

	// Scan portions of each of the user profile directories on this machine.
	// Start by identifying the subdirectories under the profiles root directory (typically "C:\Users")
	std::vector<std::wstring> vUserProfileDirs;
	if (GetSubdirectories(WindowsDirectories::ProfilesDirectory(), vUserProfileDirs))
	{
		// Iterate through each
		std::vector<std::wstring>::const_iterator iterUserProfDirs;
		for (
			iterUserProfDirs = vUserProfileDirs.begin();
			iterUserProfDirs != vUserProfileDirs.end();
			++iterUserProfDirs
			)
		{
			// Look into all the user profiles except for the Default and Public user profiles.
			if (
				WindowsDirectories::DefaultUserProfileDirectory() != *iterUserProfDirs &&
				WindowsDirectories::PublicUserProfileDirectory() != *iterUserProfDirs
				)
			{
				ScanPortionsOfUserProfile(*iterUserProfDirs, strErrorInfo);
			}
		}
	}
}

// ------------------------------------------------------------------------------------------
// Scanning user profiles: don't scan an entire user profile directory. Doing so will be expensive
// in terms of time and CPU/disk hit. The code below optimizes the search to avoid locations that
// are unlikely to be fruitful.
//
// The scan looks only in AppData\Local and AppData\Roaming, and within those the scan skips
// a lot of directories that are very unlikely to contain files of interest, and of the ones
// that are likely to contain files of interest, they are known and rules can be defined
// separately.

// Subdirectories under AppData\Local not to scan
static const wchar_t* szAppdatalocal_exclusions[] = {
	//L"Application Data",          // Hidden app-compat junction - already skipping reparse points
	L"Comms",
	L"ConnectedDevicesPlatform",
	L"D3DSCache",
	L"Google",                    // Will dig into this at a lower level with additional exceptions
	L"GroupPolicy",
	//L"History",                   // Hidden app-compat junction - already skipping reparse points
	L"Microsoft_Corporation",
	L"Microsoft",                 // Will dig into this at a lower level with additional exceptions
	L"MicrosoftEdge",
	L"Packages",
	L"PeerDistRepub",
	L"PlaceholderTileLogoFolder",
	L"Publishers",
	L"SquirrelTemp",
	L"Temp",
	//L"Temporary Internet Files",  // Hidden app-compat junction - already skipping reparse points
	L"VirtualStore",
	NULL
};

// Subdirectories under AppData\Local\Microsoft not to scan
static const wchar_t* szAppdatalocalMSFT_exclusions[] = {
	L"CLR_v2.0",
	L"CLR_v4.0",
	L"CLR_v4.0_32",
	L"Credentials",
	L"Edge",                // Edge will have executable content, which we can establish rules for elsewhere. This dir can get a LOT of files and subdirs.
	L"EDP",
	L"Event Viewer",
	L"Excel",
	L"Feeds",
	L"Feeds Cache",
	L"fluency",
	L"FontCache",
	L"FORMS",
	L"GameDVR",
	L"GraphicsCache",
	L"input",
	L"InputPersonalization",
	L"Internet Explorer",
	L"Media Player",
	L"MSIPC",
	L"Office",
	//L"OneDrive",          // Can't exclude this until the OneDrive team gets much better about putting version resource information in their binaries
	L"Outlook",
	L"PenWorkspace",
	L"PlayReady",
	L"TaskSchedulerConfig",
	L"Teams",               // Use predefined Teams rules instead of content in here
	L"TeamsMeetingAddin",   // Use predefined Teams rules instead of content in here
	L"TeamsPresenceAddin",  // Use predefined Teams rules instead of content in here
	L"TokenBroker",
	L"Vault",
	L"Windows",
	L"Windows Sidebar",
	L"WindowsApps",
	L"XboxLive",
	NULL
};

// Subdirectories under AppData\Local\Google not to scan
static const wchar_t* szAppdatalocalGOOG_exclusions[] = {
	L"Chrome",  // Chrome will have executable content, which we can establish rules for elsewhere. This dir can get a LOT of files and subdirs.
	L"DriveFS",
	NULL
};

// Subdirectories under AppData\Roaming not to scan
static const wchar_t* szAppdataroaming_exclusions[] = {
	L"Microsoft",
	NULL
};

// Set up hash-based lookups to compare values against the above names
static CaseInsensitiveStringLookup lookupAppdatalocal_exclusions;
static CaseInsensitiveStringLookup lookupAppdatalocalMSFT_exclusions;
static CaseInsensitiveStringLookup lookupAppdatalocalGOOG_exclusions;
static CaseInsensitiveStringLookup lookupAppdataroaming_exclusions;
// Initialize the lookups on first use
static void InitAppdataLookups()
{
	static bool bAppdataLookupsInitialized = false;
	if (bAppdataLookupsInitialized)
		return;
	bAppdataLookupsInitialized = true;

	// Put upper-cased versions of each of the sets of names into corresponding hash-based set.
	// Upper-case to ensure case-insensitive compare.
	lookupAppdatalocal_exclusions.Add(szAppdatalocal_exclusions);
	lookupAppdatalocalMSFT_exclusions.Add(szAppdatalocalMSFT_exclusions);
	lookupAppdatalocalGOOG_exclusions.Add(szAppdatalocalGOOG_exclusions);
	lookupAppdataroaming_exclusions.Add(szAppdataroaming_exclusions);
}

/// <summary>
/// Scans portions of a user profile directory for AppLocker-relevant files.
/// </summary>
/// <param name="sUserProfileDir">Full path to a user profile directory to scan; e.g., "C:\Users\john.bigboote"</param>
void EndpointFullScan::ScanPortionsOfUserProfile(const std::wstring& sUserProfileDir, std::wstringstream& strErrorInfo)
{
	// InitAppdataLookups does all its work only the first time it's called.
	InitAppdataLookups();

	// Get the full paths of the subdirectories to search, and relative paths to use within corresponding app labels
	// AppData\Local
	std::wstring sAppdatalocal_pathRel = WindowsDirectories::AppDataLocalSubdir();
	std::wstring sAppdatalocal_path = sUserProfileDir + L"\\" + sAppdatalocal_pathRel;
	// AppData\Local\Microsoft
	std::wstring sAppdatalocalMSFT_pathRel = sAppdatalocal_pathRel + L"\\Microsoft";
	std::wstring sAppdatalocalMSFT_path = sUserProfileDir + L"\\" + sAppdatalocalMSFT_pathRel;
	// AppData\Local\Google
	std::wstring sAppdatalocalGOOG_pathRel = sAppdatalocal_pathRel + L"\\Google";
	std::wstring sAppdatalocalGOOG_path = sUserProfileDir + L"\\" + sAppdatalocalGOOG_pathRel;
	// AppData\Roaming
	std::wstring sAppdataroaming_pathRel = WindowsDirectories::AppDataRoamingSubdir();
	std::wstring sAppdataroaming_path = sUserProfileDir + L"\\" + sAppdataroaming_pathRel;

	// Now scan each of those, with corresponding sets if subdirectories to skip
	ScanUserProfileSubdirWithExclusions(sAppdatalocal_path,     sAppdatalocal_pathRel,     lookupAppdatalocal_exclusions,     strErrorInfo);
	ScanUserProfileSubdirWithExclusions(sAppdatalocalMSFT_path, sAppdatalocalMSFT_pathRel, lookupAppdatalocalMSFT_exclusions, strErrorInfo);
	ScanUserProfileSubdirWithExclusions(sAppdatalocalGOOG_path, sAppdatalocalGOOG_pathRel, lookupAppdatalocalGOOG_exclusions, strErrorInfo);
	ScanUserProfileSubdirWithExclusions(sAppdataroaming_path,   sAppdataroaming_pathRel,   lookupAppdataroaming_exclusions,   strErrorInfo);
}

/// <summary>
/// Scans a user profile subdirectory for AppLocker-relevant files, ignoring selected subdirectories.
/// </summary>
/// <param name="sFullAppdataPath">Full path to a user profile subdirectory to scan; e.g., "C:\Users\john.bigboote\AppData\Local"</param>
/// <param name="sRelativeAppdataPath">Relative path to incorporate into app label; e.g., "AppData\Local"</param>
/// <param name="exclusions">Hash-based lookup object to determine whether a given subdirectory should be scanned or excluded from the scan</param>
/// <param name="strErrorInfo">Output: text representation of any errors that occur</param>
void EndpointFullScan::ScanUserProfileSubdirWithExclusions(
	const std::wstring& sFullAppdataPath, 
	const std::wstring& sRelativeAppdataPath, 
	const CaseInsensitiveStringLookup& exclusions, 
	std::wstringstream& strErrorInfo)
{
	// Get all the subdirectories of the input sFullAppdataPath.
	std::vector<std::wstring> subdirectories;
	if (GetSubdirectories(sFullAppdataPath, subdirectories, true))
	{
		// Look at each of them in turn
		std::vector<std::wstring>::const_iterator iterSubdirs;
		for (
			iterSubdirs = subdirectories.begin();
			iterSubdirs != subdirectories.end();
			++iterSubdirs
			)
		{
			// Inspect the subdirectory only if it's not in the exclusions set
			if (!exclusions.IsInSet(*iterSubdirs))
			{
				// Directory path to inspect
				std::wstring sPath = sFullAppdataPath + L"\\" + *iterSubdirs;
				// App label to associate with any files in the directory hierarchy
				std::wstring sAppLabel = *iterSubdirs + L" (" + sRelativeAppdataPath + L")";

				ScanDirectoryHierarchyForAppLockerRelevantFiles(sPath.c_str(), sAppLabel.c_str(), NULL, strErrorInfo);
			}
		}
	}
}

void EndpointFullScan::ScanInstalledPackagedApps(std::wstringstream& strErrorInfo)
{
	//GetPackagedAppInfoResult_t result =
	GetPackagedAppInfo(m_PackagedAppInfo, strErrorInfo);
}
