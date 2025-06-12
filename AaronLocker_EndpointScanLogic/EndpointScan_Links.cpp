// Interface to scan an endpoint's shortcut files to support mapping file paths to application display names

#include "EndpointScan_Links.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "../AaronLocker_CommonUtils/FileSystemUtils.h"
#include "../AppLockerFunctionality/AppLockerFileDetails.h"
#include <sstream>

EndpointScan_Links::EndpointScan_Links()
{
}

EndpointScan_Links::~EndpointScan_Links()
{
}

/// <summary>
/// Internal helper function that inspects all the *.lnk files in a directory and adds information about
/// the "interesting" ones to a collection.
/// </summary>
/// <param name="sDirName">Input: directory to scan for *.lnk files</param>
/// <param name="sli">Initialized ShellLinkInfo object with which to retrieve data</param>
/// <param name="dataCollection">Collection to add data into</param>
static void InspectLnkFilesInThisDirectory(
	const std::wstring& sDirName, 
	ShellLinkDataContext_t::LinkLocation_t linkLocation,
	const std::wstring& sBaseDirectory,
	ShellLinkInfo& sli, 
	ShellLinkDataContextCollection_t& dataCollection, 
	std::wstringstream&) // unused strErrorInfo)
{
	// Get all the *.lnk files in the specified directory
	std::vector<std::wstring> vFiles;
	GetFiles(sDirName, L"*.lnk", vFiles);
	// Iterate through them all
	for (
		std::vector<std::wstring>::const_iterator iterFiles = vFiles.begin();
		iterFiles != vFiles.end();
		++iterFiles
		)
	{
		// Get information from the link file
		ShellLinkDataContext_t data;
		if (sli.Get(*iterFiles, data))
		{
			// Ignore the link if there's no file system path
			if (data.sFileSystemPath.length() > 0)
			{
				// Ignore the link if it points anywhere in/under the Windows directory
				if (!PathStartsWithDirectory(data.sFileSystemPath, WindowsDirectories::WindowsDirectory()))
				{
					// Commenting out a bunch of checks - no need to inspect file content or determine whether the actual target file
					// is a file of interest to AppLocker - this is just about mapping directories to app names.

					// Add context about the link to the data:
					// High-level where it's located (all-users' Start Menu, per-user Desktop, etc.)
					data.linkLocation = linkLocation;
					// Subdirectory under that high-level location.
					std::wstring sDir = GetDirectoryNameFromFilePath(*iterFiles);
					// This condition should always be true, but check it anyway to avoid a crash.
					if (sDir.length() > sBaseDirectory.length() + 1)
						data.sLinkRelativeSubdir = sDir.substr(sBaseDirectory.length() + 1);
					// Add it to the collection.
					dataCollection.push_back(data);
				}
			}
		}
	}
}

/// <summary>
/// Internal helper function that scans a directory hierarchy for *.lnk files and adds information
/// about the "interesting" ones to a collection.
/// </summary>
/// <param name="sRootDirName">Input: directory to scan recursively for *.lnk files</param>
/// <param name="sli">Initialized ShellLinkInfo object with which to retrieve data</param>
/// <param name="dataCollection">Collection to add data into</param>
static void InspectLnkFilesInDirHierarchy(
	const std::wstring& sRootDirName, 
	ShellLinkDataContext_t::LinkLocation_t linkLocation,
	const std::wstring& sBaseDirectory,
	ShellLinkInfo& sli,
	ShellLinkDataContextCollection_t& dataCollection, 
	std::wstringstream& strErrorInfo)
{
	DirWalker dirWalker;
	if (!dirWalker.Initialize(sRootDirName.c_str(), strErrorInfo))
		return;

	std::wstring sCurrDir;
	while (dirWalker.GetCurrent(sCurrDir))
	{
		// Look at *.lnk files in this directory
		InspectLnkFilesInThisDirectory(sCurrDir, linkLocation, sBaseDirectory, sli, dataCollection, strErrorInfo);

		dirWalker.DoneWithCurrent();
	}
}

bool EndpointScan_Links::PerformFullScan(std::wstring& sErrorInfo)
{
	sErrorInfo.clear();

	// Initialize/reinitialize (in case this has been called before)
	m_ShellLinkDataCollection.clear();

	// Instantiate and initialize an object with which to inspect *.lnk files.
	// If initialization fails, quit now.
	ShellLinkInfo sli;
	if (!sli.Ready())
	{
		sErrorInfo = L"Shell link scan could not be performed.";
		return false;
	}

	std::wstringstream strErrorInfo;

	// Shortcuts in the "Start Menu" and "Start Menu\Programs" subdirectories are treated the same.
	// We don't want "Programs" to show as part of the relative subdirs. So do a single-dir scan
	// of the "Start Menu" directory and a recursive of the Programs directory, treating each as the
	// base directory in turn.

	// Single-directory scan of the "Start Menu" top-level directory.
	std::wstring sBaseDir = WindowsDirectories::CommonStartMenu();
	InspectLnkFilesInThisDirectory(
		sBaseDir,
		ShellLinkDataContext_t::LinkLocation_t::AllUsersStartMenu,
		sBaseDir,
		sli,
		m_ShellLinkDataCollection,
		strErrorInfo
	);
	// Recursive search in the system-wide Start Menu for shortcuts to programs of interest.
	sBaseDir = WindowsDirectories::CommonStartMenuPrograms();
	InspectLnkFilesInDirHierarchy(
		sBaseDir, 
		ShellLinkDataContext_t::LinkLocation_t::AllUsersStartMenu, 
		sBaseDir, 
		sli, 
		m_ShellLinkDataCollection, 
		strErrorInfo);

	// Next, look into the per-user Start menus. (Will also pick up all-users' Desktop in this loop.)
	std::vector<std::wstring> vUserProfileDirs;
	if (GetSubdirectories(WindowsDirectories::ProfilesDirectory(), vUserProfileDirs))
	{
		// Iterate through each profile subdirectory
		std::vector<std::wstring>::const_iterator iterUserProfDirs;
		for (
			iterUserProfDirs = vUserProfileDirs.begin();
			iterUserProfDirs != vUserProfileDirs.end();
			++iterUserProfDirs
			)
		{
			// Don't inspect anything in the Default user profile
			if (WindowsDirectories::DefaultUserProfileDirectory() != *iterUserProfDirs)
			{
				bool bIsPublicUserProfile = WindowsDirectories::PublicUserProfileDirectory() == *iterUserProfDirs;

				// Inspect the user profile's Desktop directory, but not any subdirectories.
				// Note that the "Public" one is the all-users' Desktop.
				std::wstring sUserDesktop = *iterUserProfDirs + L"\\" + WindowsDirectories::DesktopSubdir();
				InspectLnkFilesInThisDirectory(
					sUserDesktop, 
					(bIsPublicUserProfile ? ShellLinkDataContext_t::LinkLocation_t::AllUsersDesktop : ShellLinkDataContext_t::LinkLocation_t::PerUserDesktop),
					sUserDesktop,
					sli, 
					m_ShellLinkDataCollection, 
					strErrorInfo);
				// Inspect the user profile's Start Menu directory recursively. (Public shouldn't have one.)
				if (!bIsPublicUserProfile)
				{
					// Same issue here with separate single-dir scan of "Start Menu" and recursive scan of Start Menu\Programs 
					sBaseDir = *iterUserProfDirs + L"\\" + WindowsDirectories::StartMenuSubdir();
					InspectLnkFilesInThisDirectory(
						sBaseDir,
						ShellLinkDataContext_t::LinkLocation_t::PerUserStartMenu,
						sBaseDir,
						sli,
						m_ShellLinkDataCollection,
						strErrorInfo);
					sBaseDir = *iterUserProfDirs + L"\\" + WindowsDirectories::StartMenuProgramsSubdir();
					InspectLnkFilesInDirHierarchy(
						sBaseDir, 
						ShellLinkDataContext_t::LinkLocation_t::PerUserStartMenu,
						sBaseDir,
						sli, 
						m_ShellLinkDataCollection, 
						strErrorInfo);
				}
			}
		}
	}

	sErrorInfo = strErrorInfo.str();

	return true;
}

const ShellLinkDataContextCollection_t& EndpointScan_Links::ScanResults() const
{
	return m_ShellLinkDataCollection;
}
