// Map arbitrary file paths to application display names, based on Start Menu and Desktop shortcuts
/*
 ------------------------------------------------------------------------------------------
	Based on inspection of link data collected from a few machines, I defined the following procedures to build a mapping
	from an arbitrary file path to an application display name. (Note that "link," "shortcut," and "shortcut file" are
	used interchangeably. Note also that in this context, "link" refers to a shell link, not to file system symbolic links,
	hard links, etc. Historical artifact.)

	The PathToAppMap class is derived from std::map<std::wstring, std::wstring>, where the key is an encoded and
	upper-cased directory name, and the value is an application display name. The assumption that any files
	in that directory or below it are associated with the app.

	When looking up an entry, start by looking up the input file or directory. If not found, look up its parent
	directory, then that directory's parent directory, and so on, until a mapping is found or the search can't
	continue any higher. But we don't want to keep searching all the way up to the root directory - we want to
	stop the search if it goes up to the Program Files/Program Files (x86) directory, to a user profile's
	AppData\Local\Microsoft, AppData\Local, AppData\Roaming\Microsoft, or AppData\Roaming directory, etc. To
	stop the search from proceeding past those points, those path parts are replaced in the lookup with a
	pseudo-drive notation. For example, a shortcut that points to a file in the
	C:\Users\Aaron\AppData\Local\Microsoft\Teams directory will be result in an entry with the key "ADLM:TEAMS",
	where "ADLM:" refers to AppData\Local\Microsoft under any user profile, and "TEAMS" is the capitalized
	subdirectory name under AppData\Local\Microsoft.

	The keys for all entries get this pseudo-drive encoding and capitalization, and the class member function that
	performs lookups performs the same transformation on the input path prior to lookup.

	Because Microsoft Office apps are many and varied with many shortcuts under many target directories, all files
	anywhere under Program Files\Microsoft Office or Program Files (x86)\Microsoft Office are mapped to the app
	name "Microsoft Office". This is accomplished by creating two default entries in the map: "PF:Microsoft Office"
	and "PFX86:Microsoft Office". By creating these entries on construction, no other entries will be added for
	shortcuts pointing to Office subdirectories, as these default entries will always override them.

	App names associated with links in the system-wide Start Menu take precedence over other shortcuts. Next are
	links from the system-wide Desktop (Desktop of the Public profile), then links from per-user Start Menus,
	and then finally shortcuts on per-user Desktops. Shortcuts on individual user's desktops are the ones most
	likely to have been personalized for that user.

	If a Start Menu has a subfolder or subfolder hierarchy with multiple shortcuts and all those shortcuts point to 
	files within the same directory hierarchy, create a map entry pointing to the longest common subdirectory and 
	using the top-level subfolder name as the application name. For example, consider these shortcuts and their target
	files:

	Start Menu relative path                                                   App path
	Windows Kits\bin\Windows Kits Feedback.lnk                                 C:\Program Files (x86)\Windows Kits\10\bin\microsoft.windowskits.feedback.exe
	Windows Kits\Debugging Tools for Windows (ARM)\Global Flags (ARM).lnk      C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\gflags.exe
	Windows Kits\Debugging Tools for Windows (ARM)\WinDbg (ARM).lnk            C:\Program Files (x86)\Windows Kits\10\Debuggers\arm\windbg.exe
	Windows Kits\Debugging Tools for Windows (ARM64)\Global Flags (ARM64).lnk  C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\gflags.exe
	Windows Kits\Debugging Tools for Windows (ARM64)\WinDbg (ARM64).lnk        C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\windbg.exe
	Windows Kits\Debugging Tools for Windows (X64)\Global Flags (X64).lnk      C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\gflags.exe
	Windows Kits\Debugging Tools for Windows (X64)\WinDbg (X64).lnk            C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe
	Windows Kits\Debugging Tools for Windows (X86)\Global Flags (X86).lnk      C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\gflags.exe
	Windows Kits\Debugging Tools for Windows (X86)\WinDbg (X86).lnk            C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe
	Windows Kits\Windows App Certification Kit\Windows App Cert Kit.lnk        C:\Program Files (x86)\Windows Kits\10\App Certification Kit\appcertui.exe
	Windows Kits\Windows Performance Toolkit\GPUView.lnk                       C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\gpuview\GPUView.exe
	Windows Kits\Windows Performance Toolkit\Windows Performance Analyzer.lnk  C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\wpa.exe
	Windows Kits\Windows Performance Toolkit\Windows Performance Recorder.lnk  C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\WPRUI.exe

	All the shortcuts are in subfolders of the "Windows Kits" Start Menu subfolder. The longest common subdirectory of the
	shortcuts' target files is "C:\Program Files (x86)\Windows Kits\10". A single entry will be added to the map with the 
	encoded/capitalized path "PFX86:WINDOWS KITS\10" and the application name "Windows Kits".

	For these remaining cases:
		* A Start Menu has a subfolder/hierarchy containing only one shortcut; or
		* A Start Menu has a subfolder/hierarchy containing multiple shortcuts but they don't point to a common subdirectory; or
		* Shortcuts on a Desktop or at the top level of a Start Menu;
	Add an entry to the map for each shortcut, using the encoded/capitalized target path of the shortcut and the link's name.
	A link's name is its localized name, if one is present, or the link file name without the extension.

 ------------------------------------------------------------------------------------------
*/

#include <regex>
#include <sstream>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "PathToAppNameMap.h"

// ------------------------------------------------------------------------------------------
// Forward declarations of non-member helper functions defined later in this module

/// <summary>
/// Looks for patterns in paths to replace with the pseudo-drive notation, and returns a string with that replacement.
/// </summary>
/// <param name="sInput">Input: path to transform</param>
/// <param name="sOutput">Output: transformed path</param>
static void PathPatternReplacement(const std::wstring& sInput, std::wstring& sOutput);

/// <summary>
/// Returns the longest common subdirectory between two input paths.
/// The output parameter can also refer to the same string as one of the input parameters.
/// The inputs are EXPECTED to have the pseudo-drive notation applied prior to input.
/// </summary>
/// <param name="sPath1">Input: first path to compare</param>
/// <param name="sPath2">Input: second path to compare</param>
/// <param name="sCommonPath">Output: the longest common path between the two, or an empty string if no common path found.</param>
/// <returns>true if common subdirectory found, false otherwise</returns>
static bool FindCommonSubdir(const std::wstring& sPath1, const std::wstring& sPath2, std::wstring& sCommonPath);

// ------------------------------------------------------------------------------------------
// Definitions of pseudo-drives used to simplify internal mapping

static const wchar_t* szDrivePublic                  = L"PUB:";
static const wchar_t* szDriveLocalAppDataMicrosoft   = L"ADLM:";
static const wchar_t* szDriveLocalAppDataTemp        = L"TEMP:";
static const wchar_t* szDriveLocalAppData            = L"ADL:";
static const wchar_t* szDriveRoamingAppDataMicrosoft = L"ADRM:";
static const wchar_t* szDriveRoamingAppData          = L"ADR:";
static const wchar_t* szDriveUserDownloads           = L"UDL:";
static const wchar_t* szDriveUserDesktop             = L"UDESK:";
static const wchar_t* szDriveUserProfile             = L"USER:";
static const wchar_t* szDriveProgramFilesX86         = L"PFX86:";
static const wchar_t* szDriveProgramFiles            = L"PF:";
static const wchar_t* szDriveProgramDataMicrosoft    = L"PDM:";
static const wchar_t* szDriveProgramData             = L"PD:";
static const wchar_t* szDriveWindowsData             = L"WIN:";
static const wchar_t* szDriveRootDir                 = L"ROOT:";

static const wchar_t* PseudoDriveToReadable(const wchar_t* szPseudoDrive)
{
	if (nullptr != szPseudoDrive)
	{
		if (0 == wcscmp(szPseudoDrive, szDrivePublic))
			return L"Public User Profile";
		if (0 == wcscmp(szPseudoDrive, szDriveLocalAppDataMicrosoft))
			return L"local appdata";
		if (0 == wcscmp(szPseudoDrive, szDriveLocalAppDataTemp))
			return L"local appdata temp";
		if (0 == wcscmp(szPseudoDrive, szDriveLocalAppData))
			return L"local appdata";
		if (0 == wcscmp(szPseudoDrive, szDriveRoamingAppDataMicrosoft))
			return L"roaming appdata";
		if (0 == wcscmp(szPseudoDrive, szDriveRoamingAppData))
			return L"roaming appdata";
		if (0 == wcscmp(szPseudoDrive, szDriveUserDownloads))
			return L"user downloads";
		if (0 == wcscmp(szPseudoDrive, szDriveUserDesktop))
			return L"user desktop";
		if (0 == wcscmp(szPseudoDrive, szDriveUserProfile))
			return L"user profile";
		if (0 == wcscmp(szPseudoDrive, szDriveProgramFilesX86))
			return L"Program Files (x86)";
		if (0 == wcscmp(szPseudoDrive, szDriveProgramFiles))
			return L"Program Files";
		if (0 == wcscmp(szPseudoDrive, szDriveProgramDataMicrosoft))
			return L"ProgramData\\Microsoft";
		if (0 == wcscmp(szPseudoDrive, szDriveProgramData))
			return L"ProgramData";
		if (0 == wcscmp(szPseudoDrive, szDriveWindowsData))
			return L"Windows directory";
		if (0 == wcscmp(szPseudoDrive, szDriveRootDir))
			return L"root directory";
	}
	return nullptr;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Constructor. Adds default entries.
/// </summary>
PathToAppMap::PathToAppMap()
{
	AddDefaultEntries();
}

/// <summary>
/// Add entries to the map from information gathered from shortcuts.
/// </summary>
/// <param name="shellLinks">Input: information collected from shell links</param>
void PathToAppMap::AddEntries(const ShellLinkDataContextCollection_t& shellLinks)
{
	// Define a structure to capture the information of interest from the input data collection
	struct linkInfo_t
	{
		std::wstring 
			sName,            // the link's name (localized if that info is present) 
			sPath,            // directory of the target file, with pseudo-drive notation described elsewhere
			sStartMenuSubdir; // the link's top-level subdirectory if in a Start Menu subdirectory hierarchy
	};

	// We want to treat anything in the "Startup" Start Menu subfolder as top-level Start Menu items and not give them
	// the app name of "Startup". Get the name of the "Startup" subfolder by itself. "GetFileNameFromFilePath" when applied to a
	// directory path returns the leaf directory name.
	const std::wstring sStartupFolderName = GetFileNameFromFilePath(WindowsDirectories::CommonStartMenuStartup());

	// Split the input collection up by grouping into vectors by precedence order by link location, and then 
	// separate those that are in Start Menu subdirectories (index 0) from those that aren't (index 1).
	std::vector<linkInfo_t> linkInfoByLocation[ShellLinkDataContext_t::numLinkLocations][2];
	for (
		ShellLinkDataContextCollection_t::const_iterator iterLink = shellLinks.begin();
		iterLink != shellLinks.end();
		++iterLink
		)
	{
		// Use the linkLocation enum as the vector index.
		size_t ixLoc = (size_t)iterLink->linkLocation;
		// Make sure the index is not out of bounds.
		if (ixLoc < ShellLinkDataContext_t::numLinkLocations)
		{
			// Data to add to the vector
			linkInfo_t linkInfo;
			// Assume no Start Menu subdirectory - index 1
			size_t ixSMSubdir = 1;
			// Use the localized name if present, regular name otherwise
			linkInfo.sName = (iterLink->sLocalizedName.length() > 0 ? iterLink->sLocalizedName : iterLink->sLinkName);
			// Get the target file's parent directory, then do the pseudo-drive pattern replacement
			PathPatternReplacement(GetDirectoryNameFromFilePath(iterLink->sFileSystemPath), linkInfo.sPath);
			// If the link is in a Start Menu subdirectory other than the Startup folder...
			if (iterLink->sLinkRelativeSubdir.length() > 0 && !EqualCaseInsensitive(iterLink->sLinkRelativeSubdir, sStartupFolderName))
			{
				// Index 0 for links in subfolders...
				ixSMSubdir = 0;
				// Keep only the top-level subdirectory name
				std::vector<std::wstring> vSubdirs;
				SplitStringToVector(iterLink->sLinkRelativeSubdir, L'\\', vSubdirs);
				linkInfo.sStartMenuSubdir = vSubdirs[0];
			}
			// Add the data to the appropriate vector.
			linkInfoByLocation[ixLoc][ixSMSubdir].push_back(linkInfo);
		}
	}

	// Go through link locations in precedence order by link location
	for (size_t ixLoc = 0; ixLoc < ShellLinkDataContext_t::numLinkLocations; ++ixLoc)
	{
		// First deal with the ones in Start Menu subdirectories.
		// Group these by their top-level Start Menu subdirectory
		// New temporary map object: subdirectory name --> vector of linkInfo for links under that subdirectory.
		std::map<std::wstring, std::vector<linkInfo_t>> subdirMap;
		// and an iterator for that map
		std::map<std::wstring, std::vector<linkInfo_t>>::iterator iterSubdirMap;
		// and an iterator for the linkInfo data we're looking at
		std::vector<linkInfo_t>::const_iterator iterLI;
		// Populate this map:
		for (
			// index 0 - these are the ones that are in Start Menu subdirectories
			iterLI = linkInfoByLocation[ixLoc][0].begin();
			iterLI != linkInfoByLocation[ixLoc][0].end();
			++iterLI
			)
		{
			// Is there an entry yet for this subdirectory?
			iterSubdirMap = subdirMap.find(iterLI->sStartMenuSubdir);
			if (subdirMap.end() == iterSubdirMap)
			{
				// If not, create a new vector of linkInfo with the current entry and add it to the new map.
				std::vector<linkInfo_t> vLI;
				vLI.push_back(*iterLI);
				subdirMap[iterLI->sStartMenuSubdir] = vLI;
			}
			else
			{
				// There is an entry: add this linkInfo to its vector.
				iterSubdirMap->second.push_back(*iterLI);
			}
		}

		// Now that the map is populated, process the items in each subdirectory group.
		for (
			iterSubdirMap = subdirMap.begin();
			iterSubdirMap != subdirMap.end();
			++iterSubdirMap
			)
		{
			// If there is only one entry in this subdirectory, add it to the map using its link name
			if (1 == iterSubdirMap->second.size())
			{
				const linkInfo_t& li = iterSubdirMap->second[0];
				AddEntry(li.sPath, li.sName);
			}
			else
			{
				// Find the longest common target subdir between all the items in the group.
				// Initialize to the path in the first item
				std::wstring sCommonPath = iterSubdirMap->second[0].sPath;
				for (
					size_t ixSubdirItem = 1; // start loop with 1, not 0, because we already have the value from index 0.
					ixSubdirItem < iterSubdirMap->second.size();
					++ixSubdirItem
					)
				{
					// Find common path between previous value and current; put new common subdir back into sCommonPath
					FindCommonSubdir(sCommonPath, iterSubdirMap->second[ixSubdirItem].sPath, sCommonPath);
				}
				// If there's a common target subdir, add it to the path/app map using the Start Menu subdirectory name
				// Otherwise, add each item separately using its link name.
				if (sCommonPath.length() > 0)
				{
					AddEntry(sCommonPath, iterSubdirMap->first);
				}
				else
				{
					// No common subdirectory found: create an entry for each item in the subdirectory hierarchy.
					// Note that if there are some with common subdirectories, they might conflict and only the
					// first one will go in.
					for (
						size_t ixSubdirItem = 0;
						ixSubdirItem < iterSubdirMap->second.size();
						++ixSubdirItem
						)
					{
						const linkInfo_t& li = iterSubdirMap->second[ixSubdirItem];
						AddEntry(li.sPath, li.sName);
					}
				}
			}
		}

		// Now go through the items not in Start Menu subdirectories: top-level Start Menu items, and Desktop shortcuts.
		for (
			// Index 1 for this linkLocation are the entries not in subdirectories.
			iterLI = linkInfoByLocation[ixLoc][1].begin();
			iterLI != linkInfoByLocation[ixLoc][1].end();
			++iterLI
			)
		{
			// Just add them straight in, if something conflicting hasn't gotten there yet.
			AddEntry(iterLI->sPath, iterLI->sName);
		}
	}
}

/// <summary>
/// AddEntry is a private method intended to be called only from AddEntries. It assumes that the input
/// path has already had its pseudo-drive encoding (e.g., "PF:" replacing "C:\Program Files\").
/// The path/appname entry is added to the map only if there isn't already an entry for this path
/// or an antecedent (higher-level) path.
/// </summary>
/// <param name="sPath">Input: encoded path under which app files are found</param>
/// <param name="sAppName">Input: application name to associate with files under this path</param>
/// <returns>true if added, false if there is already an entry for this path or a parent/antecedent directory.</returns>
bool PathToAppMap::AddEntry(const std::wstring& sPath, const std::wstring& sAppName)
{
	// Add only if there's not an entry already for this path or higher up in path hierarchy
	// Get the candidate path and capitalize it
	std::wstring sCandidate(sPath);
	WString_To_Upper(sCandidate);
	while (sCandidate.length() > 0)
	{
		// If this path is already in the map, exit.
		if (this->count(sCandidate))
			return false;
		// Next, look at this directory's parent.
		sCandidate = GetDirectoryNameFromFilePath(sCandidate);
	}
	// This entry is not in the map yet. Add it (capitalized) and the app name.
	sCandidate = sPath;
	(*this)[WString_To_Upper(sCandidate)] = sAppName;
	return true;
}

/// <summary>
/// Look up an application name based on an input file path. Looks for the input file/directory,
/// then its parent directories until a match is found or can't search any further.
/// </summary>
/// <param name="sPath">Input: path to a file or directory</param>
/// <param name="sAppName">Output: application display name, if mapping found for the input path</param>
/// <returns>true if mapping found, false otherwise</returns>
bool PathToAppMap::FindEntry(const std::wstring& sPath, std::wstring& sAppName)
{
	// Initialize output
	sAppName.clear();

	// If the map has nothing in it, don't do all the work below.
	if (this->empty())
		return false;

	// Find an entry for the current entry or a parent directory (or higher)
	std::wstring sPseudoPath, sCandidate;
	// Encode the input path with pseudo-drive notation.
	PathPatternReplacement(sPath, sPseudoPath);
	sCandidate = sPseudoPath;
	// Upper-case the lookup candidate path.
	WString_To_Upper(sCandidate);
	std::map<std::wstring, std::wstring>::const_iterator iterElem;
	while (sCandidate.length() > 0)
	{
		// Is this path in the map?
		iterElem = this->find(sCandidate);
		if (iterElem != this->end())
		{
			// Yes - return the associated app name
			sAppName = iterElem->second;
			return true;
		}
		// No - next look at this path's parent directory.
		sCandidate = GetDirectoryNameFromFilePath(sCandidate);
	}

	// Lookup based on desktop and start-menu shortcuts didn't resolve.
	// Try to derive something from the pseudopath.
	// NOTE: trying to retrieve data from the file right now or access the actual path in any way could be very
	// problematic, ESPECIALLY if it's on a remote machine. This code doesn't run with the user's creds. Safest
	// just to work with the file path as given.
	std::vector<std::wstring> vDrivePath, vPathParts;
	// Split at the drive specifier
	SplitStringToVector(sPseudoPath, L':', vDrivePath);
	// Put the drive separator back on the drive spec.
	vDrivePath[0] += L':';
	// If it's in a user's Desktop or Downloads, report those
	if (szDriveUserDesktop == vDrivePath[0])
	{
		sAppName = L"[User Desktop]";
		return true;
	}
	if (szDriveUserDownloads == vDrivePath[0])
	{
		sAppName = L"[User Downloads]";
		return true;
	}
	// If it's in a user temp dir or in a user profile but outside of AppData\Local and AppData\Roaming, return false
	if (szDriveLocalAppDataTemp == vDrivePath[0] || szDriveUserProfile == vDrivePath[0])
	{
		return false;
	}
	if (vDrivePath.size() >= 2)
	{
		std::wstringstream strRetval;
		// Split at the path separators (assuming only backslash here)
		SplitStringToVector(vDrivePath[1], L'\\', vPathParts);
		// If pseudo-drive is a Microsoft one (ADLM or ADRM), the return value is "Microsoft " plus the first directory name under it
		if (szDriveLocalAppDataMicrosoft == vDrivePath[0] || szDriveRoamingAppDataMicrosoft == vDrivePath[0])
		{
			strRetval << L"Microsoft " << vPathParts[0];
		}
		else
		{
			// Top-level directory under pseudo-root is the first part of the name
			strRetval << vPathParts[0];
			// If there's at least one more directory name before the file name, pick up that directory name.
			if (vPathParts.size() > 2)
			{
				strRetval << L" " << vPathParts[1];
			}
		}
		// Clarify that this "product name" comes from the file path.
		const wchar_t* szUnder = PseudoDriveToReadable(vDrivePath[0].c_str());
		if (nullptr != szUnder)
			strRetval << L" (from path, under " << szUnder << L")";
		else
			strRetval << L" (from path)";
		sAppName = strRetval.str();
		return true;
	}

	// Couldn't build anything - return false.
	return false;
}

void PathToAppMap::AddDefaultEntries()
{
	// Hardcoded initial entries for Office
	AddEntry(L"PF:Microsoft Office", L"Microsoft Office");
	AddEntry(L"PFX86:Microsoft Office", L"Microsoft Office");
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// Internal helper functions
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

// Regular expressions to search for directory patterns to replace with pseudo-drive notation
// See InitDirPatterns() for descriptions of each
static std::wregex
	regexPublicPattern,
	regexLocalAppDataMicrosoftPattern,
	regexLocalAppDataTempPattern,
	regexLocalAppDataPattern,
	regexRoamingAppDataMicrosoftPattern,
	regexRoamingAppDataPattern,
	regexUserDownloadsPattern,
	regexUserDesktopPattern,
	regexUserProfilePattern,
	regexProgramFilesX86Pattern,
	regexProgramFilesPattern,
	regexProgramDataMicrosoftPattern,
	regexProgramDataPattern,
	regexWindowsDataPattern,
	regexRootDirPattern
	;
// Processing to be done for each regular expression pattern:
// * Prepend "^" to the pattern to match only at the beginning of a string.
// * Add a trailing backslash to the directory name
// * Escape all the backslash characters (replace \ with \\)
// * Escape all the parenthesis characters
// * Regular expression is case-insensitive
// Generally, other characters would need to be escaped in regular expressions, including [ ] { } . ^ $,
// but they are probably unlikely to be in the directory patterns we are defining here.
static inline void InitDirPatternRegex(std::wregex& reg, const std::wstring& sInput)
{
	std::wstring sTemp = std::wstring(L"^") + sInput + L"\\";
	sTemp = replaceStringAll(sTemp, L"\\", L"\\\\");
	sTemp = replaceStringAll(sTemp, L"(", L"\\(");
	sTemp = replaceStringAll(sTemp, L")", L"\\)");
	reg.assign(sTemp, std::regex_constants::icase);
}

// Initialize all the regular expressions used to map directory patterns to pseudo-drive notation.
// Note that these patterns must be searched in a specific order so that overlapping patterns such as
// AppData\Local\Microsoft and AppData\Local allow the longer match first.
static void InitDirPatterns()
{
	// Public user profile; typically C:\Users\Public
	InitDirPatternRegex(regexPublicPattern,                  WindowsDirectories::PublicUserProfileDirectory());
	// User profile's AppData\Local\Microsoft subdirectory; typically C:\Users\...\AppData\Local\Microsoft
	InitDirPatternRegex(regexLocalAppDataMicrosoftPattern,   WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::AppDataLocalSubdir() + L"\\Microsoft");
	// User profile's AppData\Local\Temp subdirectory; typically C:\Users\...\AppData\Local\Temp
	InitDirPatternRegex(regexLocalAppDataTempPattern,        WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::AppDataLocalTempSubdir());
	// User profile's AppData\Local subdirectory; typically C:\Users\...\AppData\Local
	InitDirPatternRegex(regexLocalAppDataPattern,            WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::AppDataLocalSubdir());
	// User profile's AppData\Roaming\Microsoft subdirectory; typically C:\Users\...\AppData\Roaming\Microsoft
	InitDirPatternRegex(regexRoamingAppDataMicrosoftPattern, WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::AppDataRoamingSubdir() + L"\\Microsoft");
	// User profile's AppData\Roaming subdirectory; typically C:\Users\...\AppData\Roaming
	InitDirPatternRegex(regexRoamingAppDataPattern,          WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::AppDataRoamingSubdir());
	// User profile's Downloads subdirectory; typically C:\Users\...\Downloads
	InitDirPatternRegex(regexUserDownloadsPattern,           WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::DownloadsSubdir());
	// User profile's Desktop subdirectory; typically C:\Users\...\Desktop
	InitDirPatternRegex(regexUserDesktopPattern,             WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*\\" + WindowsDirectories::DesktopSubdir());
	// User profile; e.g., C:\Users\user1
	InitDirPatternRegex(regexUserProfilePattern,             WindowsDirectories::ProfilesDirectory() + L"\\[^\\]*");
	// Typically C:\Program Files (x86)
	InitDirPatternRegex(regexProgramFilesX86Pattern,         WindowsDirectories::ProgramFilesX86());
	// Typically C:\Program Files
	InitDirPatternRegex(regexProgramFilesPattern,            WindowsDirectories::ProgramFiles());
	// Microsoft subdirectory under ProgramData; typically C:\ProgramData\Microsoft
	InitDirPatternRegex(regexProgramDataMicrosoftPattern,    WindowsDirectories::ProgramData() + L"\\Microsoft");
	// Typically C:\ProgramData
	InitDirPatternRegex(regexProgramDataPattern,             WindowsDirectories::ProgramData());
	// Typically C:\Windows
	InitDirPatternRegex(regexWindowsDataPattern,             WindowsDirectories::WindowsDirectory());
	// Typically C: -- for non-default root subdirectories
	InitDirPatternRegex(regexRootDirPattern,                 WindowsDirectories::SystemDriveDirectory());
}

/// <summary>
/// Looks for patterns in paths to replace with the pseudo-drive notation, and returns a string with that replacement.
/// </summary>
/// <param name="sInput">Input: path to transform</param>
/// <param name="sOutput">Output: transformed path</param>


// To "pin" directory searches not to go above certain points in the file system, replace
// those parts of the input path with a pseudo-drive notation.
// E.g., if input is "C:\Program Files\Contoso\Processing", the output will be "PF:Contoso\Processing".
static void PathPatternReplacement(const std::wstring& sInput, std::wstring& sOutput)
{
	// Initialize the regular expression patterns the first time through.
	static bool bInitialized = false;
	if (!bInitialized)
	{
		InitDirPatterns();
		bInitialized = true;
	}
	sOutput = sInput;

	// Replace AppLocker pseudo-environment variables with actual values, where possible.
	// Note that this is possible only with OSDRIVE and WINDIR. SYSTEM32 and PROGRAMFILES
	// are ambiguous on 64-bit Windows; HOT and REMOVABLE can refer to multiple drive letters.
	const std::wstring sOSDRIVE = L"%OSDRIVE%";
	const std::wstring sWINDIR = L"%WINDIR%";
	if (StartsWith(sOutput, sOSDRIVE, false))
	{
		// E.g., replace %OSDRIVE% with "C:" 
		sOutput = WindowsDirectories::SystemDriveDirectory() + sOutput.substr(sOSDRIVE.length());
	}
	else if (StartsWith(sOutput, sWINDIR, false))
	{
		// E.g., replace %WINDIR% with "C:\Windows"
		sOutput = WindowsDirectories::WindowsDirectory() + sOutput.substr(sWINDIR.length());
	}

	// If the input includes short-path (8.3) names (e.g., "C:\Users\User1\DOWNLO~1\FIREFO~1.EXE"), the lookup might not work.
	// If the target file still exists, get its long name. Note that: it's unreliable to try to guess at what the long name is,
	// and according to documentation for GetLongPathName, it's unreliable to assume that a short name will have a tilde character.
	// So, just go ahead and try to convert the name we've got to a long name. If it succeeds, use it; otherwise just continue
	// using the name we've got.
	// Define separate scope for these variables so they don't accidentally get used later.
	{	
		const DWORD dwLongNameLength = MAX_PATH * 2;
		wchar_t* pszLongName = new wchar_t[dwLongNameLength];
		if (GetLongPathNameW(sOutput.c_str(), pszLongName, dwLongNameLength))
		{
			sOutput = pszLongName;
		}
		delete[] pszLongName;
	}

	// Note that these patterns must be replaced in a specific order so that overlapping patterns such as
	// AppData\Local\Microsoft and AppData\Local allow the longer match first.
	sOutput = std::regex_replace(sOutput, regexPublicPattern,                  szDrivePublic);
	sOutput = std::regex_replace(sOutput, regexLocalAppDataMicrosoftPattern,   szDriveLocalAppDataMicrosoft);
	sOutput = std::regex_replace(sOutput, regexLocalAppDataTempPattern,        szDriveLocalAppDataTemp);
	sOutput = std::regex_replace(sOutput, regexLocalAppDataPattern,            szDriveLocalAppData);
	sOutput = std::regex_replace(sOutput, regexRoamingAppDataMicrosoftPattern, szDriveRoamingAppDataMicrosoft);
	sOutput = std::regex_replace(sOutput, regexRoamingAppDataPattern,          szDriveRoamingAppData);
	sOutput = std::regex_replace(sOutput, regexUserDownloadsPattern,           szDriveUserDownloads);
	sOutput = std::regex_replace(sOutput, regexUserDesktopPattern,             szDriveUserDesktop);
	sOutput = std::regex_replace(sOutput, regexUserProfilePattern,             szDriveUserProfile);
	sOutput = std::regex_replace(sOutput, regexProgramFilesX86Pattern,         szDriveProgramFilesX86);
	sOutput = std::regex_replace(sOutput, regexProgramFilesPattern,            szDriveProgramFiles);
	sOutput = std::regex_replace(sOutput, regexProgramDataMicrosoftPattern,    szDriveProgramDataMicrosoft);
	sOutput = std::regex_replace(sOutput, regexProgramDataPattern,             szDriveProgramData);
	sOutput = std::regex_replace(sOutput, regexWindowsDataPattern,             szDriveWindowsData);
	sOutput = std::regex_replace(sOutput, regexRootDirPattern,                 szDriveRootDir);
}


/// <summary>
/// Returns the longest common subdirectory between two input paths.
/// The output parameter can also refer to the same string as one of the input parameters.
/// The inputs are EXPECTED to have the pseudo-drive notation applied prior to input.
/// </summary>
/// <param name="sPath1">Input: first path to compare</param>
/// <param name="sPath2">Input: second path to compare</param>
/// <param name="sCommonPath">Output: the longest common path between the two, or an empty string if no common path found.</param>
/// <returns>true if common subdirectory found, false otherwise</returns>
static bool FindCommonSubdir(const std::wstring& sPath1, const std::wstring& sPath2, std::wstring& sCommonPath)
{
	// Split the two inputs on backslash characters. As the input paths EXPECTED to have pseudo-drive 
	// notation applied (e.g., "ADLM:WebEx\WebEx\Application"), the first split part will have both the 
	// pseudo-drive and the first subdirectory.
	// If the first elements don't match, there's no common subdirectory.

	// vPath1, vPath2: directory parts for the two paths:
	std::vector<std::wstring> vPath1, vPath2;
	SplitStringToVector(sPath1, L'\\', vPath1);
	SplitStringToVector(sPath2, L'\\', vPath2);
	// Get the lengths of the two vectors - number of subdirectory pieces
	size_t nPath1 = vPath1.size();
	size_t nPath2 = vPath2.size();
	// String length of the common/matching parts
	size_t nLength = 0;
	for (size_t ixPart = 0; ixPart < nPath1 && ixPart < nPath2; ++ixPart)
	{
		// Case-insensitive compare of the current directory parts
		if (EqualCaseInsensitive(vPath1[ixPart], vPath2[ixPart]))
		{
			// Add length of the matched part, plus one for the subsequent path separator.
			nLength += vPath1[ixPart].length() + 1;
		}
		else
		{
			// Didn't match - exit the loop
			break;
		}
	}
	// If anything matched, return the matching substring
	if (nLength > 0)
	{
		// "nLength - 1" to remove the last trailing path separator we added.
		sCommonPath = sPath1.substr(0, nLength - 1);
		return true;
	}
	else
	{
		// No match; clear the output.
		sCommonPath.clear();
		return false;
	}
}
