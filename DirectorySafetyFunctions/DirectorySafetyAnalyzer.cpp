#include "pch.h"
#include <UserEnv.h>
#pragma comment(lib, "Userenv.lib")
#include "SecurityDescriptorAnalyzer.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "DirectorySafetyAnalyzer.h"


// ------------------------------------------------------------------------------------------

// Get the user profile root directory path one time.
const wchar_t* szUserProfileRootDir()
{
	static wchar_t st_userprofilepath[MAX_PATH*2] = { 0 };
	if (L'\0' == st_userprofilepath[0])
	{
		DWORD cchSize = sizeof(st_userprofilepath) / sizeof(st_userprofilepath[0]);
		GetProfilesDirectoryW(st_userprofilepath, &cchSize);
	}
	return st_userprofilepath;
}

const wchar_t* szBS = L"\\";
// Typically "C:\Users"
const std::wstring sUserProfile = szUserProfileRootDir();
// Typically "C:\Users\"
const std::wstring sUserProfileBS = sUserProfile + szBS;
// Length to compare
const size_t sUserProfileBSLen = sUserProfileBS.size();

// Returns true if the input file system path is equal to or begins with the special case 
// directories.
// Look for equality to the directory names or begins with the directory name plus backslash
// separator.
bool MatchesSpecialCases(const wchar_t* szFileSystemPath)
{
	// Verify that it's not a NULL pointer
	if (!szFileSystemPath)
		return false;
	return (
		// is user profile directory, or
		0 == StringCompareCaseInsensitive(szFileSystemPath, sUserProfile.c_str()) ||
		// is under user profile directory, or
		0 == StringCompareNumberedCaseInsensitive(szFileSystemPath, sUserProfileBS.c_str(), sUserProfileBSLen)
		);
}

// ------------------------------------------------------------------------------------------
/// Inspects a file system object's security descriptor and determines whether any non-admin entities 
/// are granted write permissions to the object.
/// Intended primarily for directories but can also be used for files.
/// Takes special cases into account -- such as root directory of user profile directories
/// (e.g., "C:\Users") -- treating them as always unsafe.
/// NOTE: this function does not disable file system redirection if executed in WOW64. (InspectDirectoryHierarchySafety does.)
bool DirectorySafetyAnalyzer::InspectDirectorySafety(
	const wchar_t* szFileSystemPath, 
	const SidsToFilter& sidsToFilter, 
	bool& bIsNonadminWritable, 
	bool& bNeedsAltDataStreamExclusion, 
	std::vector<CSid>& nonadminSids, 
	std::wstring& sErrorInfo)
{
	// Initialize return value and output parameters
	bool retval;
	bIsNonadminWritable = false;
	bNeedsAltDataStreamExclusion = false;
	nonadminSids.clear();
	sErrorInfo.clear();

	// If one of the special-case directories, treat it as unsafe.
	if (MatchesSpecialCases(szFileSystemPath))
	{
		bIsNonadminWritable = bNeedsAltDataStreamExclusion = true;
		// Put a BUILTIN\Users SID into the list, just so it's not empty.
		nonadminSids.push_back(CSid(SidString::BuiltinUsers));
		//sErrorInfo = L"Directory is special-cased.";
		retval = true;
	}
	else
	{
		// Inspect the directory's security descriptor
		retval = SecurityDescriptorAnalyzer::IsNonadminWritable(
			szFileSystemPath,
			sidsToFilter,
			bIsNonadminWritable,
			bNeedsAltDataStreamExclusion,
			nonadminSids,
			sErrorInfo);
	}
	return retval;
}

// ------------------------------------------------------------------------------------------


// ------------------------------------------------------------------------------------------
/// <summary>
/// Entry point for recursive inspection of directory hierarchy for "unsafe" directories.
/// Disables file system redirection when executed in WOW64.
/// </summary>
/// <param name="szFileSystemPath"></param>
/// <param name="bRecurseIntoUnsafeDirectories"></param>
/// <param name="sidsToFilter"></param>
/// <param name="unsafeDirectoryInfo"></param>
/// <param name="strErrorInfo"></param>
/// <returns></returns>
bool DirectorySafetyAnalyzer::InspectDirectoryHierarchySafety(
	const wchar_t* szFileSystemPath,
	bool bRecurseIntoUnsafeDirectories,
	const SidsToFilter& sidsToFilter,
	UnsafeDirectoryCollection_t& unsafeDirectoryInfo,
	std::wstringstream& strErrorInfo)
{
	if (NULL == szFileSystemPath)
		return false;

	// Output parameters are appended to, so don't initialize their values.

	// Disable WOW64 file system redirection for the duration of this function.
	// Reverts to previous state when this variable goes out of scope.
	Wow64FsRedirection fsredir(true);

	DirWalker dirWalker;
	if (!dirWalker.Initialize(szFileSystemPath, strErrorInfo))
		return false;

	std::wstring sCurrDir;
	while (dirWalker.GetCurrent(sCurrDir))
	{
		// TBD whether we need to inspect the current directory's subdirectories
		bool bInspectCurrDirSubdirectories = false;

		// Inspect the current directory's security descriptor
		bool bIsNonadminWritable, bNeedsAltDataStreamExclusion;
		std::vector<CSid> nonadminSids;
		std::wstring sErrorInfo;
		bool ret = InspectDirectorySafety(
			sCurrDir.c_str(),
			sidsToFilter,
			bIsNonadminWritable,
			bNeedsAltDataStreamExclusion,
			nonadminSids,
			sErrorInfo);
		if (ret)
		{
			// If the directory is nonadmin-writable ("unsafe"), add it to the unsafeDirectoryInfo collection.
			if (bIsNonadminWritable)
			{
				// Convert the CSids into a string. Convert local accounts to names. Leave others as SIDs.
				std::wstringstream strNonadminSids;
				for (
					std::vector<CSid>::const_iterator iterSids = nonadminSids.begin();
					iterSids != nonadminSids.end();
					++iterSids
					)
				{
					if (iterSids->IsMachineLocal())
						strNonadminSids << iterSids->toDomainAndUsername() << L"; ";
					else
						strNonadminSids << iterSids->toSidString() << L"; ";
				}

				unsafeDirectoryInfo.push_back(
					UnsafeDirectoryInfo_t(sCurrDir, bNeedsAltDataStreamExclusion, strNonadminSids.str())
				);
			}
			// If any error text returned, add a line to the wstringstream.
			if (sErrorInfo.size() > 0)
			{
				strErrorInfo << sCurrDir << L": " << sErrorInfo << std::endl;
			}

			// Continue recursing if this is a "safe" directory or if bRecurseIntoUnsafeDirectories says to continue anyway.
			// Don't recurse if InspectDirectorySafety failed.
			bInspectCurrDirSubdirectories = (!bIsNonadminWritable || bRecurseIntoUnsafeDirectories);
		}
		else
		{
			strErrorInfo << sCurrDir << L": " << sErrorInfo << std::endl;
		}

		dirWalker.DoneWithCurrent(bInspectCurrDirSubdirectories);
	}

	return true;
}
