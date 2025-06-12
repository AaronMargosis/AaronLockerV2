#pragma once

#include <string>
#include <vector>

/// <summary>
/// File information to report
/// </summary>
struct FileInfo_t
{
	std::wstring sFullPath, sLastWriteTime, sCreateTime;
	LARGE_INTEGER filesize;
	bool bIsDirectory;

	FileInfo_t() : bIsDirectory(false)
	{
		filesize = { 0 };
	}
};
typedef std::vector<FileInfo_t> FileInfoCollection_t;


// As a last resort, it might be necessary to clear the contents of the directory
// containing the files containing effective AppLocker policy, under
// C:\Windows\System32\AppLocker. Sometimes files remain when there's no
// Group Policy or CSP/MDM policies behind them.


/// <summary>
/// AppLocker's actual policy cache is in binary files in System32\AppLocker. 
/// Sometimes (it seems) policy artifacts end up in these files and are out of sync
/// with LGPO and CSP/MDM, and configuration via LGPO or CSP/MDM fails to override or
/// replace this content. As a VERY LAST RESORT, policy can be removed by
/// deleting the files in this directory.
/// This class provides visibility into the content of that directory, and
/// the ability to remove it.
/// </summary>
class EmergencyClean
{
public:
	/// <summary>
	/// Returns a listing of all files/directories under System32\AppLocker.
	/// </summary>
	/// <param name="fileInfoCollection">Output: the collection object to populate with file/directory information</param>
	/// <returns></returns>
	static bool ListAppLockerBinaryFiles(FileInfoCollection_t& fileInfoCollection);

	/// <summary>
	/// Delete all files and directories under System32\AppLocker.
	/// </summary>
	/// <returns>true if successful, false otherwise</returns>
	static bool DeleteAppLockerBinaryFiles();
};

