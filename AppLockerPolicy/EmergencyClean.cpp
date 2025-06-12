#include "pch.h"

// Have to do this to get the shellapi functions
#define WINVER 0x0500
#include <Windows.h>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "EmergencyClean.h"


// Helper function that gets information about a file or directory and adds it to fileInfoCollection.
static void AddFSObjectToCollection(const std::wstring& sObjName, bool bIsDirectory, FileInfoCollection_t& fileInfoCollection)
{
	FileInfo_t fileInfo;
	fileInfo.bIsDirectory = bIsDirectory;
	fileInfo.sFullPath = sObjName;

	DWORD dwFlags = (bIsDirectory ? FILE_FLAG_BACKUP_SEMANTICS : 0);
	Wow64FsRedirection wow64FSRedir(true);
	HANDLE hFile = CreateFileW(sObjName.c_str(), 0, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, dwFlags, NULL);
	wow64FSRedir.Revert();
	if (INVALID_HANDLE_VALUE != hFile)
	{
		FILETIME ftCreateTime, ftLastAccessTime, ftLastWriteTime;
		if (GetFileTime(hFile, &ftCreateTime, &ftLastAccessTime, &ftLastWriteTime))
		{
			fileInfo.sCreateTime = FileTimeToWString(ftCreateTime);
			fileInfo.sLastWriteTime = FileTimeToWString(ftLastWriteTime);
		}
		if (!bIsDirectory)
		{
			GetFileSizeEx(hFile, &fileInfo.filesize);
		}
		CloseHandle(hFile);
	}
	fileInfoCollection.push_back(fileInfo);
}

// Populates a FileInfoCollection_t with information about all files/directories under a directory.
static bool RecursiveFileList(const std::wstring& sDirectory, FileInfoCollection_t& fileInfoCollection)
{
	DirWalker dirWalker;
	std::wstringstream strErrorInfo;
	if (!dirWalker.Initialize(sDirectory.c_str(), strErrorInfo))
		return false;

	std::wstring sCurrDir;
	while (dirWalker.GetCurrent(sCurrDir))
	{
		// Add the current directory to the collection
		AddFSObjectToCollection(sCurrDir, true, fileInfoCollection);

		// Add all the files in the current directory to the collection
		std::vector<std::wstring> files, subdirectories;
		if (GetFiles(sCurrDir, files, false))
		{
			for (
				std::vector<std::wstring>::const_iterator iterFiles = files.begin();
				iterFiles != files.end();
				++iterFiles
				)
			{
				AddFSObjectToCollection(*iterFiles, false, fileInfoCollection);
			}
		}

		dirWalker.DoneWithCurrent();
	}

	return true;
}

/// <summary>
/// Returns a listing of all files/directories under System32\AppLocker.
/// </summary>
/// <param name="fileInfoCollection">Output: the collection object to populate with file/directory information</param>
/// <returns></returns>
bool EmergencyClean::ListAppLockerBinaryFiles(FileInfoCollection_t& fileInfoCollection)
{
	fileInfoCollection.clear();
	const std::wstring sRootDir = WindowsDirectories::System32Directory() + L"\\AppLocker";
	return RecursiveFileList(sRootDir, fileInfoCollection);
}

bool EmergencyClean::DeleteAppLockerBinaryFiles()
{
	//TODO: consider reimplementing and not deleting AppCache.dat, AppCache.dat.LOG1, AppCache.dat.LOG2. (Does this matter? Would this be better?)
	SHFILEOPSTRUCTW fileop = { 0 };
	// Ensure that the path is double-NUL-terminated
	wchar_t szPathSpec[MAX_PATH] = { 0 };
	const std::wstring sRootDir = WindowsDirectories::System32Directory() + L"\\AppLocker\\*";
	wcscpy_s(szPathSpec, sRootDir.c_str());
	fileop.pFrom = szPathSpec;
	fileop.wFunc = FO_DELETE;
	fileop.fFlags = FOF_NO_UI;
	Wow64FsRedirection wow64FSRedir(true);
	int shfoRet = SHFileOperationW(&fileop);
	return (0 == shfoRet && FALSE == fileop.fAnyOperationsAborted);
}
