#include "pch.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "EndpointScan_Base.h"

EndpointScan_Base::EndpointScan_Base(const SidsToFilter& sidsToFilter)
	: m_sidsToFilter(sidsToFilter),
	  m_bFavorProvidedAppLabel(false)
{
	m_StartTime = { 0 };
	m_EndTime = { 0 };
}

EndpointScan_Base::~EndpointScan_Base()
{
}

/// <summary>
/// Inspects a directory hierarchy for nonadmin-writable directories.
/// Note that this function disables 64-bit file system redirection.
/// </summary>
/// <param name="szRootDirectory">Input: file system root directory to inspect</param>
/// <param name="sidsToFilter">Input: admin/equivalent SIDs in security descriptor to ignore</param>
/// <param name="unsafeDirectoryInfo">Output (appended): collection of UnsafeDirectoryInfo_t objects for any identified unsafe directories. (Appended, not cleared first.)</param>
/// <param name="strErrorInfo">Output (appended): textual information about any errors encountered. (Appended, not cleared first.)</param>
/// <returns>true if inspection succeeds; false otherwise.</returns>
bool EndpointScan_Base::ScanDirectoryHierarchyForUnsafeSubdirs(const wchar_t* szRootDirectory, const SidsToFilter& sidsToFilter, UnsafeDirectoryCollection_t& unsafeDirectoryInfo, std::wstringstream& strErrorInfo)
{
	bool retval = DirectorySafetyAnalyzer::InspectDirectoryHierarchySafety(
		szRootDirectory,
		false,
		sidsToFilter,
		unsafeDirectoryInfo,
		strErrorInfo
	);
	return retval;
}

/// <summary>
/// Internal helper function to determine whether a file path is in a safe or unsafe directory.
/// Perform the detailed check at most one time per directory, and when needed for a file in the directory.
/// </summary>
/// <param name="sFilepath">Input: file path to inspect</param>
/// <param name="pvUnsafeDirectoryInfo">Pointer to collection of info about unsafe directories; NULL means unsafe</param>
/// <returns>true if safe directory, false otherwise</returns>
inline bool IsThisDirectorySafe(const std::wstring& sFilepath, UnsafeDirectoryCollection_t* pvUnsafeDirectoryInfo)
{
	// NULL pointer for the collection means unsafe directory
	if (NULL == pvUnsafeDirectoryInfo)
		return false;
	// Empty collection means safe directory
	else if (0 == pvUnsafeDirectoryInfo->size())
		return true;
	else
	{
		// Iterate through the collection, and see whether the file path begins with one of the unsafe directory paths.
		UnsafeDirectoryCollection_t::const_iterator iter;
		for (
			iter = pvUnsafeDirectoryInfo->begin();
			iter != pvUnsafeDirectoryInfo->end();
			++iter
			)
		{
			// Unsafe directory followed by backslash
			// (Can't do a starts-with comparison against the file path without the backslash delimiter.
			// E.g., if I have unsafe dir "C:\Temp" and the file path is "C:\Tempest\file.exe", the file
			// path does start with the unsafe dir name, but that's not a correct comparison.
			std::wstring sUnsafeDir = iter->m_sFileSystemPath + L"\\";
			if (0 == StringCompareNumberedCaseInsensitive(sFilepath.c_str(), sUnsafeDir.c_str(), sUnsafeDir.length()))
			{
				// File path starts with an unsafe directory (with a backslash)
				return false;
			}
		}
		// Didn't match any of the unsafe directories. Safe directory.
		return true;
	}
}


/// <summary>
/// Look for files in and under szRootDirectory for AppLocker-relevant files and add their details to the FileDetails collection.
/// </summary>
/// <param name="szRootDirectory">Directory to begin searching in</param>
/// <param name="szAppLabel">App label to associate with the files</param>
/// <param name="pvUnsafeDirectoryInfo">Collection of known unsafe subdirectories.
/// If NULL, assumed that all subdirectories are unsafe.
/// If empty list, assumed that all subdirectories are safe.</param>
/// <param name="strErrorInfo">Output (appended): textual information about any errors encountered. (Appended, not cleared first.)</param>
void EndpointScan_Base::ScanDirectoryHierarchyForAppLockerRelevantFiles(const wchar_t* szRootDirectory, const wchar_t* szAppLabel, UnsafeDirectoryCollection_t* pvUnsafeDirectoryInfo, std::wstringstream& strErrorInfo)
{
	DirWalker dirWalker;
	if (!dirWalker.Initialize(szRootDirectory, strErrorInfo))
		return;

	std::wstring sCurrDir;
	while (dirWalker.GetCurrent(sCurrDir))
	{
		// Inspect all the files in this directory
		std::vector<std::wstring> files;
		if (GetFiles(sCurrDir, files))
		{
			// Inspect current directory's safety only if it contains files to inspect. Don't spend the cycles otherwise.
			bool bIsSafeDir = false;
			if (files.size() > 0)
			{
				// Test directory safety using first file in the files collection. Makes the comparison against the
				// unsafe-directory collection a little easier, as it will always have a backslash after the directory
				// name. (See comments in IsThisDirectorySafe for explanation.)
				bIsSafeDir = IsThisDirectorySafe(files[0], pvUnsafeDirectoryInfo);
			}

			std::vector<std::wstring>::const_iterator iterFiles;
			for (
				iterFiles = files.begin();
				iterFiles != files.end();
				++iterFiles
				)
			{
				ScanOneFile(*iterFiles, szAppLabel, bIsSafeDir, strErrorInfo);
			}
		}

		dirWalker.DoneWithCurrent();
	}
}

void EndpointScan_Base::ScanOneFile(const std::wstring& sFilePath, const wchar_t* szAppLabel, bool bIsSafeDirectory, std::wstringstream& strErrorInfo)
{
	// Make sure szAppLabel isn't a NULL pointer.
	if (NULL == szAppLabel)
		szAppLabel = L"";
	// Determine whether the file is AppLocker-relevant and fully present (not needing download)
	const wchar_t* szFilePath = sFilePath.c_str();
	AppLockerFileDetails alfd(szFilePath);
	// Don't try to inspect file content if doing so would require downloading
	if (alfd.FileExistsFullyPresent())
	{
		PEFileInfo peFileInfo;
		DWORD dwFileApiError;
		AppLockerFileDetails_ftype_t ftype = alfd.GetFileType(peFileInfo, true, dwFileApiError);
		bool bAddThisFile = false;
		switch (ftype)
		{
			// AppLocker-relevant file types
		case AppLockerFileDetails_ftype_t::ft_EXE:
		case AppLockerFileDetails_ftype_t::ft_DLL:
		case AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL:
		case AppLockerFileDetails_ftype_t::ft_MSI:
		case AppLockerFileDetails_ftype_t::ft_Script:
			bAddThisFile = true;
			break;

			// See whether "unknown" because we couldn't inspect content.
		case AppLockerFileDetails_ftype_t::ft_Unknown:
			if (0 != dwFileApiError)
			{
				strErrorInfo << L"Couldn't inspect " << szFilePath << L": " << SysErrorMessage(dwFileApiError) << std::endl;
			}
			break;

			// Do nothing with files of these types
		case AppLockerFileDetails_ftype_t::ft_KnownNonCodeExtension:
		case AppLockerFileDetails_ftype_t::ft_ScriptJS:
		case AppLockerFileDetails_ftype_t::ft_Appx:
		default:
			break;
		}

		if (bAddThisFile)
		{
			// Prepare a file-details structure about this file
			// See FileDetails_t declaration for documentation about all its attributes
			FileDetails_t fileDetails;

			AppLockerFileInformation alfi(szFilePath);
			// GetHash256Info returns the filename portion of the file path to include in an AppLocker rule.
			// Ignoring what it returns because we can reconstitute it again later from the full path.
			std::wstring sFilenameIgnored;
			DWORD dwApiError = 0;
			// If we can't get the hash for any reason, don't continue (e.g., zero-length file)
			bAddThisFile = alfi.GetHash256Info(fileDetails.m_ALHash, fileDetails.m_FlatFileHash, sFilenameIgnored, fileDetails.m_fileSize, dwApiError);
			if (bAddThisFile)
			{
				// If an app label is provided and favored, use it as the app label.
				// Otherwise, favor a path-to-appname mapping if one is available.
				if (m_bFavorProvidedAppLabel && *szAppLabel)
				{
					fileDetails.m_sAppLabel = szAppLabel;
				}
				else
				{
					std::wstring sAppName;
					if (m_PathToAppMap.FindEntry(sFilePath, sAppName))
						fileDetails.m_sAppLabel = sAppName;
					else
						fileDetails.m_sAppLabel = szAppLabel;
				}
				fileDetails.m_bIsSafeDir = bIsSafeDirectory;
				fileDetails.m_fileType = ftype;
				fileDetails.m_sFilePath = sFilePath;
				if (peFileInfo.m_bIsPEFile)
				{
					fileDetails.m_PEImageFileMachineType = peFileInfo.ImageFileMachineString();
				}
				if (AppLockerFileDetails_ftype_t::ft_MSI != ftype)
				{
					// Using this instead of szFilePath gets the extended-path name if needed.
					VersionInfo vi(alfi.FileDetails().FilePath().c_str());
					fileDetails.m_sVerProductName = vi.ProductName();
					fileDetails.m_sVerFileDescription = vi.FileDescription();
					alfi.GetPublisherInfo(fileDetails.m_ALPublisherName, fileDetails.m_ALProductName, fileDetails.m_ALBinaryName, fileDetails.m_ALBinaryVersion, fileDetails.m_sX500CertSigner, fileDetails.m_sSigningTimestamp, dwApiError);
					peFileInfo.LinkTimestamp(fileDetails.m_sPEFileLinkDate);
				}
				else
				{
					MsiFileInfo_t msiFileInfo;
					bool gpiRet = alfi.GetPublisherInfo(fileDetails.m_ALPublisherName, fileDetails.m_sX500CertSigner, fileDetails.m_sSigningTimestamp, msiFileInfo, dwApiError);
					fileDetails.m_sVerProductName = msiFileInfo.sProductName;
					if (gpiRet)
					{
						fileDetails.m_ALProductName = msiFileInfo.sALProductName;
						fileDetails.m_ALBinaryName = msiFileInfo.sALBinaryName;
						fileDetails.m_ALBinaryVersion = msiFileInfo.sALBinaryVersion;
					}
				}
				std::wstring sAltName;
				HANDLE hFile = OpenExistingFile_ExtendedPath(szFilePath, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, dwApiError, sAltName);
				if (INVALID_HANDLE_VALUE != hFile)
				{
					// Visual Studio compiler keeps reporting warning C6001 "Using uninitialized memory '*hFile'" 
					// for the GetFileTime call on the next line. I have no idea why. hFile is *always* assigned 
					// the return value of CreateFileW before it gets here. Reported VS bug to Microsoft Jan 3 2021.
					FILETIME ftCreateTime, ftLastAccessTime, ftLastWriteTime; // Last-access-time is useless to us.
					if (GetFileTime(hFile, &ftCreateTime, &ftLastAccessTime, &ftLastWriteTime))
					{
						fileDetails.m_ftCreateTime = FileTimeToWString(ftCreateTime);
						fileDetails.m_ftLastWriteTime = FileTimeToWString(ftLastWriteTime);
					}
					CloseHandle(hFile);
				}
				// Add the file details to the results collection
				m_FileDetails.push_back(fileDetails);
			}

			if (0 != dwApiError)
			{
				strErrorInfo << L"Error inspecting " << szFilePath << L": " << SysErrorMessageWithCode(dwApiError) << std::endl;
			}
		}
	}
}

bool EndpointScan_Base::ScanForShellLinks(std::wstringstream& strErrorInfo)
{
	std::wstring sErrorInfo;
	bool retval = m_linkScanner.PerformFullScan(sErrorInfo);
	if (sErrorInfo.length() > 0)
		strErrorInfo << sErrorInfo;
	return retval;
}

void EndpointScan_Base::InitializePathToAppMap(const ShellLinkDataContextCollection_t& shellLinks)
{
	m_PathToAppMap.AddEntries(shellLinks);
}
