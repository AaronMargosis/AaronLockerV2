#include "pch.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "EndpointOneDirectoryScan.h"

EndpointOneDirectoryScan::EndpointOneDirectoryScan(const SidsToFilter& sidsToFilter)
	: EndpointScan_Base(sidsToFilter)
{
	// App label provided in a one-directory scan takes precedence over derived labels.
	m_bFavorProvidedAppLabel = true;
}

EndpointOneDirectoryScan::~EndpointOneDirectoryScan()
{
}

bool EndpointOneDirectoryScan::ScanDirectory(
	const wchar_t* szFileOrDirectoryPath,
	const wchar_t* szAppLabel)
{
	std::wstringstream strErrorInfo;
	ScanStarted();
	bool retval = ScanDirectory_Impl(szFileOrDirectoryPath, szAppLabel, strErrorInfo);
	// Shell-link scan won't be needed for single-directory scans, but leave it in for now to get more data to improve path-to-appname mapping.
	if (retval)
		retval = ScanForShellLinks(strErrorInfo);
	ScanEnded();
	m_sErrorInfo = strErrorInfo.str();
	return retval;
}

bool EndpointOneDirectoryScan::ScanDirectory_Impl(
	const wchar_t* szFileOrDirectoryPath,
	const wchar_t* szAppLabel,
	std::wstringstream& strErrorInfo)
{
	// Note: do not initialize the results collection. 
	// This function can be called multiple times to accumulate results.

	// Basic check -- if input is NULL or empty, just exit.
	if (!szFileOrDirectoryPath || !*szFileOrDirectoryPath)
		return false;

	// Make sure app label isn't a null pointer.
	if (!szAppLabel)
		szAppLabel = L"";

	// Initialize return value
	bool retval = false;

	// Option to scan just a single file instead of an entire directory hierarchy
	bool bScanOneFile = false;

	std::wstring 
		sFileOrDirectoryPath(szFileOrDirectoryPath),
		sFilePath,
		sDirectoryPath;

	//Replace %OSDRIVE% or %WINDIR% in the input if found.
	const std::wstring sOSDRIVE = L"%OSDRIVE%";
	const std::wstring sWINDIR = L"%WINDIR%";
	if (StartsWith(sFileOrDirectoryPath, sOSDRIVE, false))
	{
		// E.g., replace %OSDRIVE% with "C:" 
		sFileOrDirectoryPath = WindowsDirectories::SystemDriveDirectory() + sFileOrDirectoryPath.substr(sOSDRIVE.length());
	}
	else if (StartsWith(sFileOrDirectoryPath, sWINDIR, false))
	{
		// E.g., replace %WINDIR% with "C:\Windows"
		sFileOrDirectoryPath = WindowsDirectories::WindowsDirectory() + sFileOrDirectoryPath.substr(sWINDIR.length());
	}

	// Reject the path if it still starts with %
	// AppLocker's use of %PROGRAMFILES% and %SYSTEM32% are ambiguous on 64-bit Windows:
	// %PROGRAMFILES% can refer to PF or PFx86; %SYSTEM32% can refer to System32 or SysWOW64.
	// %REMOVABLE% and %HOT% could be any drive, or user-specific environment variables.
	if (L'%' == sFileOrDirectoryPath[0])
	{
		strErrorInfo << L"Cannot process this path: " << sFileOrDirectoryPath << std::endl;
		goto AllDone;
	}
	
	{ // Create a scope in which to define and use dwFileAttributes, rather than declare it up top.

		//Verify that the file system object exists.
		DWORD dwLastError;
		std::wstring sAltName;
		DWORD dwFileAttributes = GetFileAttributes_ExtendedPath(sFileOrDirectoryPath.c_str(), dwLastError, sAltName);
		if (INVALID_FILE_ATTRIBUTES == dwFileAttributes)
		{
			strErrorInfo << sFileOrDirectoryPath << L": " << SysErrorMessage(dwLastError) << std::endl;
			goto AllDone;
		}

		// Get the directory by itself; also the full file path if the input is a file.
		if (0 == (FILE_ATTRIBUTE_DIRECTORY & dwFileAttributes))
		{
			sFilePath = sFileOrDirectoryPath;
			sDirectoryPath = GetDirectoryNameFromFilePath(sFileOrDirectoryPath);
		}
		else
		{
			sFilePath.clear();
			sDirectoryPath = sFileOrDirectoryPath;
		}
	}

	// One-file scan if input is an existing file, and:
	// * is a .msi file (anywhere)
	// * is in a user's Desktop or Downloads directory.

	// If the input is a file, see whether it's an MSI. One-file scan if it is.
	if (sFilePath.length() > 0)
	{
		AppLockerFileDetails alfd(sFilePath.c_str());
		AppLockerFileDetails_ftype_t ftype = alfd.GetFileTypeBasedOnExtension();
		if (AppLockerFileDetails_ftype_t::ft_MSI == ftype)
		{
			bScanOneFile = true;
		}
	}

	// Do not scan a Desktop or Downloads directory directly, but it's OK to scan a subdirectory.
	// Reason: if the purpose is to allow a specific app in that directory, we're likely to pick up a bunch of other
	// unrelated files in that directory. We don't want to create rules inadvertently for everything the user might have downloaded.
	// Also: disallow scanning an entire user profile.
	// Consider implementing: Public Desktop is a safe directory; could allow an exception for it. Hopefully that's unlikely ever
	// to be needed, though. Usually there's a shortcut on the desktop to a file under Program Files.
	// (No need to perform this check if already performing a one-file scan.) 
	if (!bScanOneFile)
	{
		// If the directory is under a user profile (e.g., under "C:\Users\"), ...
		// sProfilesDirBS is "profiles directory plus backslash"...
		const std::wstring sProfilesDirBS = WindowsDirectories::ProfilesDirectory() + L"\\";
		if (StartsWith(sDirectoryPath, sProfilesDirBS, false))
		{
			// Get the file path parts after the profile root; e.g., after "C:\Users\".
			// User profile name will be in element 0.
			std::vector<std::wstring> vFilePathParts;
			SplitStringToVector(sDirectoryPath.substr(sProfilesDirBS.length()), L'\\', vFilePathParts);

			// Disallow scanning an entire user profile.
			if (vFilePathParts.size() < 2)
			{
				strErrorInfo << L"Directory is too broad to search: " << sDirectoryPath << std::endl;
				goto AllDone;
			}

			if (vFilePathParts.size() == 2)
			{
				// The directory path is a direct subdirectory of the user profile.
				// The subdirectory name is in element 1.
				// See whether it's the Desktop or Downloads subdirectory.
				if (
					EqualCaseInsensitive(WindowsDirectories::DesktopSubdir(), vFilePathParts[1]) ||
					EqualCaseInsensitive(WindowsDirectories::DownloadsSubdir(), vFilePathParts[1])
					)
				{
					// If input is a file, make this a one-file scan instead of a directory scan
					if (sFilePath.length() > 0)
					{
						bScanOneFile = true;
					}
					else
					{
						// If input was just a Desktop or Downloads directory, disallow
						strErrorInfo << L"Not a good place to scan for apps: " << sDirectoryPath << std::endl;
						goto AllDone;
					}
				}
			}
		}
	}

	// Reject the input path for a directory-hierarchy search if it's SystemDrive, SystemDrive\, the user profile root directory, 
	// the PF directories, or anywhere under the Windows directory.
	if (!bScanOneFile)
	{
		if (
			// E.g., directory is "C:"
			EqualCaseInsensitive(sDirectoryPath, WindowsDirectories::SystemDriveDirectory()) ||
			// E.g., directory is "C:\"
			EqualCaseInsensitive(sDirectoryPath, WindowsDirectories::SystemDriveDirectory() + L"\\") ||
			// E.g., directory is "C:\Users"
			EqualCaseInsensitive(sDirectoryPath, WindowsDirectories::ProfilesDirectory()) ||
			// E.g., path is "C:\Windows" or under it
			PathStartsWithDirectory(sDirectoryPath, WindowsDirectories::WindowsDirectory()) ||
			// E.g., path is "C:\Program Files"
			EqualCaseInsensitive(sDirectoryPath, WindowsDirectories::ProgramFiles()) ||
			// E.g., "C:\Program Files (x86)" exists and path equals that
			(WindowsDirectories::ProgramFilesX86().length() > 0 && EqualCaseInsensitive(sDirectoryPath, WindowsDirectories::ProgramFilesX86()))
			)
		{
			strErrorInfo << L"Directory is too broad to search or is an invalid location for this tool: " << sDirectoryPath << std::endl;
			goto AllDone;
		}
	}

	if (bScanOneFile)
	{
		// For a one-file scan, assume it's in an unsafe directory, since we're not going to inspect the directory
		// hierarchy. One-file scan shouldn't result in a path rule - only a publisher or a hash rule.
		ScanOneFile(sFilePath, szAppLabel, false, strErrorInfo);
		retval = true;
	}
	else
	{
		UnsafeDirectoryCollection_t unsafeDirectoryInfo;

		if (ScanDirectoryHierarchyForUnsafeSubdirs(
			sDirectoryPath.c_str(),
			m_sidsToFilter,
			unsafeDirectoryInfo,
			strErrorInfo))
		{
			ScanDirectoryHierarchyForAppLockerRelevantFiles(sDirectoryPath.c_str(), szAppLabel, &unsafeDirectoryInfo, strErrorInfo);
			retval = true;
		}
	}

AllDone:
	return retval;
}
