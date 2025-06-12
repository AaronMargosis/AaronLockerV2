#include "pch.h"
#include <unordered_set>
#include <unordered_map>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "MsiFileInfo.h"
#include "AppLockerFileDetails.h"

// AppLockerFileDetails: Interface to additional AppLocker-relevant information, including apparent file type for rule collections.


// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
/// <summary>
/// ExtensionLookups is a singleton class for optimized lookup of file extensions, to save (where 
/// possible) the trouble of inspecting file content to determine whether the files contain code 
/// and of what kind. Some file extensions are (almost) always a particular AppLocker-relevant code
/// type, and some file extensions are (almost) never code. Files with unknown file extensions
/// generally need to be inspected because they often contain EXE or DLL content. Inspecting
/// all file content is expensive, though, so doing so should be minimized.
/// </summary>
class ExtensionLookups
{
public:
	/// <summary>
	/// Indicates whether the file's extension is usually not relevant to AppLocker so that
	/// content inspection is not needed. E.g., don't want to open every .PDF to determine whether
	/// it's actually a PE file.
	/// </summary>
	/// <param name="sExtension">File extension (without dot) to inspect</param>
	/// <returns>true if the extension represents a known non-code file type</returns>
	static bool IsExtensionKnownNonCode(const std::wstring& sExtension)
	{
		// Ensure one-time initialization of set of extensions
		if (!st_bInitialized) { Initialize(); }
		// Returns true if sExtension is in the set
		return st_KnownNonCodeExtensions.IsInSet(sExtension);
	}

	/// <summary>
	/// Returns the AppLocker-relevant file type based on file extension alone.
	/// Note that the set of file extensions here is what Get-AppLockerFileInformation -Directory
	/// looks for.
	/// </summary>
	/// <param name="sExtension">File extension (without dot) to inspect</param>
	/// <returns>Value in the AppLockerFileDetails_ftype_t enumeration</returns>
	static AppLockerFileDetails_ftype_t GetFileTypeBasedOnExtension(const std::wstring& sExtension)
	{
		// Ensure one-time initialization of set of extensions
		if (!st_bInitialized) { Initialize(); }
		// Check for known non-code extension
		if (IsExtensionKnownNonCode(sExtension))
		{
			return AppLockerFileDetails_ftype_t::ft_KnownNonCodeExtension;
		}
		// Look for extension in the set of extensions that Get-AppLockerFileInformation looks for.
		// All the entries in the map are lower case, so make sure it's lower case before looking.
		std::wstring sExtensionLC = sExtension;
		std::unordered_map<std::wstring, AppLockerFileDetails_ftype_t>::const_iterator iter =
			st_ExtensionToFType.find(WString_To_Lower(sExtensionLC));
		// If the extension is found in the map object, return its associated file type;
		// otherwise, return unknown.
		if (iter != st_ExtensionToFType.end())
			return iter->second;
		else
			return AppLockerFileDetails_ftype_t::ft_Unknown;
	}

private:
	// Set of known non-code extensions. See initialization below for details.
	static CaseInsensitiveStringLookup st_KnownNonCodeExtensions;
	// Set of known code extensions that Get-AppLockerFileInformation -Directory looks for
	static std::unordered_map<std::wstring, AppLockerFileDetails_ftype_t> st_ExtensionToFType;
	// For one-time initialization
	static bool st_bInitialized;
	static void Initialize();
};

// One-time initialization
bool ExtensionLookups::st_bInitialized = false;

/// <summary>
/// st_KnownNonCodeExtensions: set of known non-code extensions. See Initialize() below for details.
/// </summary>
CaseInsensitiveStringLookup ExtensionLookups::st_KnownNonCodeExtensions;

/// <summary>
/// st_ExtensionToFType: a set of known file extensions that map to known code file formats that
/// AppLocker can manage, saving the expense of opening the file to determine its actual file type.
/// Originally based on the set of file extensions that Get-AppLockerFileInformation -Directory looks for,
/// the list has been extended.
/// Initialization at instantiation rather than at first use.
/// TODO: Based on real-world inspection of files in unsafe directories, consider extending this list where extensions
/// are RELIABLY associated with AppLocker-relevant file types or with non-code file types.
/// </summary>
std::unordered_map<std::wstring, AppLockerFileDetails_ftype_t> ExtensionLookups::st_ExtensionToFType = {

	//
	// If any extensions are ever added to this collection, make sure they are lower case.
	//
	{ L"com", AppLockerFileDetails_ftype_t::ft_EXE },
	{ L"exe", AppLockerFileDetails_ftype_t::ft_EXE },
	{ L"scr", AppLockerFileDetails_ftype_t::ft_EXE },

	{ L"dll", AppLockerFileDetails_ftype_t::ft_DLL },
	{ L"ocx", AppLockerFileDetails_ftype_t::ft_DLL },

	{ L"msi", AppLockerFileDetails_ftype_t::ft_MSI },
	{ L"msp", AppLockerFileDetails_ftype_t::ft_MSI },
	{ L"mst", AppLockerFileDetails_ftype_t::ft_MSI },

	{ L"bat", AppLockerFileDetails_ftype_t::ft_Script },
	{ L"cmd", AppLockerFileDetails_ftype_t::ft_Script },
	{ L"ps1", AppLockerFileDetails_ftype_t::ft_Script },
	{ L"vbs", AppLockerFileDetails_ftype_t::ft_Script },
	{ L"wsf", AppLockerFileDetails_ftype_t::ft_Script },
	{ L"wsh", AppLockerFileDetails_ftype_t::ft_Script },

	// Most .js files are executed in non-AppLocker-aware host processes.
	// See declaration of ft_ScriptJS for more information.
	{ L"js",  AppLockerFileDetails_ftype_t::ft_ScriptJS },

	// Determine whether/how to support appx files at some point.
	//{ L"appx", AppLockerFileDetails_ftype_t::ft_Appx },
};

// One-time initialization of the KnownNonCodeExtensions set
//static
void ExtensionLookups::Initialize()
{
	st_bInitialized = true;

	st_KnownNonCodeExtensions.clear();
	
	// Sets of common file extensions that rarely if ever contain code that can be controlled via AppLocker.
	// 
	// NOTE THAT IF YOU EDIT THE arrKnownNonCodeExtensions ARRAY:
	// * Extension must not begin with a ".".
	// * Extensions cannot contain embedded dot characters. For example, a file named "lpc.win32.bundle" has the extension "bundle" and not "win32.bundle"
	// * Do not add into this set any of the extensions that are in the st_ExtensionToFType collection.
	// * Order doesn't matter.
	//
	// N.B., if an instance of one of these files turns out to contain executable code and we didn't create a rule for it because of the file extension,
	// that's generally a GOOD thing.
	const wchar_t* arrKnownNonCodeExtensions[] = {
		L"admx", L"adml", L"opax", L"opal",
		L"etl", L"evtx", L"msc", L"pdb",
		L"chm", L"hlp",
		L"gif", L"jpg", L"jpeg", L"png", L"bmp", L"svg", L"ico", L"pfm", L"ttf", L"fon", L"otf", L"cur",
		L"html", L"htm", L"hta", L"css", L"json", L"md",
		L"txt", L"log", L"xml", L"xsl", L"ini", L"csv", L"reg", L"mof",
		L"pdf", L"tif", L"tiff", L"xps", L"rtf",
		L"lnk", L"url", L"inf",
		L"config",
		L"odl", L"odlgz", L"odlsent",                                        // OneDrive data files
		L"mui",                                                              // .mui is a DLL but it is always loaded as data-only, so no need for AppLocker rules
		L"doc", L"docx", L"docm", L"dot", L"dotx", L"dotm",                  // Microsoft Word
		L"xls", L"xlsx", L"xlsm", L"xlt", L"xltx", L"xltm",                  // Microsoft Excel
		L"ppt", L"pptx", L"pptm", L"pot", L"potx", L"potm", L"pps", L"ppsx", // Microsoft PowerPoint
		L"zip", L"7z", L"tar", L"cab",
		L"wav", L"wmv", L"mp3", L"mp4", L"mpg", L"mpeg", L"avi", L"mov",
		NULL
	};
	// Add each of the above extensions into the array.
	st_KnownNonCodeExtensions.Add(arrKnownNonCodeExtensions);
}


// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

// Constructor
AppLockerFileDetails::AppLockerFileDetails(const wchar_t* szFilePath)
{
	if (NULL != szFilePath)
	{
		m_sFilePath = szFilePath;
	}
}

AppLockerFileDetails::~AppLockerFileDetails()
{
}

const std::wstring& AppLockerFileDetails::FilePath() const
{
	// If a call to FileExistsFullyPresent() or FileSize() required an extended-file specifier, use that path going forward.
	if (m_sAltFilePath.length() > 0)
		return m_sAltFilePath;
	else
		return m_sFilePath;
}

// Verify that the file path represents an existing file that is fully present in the target location.
// ("fully present;" e.g., doesn't need to be downloaded from OneDrive).
// Note that some reserved names like CON, NUL, COM1, etc., look like files to the GetFileAttributes API.
// Best we can do is to make sure that the name is *something* and isn't a directory.
bool AppLockerFileDetails::FileExistsFullyPresent() const
{
	// Ensure file path has been set
	if (!BasicValidation())
		return false;
	// Disable WOW64 file system redirection for the duration of the function; revert on exit (variable goes out of scope)
	Wow64FsRedirection wow64FSRedir(true);
	// Retrieve attributes
	DWORD dwLastError;
	// Note that this call can set the extended-path alternate file path for all future use
	DWORD dwFileAttributes = GetFileAttributes_ExtendedPath(FilePath().c_str(), dwLastError, m_sAltFilePath);
	// Check for error
	if (INVALID_FILE_ATTRIBUTES == dwFileAttributes)
		return false;
	// Check for directory, offline, downloaded on demand, etc.
	const DWORD dwUngoodFileAttributes =
		FILE_ATTRIBUTE_DIRECTORY | 
		FILE_ATTRIBUTE_REPARSE_POINT |
		FILE_ATTRIBUTE_OFFLINE | 
		FILE_ATTRIBUTE_RECALL_ON_OPEN | 
		FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
	// If any "ungood" attributes, say that it's not a file here.
	if ( dwUngoodFileAttributes & dwFileAttributes)
		return false;
	return true;
}

// Get the file's size
bool AppLockerFileDetails::FileSize(LARGE_INTEGER& filesize) const
{
	// Disable WOW64 file system redirection for the duration of the function; revert on exit (variable goes out of scope)
	Wow64FsRedirection wow64FSRedir(true);
	filesize.QuadPart = 0;
	DWORD dwLastError;
	// Note that this call can set the extended-path alternate file path for all future use
	HANDLE hFile = OpenExistingFile_ExtendedPath(FilePath().c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, dwLastError, m_sAltFilePath);
	if (INVALID_HANDLE_VALUE == hFile)
		return false;
	bool retval = (FALSE != GetFileSizeEx(hFile, &filesize));
	CloseHandle(hFile);
	return retval;
}

// Get the file name by itself from the path.
// File name assumed to be whatever's after the last backslash.
std::wstring AppLockerFileDetails::GetFileNameFromFilePath() const
{
	return ::GetFileNameFromFilePath(m_sFilePath);
}

// Get the file extension, not including the dot.
// Note that directory names can contain dots, and that file names can contain multiple dots.
std::wstring AppLockerFileDetails::GetFileExtensionFromFilePath() const
{
	return ::GetFileExtensionFromFilePath(m_sFilePath);
}


/// <summary>
/// Calls Windows API to determine whether the file is a valid MSI package, regardless of extension.
/// </summary>
/// <returns>true if the file is a valid MSI package; false otherwise.</returns>
bool AppLockerFileDetails::IsMSI() const
{
	return MsiFileInfo::IsMSI(FilePath().c_str());
}

/// <summary>
/// Indicates whether the file's extension is usually not relevant to AppLocker so that
/// content inspection is not needed. E.g., don't want to open every .PDF to determine whether
/// it's actually a PE file.
/// </summary>
bool AppLockerFileDetails::IsExtensionKnownNonCode() const
{
	std::wstring sExt = GetFileExtensionFromFilePath();
	return ExtensionLookups::IsExtensionKnownNonCode(sExt);
}

/// <summary>
/// Returns the AppLocker-relevant file type based on file extension alone.
/// </summary>
/// <returns>Value in the AppLockerFileDetails_ftype_t enumeration</returns>
AppLockerFileDetails_ftype_t AppLockerFileDetails::GetFileTypeBasedOnExtension() const
{
	std::wstring sExt = GetFileExtensionFromFilePath();
	return ExtensionLookups::GetFileTypeBasedOnExtension(sExt);
}

/// <summary>
/// Returns the AppLocker-relevant file type based on file extension or file content.
/// If bFavorExtension is true (default), returns file type based on hardcoded set of
/// known extensions; if extension is not known, inspects file content for EXE, DLL, or MSI
/// content. If bFavorExtension is false, inspects file content first for EXE, DLL, or MSI 
/// content, and if still unknown, then returns type based on file extension.
/// If the file is a Portable Executable file, additional information can be returned through
/// the peFileInfo parameter.
/// </summary>
/// <param name="peFileInfo">Output: If the file is a Portable Executable (PE) file, additional information can be returned through peFileInfo</param>
/// <param name="bFavorExtension">Input: indicates whether to evaluate file extension first, or only after file content inspection doesn't return EXE, DLL, or MSI.</param>
/// <param name="dwFileApiError">Output: error code from file API if opening the file fails.</param>
/// <returns>Returns the AppLocker-relevant file type.</returns>
AppLockerFileDetails_ftype_t AppLockerFileDetails::GetFileType(PEFileInfo& peFileInfo, bool bFavorExtension, DWORD& dwFileApiError) const
{
	peFileInfo.Clear();
	dwFileApiError = 0;
	if (bFavorExtension)
	{
		// If the file extension is known, return that file type --
		// but if it's a DLL, do a content check to determine whether it's a resource-only DLL.
		AppLockerFileDetails_ftype_t retval = GetFileTypeBasedOnExtension();
		if (AppLockerFileDetails_ftype_t::ft_DLL == retval || AppLockerFileDetails_ftype_t::ft_EXE == retval)
		{
			// Get additional PE file information
			if (peFileInfo.IsPEFile(FilePath().c_str(), dwFileApiError))
			{
				if (peFileInfo.IsResourceOnlyDll())
				{
					// Change return value from ft_DLL to ft_ResourceOnlyDLL.
					retval = AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL;
				}
			}
			else
			{
				// It has a PE extension but it's not a PE file. Possibly DOS/Win16, but not something AppLocker works with.
				return AppLockerFileDetails_ftype_t::ft_Unknown;
			}
		}
		// If file type determined, return it; otherwise, keep looking.
		if (AppLockerFileDetails_ftype_t::ft_Unknown != retval)
		{
			return retval;
		}
		// Ignoring file extension, determine whether the file is an AppLocker-relevant PE
		if (peFileInfo.IsPEFile(FilePath().c_str(), dwFileApiError))
		{
			// Check resource-only DLL before checking DLL. (All resource-only DLLs are also DLLs.)
			if (peFileInfo.IsResourceOnlyDll())
				return AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL;
			else if (peFileInfo.IsDll())
				return AppLockerFileDetails_ftype_t::ft_DLL;
			else if (peFileInfo.IsExe())
				return AppLockerFileDetails_ftype_t::ft_EXE;
			else
				// PE file that isn't a user-mode EXE or DLL - not of interest to AppLocker.
				return AppLockerFileDetails_ftype_t::ft_Unknown;
		}
		// Ignoring file extension, determine whether the file is an MSI
		if (IsMSI())
			return AppLockerFileDetails_ftype_t::ft_MSI;
		return AppLockerFileDetails_ftype_t::ft_Unknown;
	}
	else
	{
		// Ignore file extension. Look for Portable Executable and then for MSI. If neither, then look at extension.
		// Ignoring file extension, determine whether the file is an AppLocker-relevant PE
		if (peFileInfo.IsPEFile(FilePath().c_str(), dwFileApiError))
		{
			// Check resource-only DLL before checking DLL. (All resource-only DLLs are also DLLs.)
			if (peFileInfo.IsResourceOnlyDll())
				return AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL;
			else if (peFileInfo.IsDll())
				return AppLockerFileDetails_ftype_t::ft_DLL;
			else if (peFileInfo.IsExe())
				return AppLockerFileDetails_ftype_t::ft_EXE;
			else
				// PE file that isn't a user-mode EXE or DLL - not of interest to AppLocker.
				return AppLockerFileDetails_ftype_t::ft_Unknown;
		}
		// Ignoring file extension, determine whether the file is an MSI
		if (IsMSI())
			return AppLockerFileDetails_ftype_t::ft_MSI;
		return GetFileTypeBasedOnExtension();
	}
}


