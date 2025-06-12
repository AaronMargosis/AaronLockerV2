#include "pch.h"
#include <unordered_set>
#include <shlobj_core.h>
#include <UserEnv.h>
#pragma comment(lib, "Userenv.lib")
#include "../AaronLocker_CommonUtils/StringUtils.h"
#include "../AaronLocker_CommonUtils/CaseInsensitiveStringLookup.h"
#include "../AaronLocker_CommonUtils/FileSystemUtils.h"
#include "WindowsDirectories.h"

// Implemented so that the "static initialization order fiasco" doesn't happen.
// https://isocpp.org/wiki/faq/ctors#static-init-order
// I.e., it works even if another compilation unit's static initialization depends on methods in this
// compilation unit and happens before this compilation unit's static initialization.

// ------------------------------------------------------------------------------------------
// Private implementation for this compilation unit, created and fully initialized on first use.
class WindowsDirectories_SingletonImpl
{
public:
	// Access to these instance variables guaranteed to take place after initialization.
	std::wstring sSystemDriveDirectory;
	std::wstring sWindowsDirectory;
	std::wstring sSystem32Directory;
	std::wstring sProgramFiles;
	std::wstring sProgramFilesX86;
	std::wstring sProgramData;
	std::wstring sCommonStartMenu;
	std::wstring sCommonStartMenuPrograms;
	std::wstring sCommonStartMenuStartup;
	std::wstring sProfilesDirectory;
	std::wstring sDefaultUserProfileDirectory;
	std::wstring sPublicUserProfileDirectory;
	std::wstring sAppDataLocalSubdir;
	std::wstring sAppDataRoamingSubdir;
	std::wstring sAppDataLocalTempSubdir;
	std::wstring sDesktopSubdir;
	std::wstring sDownloadsSubdir;
	std::wstring sStartMenuSubdir;
	std::wstring sStartMenuProgramsSubdir;
	std::wstring sStartMenuStartupSubdir;
	CaseInsensitiveStringLookup lookupDefaultRootDirs;

public:
	/// <summary>
	/// The only way to get access to the member variables is through this singleton accessor
	/// method which returns a reference to the singleton instance, created and initialized on
	/// first access.
	/// </summary>
	static const WindowsDirectories_SingletonImpl& Get()
	{
		if (NULL == pInstance)
		{
			pInstance = new WindowsDirectories_SingletonImpl();
		}
		return *pInstance;
	}

private:
	// Internal reference to singleton instance
	static WindowsDirectories_SingletonImpl* pInstance;
	// Constructor accessible only to the static Get() method.
	WindowsDirectories_SingletonImpl() { Initialize(); }
	~WindowsDirectories_SingletonImpl() {}
	// One-time initialization of the singleton instance.
	void Initialize();

private:
	// Not implemented
	WindowsDirectories_SingletonImpl(const WindowsDirectories_SingletonImpl&) = delete;
	WindowsDirectories_SingletonImpl& operator = (const WindowsDirectories_SingletonImpl&) = delete;
};

// Private static member that points to the singleton instance
WindowsDirectories_SingletonImpl* WindowsDirectories_SingletonImpl::pInstance = NULL;

// ------------------------------------------------------------------------------------------
// Helper functions to initialize wstring values from named environment variables or folder IDs

static bool InitFromEnvVar(std::wstring& str, const wchar_t* szEnvVar)
{
	const DWORD cchBufsize = MAX_PATH * 2;
	wchar_t filepathbuffer[cchBufsize];
	if (GetEnvironmentVariableW(szEnvVar, filepathbuffer, cchBufsize) > 0)
	{
		str = filepathbuffer;
		return true;
	}
	return false;
}

// Get the default full path associated with the folder ID for the "default user."
// Note that it does not verify the existence of the directory in the default user profile.
// E.g., there is no "Startup" subdir in the default user's Start Menu; not verifying
// enables this function to return the value anyway.
// See the additional commentary above the InitFromFolderIdSubstring definition.
static bool InitFromFolderId(std::wstring& str, REFKNOWNFOLDERID rfid)
{
	PWSTR pszPath = NULL;
	bool retval = false;
	// hToken parameter set to -1 for "default user"
	if (SUCCEEDED(SHGetKnownFolderPath(rfid, KF_FLAG_DONT_VERIFY, HANDLE(-1), &pszPath)))
	{
		str = pszPath;
		retval = true;
	}
	CoTaskMemFree(pszPath);
	return retval;
}

// Get the relative portion path associated with the folder ID, removing the base path
// E.g., if the folder ID lookup returns "C:\Users\Default\AppData\Local" and the base is 
// "C:\Users\Default", this function returns "AppData\Local".
// Note that appending the returned value to another user's profile gets the *default* location --
// the actual location might have been changed through user choice (e.g., Documents -> Properties -> Location),
// through Group Policy, or by an app (e.g., OneDrive redirecting a user's default Documents folder
// to the user's OneDrive Documents).
static bool InitFromFolderIdSubstring(std::wstring& str, REFKNOWNFOLDERID rfid, const std::wstring& sBase)
{
	std::wstring strFullPath;
	bool retval = InitFromFolderId(strFullPath, rfid);
	if (retval)
	{
		// Skip the part that matches the input string plus one to cover the backslash
		str = strFullPath.substr(sBase.length() + 1);
	}
	return retval;
}

// ------------------------------------------------------------------------------------------
// One time initialization
void WindowsDirectories_SingletonImpl::Initialize()
{
	const DWORD cchBufsize = MAX_PATH * 2;
	DWORD cchSize = cchBufsize;
	wchar_t filepathbuffer[cchBufsize];

	// SystemDrive (typically C:). I didn't find an API that returned this value; the best way I
	// could come up with is the environment variable.
	InitFromEnvVar(sSystemDriveDirectory, L"SystemDrive");

	// Windows directory (typically C:\Windows)
	if (GetWindowsDirectoryW(filepathbuffer, cchBufsize) > 0)
	{
		sWindowsDirectory = filepathbuffer;
	}

	// System32Directory (typically C:\Windows\system32, and returns the same thing whether x64 or WOW64)
	if (GetSystemDirectoryW(filepathbuffer, cchBufsize) > 0)
	{
		sSystem32Directory = filepathbuffer;
	}

	// Program Files directories, in a way that works identically for x86 and x64 code
	// and on 32- and 64-bit Windows. The standard APIs return different data for x86 and
	// x64 code, so I'm going to lean on environment variables instead. Typical observed
	// values listed in this table:
	//
	// Env var            x86 on 32-bit Win   x86 on 64-bit Win       x64 on 64-bit Win
	// ProgramFiles       C:\Program Files    C:\Program Files (x86)  C:\Program Files
	// ProgramW6432       [not present]       C:\Program Files        C:\Program Files
	// ProgramFiles(x86)  [not present]       C:\Program Files (x86)  C:\Program Files (x86)
	//
	// For any code on 64-bit Windows:
	if (!InitFromEnvVar(sProgramFiles, L"ProgramW6432"))
	{
		// For x86 code on 32-bit Windows:
		InitFromEnvVar(sProgramFiles, L"ProgramFiles");
	}
	// For x86 or x64 code on 64-bit Windows. 
	// sProgramFilesX86 is left empty on 32-bit Windows.
	InitFromEnvVar(sProgramFilesX86, L"ProgramFiles(x86)");

	// ProgramData
	InitFromFolderId(sProgramData, FOLDERID_ProgramData);

	// CommonStartMenu, CommonStartMenuPrograms, and CommonStartMenuStartup
	InitFromFolderId(sCommonStartMenu, FOLDERID_CommonStartMenu);
	InitFromFolderId(sCommonStartMenuPrograms, FOLDERID_CommonPrograms);
	InitFromFolderId(sCommonStartMenuStartup, FOLDERID_CommonStartup);

	// Profiles directory (typically C:\Users
	cchSize = cchBufsize;
	if (GetProfilesDirectoryW(filepathbuffer, &cchSize))
	{
		sProfilesDirectory = filepathbuffer;
	}

	// Default user profile
	cchSize = cchBufsize;
	if (GetDefaultUserProfileDirectoryW(filepathbuffer, &cchSize))
	{
		sDefaultUserProfileDirectory = filepathbuffer;
	}

	// Public user profile directory
	InitFromFolderId(sPublicUserProfileDirectory, FOLDERID_Public);

	// Default subdirectory paths (doesn't account for individual users' redirected directories)
	// AppData\Local subdir (that can be appended to user profile directories)
	InitFromFolderIdSubstring(sAppDataLocalSubdir, FOLDERID_LocalAppData, sDefaultUserProfileDirectory);
	// AppData\Roaming subdir (that can be appended to user profile directories)
	InitFromFolderIdSubstring(sAppDataRoamingSubdir, FOLDERID_RoamingAppData, sDefaultUserProfileDirectory);
	// AppData\Local\Temp subdir (that can be appended to user profile directories)
	// Note that this value includes hardcoded "Temp" as there isn't a GUID or an API to get this value by itself
	// in the absence of a non-System user context.
	sAppDataLocalTempSubdir = sAppDataLocalSubdir + L"\\Temp";
	// Desktop
	InitFromFolderIdSubstring(sDesktopSubdir, FOLDERID_Desktop, sDefaultUserProfileDirectory);
	// Downloads
	InitFromFolderIdSubstring(sDownloadsSubdir, FOLDERID_Downloads, sDefaultUserProfileDirectory);
	// Start Menu
	InitFromFolderIdSubstring(sStartMenuSubdir, FOLDERID_StartMenu, sDefaultUserProfileDirectory);
	// Start Menu Programs
	InitFromFolderIdSubstring(sStartMenuProgramsSubdir, FOLDERID_Programs, sDefaultUserProfileDirectory);
	// Start Menu Startup folder
	InitFromFolderIdSubstring(sStartMenuStartupSubdir, FOLDERID_Startup, sDefaultUserProfileDirectory);

	/// <summary>
	/// List of root-directory subdirectories that are always (or frequently) on all Windows systems.
	/// </summary>
	const wchar_t* szDefaultRootDirs[] = {
		L"$Recycle.Bin",
		L"$WINDOWS.~BT", // Appears during in-place upgrades
		L"Config.Msi",
		L"MSOCache",
		L"MSOTraceLite",
		L"OneDriveTemp",
		L"PerfLogs",
		L"Program Files",
		L"Program Files (x86)",
		L"ProgramData",
		L"Recovery",
		L"System Volume Information",
		L"Users",
		L"Windows",
		L"Windows.old"
	};
	const size_t nDefaultRootDirs = sizeof(szDefaultRootDirs) / sizeof(szDefaultRootDirs[0]);

	lookupDefaultRootDirs.Add(szDefaultRootDirs, nDefaultRootDirs);
}

// ------------------------------------------------------------------------------------------
// WindowsDirectories static member functions

const std::wstring& WindowsDirectories::SystemDriveDirectory()
{
	return WindowsDirectories_SingletonImpl::Get().sSystemDriveDirectory;
}

const std::wstring& WindowsDirectories::WindowsDirectory()
{
	return WindowsDirectories_SingletonImpl::Get().sWindowsDirectory;
}

const std::wstring& WindowsDirectories::System32Directory()
{
	return WindowsDirectories_SingletonImpl::Get().sSystem32Directory;
}

const std::wstring& WindowsDirectories::ProgramFiles()
{
	return WindowsDirectories_SingletonImpl::Get().sProgramFiles;
}

const std::wstring& WindowsDirectories::ProgramFilesX86()
{
	return WindowsDirectories_SingletonImpl::Get().sProgramFilesX86;
}

const std::wstring& WindowsDirectories::ProgramData()
{
	return WindowsDirectories_SingletonImpl::Get().sProgramData;
}

const std::wstring& WindowsDirectories::CommonStartMenu()
{
	return WindowsDirectories_SingletonImpl::Get().sCommonStartMenu;
}

const std::wstring& WindowsDirectories::CommonStartMenuPrograms()
{
	return WindowsDirectories_SingletonImpl::Get().sCommonStartMenuPrograms;
}

const std::wstring& WindowsDirectories::CommonStartMenuStartup()
{
	return WindowsDirectories_SingletonImpl::Get().sCommonStartMenuStartup;
}

const std::wstring& WindowsDirectories::ProfilesDirectory()
{
	return WindowsDirectories_SingletonImpl::Get().sProfilesDirectory;
}

const std::wstring& WindowsDirectories::DefaultUserProfileDirectory()
{
	return WindowsDirectories_SingletonImpl::Get().sDefaultUserProfileDirectory;
}

const std::wstring& WindowsDirectories::PublicUserProfileDirectory()
{
	return WindowsDirectories_SingletonImpl::Get().sPublicUserProfileDirectory;
}

const std::wstring& WindowsDirectories::AppDataLocalSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sAppDataLocalSubdir;
}

const std::wstring& WindowsDirectories::AppDataRoamingSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sAppDataRoamingSubdir;
}

const std::wstring& WindowsDirectories::AppDataLocalTempSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sAppDataLocalTempSubdir;
}

const std::wstring& WindowsDirectories::DesktopSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sDesktopSubdir;
}

const std::wstring& WindowsDirectories::DownloadsSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sDownloadsSubdir;
}

const std::wstring& WindowsDirectories::StartMenuSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sStartMenuSubdir;
}

const std::wstring& WindowsDirectories::StartMenuProgramsSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sStartMenuProgramsSubdir;
}

const std::wstring& WindowsDirectories::StartMenuStartupSubdir()
{
	return WindowsDirectories_SingletonImpl::Get().sStartMenuStartupSubdir;
}

bool WindowsDirectories::IsDefaultRootDirName(const wchar_t* szDirName)
{
	return WindowsDirectories_SingletonImpl::Get().lookupDefaultRootDirs.IsInSet(szDirName);
}

const std::wstring& WindowsDirectories::ThisExeDirectory()
{
	// Initialize sThisExeDirectory the first time it's called in this process:
	static std::wstring sThisExeDirectory;
	if (0 == sThisExeDirectory.length())
	{
		wchar_t szPath[MAX_PATH + 1] = { 0 };
		if (GetModuleFileNameW(NULL, szPath, MAX_PATH))
		{
			sThisExeDirectory = GetDirectoryNameFromFilePath(szPath);
		}
	}
	return sThisExeDirectory;
}
