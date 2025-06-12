// Access to Windows directory locations
#pragma once

#include <string>
#include <vector>

/// <summary>
/// Windows absolute and relative paths
/// Each value initialized only once per execution.
/// </summary>
class WindowsDirectories
{
public:
	/// <summary>
	/// System drive; typically "C:"
	/// </summary>
	static const std::wstring& SystemDriveDirectory();

	/// <summary>
	/// Windows directory; typically "C:\Windows"
	/// </summary>
	static const std::wstring& WindowsDirectory();
	
	/// <summary>
	/// Windows System32 directory; typically "C:\Windows\System32"
	/// Returns the same value whether x86 or x64 code on 32- or 64-bit Windows
	/// </summary>
	static const std::wstring& System32Directory();
	
	/// <summary>
	/// Full path to Program Files directory; typically "C:\Program Files"
	/// Returns the same value whether x86 or x64 code on 32- or 64-bit Windows
	/// </summary>
	static const std::wstring& ProgramFiles();
	
	/// <summary>
	/// Full path to Program Files (x86) directory, if it exists; typically "C:\Program Files (x86)"
	/// Returns the same value whether x86 or x64 code on 64-bit Windows.
	/// Returns an empty string on 32-bit Windows.
	/// </summary>
	static const std::wstring& ProgramFilesX86();
	
	/// <summary>
	/// The ProgramData/AllUsersProfile directory; typically "C:\ProgramData"
	/// </summary>
	static const std::wstring& ProgramData();

	/// <summary>
	/// The system-wide Start Menu
	/// </summary>
	static const std::wstring& CommonStartMenu();

	/// <summary>
	/// The system-wide Start Menu Programs
	/// </summary>
	static const std::wstring& CommonStartMenuPrograms();

	/// <summary>
	/// The system-wide Start Menu Startup folder
	/// </summary>
	static const std::wstring& CommonStartMenuStartup();

	/// <summary>
	/// Root directory for user profiles; typically "C:\Users"
	/// </summary>
	static const std::wstring& ProfilesDirectory();

	/// <summary>
	/// The default user profile directory; typically "C:\Users\Default"
	/// </summary>
	static const std::wstring& DefaultUserProfileDirectory();

	/// <summary>
	/// The public user profile directory; typically "C:\Users\Public"
	/// </summary>
	static const std::wstring& PublicUserProfileDirectory();

	/// <summary>
	/// The local appdata subdirectory relative to a user profile directory; typically "AppData\Local"
	/// </summary>
	static const std::wstring& AppDataLocalSubdir();

	/// <summary>
	/// The roaming appdata subdirectory relative to a user profile directory; typically "AppData\Roaming"
	/// </summary>
	static const std::wstring& AppDataRoamingSubdir();

	/// <summary>
	/// The local appdata temp subdirectory relative to a user profile directory; typically "AppData\Local\Temp"
	/// (Note that while the AppDataLocal subdirectory comes from a Windows-provided name, the "Temp" portion is
	/// hardcoded and based on observation only.)
	/// </summary>
	/// <returns></returns>
	static const std::wstring& AppDataLocalTempSubdir();

	/// <summary>
	/// The Desktop subdirectory relative to a user profile directory; typically "Desktop"
	/// Note that this is the default and doesn't account for an individual user's redirected Desktop; 
	/// e.g., when OneDrive (personal or commercial) redirects...
	/// </summary>
	static const std::wstring& DesktopSubdir();

	/// <summary>
	/// The Desktop subdirectory relative to a user profile directory; typically "Downloads"
	/// </summary>
	static const std::wstring& DownloadsSubdir();

	/// <summary>
	/// The Start Menu subdirectory relative to a user profile directory
	/// </summary>
	/// <returns></returns>
	static const std::wstring& StartMenuSubdir();

	/// <summary>
	/// The Start Menu Programs subdirectory relative to a user profile directory
	/// </summary>
	/// <returns></returns>
	static const std::wstring& StartMenuProgramsSubdir();

	/// <summary>
	/// The Start Menu Startup subdirectory relative to a user profile directory
	/// </summary>
	/// <returns></returns>
	static const std::wstring& StartMenuStartupSubdir();

	/// <summary>
	/// Determines whether the supplied directory name (not full path) is a default root directory name
	/// Example: IsDefaultRootDirName(L"ProgramData") returns true.
	/// Comparison is case-insensitive.
	/// </summary>
	/// <param name="szDirName">Subdirectory name to look up</param>
	/// <returns>true if szDirName is the name of a default root subdirectory.</returns>
	static bool IsDefaultRootDirName(const wchar_t* szDirName);

	/// <summary>
	/// Returns the path to the directory in which the current executable image is.
	/// </summary>
	static const std::wstring& ThisExeDirectory();
};

