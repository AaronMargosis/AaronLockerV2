// PlatformInfo.cpp

#include <Windows.h>
#include <VersionHelpers.h>

#include "PlatformInfo.h"

/// <summary>
/// Returns true if the current platform version is Windows 10 or above, or Windows Server 2016 or above, and
/// at or above a specific build number.
/// 
/// Version to build mappings, from https://docs.microsoft.com/en-us/windows/release-health/release-information
/// as of Jan 7 2022:
/// 
/// Windows 11:
/// Version 21H2 --> build 22000
/// 
/// Windows 10:
/// Version 21H2 --> build 19044 (also WS2022; Win10 LTSC IoT Enterprise supported until Jan 13, 2032)
/// Version 21H1 --> build 19043
/// Version 20H2 --> build 19042
/// Version 2004 --> build 19041 (*)
/// Version 1909 --> build 18363
/// Version 1903 --> build 18362 (*)
/// Version 1809 --> build 17763 (also WS2019; Win10 LTSC version supported until Jan 9, 2029)
/// Version 1803 --> build 17134 (*)
/// Version 1709 --> build 16299 (*)
/// Version 1703 --> build 15063 (*)
/// Version 1607 --> build 14393 (also WS2016; Win10 LTSB version supported until Oct 13, 2026)
/// Version 1511 --> build 10586 (*)
/// Version 1507 --> build 10240 (LTSB version supported until Oct 14, 2025)
/// 
/// (*) Support has expired
/// </summary>
/// <param name="dwBuildNumber">Input: the minimum Win10 build number to check for.
/// (Note: declared here as "unsigned long" so that consumers of PlatformInfo.h don't need to have a definition for DWORD.)</param>
/// <returns>true if the current platform version is Win10+/WS2016+ and at or above the input build number.</returns>
bool IsWindows10BuildXOrGreater(unsigned long dwBuildNumber)
{
	// Check major, minor, and build number.
	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, {0}, 0, 0 };
	DWORDLONG dwlConditionMask = 0;
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

	osvi.dwMajorVersion = HIBYTE(_WIN32_WINNT_WIN10);
	osvi.dwMinorVersion = LOBYTE(_WIN32_WINNT_WIN10);
	osvi.dwBuildNumber = dwBuildNumber;

	return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask) != FALSE;
}

/// <summary>
/// Returns true if current platform is Windows 10 v1607 (build 14393) or newer, or Windows Server 2016 or newer.
/// </summary>
bool IsWindows10v1607OrGreater()
{
	return IsWindows10BuildXOrGreater(14393);
}

/// <summary>
/// Returns true if current platform is Windows 10 v1709 (build 16299) or newer, or equivalent Windows Server or newer.
/// </summary>
bool IsWindows10v1709OrGreater()
{
	return IsWindows10BuildXOrGreater(16299);
}

/// <summary>
/// Returns true if current platform is Windows 10 v1903 (build 18362) or newer, or equivalent Windows Server or newer.
/// </summary>
bool IsWindows10v1903OrGreater()
{
	return IsWindows10BuildXOrGreater(18362);
}
