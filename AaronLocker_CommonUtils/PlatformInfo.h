// PlatformInfo.h

#pragma once


/// <summary>
/// Returns true if the current platform version is Windows 10 or above, or Windows Server 2016 or above, and
/// at or above a specific build number.
/// 
/// Version to build mappings, from https://docs.microsoft.com/en-us/windows/release-health/release-information
/// as of Dec 27 2021:
/// 
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
/// (Note: declared here as "unsigned long" so that consumers of this header don't need to have a definition for DWORD.)</param>
/// <returns>true if the current platform version is Win10+/WS2016+ and at or above the input build number.</returns>
bool IsWindows10BuildXOrGreater(unsigned long dwBuildNumber);

/// <summary>
/// Returns true if current platform is Windows 10 v1607 (build 14393) or newer, or Windows Server 2016 or newer.
/// </summary>
bool IsWindows10v1607OrGreater();

/// <summary>
/// Returns true if current platform is Windows 10 v1709 (build 16299) or newer, or equivalent Windows Server or newer.
/// </summary>
bool IsWindows10v1709OrGreater();

/// <summary>
/// Returns true if current platform is Windows 10 v1903 (build 18362) or newer, or equivalent Windows Server or newer.
/// </summary>
bool IsWindows10v1903OrGreater();
