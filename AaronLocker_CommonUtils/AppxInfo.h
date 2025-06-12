// AppxInfo - gather information about all installed packaged apps on Win8.1/WS2012R2 and newer

#pragma once

// Note that this header cannot add dependencies to Windows SDK header files -- standard C++ only.

#include <string>
#include <vector>
#include <sstream>

/// <summary>
/// Information gathered about each installed packaged app
/// </summary>
struct PackagedAppInfo_t
{
	std::wstring
		Name,
		FullName,
		DisplayName,
		Publisher,
		PublisherDisplayName,
		Version,
		SignatureKind,
		InstallLocation,
		Architecture;
};
// Collection
typedef std::vector<PackagedAppInfo_t> PackagedAppInfoCollection_t;

// Possible results from packaged-app enumeration

/// <summary>
/// Possible results from packaged-app enumeration.
/// Note that the enumeration is performed by a DLL that is loaded on demand.
/// </summary>
enum class GetPackagedAppInfoResult_t
{
	NoWinRT, // Windows Runtime not present
	DllLoadFailure,
	CollectionFailure,
	Success
};

/// <summary>
/// Gather information about all installed packaged apps on the system.
/// Requires administrative rights.
/// Performs all necessary platform checks, so can be called from any client including where no WinRT is present.
/// Note that the enumeration is performed by a DLL that is loaded on demand and that must be in the same directory as
/// the calling executable, and built with the same MSVC compiler version.
/// </summary>
/// <param name="pkgInfoCollection">Output: collection of returned data about all installed packaged apps.</param>
/// <param name="strErrorInfo">Output: information about errors during the scan, if any</param>
/// <returns>One of the GetPackagedAppInfoResult_t values</returns>
GetPackagedAppInfoResult_t GetPackagedAppInfo(PackagedAppInfoCollection_t& pkgInfoCollection, std::wstringstream& strErrorInfo);
