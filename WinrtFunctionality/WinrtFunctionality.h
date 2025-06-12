#pragma once
/*
Header file to access WinRT functionality encapsulated in a DLL.

Notes about the DLL:
* It has WinRT dependencies, so shouldn't be loaded on platforms that do not have a Windows Runtime.
* Executables that load this DLL should be built with the same MSVC compiler version as this DLL. Verify by calling the CompatibleBuild entry point before using any entry points that take C++ object references.
* See ../AaronLocker_CommonUtils/AppxInfo.cpp for an example of how to use this interface.

*/

// Structure definitions
#include "../AaronLocker_CommonUtils/AppxInfo.h"


/// <summary>
/// C-style entry point that can safely be called from any binary. 
/// Pass in the value of _MSC_VER to determine whether other entry points to determine whether it's safe to call APIs that use C++ objects.
/// The caller and this DLL need to have been built by the same MSVC version.
/// If this function returns false, DO NOT call entry points with references to C++ objects.
/// </summary>
/// <param name="mscVer">Caller's definition of _MSC_VER</param>
/// <returns>true if the compiler versions match; false otherwise.</returns>
extern "C" __declspec(dllexport)
bool CompatibleBuild(unsigned long mscVer);

/// <summary>
/// Typedef to cast return value from GetProcAddress for CompatibleBuild
/// </summary>
typedef bool (*pfnCompatibleBuild_t)(unsigned long);


/// <summary>
/// DLL entry point for functionality that enumerates and returns information about all installed packaged apps.
/// Requires administrative rights.
/// </summary>
/// <param name="pkgInfoCollection">Output: collection of returned data about all installed packaged apps.</param>
/// <param name="sErrorInfo">Output: information about errors during the scan, if any</param>
/// <returns>GetPackagedAppInfoResult_t::Success or GetPackagedAppInfoResult_t::CollectionFailure</returns>
extern "C" __declspec(dllexport)
GetPackagedAppInfoResult_t GetPackagedAppInfoImpl(PackagedAppInfoCollection_t& pkgInfoCollection, std::wstring & sErrorInfo);

/// <summary>
/// Typedef to cast return value from GetProcAddress for GetPackagedAppInfoImpl
/// </summary>
typedef GetPackagedAppInfoResult_t (*pfnGetPackagedAppInfoImpl_t)(PackagedAppInfoCollection_t&, std::wstring&);
