#include <Windows.h>
#include <VersionHelpers.h>
#include <iostream>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "SysErrorMessage.h"
#include "../WinrtFunctionality/WinrtFunctionality.h"
#include "AppxInfo.h"

/// <summary>
/// Gather information about all installed packaged apps on the system.
/// Requires administrative rights.
/// Performs all necessary platform checks, so can be called from any client including where no WinRT is present.
/// Note that the enumeration is performed by a DLL that is loaded on demand and that must be in the same directory as
/// the calling executable, and built with the same MSVC compiler version.
/// </summary>
GetPackagedAppInfoResult_t GetPackagedAppInfo(PackagedAppInfoCollection_t& pkgInfoCollection, std::wstringstream& strErrorInfo)
{
    // Must be Win8.1/WS2012R2 or newer. No WinRT on Win7/WS2008R2 and we're not supporting Win8/WS2012
    if (!IsWindows8Point1OrGreater())
    {
        return GetPackagedAppInfoResult_t::NoWinRT;
    }

    // The DLL that performs the work must be in the same directory as the current executable.
    std::wstring sExeDirectory = WindowsDirectories::ThisExeDirectory();
    if (sExeDirectory.empty())
    {
        strErrorInfo << L"Error getting path of current executable" << std::endl;
        return GetPackagedAppInfoResult_t::DllLoadFailure;
    }
    std::wstring sDllPath = sExeDirectory + L"\\WinrtFunctionality.dll";

    // Load the DLL
    HMODULE hDll = LoadLibraryW(sDllPath.c_str());
    if (NULL == hDll)
    {
        DWORD dwLastErr = GetLastError();
        strErrorInfo << L"Couldn't load DLL \"" << sDllPath << L"\": " << SysErrorMessageWithCode(dwLastErr) << std::endl;
        return GetPackagedAppInfoResult_t::DllLoadFailure;
    }

    // Find and then call the C-compatible compatibility function to ensure that the DLL and this executable
    // were built with the same MSVC compiler version. This compatibility check is necessary to ensure that
    // the C++ classes that will be passed between the caller and the DLL are binary-compatible.
    pfnCompatibleBuild_t pfnCompatibleBuild = (pfnCompatibleBuild_t)GetProcAddress(hDll, "CompatibleBuild");
    if (NULL == pfnCompatibleBuild)
    {
        DWORD dwLastErr = GetLastError();
        strErrorInfo << L"GetProcAddress CompatibleBuild failed: " << SysErrorMessage(dwLastErr) << std::endl;
        return GetPackagedAppInfoResult_t::DllLoadFailure;
    }

    // Perform the compatibility check before passing C++ object references to the DLL.
    if (!(pfnCompatibleBuild(_MSC_VER)))
    {
        strErrorInfo << L"Incompatible DLL build: " << sDllPath << std::endl;
        return GetPackagedAppInfoResult_t::DllLoadFailure;
    }

    // Get the entry point of the function that performs the packaged-app enumeration.
    pfnGetPackagedAppInfoImpl_t pfnGetPackagedAppInfoImpl = (pfnGetPackagedAppInfoImpl_t)GetProcAddress(hDll, "GetPackagedAppInfoImpl");
    if (NULL == pfnGetPackagedAppInfoImpl)
    {
        DWORD dwLastErr = GetLastError();
        strErrorInfo << L"GetProcAddress GetPackagedAppInfo failed: " << SysErrorMessage(dwLastErr) << std::endl;
        return GetPackagedAppInfoResult_t::DllLoadFailure;
    }

    // Call the function in the DLL to perform the work needed.
    std::wstring sErrorInfo;
    GetPackagedAppInfoResult_t result = pfnGetPackagedAppInfoImpl(pkgInfoCollection, sErrorInfo);
    if (!sErrorInfo.empty())
    {
        // Add to error output if non-empty.
        strErrorInfo << sErrorInfo << std::endl;
    }
    return result;
}
