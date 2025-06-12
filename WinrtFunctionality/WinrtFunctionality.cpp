// Encapsulate Windows Runtime access in separate compilation units and/or PE files.

// C++/WinRT headers require C++17 or newer, and must be compiled with these switches:
//     /std:c++17 /permissive
// https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/
// https://docs.microsoft.com/en-us/windows/uwp/cpp-and-winrt-apis/get-started
// All the documentation explicitly talks about /std:c++17; some of the documentation also
// says that you need to remove /permissive- or explicitly add /permissive.
//
// Also note that C++/WinRT translates any error from an underlying API into a C++ exception:
// https://github.com/microsoft/cppwinrt/issues/1076#issuecomment-997486530


// Do a compile-time check for >= C++17:
// _MSVC_LANG is documented here: https://docs.microsoft.com/en-us/cpp/preprocessor/predefined-macros
#if _MSVC_LANG < 201703L 
#error C++/WinRT headers require C++17 or higher.
#endif

// Include WinRT headers, and add a linker command to link the necessary library
#include <winrt/Windows.ApplicationModel.h>
#include <winrt/Windows.Management.Deployment.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Foundation.Collections.h>
#pragma comment(lib, "windowsapp.lib")

#include <sstream>
#include "WinrtFunctionality.h"
#include "../AaronLocker_CommonUtils/PlatformInfo.h"

using namespace winrt;
using namespace Windows::ApplicationModel;
using namespace Windows::Management::Deployment;
using namespace Windows::Storage;

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

/// <summary>
/// C-style entry point that can safely be called from any binary. 
/// Pass in the value of _MSC_VER to determine whether other entry points to determine whether it's safe to call APIs that use C++ objects.
/// The caller and this DLL need to have been built by the same MSVC version.
/// If this function returns false, DO NOT call entry points with references to C++ objects.
/// </summary>
/// <param name="mscVer">Caller's definition of _MSC_VER</param>
/// <returns>true if the compiler versions match; false otherwise.</returns>
__declspec(dllexport)
bool CompatibleBuild(unsigned long mscVer)
{
    return (_MSC_VER == mscVer);
}

// ----------------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------------

// Commenting out unneeded references to WINRT_RoInitialize, as it doesn't appear to be in Win10 SDK headers after 10.0.19041.0.
//
// WINRT_RoInitialize might not be needed for this unit's operations;
// don't fail the build if the WINRT_RoInitAnyThreaded function is removed.
//
//#pragma warning (push)
//#pragma warning (disable: 4505) // unreferenced function with internal linkage has been removed
///// <summary>
///// Flexible wrapper around WINRT_RoInitialize that doesn't fail if it or CoInitializeEx has already initialized
///// a different threading model. (The Windows Runtime uses COM, and WINRT_RoInitialize initializes COM under the covers,
///// probably via CoInitializeEx.)
///// This function favors multi_threaded but if that fails, tries to initialize with single_threaded.
///// 
///// If WINRT_RoInitAnyThreaded returns true, WINRT_RoInitialize was called successfully one time.
///// WINRT_RoUninitialize must be called once for each successful call to WINRT_RoInitialize, so for each successful
///// invocation of WINRT_RoInitAnyThreaded, the caller must later call WINRT_RoUninitialize as many times.
///// 
///// See ../AaronLocker_CommonUtils/CoInit.h and CoInit.cpp for similar handling of CoInitializeEx.
///// </summary>
///// <returns>true if success</returns>
//static bool WINRT_RoInitAnyThreaded()
//{
//    // WINRT_RoInitialize seems to return the same return values as CoInitializeEx:
//    //   0 (S_OK) - successfully initialized
//    //   1 (S_FALSE) - success: previously initialized with the same threading model
//    //   0x80010106 (RPC_E_CHANGED_MODE) - failure: previously initialized with a different threading model.
//    // The Windows definitions for HRESULT, S_OK, etc., are not in the winrt headers, so the return
//    // value is an int32_t (4 bytes, just like HRESULT), where a return value less than zero indicates failure.
//
//    // Try multi-threaded first. If that fails, try single-threaded.
//    int32_t hr = WINRT_RoInitialize(static_cast<uint32_t>(winrt::apartment_type::multi_threaded));
//    if (hr < 0)
//        hr = WINRT_RoInitialize(static_cast<uint32_t>(winrt::apartment_type::single_threaded));
//    // Return true if one call succeeded.
//    return (hr >= 0);
//}
//#pragma warning (pop)


// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Local function that adds info returned from WinRT to a collection of structs
/// </summary>
/// <param name="package">Input: package object returned from WinRT API</param>
/// <param name="pkgInfoCollection">Collection of custom structs to add to</param>
/// <param name="bIsWindows10v1607OrGreater">Input: true if platform is Windows 10 v1607 / WS2016 or newer</param>
static void AddPkgInfoToCollection(
    const winrt::Windows::ApplicationModel::Package& package,
    PackagedAppInfoCollection_t& pkgInfoCollection,
    bool bIsWindows10v1607OrGreater
)
{
    // All the C++/WinRT methods are capable of raising exceptions, so handle (swallow) any that
    // prevent examining the package at all, while allowing the next package in the collection to
    // be processed.
    try
    {
        // New object to add to the collection
        PackagedAppInfo_t pkgInfo;

        // References that are used multiple times; retrieve them once each.
        const winrt::Windows::ApplicationModel::PackageId& pkgId = package.Id();
        const winrt::Windows::ApplicationModel::PackageVersion& ver = pkgId.Version();

        // Note that C++/WinRT translates any error from an underlying API into a C++ exception:
        // https://github.com/microsoft/cppwinrt/issues/1076#issuecomment-997486530
        // I have observed some of these property accessors raising exceptions in certain circumstances,
        // particularly those for DisplayName and InstalledLocation. To get as much data as possible for
        // each package, this implementation wraps each accessor in its own try/catch block.
        // wrapping each accessor in its own try/catch. 
        // If either Name or Publisher fail, though, don't bother saving this record.
        // But don't allow one of these exceptions to crash the process.

        try { pkgInfo.Name = pkgId.Name().c_str(); } catch (...) {}
        try { pkgInfo.FullName = pkgId.FullName().c_str(); } catch (...) {}
        try { pkgInfo.DisplayName = package.DisplayName().c_str(); } catch (...) {}
        try { pkgInfo.Publisher = pkgId.Publisher().c_str(); } catch (...) {}
        try { pkgInfo.PublisherDisplayName = package.PublisherDisplayName().c_str(); } catch (...) {}

        // Build the Version string from its component parts
        std::wstringstream strVersion;
        strVersion << ver.Major << "." << ver.Minor << "." << ver.Build << "." << ver.Revision;
        pkgInfo.Version = strVersion.str();

        // Calling the .SignatureKind() method on Win8.1 causes a null pointer read and a crash.
        // It might also crash on Windows 10 earlier than v1607, as it was introduced in that version:
        // https://docs.microsoft.com/en-us/uwp/api/windows.applicationmodel.package.signaturekind
        // So, just don't call it on Windows earlier that Win10 v1607
        if (bIsWindows10v1607OrGreater)
        {
            try {
                switch (package.SignatureKind())
                {
                case PackageSignatureKind::None:
                    pkgInfo.SignatureKind = L"None";
                    break;
                case PackageSignatureKind::Developer:
                    pkgInfo.SignatureKind = L"Developer";
                    break;
                case PackageSignatureKind::Enterprise:
                    pkgInfo.SignatureKind = L"Enterprise";
                    break;
                case PackageSignatureKind::Store:
                    pkgInfo.SignatureKind = L"Store";
                    break;
                case PackageSignatureKind::System:
                    pkgInfo.SignatureKind = L"System";
                    break;
                default:
                    pkgInfo.SignatureKind = L"Unrecognized";
                    break;
                }
            }
            catch (...) {}
        }

        try { pkgInfo.InstallLocation = package.InstalledLocation().Path().c_str(); } catch (...) {}

        /* These definitions seem to be missing in the VS 2017 build environment?
                enum class ProcessorArchitecture : int32_t
                {
                    X86 = 0,
                    Arm = 5,
                    X64 = 9,
                    Neutral = 11,
                    Arm64 = 12,
                    X86OnArm64 = 14,
                    Unknown = 65535,
                };
        */
        try {
            switch (static_cast<int32_t>(pkgId.Architecture()))
            {
            case 0: // winrt::Windows::System::ProcessorArchitecture::X86:
                pkgInfo.Architecture = L"X86";
                break;
            case 5: // winrt::Windows::System::ProcessorArchitecture::Arm:
                pkgInfo.Architecture = L"Arm";
                break;
            case 9: // winrt::Windows::System::ProcessorArchitecture::X64:
                pkgInfo.Architecture = L"X64";
                break;
            case 11: // winrt::Windows::System::ProcessorArchitecture::Neutral:
                pkgInfo.Architecture = L"Neutral";
                break;
            case 12: // winrt::Windows::System::ProcessorArchitecture::Arm64:
                pkgInfo.Architecture = L"Arm64";
                break;
            case 14: // winrt::Windows::System::ProcessorArchitecture::X86OnArm64:
                pkgInfo.Architecture = L"X86OnArm64";
                break;
            default:
                pkgInfo.Architecture = L"Unrecognized";
                break;
            }
        }
        catch (...) {}

        // If Name or Publisher is missing, don't bother adding to the collection
        if (pkgInfo.Name.length() > 0 && pkgInfo.Publisher.length() > 0)
        {
            // Add the new object to the collection.
            pkgInfoCollection.push_back(pkgInfo);
        }
    }
    catch (...) {}
}

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// DLL entry point for functionality that enumerates and returns information about all installed packaged apps.
/// Requires administrative rights.
/// </summary>
/// <param name="pkgInfoCollection">Output: collection of returned data about all installed packaged apps.</param>
/// <param name="sErrorInfo">Output: information about errors during the scan, if any</param>
/// <returns>GetPackagedAppInfoResult_t::Success or GetPackagedAppInfoResult_t::CollectionFailure</returns>
__declspec(dllexport)
GetPackagedAppInfoResult_t GetPackagedAppInfoImpl(PackagedAppInfoCollection_t& pkgInfoCollection, std::wstring& sErrorInfo)
{
    // Reference for this implementation:
    // https://social.msdn.microsoft.com/Forums/windows/en-US/19e06211-919e-4a2d-8fff-f7c68c1ac7e9/how-to-get-a-list-of-all-microsoft-store-apps-installed-on-a-system-using-native-c?forum=windowsgeneraldevelopmentissues

    // Initialize output variables
    pkgInfoCollection.clear();
    sErrorInfo.clear();

    // Have observed exceptions raised on some platforms even during instantiation of these variables. These exceptions must get caught
    // or the entire process will crash.
    // It's better to try to enumerate appx packages than to try to guess what platforms/SKUs are supported.
    // The enumeration seems to work on some server versions (e.g., full server) but not on certain others (e.g., Core), and fails differently when
    // executed from 32- or 64-bit code. Note also that cloud versions of Windows 10/11 might report as "server" SKUs.
    try
    {
        winrt::Windows::Management::Deployment::PackageManager winrtPkgManager;
        winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::ApplicationModel::Package> winrtAppModelPkgCollection;
        winrt::Windows::Foundation::Collections::IIterator<winrt::Windows::ApplicationModel::Package> winrtPackages;

        // Need to wrap the FindPackages() call in a try block, as it can throw exceptions; e.g., if called without admin rights.
        try
        {
            // Retrieve info about all installed packages
            winrtAppModelPkgCollection = winrtPkgManager.FindPackages();
        }
        catch (const winrt::hresult_access_denied&)
        {
            // Access denied - need admin rights to invoke the FindPackages() method
            sErrorInfo = L"Cannot gather packaged-app info: access denied.";
            return GetPackagedAppInfoResult_t::CollectionFailure;
        }
        catch (...)
        {
            // Something else happened. Unusual, unexpected.
            sErrorInfo = L"Cannot gather packaged-app info: unspecified error.";
            return GetPackagedAppInfoResult_t::CollectionFailure;
        }

        bool bIsWindows10v1607OrGreater = IsWindows10v1607OrGreater();

        // Iterate through the returned data and add info from each one to the caller's collection.
        // Catch and handle any failure of any the iteration methods (First, Current, MoveNext)
        try
        {
            winrtPackages = winrtAppModelPkgCollection.First();
            do
            {
                AddPkgInfoToCollection(winrtPackages.Current(), pkgInfoCollection, bIsWindows10v1607OrGreater);
            } while (winrtPackages.MoveNext());

            return GetPackagedAppInfoResult_t::Success;
        }
        catch (...)
        {
            sErrorInfo = L"Exception occurred while enumerating packaged-app info";
            return GetPackagedAppInfoResult_t::CollectionFailure;
        }
    }
    catch (...)
    {
        sErrorInfo = L"Exception occurred while preparing to enumerate packaged-app info";
        return GetPackagedAppInfoResult_t::CollectionFailure;
    }
}



