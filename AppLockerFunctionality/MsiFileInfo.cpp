// Class to get info about an MSI file for AppLocke support.
// Equivalent to parts of Get-AppLockerFileInformation / Publisher info.

#include <Windows.h>
#include <Msi.h>
#pragma comment(lib, "msi.lib")
#include "MsiFileInfo.h"
#include "../AaronLocker_CommonUtils/Wow64FsRedirection.h"
#include "../AaronLocker_CommonUtils/CoInit.h"
#include "../AaronLocker_CommonUtils/StringUtils.h"

bool MsiFileInfo::IsMSI(const wchar_t* szFilename)
{
	// Disable WOW64 file system redirection
	Wow64FsRedirection wow64FSRedir(true);
	// Note that MsiVerifyPackageW correctly handles relative paths.
	UINT ret = MsiVerifyPackageW(szFilename);
	wow64FSRedir.Revert();
	return ERROR_SUCCESS == ret;
}


bool MsiFileInfo::Get(const wchar_t* szFilename, MsiFileInfo_t& msiFileInfo)
{
	msiFileInfo.clear();
	bool retval = false;

	// Initialize COM. Doesn't matter whether apartment-threaded or multithreaded.
	HRESULT hr = CoInitAnyThreaded();
	// If COM initialization failed, we can't proceeed
	if (FAILED(hr))
		return retval;

	// Disable WOW64 file system redirection
	Wow64FsRedirection wow64FSRedir(true);

	// Should be plenty for the properties we're retrieving and the full path we're building here
	const int cchTempBufferSize = 1024;
	wchar_t* pszTempBuffer = new wchar_t[cchTempBufferSize];

	// Set MSI UI to "none". MsiOpenPackageExW will otherwise pop a "preparing to install" dialog.
	// More info here: 
	// https://microsoft.public.platformsdk.msi.narkive.com/RDFpRMiT/can-you-call-msiopenpackage-silently
	INSTALLUILEVEL origUiLevel = MsiSetInternalUI(INSTALLUILEVEL_NONE, NULL);

	// Note that MsiOpenPackageExW does NOT correctly handle relative paths, so need to try to get the full path.
	// If the API call succeeds, point szFilename to that full path. If it fails, continue using the supplied
	// szFilename value.
	// Note also that after the call to MsiOpenPackageExW, that temp buffer will be used for other operations.
	if (0 != GetFullPathNameW(szFilename, cchTempBufferSize, pszTempBuffer, NULL))
	{
		szFilename = pszTempBuffer;
	}

	MSIHANDLE hProduct = NULL;
	UINT msiRet = MsiOpenPackageExW(szFilename, MSIOPENPACKAGEFLAGS_IGNOREMACHINESTATE, &hProduct);
	if (ERROR_SUCCESS == msiRet)
	{
		// See documentation about the translation to AppLocker formatting above the declaration
		// of the MsiFileInfo_t structure.
		retval = true;
		DWORD dwCchBuffer;
		dwCchBuffer = cchTempBufferSize;
		if (ERROR_SUCCESS == MsiGetProductPropertyW(hProduct, L"ProductName", pszTempBuffer, &dwCchBuffer))
		{
			msiFileInfo.sProductName = pszTempBuffer;
			msiFileInfo.sALProductName = WCharString_To_Upper(pszTempBuffer);
		}
		dwCchBuffer = cchTempBufferSize;
		if (ERROR_SUCCESS == MsiGetProductPropertyW(hProduct, L"ProductCode", pszTempBuffer, &dwCchBuffer))
		{
			msiFileInfo.sProductCode = pszTempBuffer;
			msiFileInfo.sALBinaryName = WCharString_To_Upper(pszTempBuffer);
		}
		dwCchBuffer = cchTempBufferSize;
		if (ERROR_SUCCESS == MsiGetProductPropertyW(hProduct, L"ProductVersion", pszTempBuffer, &dwCchBuffer))
		{
			// Get the raw value
			msiFileInfo.sProductVersion = pszTempBuffer;
			// Split it into substrings at the decimals
			std::vector<std::wstring> vElems;
			SplitStringToVector(msiFileInfo.sProductVersion, L'.', vElems);
			// Initialize new values to all zeroes; if there weren't four numbers in the original
			// there will be.
			DWORD dwVer[4] = { 0 };
			size_t ixVer = 0;
			for (
				std::vector<std::wstring>::const_iterator iterElems = vElems.begin();
				iterElems != vElems.end();
				++iterElems, ++ixVer
				)
			{
				// Convert to number
				swscanf_s(iterElems->c_str(), L"%u", &dwVer[ixVer]);
			}
			// And then back to string (losing any leading zeroes, and getting all the decimal points).
			wsprintfW(pszTempBuffer, L"%u.%u.%u.%u", dwVer[0], dwVer[1], dwVer[2], dwVer[3]);
			// Set the output value
			msiFileInfo.sALBinaryVersion = pszTempBuffer;
		}
		// Close the MSI
		MsiCloseHandle(hProduct);
	}

	// Restore the original UI level.
	MsiSetInternalUI(origUiLevel, NULL);
	delete[] pszTempBuffer;
	CoUninitialize();
	return retval;
}
