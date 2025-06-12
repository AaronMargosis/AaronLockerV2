#include "pch.h"
#include <sstream>
#include <locale>
#pragma comment(lib, "Version.lib")
#include "Wow64FsRedirection.h"
#include "../AaronLocker_CommonUtils/HEX.h"
#include "VersionInfo.h"


// ------------------------------------------------------------------------------------------
/*	Note that some tools do not require strict adherence to StringFileInfo blocks matching the
	declared VarFileInfo\Translation language/codepage(s), so you might see version information
	reported by Windows properties dialogs and by Sysinternals "SigCheck -a" that are not reported
	by "(Get-AppLockerFileInformation -path $file).Publisher" or by "filever.exe -v". For example,
	older versions of Adobe's pepflashplayer.dll (used by Google Chrome and Chromium-based Microsoft 
	Edge) had that problem, so Get-AppLockerFileInformation populated the PublisherName and BinaryVersion
	properties, but left ProductName and BinaryName blank, even though other tools reported
	Adobe's intended values. (That bug was fixed in pepflashplayer.dll the last year or so.)

	This implementation offers strict and non-strict parsing options. The GetVersionInfoForAppLocker 
	static member function uses strict parsing, as AppLocker does.

	(To test with older pepflashplayer.dll files, I found that Adobe no longer makes them available.
	Older Adobe-signed examples are here, but verify before use because this is NOT an official
	source:
	https://www.dll-files.com/pepflashplayer.dll.html )
*/
/*
More detailed notes about non-strict parsing:

Microsoft documentation:
https://docs.microsoft.com/en-us/windows/win32/menurc/version-information
https://docs.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource

First, there isn't a documented or standard way to parse non-standard/misconfigured version information
resources. Even different tools from Microsoft return different results from one another for files with 
non-standard version resources, so there isn't a "right" way to do it. And again, it's not entirely 
critical to get it "right," as AppLocker won't use non-standard version resource information.

Based on my observations from testing:

If the \VarFileInfo\Translation block declares multiple language/codepage tuples, Explorer's file properties
dialog will list those languages, but it appears otherwise to ignore any tuples past the first one when querying
StringFileInfo blocks.

When querying for a specific string name that isn't in the correct StringFileInfo block, Explorer
appears to look for it in 040904b0 (US English, Unicode), then 040904e4 (US English, multilingual), 
then 04090000 (US English, 7-bit ASCII). It will also look for these US English names on French
installs of Windows. The .NET VersionInfo class looks for US English 7-bit ASCII before looking for
others. 

Similarly, Sysinternals SigCheck will look for those US English blocks, but if the \VarFileInfo\Translation
block declared a language/codepage tuple with a language other than 0409 (US English), SigCheck might first 
other codepages with that language before trying US English blocks. For example, if the Translation block 
specified 0x040c, 0x04b0 (French, Unicode), SigCheck will try 040c04e4 (French, multilingual) before trying
with US English.

None of the non-strict tools appear to limit queries just to one StringFileInfo block. If a StringFileInfo
block with a "higher precedence" doesn't have a particular string value, the tools will query other blocks
for it.

Another option to consider when all of the above fails is to perform low-level parsing using the documentation
about data layout here: https://docs.microsoft.com/en-us/windows/win32/menurc/version-information-structures
and identify StringFileInfo blocks with any language and code blocks. (But this has to fall below the
importance threshold at some point, if it hasn't already.)

*/

// ------------------------------------------------------------------------------------------

// Defined version string names needed by the AaronLocker project:
static const wchar_t* const szCompanyName = L"CompanyName";
static const wchar_t* const szFileDescription = L"FileDescription";
static const wchar_t* const szOriginalFilename = L"OriginalFilename";
static const wchar_t* const szProductName = L"ProductName";
/* The full set of version resource string names documented by Microsoft:
	Comments
	CompanyName
	FileDescription
	FileVersion
	InternalName
	LegalCopyright
	LegalTrademarks
	OriginalFilename
	PrivateBuild
	ProductName
	ProductVersion
	SpecialBuild
*/

// ------------------------------------------------------------------------------------------

/// <summary>
/// Retrieves version resource information from the named file, including the binary file version and the 
/// string information returned for the ProductName and OriginalFileName ("BinaryName") from the first
/// VarFileInfo\Translation specified in the version resource.
/// Matches behavior of Get-AppLockerFileInformation's Publisher information for signed files, including
/// for strictness of version resource inspection and for upper-casing returned data.
/// </summary>
/// <param name="szFilename">Input: file to inspect. (WOW64 file system redirection is disabled during the call.)</param>
/// <param name="sProductName">Output: the ProductName value</param>
/// <param name="sBinaryName">Output: the OriginalFilename value ("BinaryName" to AppLocker)</param>
/// <param name="wMajor">Output: binary file version, major number</param>
/// <param name="wMinor">Output: binary file version, minor number</param>
/// <param name="wBuild">Output: binary file version, build number</param>
/// <param name="wRevision">Output: binary file version, revision number</param>
/// <returns>true if at least the binary file version values are returned; false otherwise</returns>
bool VersionInfo::GetVersionInfoForAppLocker(
    const wchar_t* szFilepath, 
    std::wstring& sProductName, 
    std::wstring& sBinaryName, 
    WORD& wMajor, 
    WORD& wMinor, 
    WORD& wBuild, 
    WORD& wRevision)
{
    // Initialize return value
    bool retval = false;
	// VersionInfo with strict parsing
	VersionInfo verinfo(szFilepath, true);
	// Get ProductName and BinaryName strings, upper-cased
	sProductName = verinfo.StringName(szProductName, true);
	sBinaryName = verinfo.StringName(szOriginalFilename, true);
	// Get the binary file version. If this succeeds, return true.
	retval = verinfo.GetBinaryFileVersion(wMajor, wMinor, wBuild, wRevision);
    return retval;
}

/// <summary>
/// Constructor
/// </summary>
/// <param name="szFilepath">File to inspect. (WOW64 file system redirection is disabled during the call.)</param>
/// <param name="bStrictParsing">true for strict parsing of string info blocks; false for non-strict parsing.</param>
VersionInfo::VersionInfo(const wchar_t* szFilepath, bool bStrictParsing)
    : 
	m_pBytes(NULL), 
	m_wMajor(0), 
	m_wMinor(0), 
	m_wBuild(0), 
	m_wRevision(0), 
	m_bHasVersionInfo(false),
	m_bHasLangCodepageCodes(false),
	m_bStrictParsing(bStrictParsing),
	m_wLanguage(0),
	m_wCodePage(0)
{
    if (NULL == szFilepath)
        return;

	// Disable WOW64 file system redirection for the duration of this function.
	// Automatically revert when this object goes out of scope.
	Wow64FsRedirection wow64FSRedir(true);

	DWORD dwHandle = 0;
	const DWORD dwFlags = FILE_VER_GET_NEUTRAL;
	DWORD dwSize = GetFileVersionInfoSizeExW(dwFlags, szFilepath, &dwHandle);
	if (dwSize > 0)
	{
		m_pBytes = new byte[dwSize];
		if (GetFileVersionInfoExW(dwFlags, szFilepath, 0, dwSize, m_pBytes))
		{
			UINT uLen = 0;
			VS_FIXEDFILEINFO* pFFI = NULL;
			BOOL ret = VerQueryValueW(m_pBytes, L"\\", (LPVOID*)&pFFI, &uLen);
			if (ret)
			{
				if (0xfeef04bd == pFFI->dwSignature)
				{
					// Binary version information must come from VS_FIXEDFILEINFO, not from string information blocks.
					// Note that the compatibility/supportedOS manifest needs to be in the executable for the correct
					// file version information to be returned for Windows executables.
					m_wMajor = HIWORD(pFFI->dwFileVersionMS);
					m_wMinor = LOWORD(pFFI->dwFileVersionMS);
					m_wBuild = HIWORD(pFFI->dwFileVersionLS);
					m_wRevision = LOWORD(pFFI->dwFileVersionLS);
					// Successfully retrieved some version information
					m_bHasVersionInfo = true;

					// Retrieve the first LANGANDCODEPAGE defined in the \VarFileInfo\Translation table.
					// With strict parsing (which AppLocker uses), string values can come only from the 
					// "\StringFileInfo\XXXXYYYY" block corresponding to that language and code page.
					typedef struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } LangAndCodePage_t;
					LangAndCodePage_t* pLangAndCodePage = NULL;
					ret = VerQueryValueW(m_pBytes, L"\\VarFileInfo\\Translation", (LPVOID*)&pLangAndCodePage, &uLen);
					if (ret)
					{
						m_wLanguage = pLangAndCodePage[0].wLanguage;
						m_wCodePage = pLangAndCodePage[0].wCodePage;
						m_bHasLangCodepageCodes = true;
					}
				}
			}
		}
		if (!m_bHasVersionInfo)
		{
			delete[] m_pBytes;
			m_pBytes = NULL;
		}
	}
}

VersionInfo::~VersionInfo()
{
    delete[] m_pBytes;
}

bool VersionInfo::GetBinaryFileVersion(WORD& wMajor, WORD& wMinor, WORD& wBuild, WORD& wRevision)
{
	// Set the output parameters to the values we have. However, they are meaningful only if the function returns true.
	wMajor = m_wMajor;
	wMinor = m_wMinor;
	wBuild = m_wBuild;
	wRevision = m_wRevision;
    return m_bHasVersionInfo;
}

std::wstring VersionInfo::BinaryFileVersion()
{
	if (m_bHasVersionInfo)
	{
		// Convert the binary values into a string of the form "0.0.0.0"
		// Max value of a WORD is 65535, so the buffer needs to be at least 24 characters (including nul terminator)
		wchar_t szVersionBuf[32] = { 0 };
		wsprintfW(szVersionBuf, L"%u.%u.%u.%u", m_wMajor, m_wMinor, m_wBuild, m_wRevision);
		return std::wstring(szVersionBuf);
	}
	else
	{
		return std::wstring();
	}
}

std::wstring VersionInfo::CompanyName()
{
	return StringName(szCompanyName);
}

std::wstring VersionInfo::FileDescription()
{
	return StringName(szFileDescription);
}

std::wstring VersionInfo::ProductName()
{
	return StringName(szProductName);
}

std::wstring VersionInfo::StringName(const wchar_t* szStringName)
{
	return StringName(szStringName, false);
}

/// <summary>
/// Internal function that tries to retrieve a version resource string, with optional
/// locale-sensitive upper-casing compatible with AppLocker.
/// Depending on the strict-parsing setting, searches only a specific StringFileInfo block
/// or multiple StringFileInfo blocks if needed.
/// </summary>
/// <param name="szStringName">Version string to look for</param>
/// <param name="bUpperCase">true for locale-sensitive upper-casing; false to retrieve the value as is</param>
/// <returns>Value of the string, if present; empty string otherwise</returns>
std::wstring VersionInfo::StringName(const wchar_t* szStringName, bool bUpperCase)
{
	// Initialize return value (empty string)
	std::wstring sRetval;
	// Make sure it's safe to proceed
	if (NULL != szStringName && NULL != m_pBytes)
	{
		bool bFound = false;
		// If the \VarFileInfo\Translation block specified a language and code page, try that first
		if (m_bHasLangCodepageCodes)
		{
			bFound = StringName(szStringName, bUpperCase, m_wLanguage, m_wCodePage, sRetval);
		}
		// If found and/or if using strict mode, our search is done.
		// Otherwise, continue looking at other blocks
		if (!bFound && !m_bStrictParsing)
		{
			// If specified, use the language specified in the \VarFileInfo\Translation block,
			// and then try US English.
			WORD wLangsToTry[2] = { m_wLanguage, 0x0409 };
			size_t nLangsToTry = 2;
			if (!m_bHasLangCodepageCodes || 0x0409 == m_wLanguage)
			{
				// If the Translation block not specified or if it specified US English,
				// just try US English
				wLangsToTry[0] = 0x0409;
				nLangsToTry = 1;
			}

			// Try the above languages in combination with these code pages.
			WORD wCodePagesToTry[] = {
				0x04b0, // 1200 - Unicode
				0x04e4, // 1252 - Windows multilingual / ANSI Latin 1; Western European (Windows)
				0x0000  // 7-bit ASCII
			};
			size_t nCodePagesToTry = sizeof(wCodePagesToTry) / sizeof(wCodePagesToTry[0]);

			// Try each of the language and code page combinations. Quit if a value is found.
			for (size_t ixLang = 0; !bFound && ixLang < nLangsToTry; ++ixLang)
			{
				for (size_t ixCP = 0; !bFound && ixCP < nCodePagesToTry; ++ixCP)
				{
					bFound = StringName(szStringName, bUpperCase, wLangsToTry[ixLang], wCodePagesToTry[ixCP], sRetval);
				}
			}
		}
	}
	return sRetval;
}

/// <summary>
/// Internal function that tries to retrieve a version resource string from a specific StringFileInfo
/// block (language and code page), with optional locale-sensitive upper-casing.
/// </summary>
/// <param name="szStringName">Input: version string to look for</param>
/// <param name="bUpperCase">Input: true for locale-sensitive upper-casing; false to retrieve the value as is</param>
/// <param name="wLanguage">Input: language of StringFileInfo block to query</param>
/// <param name="wCodePage">Input: codepage of StringFileInfo block to query</param>
/// <param name="sStringValue">Output: the value in the StringFileInfo block, if found</param>
/// <returns>true if value found, false otherwise</returns>
bool VersionInfo::StringName(const wchar_t* szStringName, bool bUpperCase, WORD wLanguage, WORD wCodePage, std::wstring& sStringValue)
{
	// Initialize return value and output parameter.
	bool retval = false;
	sStringValue.clear();

	// Build the string specifying the string value to query.
	// E.g., "\StringFileInfo\040904b0\ProductName"
	std::wstringstream strSfiLC;
	strSfiLC
		<< L"\\StringFileInfo\\"
		<< HEX(wLanguage, 4)
		<< HEX(wCodePage, 4)
		<< L"\\"
		<< szStringName;

	wchar_t* pStringValue = NULL;
	UINT uLen = 0;
	if (VerQueryValueW(m_pBytes, strSfiLC.str().c_str(), (LPVOID*)&pStringValue, &uLen))
	{
		if (bUpperCase)
		{
			// Locale-sensitive upper-casing
			std::locale loc("");
			for (wchar_t* pChar = pStringValue; 0 != *pChar; ++pChar)
				*pChar = std::toupper(*pChar, loc);
		}
		sStringValue = pStringValue;
		retval = true;
	}

	return retval;
}
