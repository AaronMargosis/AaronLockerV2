#include <Windows.h>
#include <sstream>
#include "SysErrorMessage.h"
#include "HEX.h"

// --------------------------------------------------------------------------------

/// <summary>
/// Internal helper function that removes CR and LF characters from the end of a character buffer.
/// Many Windows error messages append CRLF to error text. This function removes those characters.
/// </summary>
/// <returns>The input value, now pointing to a string that no longer ends with CR LF characters.</returns>
wchar_t* RemoveTrailingCRLF(wchar_t* psz)
{
	if (NULL != psz)
	{
		wchar_t* pszEnd = wcschr(psz, L'\0');
		if (NULL != pszEnd) // 
		{
			while (pszEnd > psz && (*pszEnd == L'\0' || *pszEnd == L'\r' || *pszEnd == L'\n'))
				*pszEnd-- = L'\0';
		}
	}
	return psz;
}

static std::wstring SysErrorMessage_Impl(DWORD dwErrCode, bool bWithErrorCode, bool bNtStatus)
{
	LPWSTR pszErrMsg = NULL;
	std::wstringstream sRetval;
	DWORD flags =
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_IGNORE_INSERTS |
		FORMAT_MESSAGE_FROM_SYSTEM;
	HMODULE hModule = NULL;
	if (bNtStatus)
	{
		flags |= FORMAT_MESSAGE_FROM_HMODULE;
		hModule = GetModuleHandleW(L"ntdll.dll");
	}

	DWORD dwFM = FormatMessageW(
		flags,
		hModule,
		dwErrCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPWSTR)&pszErrMsg,
		0,
		NULL);
	if (dwFM)
	{
		sRetval << RemoveTrailingCRLF(pszErrMsg);
		LocalFree(pszErrMsg);
		if (bWithErrorCode)
		{
			sRetval << L" ";
		}
	}
	if (!dwFM || bWithErrorCode)
	{
		// Add error code to return value if explicitly requested or if unable to get human-language text.
		sRetval << L"Error # " << dwErrCode << L" (" << HEX(dwErrCode, 8, true, true) << L")";
	}

	return sRetval.str();
}

/// <summary>
/// Returns human-language error text from a Windows error code
/// </summary>
std::wstring SysErrorMessage(DWORD dwErrCode /*= GetLastError()*/, bool bNtStatus /*= false*/)
{
	return SysErrorMessage_Impl(dwErrCode, false, bNtStatus);
}

/// <summary>
/// Returns human-language error text (including the error code) from a Windows error code
/// </summary>
std::wstring SysErrorMessageWithCode(DWORD dwErrCode /*= GetLastError()*/, bool bNtStatus /*= false*/)
{
	return SysErrorMessage_Impl(dwErrCode, true, bNtStatus);
}

