// String utility functions (Windows-specific).

#pragma once

#include <Windows.h>
#include <string>
#include <locale>
#include <vector>


/// <summary>
/// Convert a SYSTEMTIME to a wstring in the form "yyyy-MM-dd HH:mm:ss.fff"
/// </summary>
inline std::wstring SystemTimeToWString(const SYSTEMTIME& st)
{
	wchar_t szTimestamp[32];
	swprintf(szTimestamp, sizeof(szTimestamp)/sizeof(szTimestamp[0]), L"%04d-%02d-%02d %02d:%02d:%02d.%03d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	return std::wstring(szTimestamp);
}

/// <summary>
/// Convert a FILETIME to a wstring in the form "yyyy-MM-dd HH:mm:ss"
/// Not including milliseconds, which aren't always tracked in file times; 
/// and Excel can natively treat this format as a date/time if it doesn't have milliseconds.
/// If bCheckForZero is true and input value is 0, returns "None."
/// </summary>
inline std::wstring FileTimeToWString(const FILETIME& ft, bool bCheckForZero = false)
{
	if (bCheckForZero && (0 == ft.dwHighDateTime && 0 == ft.dwLowDateTime))
		return L"None";

	SYSTEMTIME st;
	FileTimeToSystemTime(&ft, &st);
	wchar_t szTimestamp[32];
	swprintf(szTimestamp, sizeof(szTimestamp) / sizeof(szTimestamp[0]), L"%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	return std::wstring(szTimestamp);
}

/// <summary>
/// Convert time_t to FILETIME
/// </summary>
inline void TimetToFileTime(const time_t& t, FILETIME& ft)
{
	LONGLONG ll = Int32x32To64(t, 10000000) + 116444736000000000;
	ft.dwLowDateTime = (DWORD)ll;
	ft.dwHighDateTime = ll >> 32;
}

/// <summary>
/// Convert a time_t to a wstring in the form "yyyy-MM-dd HH:mm:ss"
/// Not including milliseconds, which aren't always tracked in file times; 
/// and Excel can natively treat this format as a date/time if it doesn't have milliseconds.
/// If bCheckForZero is true and input value is 0, returns "None."
/// </summary>
inline std::wstring TimeTToWString(const time_t& t, bool bCheckForZero = false)
{
	if (bCheckForZero && (0 == t))
		return L"None";

	FILETIME ft;
	TimetToFileTime(t, ft);
	return FileTimeToWString(ft);
}

/// <summary>
/// Convert a GUID to a wide-character string
/// </summary>
/// <param name="guid">Input: binary GUID to convert</param>
/// <returns>GUID converted to wide-character string</returns>
std::wstring GuidToString(const GUID& guid);
