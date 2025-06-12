// String utility functions.

#pragma once

#include <string>
#include <locale>
#include <vector>
#include <iostream>

// ------------------------------------------------------------------------------------------
/// <summary>
/// Compares the specified number of characters of two strings without regard to case.
/// Replacement for Microsoft CRT function, _wcsnicmp
/// </summary>
/// <param name="string1">Null-terminated string to compare</param>
/// <param name="string2">Null-terminated string to compare</param>
/// <param name="count">Maximum number of characters to compare</param>
/// <returns>0 if all compared characters are the same (case-insensitive); negative number if string1 less than string2; positive number if string1 is greater than string2.</returns>
int StringCompareNumberedCaseInsensitive(const wchar_t* string1, const wchar_t* string2, size_t count);

/// <summary>
/// Compares two strings without regard to case.
/// Replacement for Microsoft CRT function, _wcsicmp
/// </summary>
/// <param name="string1">Null-terminated string to compare</param>
/// <param name="string2">Null-terminated string to compare</param>
/// <returns>0 if strings are the same (case-insensitive); negative number if string1 less than string2; positive number if string1 is greater than string2.</returns>
int StringCompareCaseInsensitive(const wchar_t* string1, const wchar_t* string2);

/// <summary>
/// Compares two strings without regard to case.
/// Replacement for Microsoft CRT function, _wcsicmp
/// </summary>
/// <param name="string1">Null-terminated string to compare</param>
/// <param name="string2">Null-terminated string to compare</param>
/// <returns>0 if strings are the same (case-insensitive); negative number if string1 less than string2; positive number if string1 is greater than string2.</returns>
int StringCompareCaseInsensitive(const char* string1, const char* string2);

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Replacement for std::getline that treats \r\n and \n as line delimiters regardless of platform.
/// If the input line includes an embedded NUL character, the returned string is terminated at that point.
/// </summary>
/// <param name="stream">Input stream</param>
/// <param name="sLine">Output line retrieved from stream</param>
inline std::wistream& StdGetlineCRLF(std::wistream& stream, std::wstring& sLine)
{
	std::getline(stream, sLine);

	// If the retrieved line contains an embedded NUL, terminate the string at that point.
	size_t ixNUL = sLine.find(L'\0');
	if (std::wstring::npos != ixNUL)
		sLine.resize(ixNUL);

	// If the last character in the line is '\r', remove it.
	size_t nSize = sLine.size();
	if (nSize > 0 && L'\r' == sLine[nSize - 1])
		sLine.resize(nSize - 1);

	return stream;
}


// ------------------------------------------------------------------------------------------
/// <summary>
/// Convert a wstring in place to locale-sensitive upper-case
/// </summary>
/// <param name="str"></param>
/// <returns></returns>
inline std::wstring& WString_To_Upper(std::wstring& str)
{
	//TODO: Implement "wchar_t* WString_To_Upper(wchar_t* szStr, size_t count) and remove all separately-declared instances of std::locale used for upper-casing.

	//TODO: Need more testing to verify globally that this matches how AppLocker upper-cases.
	// Verified that loc("") works where locale::empty() or no locale doesn't for
	// upper-casing German character 0xf6 to 0xd6. (O with umlaut.) Example found in signature
	// of "C:\Program Files\Git\bin\bash.exe" on my machine.
	// Tested against Korean in Google Chrome goopdateres_ko.dll; no difference in representation
	// of text by AppLocker nor here. (Does upper-casing have any meaning for Asian languages?)
	//
	// Note also my test results against all wchar_t values 0x0000 to 0xFFFF:
	// ::toupper(c) and ::tolower(c) each change 26 characters out of 65536
	// std::toupper(c, loc) and std::tolower(c, loc) where loc is initialized with "" each change
	//    973 characters out of 65536.
	// std::toupper(c, loc) and std::tolower(c, loc) where loc is std::locale::empty change
	//    943 and 942 characters, respectively.
	std::locale loc("");
	size_t len = str.length();
	for (size_t ix = 0; ix < len; ++ix)
	{
		str[ix] = std::toupper(str[ix], loc);
	}
	return str;
}

/// <summary>
/// Convert a NUL-terminated wide-character string in place to locale-sensitive upper case.
/// </summary>
/// <param name="szString">Input: NUL-terminated wide-character string</param>
/// <returns>Same address as input</returns>
inline wchar_t* WCharString_To_Upper(wchar_t* szString)
{
	// Locale-sensitive upper-casing
	std::locale loc("");
	for (wchar_t* pChar = szString; 0 != *pChar; ++pChar)
		*pChar = std::toupper(*pChar, loc);
	return szString;
}

/// <summary>
/// Convert a wstring in place to locale-sensitive lower-case
/// </summary>
/// <param name="str"></param>
/// <returns></returns>
inline std::wstring& WString_To_Lower(std::wstring& str)
{
	std::locale loc("");
	size_t len = str.length();
	for (size_t ix = 0; ix < len; ++ix)
	{
		str[ix] = std::tolower(str[ix], loc);
	}
	return str;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Similar to .NET's string split method, returns a vector of substrings of the input string based
/// on the supplied delimiter.
/// </summary>
/// <param name="strInput">Input: string from which to return substrings</param>
/// <param name="delim">Input: delimiter character to separate substrings</param>
/// <param name="elems">Output: vector of substrings</param>
void SplitStringToVector(const std::wstring& strInput, wchar_t delim, std::vector<std::wstring>& elems);

/// <summary>
/// Similar to .NET's string split method, returns a vector of substrings of the input string split
/// on LF or CR+LF (\n or \r\n) regardless of platform.
/// </summary>
/// <param name="strInput">Input: string from which to return substrings</param>
/// <param name="elems">Output: vector of substrings</param>
void SplitStringToVectorCRLF(const std::wstring& strInput, std::vector<std::wstring>& elems);


/// <summary>
/// Encodes string for XML. E.g., EncodeForXml(L"<root>") returns "&lt;root&gt;".
/// </summary>
std::wstring EncodeForXml(const wchar_t* sz);


/// <summary>
/// Returns true if the input string "str" starts with the input string "with".
/// Case insensitive by default, can be overridden.
/// </summary>
/// <param name="str">Input: string to inspect</param>
/// <param name="with">Input: substring to test str with</param>
/// <param name="bCaseSensitive">Input: true for case sensitive; false for case-insensitive compare</param>
/// <returns>true if the input string "str" starts with the input string "with"</returns>
inline bool StartsWith(const std::wstring& str, const std::wstring& with, bool bCaseSensitive = false)
{
	if (bCaseSensitive)
	{
		return (0 == wcsncmp(str.c_str(), with.c_str(), with.length()));
	}
	else
	{
		return (0 == StringCompareNumberedCaseInsensitive(str.c_str(), with.c_str(), with.length()));
	}
}

/// <summary>
/// Returns true if the input string "str" ends with the character "chr".
/// </summary>
inline bool EndsWith(const std::wstring& str, wchar_t chr)
{
	size_t len = str.length();
	return (len > 0 && str[len - 1] == chr);
}

/// <summary>
/// Performs case-insensitive string equality comparison
/// </summary>
/// <param name="str1"></param>
/// <param name="str2"></param>
/// <returns>true if the input strings are the same (case insensitive)</returns>
inline bool EqualCaseInsensitive(const std::wstring& str1, const std::wstring& str2)
{
	return (0 == StringCompareCaseInsensitive(str1.c_str(), str2.c_str()));
}

/// <summary>
/// Replace all instances of one substring with another.
/// </summary>
/// <param name="str">The original string</param>
/// <param name="replace">The substring to search for</param>
/// <param name="with">The substring to put into the result in place of the searched-for substring</param>
/// <returns>The modified string</returns>
std::wstring replaceStringAll(std::wstring str,
	const std::wstring& replace,
	const std::wstring& with);


