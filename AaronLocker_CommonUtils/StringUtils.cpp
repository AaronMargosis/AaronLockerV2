#include "pch.h"
#include "StringUtils.h"

// ----------------------------------------------------------------------------------------------------
/// <summary>
/// Compares the specified number of characters of two strings without regard to case.
/// Replacement for Microsoft CRT function, _wcsnicmp
/// </summary>
/// <param name="string1">Null-terminated string to compare</param>
/// <param name="string2">Null-terminated string to compare</param>
/// <param name="count">Maximum number of characters to compare</param>
/// <returns>0 if all compared characters are the same (case-insensitive); negative number if string1 less than string2; positive number if string1 is greater than string2.</returns>
int StringCompareNumberedCaseInsensitive(const wchar_t* string1, const wchar_t* string2, size_t count)
{
	if (0 == count)
		return 0;

	std::locale loc("");

	const wchar_t* p1 = string1;
	const wchar_t* p2 = string2;

	while (count-- > 0)
	{
		wchar_t c1 = std::tolower(*p1++, loc);
		wchar_t c2 = std::tolower(*p2++, loc);
		int result = c1 - c2;
		if (0 != result || 0 == c1)
			return result;
	}
	return 0;
}

/// <summary>
/// Compares two strings without regard to case.
/// Replacement for Microsoft CRT function, _wcsicmp
/// </summary>
/// <param name="string1">Null-terminated string to compare</param>
/// <param name="string2">Null-terminated string to compare</param>
/// <returns>0 if strings are the same (case-insensitive); negative number if string1 less than string2; positive number if string1 is greater than string2.</returns>
int StringCompareCaseInsensitive(const wchar_t* string1, const wchar_t* string2)
{
	std::locale loc("");

	const wchar_t* p1 = string1;
	const wchar_t* p2 = string2;

	while (true)
	{
		wchar_t c1 = std::tolower(*p1++, loc);
		wchar_t c2 = std::tolower(*p2++, loc);
		int result = c1 - c2;
		if (0 != result || 0 == c1)
			return result;
	}
}

/// <summary>
/// Compares two strings without regard to case.
/// Replacement for Microsoft CRT function, _stricmp
/// </summary>
/// <param name="string1">Null-terminated string to compare</param>
/// <param name="string2">Null-terminated string to compare</param>
/// <returns>0 if strings are the same (case-insensitive); negative number if string1 less than string2; positive number if string1 is greater than string2.</returns>
int StringCompareCaseInsensitive(const char* string1, const char* string2)
{
	std::locale loc("");

	const char* p1 = string1;
	const char* p2 = string2;

	while (true)
	{
		char c1 = std::tolower(*p1++, loc);
		char c2 = std::tolower(*p2++, loc);
		int result = c1 - c2;
		if (0 != result || 0 == c1)
			return result;
	}
}

// ----------------------------------------------------------------------------------------------------
/// <summary>
/// Similar to .NET's string split method, returns a vector of substrings of the input string based
/// on the supplied delimiter.
/// </summary>
/// <param name="strInput">Input: string from which to return substrings</param>
/// <param name="delim">Input: delimiter character to separate substrings</param>
/// <param name="elems">Output: vector of substrings</param>
void SplitStringToVector(const std::wstring& strInput, wchar_t delim, std::vector<std::wstring>& elems)
{
	elems.clear();
	// If input string is zero length, return a zero-length vector.
	if (strInput.length() == 0)
		return;
	std::wstringstream ss(strInput);
	std::wstring item;
	// Get everything up to EOF. Problem with testing operator bool() on getline's return value is that
	// if the string ends with a delimiter, the last field ends up getting dropped. This technique
	// fixes that.
	do {
		std::getline(ss, item, delim);
		elems.push_back(item);
	} while (!ss.eof());
}

/// <summary>
/// Similar to .NET's string split method, returns a vector of substrings of the input string split
/// on LF or CR+LF (\n or \r\n) regardless of platform.
/// </summary>
/// <param name="strInput">Input: string from which to return substrings</param>
/// <param name="elems">Output: vector of substrings</param>
void SplitStringToVectorCRLF(const std::wstring& strInput, std::vector<std::wstring>& elems)
{
	elems.clear();
	// If input string is zero length, return a zero-length vector.
	if (strInput.length() == 0)
		return;
	std::wstringstream ss(strInput);
	std::wstring item;
	// Get everything up to EOF. Problem with testing operator bool() on getline's return value is that
	// if the string ends with a delimiter, the last field ends up getting dropped. This technique
	// fixes that.
	do {
		// Split on \n.
		std::getline(ss, item, L'\n');
		// If the remaining line ends with \r, remove it before adding to the output vector.
		if (item.size() > 0 && L'\r' == item[item.size() - 1])
			item.resize(item.size() - 1);
		elems.push_back(item);
	} while (!ss.eof());
}

// ----------------------------------------------------------------------------------------------------
/// <summary>
/// Replace all instances of one substring with another.
/// </summary>
/// <param name="str">The original string</param>
/// <param name="replace">The substring to search for</param>
/// <param name="with">The substring to put into the result in place of the searched-for substring</param>
/// <returns>The modified string</returns>
std::wstring replaceStringAll(std::wstring str,
	const std::wstring& replace,
	const std::wstring& with) {
	if (!replace.empty()) {
		std::size_t pos = 0;
		while ((pos = str.find(replace, pos)) != std::string::npos) {
			str.replace(pos, replace.length(), with);
			pos += with.length();
		}
	}
	return str;
}

// ----------------------------------------------------------------------------------------------------
/// <summary>
/// Encodes string for XML. E.g., EncodeForXml(L"<root>") returns "&lt;root&gt;".
/// </summary>
std::wstring EncodeForXml(const wchar_t* sz)
{
	// Handle null or empty strings quickly.
	if (!sz || !*sz)
		return L"";

	std::wstring retval(wcslen(sz) * 4, 0); // pre-allocate some bytes to avoid reallocation
	retval = L"";
	for (const wchar_t* pSz = sz; *pSz; ++pSz)
	{
		wchar_t c = *pSz;
		switch (c)
		{
		case L'&':
			retval.append(L"&amp;");
			break;
		case L'<':
			retval.append(L"&lt;");
			break;
		case L'>':
			retval.append(L"&gt;");
			break;
		case L'\'':
			retval.append(L"&apos;");
			break;
		case L'\"':
			retval.append(L"&quot;");
			break;
		default:
			// All other printable characters appended without modification
			if (c >= 0x20)
			{
				retval.append(1, c);
			}
			else
			{
				// Encoding for control characters 0 through 0x1f
				wchar_t buf[8];
				swprintf(buf, sizeof(buf) / sizeof(buf[0]), L"&#x%02X;", (int)(c & 0xFFFF));
				retval.append(buf);
			}
			break;
		}
	}

	return retval;
}

