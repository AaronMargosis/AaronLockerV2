// Implementation for providing a locale for opening a UTF-8 encoded fstream for reading or writing.
//
//
// *** NOTE that codecvt_* is DEPRECATED beginning in C++17 and nothing replaces it yet. ***
//
//

#include "pch.h"
#include <stdio.h>
#include "Utf8FileUtility.h"

#include <codecvt>

// Microsoft defines std::locale::empty() which returns a transparent locale with no facets.
// Examples online of how to create a locale object with a codecvt spec show using
// empty() as the first parameter to the locale constructor to return. But
// std::locale::empty() does not appear to be part of the standard, so using another
// locale object instead...
static std::locale localeBase("");


const std::locale& Utf8FileUtility::LocaleForReadingUtf8File()
{
	static std::locale loc(localeBase, new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>);
	return loc;
}

const std::locale& Utf8FileUtility::LocaleForWritingUtf8File()
{
	static std::locale loc(localeBase, new std::codecvt_utf8<wchar_t, 0x10ffff, std::generate_header>);
	return loc;
}

const std::locale& Utf8FileUtility::LocaleForWritingUtf8NoHeader()
{
	static std::locale loc(localeBase, new std::codecvt_utf8<wchar_t, 0x10ffff>);
	return loc;
}

const std::locale& Utf8FileUtility::LocaleForReadingUtf16LEFile()
{
	static std::locale loc(localeBase, new std::codecvt_utf16<wchar_t, 0x10ffff, (std::codecvt_mode)(std::little_endian | std::consume_header)>);
	return loc;
}

const std::locale& Utf8FileUtility::LocaleForWritingUtf16LEFile()
{
	static std::locale loc(localeBase, new std::codecvt_utf16<wchar_t, 0x10ffff, (std::codecvt_mode)(std::little_endian | std::generate_header)>);
	return loc;
}

const std::locale& Utf8FileUtility::LocaleForReadingUtf16BEFile()
{
	static std::locale loc(localeBase, new std::codecvt_utf16<wchar_t, 0x10ffff, std::consume_header>);
	return loc;
}

const std::locale& Utf8FileUtility::LocaleForWritingUtf16BEFile()
{
	static std::locale loc(localeBase, new std::codecvt_utf16<wchar_t, 0x10ffff, std::generate_header>);
	return loc;
}

/// <summary>
/// Opens a file stream for reading, imbuing it with the correct std::locale if the file's first bytes
/// are a byte order marker. Also opens the file in binary mode if UTF-16.
/// If this function returns true, the caller must call .close() on the file stream when done with it.
/// </summary>
/// <param name="fs">File stream to operate on.</param>
/// <param name="szFilename">Name of the file to open</param>
/// <returns>true if file stream opened successfully; false otherwise.</returns>
bool Utf8FileUtility::OpenForReadingWithLocale(std::wifstream& fs, const wchar_t* szFilename)
{
	// Open the file and read the first four bytes (need four to identify UTF-32, but this doesn't support UTF-32 at this time.)

	/*
	* Windows API implementation:
		HANDLE hFile = CreateFileW(szFilename, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (INVALID_HANDLE_VALUE == hFile)
			return false;
		DWORD numread = 0;
		byte bomBytes[4] = { 0 };
		BOOL rfRet = ReadFile(hFile, &bomBytes, sizeof(bomBytes), &numread, NULL);
		CloseHandle(hFile);
		if (!rfRet)
			return false;
	*/
	// MSVC C++ offers _wfopen_s, but that's non-standard...
	FILE* fp = NULL;
	_wfopen_s(&fp, szFilename, L"r");
	if (NULL == fp)
		return false;
	byte bomBytes[4] = { 0 };
	size_t numread = fread(bomBytes, sizeof(byte), 4, fp);
	fclose(fp);

	// Not supporting UTF-32
	bool bUtf16LE = false, bUtf16BE = false, bUtf8 = false;

	// UTF-16 little-endian
	if (numread >= 2 && bomBytes[0] == 0xFF && bomBytes[1] == 0xFE)
		bUtf16LE = true;
	// UTF-16 big-endian
	else if (numread >= 2 && bomBytes[0] == 0xFE && bomBytes[1] == 0xFF)
		bUtf16BE = true;
	// UTF-8
	else if (numread >= 3 && bomBytes[0] == 0xEF && bomBytes[1] == 0xBB && bomBytes[2] == 0xBF)
		bUtf8 = true;

	// Mode to open the file with. Need to add in binary for UTF-16 (more important when writing, though)
	std::ios_base::openmode mode = std::ios_base::in;
	if (bUtf16BE || bUtf16LE)
		mode |= std::ios_base::binary;
	fs.open(szFilename, mode);
	if (fs.fail())
		return false;

	// Imbue with appropriate locale depending on BOM.
	if (bUtf8)
		fs.imbue(LocaleForReadingUtf8File());
	else if (bUtf16LE)
		fs.imbue(LocaleForReadingUtf16LEFile());
	else if (bUtf16BE)
		fs.imbue(LocaleForReadingUtf16BEFile());

	return true;
}
