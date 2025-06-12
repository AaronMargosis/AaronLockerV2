// Encapsulate logic for UTF-8 encoding for reading and writing files.

#pragma once

#include <locale>
#include <fstream>

//TODO: Rename "Utf8FileUtility" class, .h and .cpp files to "UnicodeFileUtility," or better "UnicodeStreamUtility."
class Utf8FileUtility
{
public:
	/// <summary>
	/// Returns a locale that can be imbued into an fstream for reading a UTF-8 encoded file with BOM.
	/// </summary>
	static const std::locale& LocaleForReadingUtf8File();

	/// <summary>
	/// Returns a locale that can be imbued into an fstream for writing a UTF-8 encoded file with BOM.
	/// </summary>
	static const std::locale& LocaleForWritingUtf8File();

	/// <summary>
	/// Returns a locale that can be imbued into an fstream for writing a UTF-8 encoded stream without BOM
	/// (e.g., for console output).
	/// </summary>
	static const std::locale& LocaleForWritingUtf8NoHeader();

	/// <summary>
	/// Returns a locale that can be imbued into an fstream for reading a UTF-16 little-endian encoded file with BOM.
	/// </summary>
	static const std::locale& LocaleForReadingUtf16LEFile();

	/// <summary>
	/// Returns a locale that can be imbued into an fstream for writing a UTF-16 little-endian encoded file with BOM.
	/// File should be opened with std::ios_base::binary or it will probably end up corrupted. (CR, LF screw it up.)
	/// </summary>
	static const std::locale& LocaleForWritingUtf16LEFile();

	/// <summary>
	/// Returns a locale that can be imbued into an fstream for reading a UTF-16 big-endian encoded file with BOM.
	/// </summary>
	static const std::locale& LocaleForReadingUtf16BEFile();

	/// <summary>
	/// Returns a locale that can be imbued into an fstream for writing a UTF-16 big-endian encoded file with BOM.
	/// File should be opened with std::ios_base::binary or it will probably end up corrupted. (CR, LF screw it up.)
	/// </summary>
	static const std::locale& LocaleForWritingUtf16BEFile();

	/// <summary>
	/// Opens a file stream for reading, imbuing it with the correct std::locale if the file's first bytes
	/// are a byte order marker. Also opens the file in binary mode if UTF-16.
	/// If this function returns true, the caller must call .close() on the file stream when done with it.
	/// </summary>
	/// <param name="fs">File stream to operate on.</param>
	/// <param name="szFilename">Name of the file to open</param>
	/// <returns>true if file stream opened successfully; false otherwise.</returns>
	static bool OpenForReadingWithLocale(std::wifstream& fs, const wchar_t* szFilename);

};

