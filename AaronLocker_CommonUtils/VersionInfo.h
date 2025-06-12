#pragma once
#include <Windows.h>
#include <string>

/// <summary>
/// Class to encapsulate retrieval of version resource information, offering both strict and
/// non-strict parsing of string info blocks. AppLocker relies on strict parsing. See the .cpp
/// file for more details about that.
/// </summary>
class VersionInfo
{
public:
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
	static bool GetVersionInfoForAppLocker(
		const wchar_t* szFilepath,
		std::wstring& sProductName,
		std::wstring& sBinaryName,
		WORD& wMajor,
		WORD& wMinor,
		WORD& wBuild,
		WORD& wRevision
	);

	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="szFilepath">File to inspect. (WOW64 file system redirection is disabled during the call.)</param>
	/// <param name="bStrictParsing">true for strict parsing of string info blocks; false for non-strict parsing.</param>
	VersionInfo(const wchar_t* szFilepath, bool bStrictParsing = false);
	~VersionInfo();

	/// <summary>
	/// Indicates whether the file contains a version resource at all. If so, it can return binary file version numbers.
	/// </summary>
	bool HasVersionInformation() const { return m_bHasVersionInfo; }

	/// <summary>
	/// Returns language-independent (binary) file version numbers, if present.
	/// </summary>
	/// <param name="wMajor"></param>
	/// <param name="wMinor"></param>
	/// <param name="wBuild"></param>
	/// <param name="wRevision"></param>
	/// <returns>true if the file has version numbers; false otherwise</returns>
	bool GetBinaryFileVersion(
		WORD& wMajor,
		WORD& wMinor,
		WORD& wBuild,
		WORD& wRevision
	);
	/// <summary>
	/// Returns language-indepedent (binary) file version as a string in a.b.c.d format.
	/// Returns an empty string if the file doesn't have a version resource.
	/// </summary>
	std::wstring BinaryFileVersion();

	/// <summary>
	/// Returns CompanyName from the version resource, if present.
	/// </summary>
	std::wstring CompanyName();
	/// <summary>
	/// Returns FileDescription from the version resource, if present.
	/// </summary>
	std::wstring FileDescription();
	/// <summary>
	/// Returns ProductName from the version resource, if present.
	/// </summary>
	std::wstring ProductName();
	/// <summary>
	/// Returns the value, if present, for the input version resource string.
	/// The following names are documented/recommended, but version resources
	/// can have arbitrary names in them.
	///      Comments
	///      CompanyName
	///      FileDescription
	///      FileVersion
	///      InternalName
	///      LegalCopyright
	///      LegalTrademarks
	///      OriginalFilename
	///      PrivateBuild
	///      ProductName
	///      ProductVersion
	///      SpecialBuild
	/// </summary>
	/// <param name="szStringName">Version string to look for</param>
	/// <returns>Value of the string, if present; empty string otherwise</returns>
	std::wstring StringName(const wchar_t* szStringName);

private:
	/// <summary>
	/// Internal function that tries to retrieve a version resource string, with optional
	/// locale-sensitive upper-casing compatible with AppLocker.
	/// Depending on the strict-parsing setting, searches only a specific StringFileInfo block
	/// or multiple StringFileInfo blocks if needed.
	/// </summary>
	/// <param name="szStringName">Version string to look for</param>
	/// <param name="bUpperCase">true for locale-sensitive upper-casing; false to retrieve the value as is</param>
	/// <returns>Value of the string, if present; empty string otherwise</returns>
	std::wstring StringName(const wchar_t* szStringName, bool bUpperCase);

	/// <summary>
	/// Internal function that tries to retrieve a version resource string from a specific StringFileInfo
	/// block (language and code page), with optional locale-sensitive upper-casing.
	/// </summary>
	/// <param name="szStringName"></param>
	/// <param name="bUpperCase"></param>
	/// <param name="wLanguage"></param>
	/// <param name="wCodePage"></param>
	/// <param name="sStringValue"></param>
	/// <returns></returns>
	bool StringName(const wchar_t* szStringName, bool bUpperCase, WORD wLanguage, WORD wCodePage, std::wstring& sStringValue);

private:
	// Data
	// Version resource buffer
	byte* m_pBytes;
	// Determines whether to implement strict parsing rules
	bool m_bStrictParsing;
	// Indicates whether the file has a version resource
	bool m_bHasVersionInfo;
	// Indicates whether the file's version resource specified language and code page in
	// a \VarFileInfo\Translation block.
	bool m_bHasLangCodepageCodes;
	// Language and code page retrieved from the file's \VarFileInfo\Translation block
	WORD m_wLanguage, m_wCodePage;
	// Language-independent (binary) file version values retrieved from the VS_FIXEDFILEINFO structure 
	// during initial parsing
	WORD m_wMajor, m_wMinor, m_wBuild, m_wRevision;

private:
	// Not implemented
	VersionInfo(const VersionInfo&) = delete;
	VersionInfo& operator = (const VersionInfo&) = delete;
};

