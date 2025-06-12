// Class to get info about an MSI file for AppLocke support.
// Equivalent to parts of Get-AppLockerFileInformation / Publisher info.

#pragma once

#include <string>


/// <summary>
/// For the MSI publisher rules, AppLocker can map values from the MSI file's Property table to
/// publisher rule attributes, after applying AppLocker's formatting:
/// MSI property     -> Publisher rule attribute
///   ProductName    ->   ProductName
///   ProductCode    ->   BinaryName
///   ProductVersion ->   BinaryVersion
/// The ProductName and BinaryName values are capitalized in a locale-sensitive way.
/// The ProductVersion is formatted so that there are four numbers separated by decimals,
/// with no leading zeroes. For example, an MSI ProductVersion value of "020.000.1621" is
/// translated to "20.0.1621.0".
/// </summary>
struct MsiFileInfo_t
{
	std::wstring
		// Raw data as retrieved from MSI properties:
		sProductName,      // ProductName property - raw data that maps to AppLocker product name
		sProductCode,      // ProductCode property - raw data that maps to AppLocker "binary" name
		sProductVersion,   // ProductVersion property - raw data that maps to AppLocker binary version
		// Capitalized/formatted versions of those values in the form that AppLocker uses.
		sALProductName,    // IF the file is signed, product name for AppLocker rule, properly capitalized/formatted
		sALBinaryName,     // IF the file is signed, binary name for AppLocker rule, properly capitalized/formatted
		sALBinaryVersion;  // IF the file is signed, binary version for AppLocker rule, properly formatted

	void clear()
	{
		sProductName.clear();
		sProductCode.clear();
		sProductVersion.clear();
		sALProductName.clear();
		sALBinaryName.clear();
		sALBinaryVersion.clear();
	}
};

/// <summary>
/// Class to retrieve MSI-related information about a file to support AppLocker rules
/// </summary>
class MsiFileInfo
{
public:
	/// <summary>
	/// Returns true if the file is a valid Microsoft Installer file (including .msi, .msp, ...)
	/// </summary>
	static bool IsMSI(const wchar_t* szFilename);

	/// <summary>
	/// Retrieves information from an MSI file to support AppLocker rules.
	/// Note that this function does not determine whether the file is signed.
	/// </summary>
	/// <param name="szFilename">Input: the file to inspect</param>
	/// <param name="msiFileInfo">Output: the data retrieved. Note that the sAL* fields should not be used if the file is not signed.</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool Get(const wchar_t* szFilename, MsiFileInfo_t& msiFileInfo);
};