#pragma once

#include <string>
#include <vector>
#include "../AppLockerFunctionality/AppLockerFileDetails_ftype.h"
#include "../AaronLocker_CommonUtils/ShellLinkInfo_Struct.h"

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Structure providing information for AppLocker publisher-rule exclusions, particularly
/// for files under the Windows directory.
/// Designed to disallow non-admin execution of built-in executables that can be used for AppLocker
/// bypasses or for other nefarious purposes. 
/// </summary>
struct PubInfoForExclusions_t {
	std::wstring m_sPublisherName;
	std::wstring m_sProductName;
	std::wstring m_sBinaryName;

	PubInfoForExclusions_t(
		const std::wstring& sPublisherName,
		const std::wstring& sProductName,
		const std::wstring& sBinaryName
	) : m_sPublisherName(sPublisherName),
		m_sProductName(sProductName),
		m_sBinaryName(sBinaryName)
	{}
};

typedef std::vector<PubInfoForExclusions_t> PubInfoForExclusionsCollecton_t;

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Structure providing information for AppLocker path rules for safe directories.
/// </summary>
struct SafePathInfo_t {
	std::wstring
		m_sLabel, // label that can be used in the rule name and/or description
		m_sPath;  // the file system path

	SafePathInfo_t(
		const std::wstring& sLabel,
		const std::wstring& sPath
	) : m_sLabel(sLabel), m_sPath(sPath)
	{}
};

typedef std::vector<SafePathInfo_t> SafePathInfoCollection_t;

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Structure describing AppLocker-relevant details about files to consider creating rules for.
/// Some of the data is for informational purposes to help a person determine whether to create 
/// rules allowing the file.
/// Implementation note: hash, file size, and file times were binary in the original implementation
/// but are now all strings, both because nothing forward of this code actually needs binary -- text is
/// good -- but also to simplify serialization/deserialization.
/// Original implementation also captured last-access-time, but since it gets updated every time our
/// scan runs, it has no value at all.
/// </summary>
struct FileDetails_t {
	// Determined from outside the file
	std::wstring m_sAppLabel;                    // Information that can be used in rule name/description
	bool m_bIsSafeDir;                           // Safe dir can use path rules; unsafe requires publisher or hash rules
	// Determined from the file itself
	AppLockerFileDetails_ftype_t m_fileType;     // determines which rule collection to use
	std::wstring m_sFilePath;                    // full path to the file
	std::wstring m_sVerProductName;              // Product name from version resource (for information only, not for AppLocker publisher rule)
	std::wstring m_sVerFileDescription;          // File description from version resource
	std::wstring m_sX500CertSigner;              // For a signed file, the full subject name in X.500 form
	std::wstring m_ALPublisherName;              // For a signed file, publisher name for AppLocker rule
	std::wstring m_ALProductName;                // For a signed file, product name for AppLocker rule
	std::wstring m_ALBinaryName;                 // For a signed file, binary name for AppLocker rule
	std::wstring m_ALBinaryVersion;              // For a signed file, binary version for AppLocker rule
	std::wstring m_ALHash;                       // Hash value for hash rules
	std::wstring m_FlatFileHash;                 // Flat file hash (can be used with reputation services)
	std::wstring m_fileSize;                     // File size (can be used in hash rule)
	std::wstring m_PEImageFileMachineType;       // PE image file machine type
	std::wstring m_sSigningTimestamp;            // Date/time of signing, if file is signed and timestamped
	std::wstring m_sPEFileLinkDate;              // Date/time file was linked, if file is a PE file and not a repeatable build (in which the field is not a link date)
	std::wstring m_ftCreateTime;                 // File creation time according to the file system
	std::wstring m_ftLastWriteTime;              // File last write time according to the file system

	FileDetails_t() : // Constructor
		m_bIsSafeDir(false),
		m_fileType(AppLockerFileDetails_ftype_t::ft_Unknown)
	{}
};

typedef std::vector<FileDetails_t> FileDetailsCollection_t;

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Struct to add context to shell link data based on where the link file is located.
/// Useful to apply different precedence on a link's "app name" depending on where the link file is,
/// and subdirectories in the Start Menu can carry helpful information.
/// </summary>
struct ShellLinkDataContext_t : ShellLinkData_t
{
	// Keep these in precedence order of which entries are preferred for determining app name
	// from most preferred to least. Also ensure that the last defined value is used in the
	// definition of numLinkLocations.
	enum class LinkLocation_t {
		AllUsersStartMenu,
		AllUsersDesktop,
		PerUserStartMenu,
		PerUserDesktop,
		Other
	};
	static const size_t numLinkLocations = (size_t)LinkLocation_t::Other + 1;

	/// <summary>
	/// Indicates whether a link file is in the all users' Start Menu, all users' Desktop, etc.
	/// </summary>
	LinkLocation_t linkLocation;

	/// <summary>
	/// Subdirectory/subdirectories under the base Start Menu (whether it's the all-users' or a per-user Start Menu)
	/// </summary>
	std::wstring sLinkRelativeSubdir;
};

typedef std::vector<ShellLinkDataContext_t> ShellLinkDataContextCollection_t;
