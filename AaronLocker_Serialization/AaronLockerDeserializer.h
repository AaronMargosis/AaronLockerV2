// Interface for deserializing a full- or one-directory-scan from a file.

#pragma once

#include "../DirectorySafetyFunctions/DirectorySafetyStructs.h"
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Structs.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"


class AaronLockerDeserializer
{
public:
	AaronLockerDeserializer();
	// Default implementation of dtor, cctor, and assignment
	~AaronLockerDeserializer() = default;
	AaronLockerDeserializer(const AaronLockerDeserializer&) = default;
	AaronLockerDeserializer& operator = (const AaronLockerDeserializer&) = default;

public:
	/// <summary>
	/// Reads content from a file and populates the data below
	/// </summary>
	/// <param name="szFilename"></param>
	/// <returns></returns>
	bool Deserialize(const wchar_t* szFilename, std::wstring& sErrorInfo);

public:
	// Data that can be captured through deserialization.
	// Just making them public members...

	// This class can represent multiple types of scan operations
	enum class scantype_t {
		Unknown,
		FullScan,
		OneDirectoryScan
	};
	scantype_t m_scantype;

	// These strings are populated only for one-directory scan:
	std::wstring m_sOneDirScan_Directory, m_sOneDirScan_AppName;

	// Computer the scan was performed on
	std::wstring m_sComputerName;
	// When the scan started and ended
	std::wstring m_sStartTime, m_sEndTime;
	// Windows directories
	std::wstring m_sSystemDrive, m_sWindowsDir, m_sProgramFilesDir, m_sProgramFilesX86Dir;
	// Errors accumulated during the scan
	std::wstring m_sErrorInfo;

	// Populated only for a full scan:
	UnsafeDirectoryCollection_t
		m_unsafeWindowsSubdirs,
		m_unsafeProgFilesSubdirs;
	// Populated only for a full scan:
	PubInfoForExclusionsCollecton_t
		m_PubInfoForWindowsExclusions;
	// Populated only for a full scan:
	SafePathInfoCollection_t
		m_PlatformSafePathInfo;
	// Populated only for a full scan:
	PackagedAppInfoCollection_t
		m_PackagedAppInfo;

	// Populated for full scan or one-directory scan:
	FileDetailsCollection_t
		m_FileDetails;
	ShellLinkDataContextCollection_t
		m_ShellLinks;
};

