// Implementation for serializing full- or one-directory-scans to an output stream.

#include "pch.h"
#include "AaronLockerSerializer.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "CommonDefs.h"


// ------------------------------------------------------------------------------------------
// Implemented with internal functions that aren't exposed in the class interface so that internal
// changes aren't reflected in the class interface.
static bool SerializeStartFull(std::wostream& os);
static bool SerializeStartOneDirectory(const std::wstring& sDirectoryName, const std::wstring& sAppname, std::wostream& os);
static bool SerializeHeaderInfo(const SYSTEMTIME& stScanStarted, const SYSTEMTIME& stScanEnded, std::wostream& os);
static bool SerializeErrorInfo(const std::wstring& sErrorInfo, std::wostream& os);
static bool SerializeUnsafeDirs(const wchar_t* szLabel, const UnsafeDirectoryCollection_t& unsafeSubdirs, std::wostream& os);
//static bool SerializePubInfoForWinExclusions(const PubInfoForExclusionsCollecton_t& pubInfoForWinExclusions, std::wostream& os);
static bool SerializeSafePathInfo(const SafePathInfoCollection_t& platSafePathInfo, std::wostream& os);
static bool SerializeFileDetails(const FileDetailsCollection_t& fileDetails, std::wostream& os);
static bool SerializePackagedAppInfo(const PackagedAppInfoCollection_t& pkgInfoCollection, std::wostream& os);
static bool SerializeShellLinks(const ShellLinkDataContextCollection_t& shellLinks, std::wostream& os, bool bIncludeHeader);

// ------------------------------------------------------------------------------------------

// Serializes a full scan
bool AaronLockerSerializer::Serialize(const EndpointFullScan& scan, std::wostream& os)
{
	SerializeStartFull(os);
	SerializeHeaderInfo(scan.GetStartTime(), scan.GetEndTime(), os);
	SerializeErrorInfo(scan.ErrorInfo(), os);
	SerializeUnsafeDirs(szHeader_UnsafeDirectoriesWindows, scan.ScanResults_UnsafeWindowsSubdirs(), os);
	SerializeUnsafeDirs(szHeader_UnsafeDirectoriesProgramFiles, scan.ScanResults_UnsafeProgFilesSubdirs(), os);
	//SerializePubInfoForWinExclusions(scan.ScanResults_PubInfoForWindowsExclusions(), os);
	SerializeSafePathInfo(scan.ScanResults_PlatformSafePathInfo(), os);
	SerializeFileDetails(scan.ScanResults_FileDetails(), os);
	SerializePackagedAppInfo(scan.ScanResults_InstalledPackagedApps(), os);
	//TODO: These scan results won't be needed for rule-processing, but keep them in for now so that the link-to-appname processing can be improved.
	SerializeShellLinks(scan.ScanResults_ShellLinks(), os, true);

	return true;
}

// Serializes a single-directory scan
bool AaronLockerSerializer::Serialize(const EndpointOneDirectoryScan& scan, const std::wstring& sDirectoryName, const std::wstring& sAppname, std::wostream& os)
{
	SerializeStartOneDirectory(sDirectoryName, sAppname, os);
	SerializeHeaderInfo(scan.GetStartTime(), scan.GetEndTime(), os);
	SerializeErrorInfo(scan.ErrorInfo(), os);
	SerializeFileDetails(scan.ScanResults_FileDetails(), os);
	//TODO: These scan results won't be needed for rule-processing, but keep them in for now so that the link-to-appname processing can be improved.
	SerializeShellLinks(scan.ScanResults_ShellLinks(), os, true);

	return true;
}

bool AaronLockerSerializer::Serialize(const EndpointScan_Links& scan, std::wostream& os)
{
	SerializeShellLinks(scan.ScanResults(), os, false);

	return true;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Get computer name to include in the serialized output.
/// </summary>
static std::wstring ComputerName()
{
	std::wstring retval;
	DWORD bufsize = 0;
	GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, NULL, &bufsize);
	if (bufsize > 0)
	{
		wchar_t* szBuffer = new wchar_t[bufsize];
		if (GetComputerNameExW(ComputerNamePhysicalDnsFullyQualified, szBuffer, &bufsize))
		{
			retval = szBuffer;
		}
		delete[] szBuffer;
	}
	return retval;
}

// ------------------------------------------------------------------------------------------

bool SerializeStartFull(std::wostream& os)
{
	os 
		<< szHeader_ScanTypeFull << std::endl
		;

	return true;
}

bool SerializeStartOneDirectory(const std::wstring& sDirectoryName, const std::wstring& sAppname, std::wostream& os)
{
	os
		<< szHeader_ScanTypeDirectory << std::endl
		<< sDirectoryName << std::endl
		<< sAppname << std::endl
		;
	
	return true;
}

bool SerializeHeaderInfo(const SYSTEMTIME& stScanStarted, const SYSTEMTIME& stScanEnded, std::wostream& os)
{
	// Common header information: computer name, the scan's start/end times, and selected directory mappings on the scanned system.
	os
		<< szHeader_ComputerName << ComputerName() << std::endl
		<< szHeader_ScanStarted << SystemTimeToWString(stScanStarted) << std::endl
		<< szHeader_ScanEnded << SystemTimeToWString(stScanEnded) << std::endl
		<< szHeader_WindowsDirectories << std::endl
		<< WindowsDirectories::SystemDriveDirectory() << std::endl
		<< WindowsDirectories::WindowsDirectory() << std::endl
		<< WindowsDirectories::ProgramFiles() << std::endl
		<< WindowsDirectories::ProgramFilesX86() << std::endl
		<< std::endl
		;

	return true;
}

bool SerializeErrorInfo(const std::wstring& sErrorInfo, std::wostream& os)
{
	os << szHeader_ErrorInfo << std::endl;

	// Any error information from the scan operation, with blank lines removed.
	std::vector<std::wstring> vLines;
	SplitStringToVectorCRLF(sErrorInfo, vLines);
	for (
		std::vector<std::wstring>::const_iterator iterLine = vLines.begin();
		iterLine != vLines.end();
		++iterLine
		)
	{
		if (iterLine->size() > 0)
		{
			os << *iterLine << std::endl;
		}
	}
	os << std::endl;

	return true;
}

bool SerializeUnsafeDirs(const wchar_t* szLabel, const UnsafeDirectoryCollection_t& unsafeSubdirs, std::wostream& os)
{
	os 
		// The specific header for Windows or ProgramFiles (szLabel)
		<< szLabel << std::endl;
	os
		// CSV headers for the coming data
		<< L"FileSystemPath" << szDelim
		<< L"NeedsADSExclusion" << szDelim
		<< L"NonAdminSIDs" << std::endl;
	UnsafeDirectoryCollection_t::const_iterator iterUnsafeDirInfo;
	for (
		iterUnsafeDirInfo = unsafeSubdirs.begin();
		iterUnsafeDirInfo != unsafeSubdirs.end();
		++iterUnsafeDirInfo
		)
	{
		/*
			std::wstring  m_sFileSystemPath;
			bool          m_bNeedsAltDataStreamExclusion;
			std::wstring  m_nonadminSids;
		*/
		os
			<< iterUnsafeDirInfo->m_sFileSystemPath << szDelim
			<< Bool2Str(iterUnsafeDirInfo->m_bNeedsAltDataStreamExclusion) << szDelim
			<< iterUnsafeDirInfo->m_nonadminSids << std::endl;
	}
	os << std::endl;

	return true;
}

// Not needed at this time. Leaving it in, commented, just in case.
//bool SerializePubInfoForWinExclusions(const PubInfoForExclusionsCollecton_t& pubInfoForWinExclusions, std::wostream& os)
//{
//	os 
//		// The header for this section
//		<< szHeader_PubInfoWindowsDirExclusions << std::endl;
//	os
//		// CSV headers for the coming data
//		<< L"PublisherName" << szDelim
//		<< L"ProductName" << szDelim
//		<< L"BinaryName" << std::endl;
//
//	PubInfoForExclusionsCollecton_t::const_iterator iterWinExclusionInfo;
//	for (
//		iterWinExclusionInfo = pubInfoForWinExclusions.begin();
//		iterWinExclusionInfo != pubInfoForWinExclusions.end();
//		++iterWinExclusionInfo
//		)
//	{
//		/*
//			std::wstring m_sPublisherName;
//			std::wstring m_sProductName;
//			std::wstring m_sBinaryName;
//		*/
//		os
//			<< iterWinExclusionInfo->m_sPublisherName << szDelim
//			<< iterWinExclusionInfo->m_sProductName << szDelim
//			<< iterWinExclusionInfo->m_sBinaryName << std::endl;
//	}
//	os << std::endl;
//
//	return true;
//}

bool SerializeSafePathInfo(const SafePathInfoCollection_t& platSafePathInfo, std::wostream& os)
{
	os 
		<< szHeader_PlatformSafePathInfo << std::endl;
	os
		<< L"Label" << szDelim
		<< L"Path" << std::endl;
	SafePathInfoCollection_t::const_iterator iterSafePathInfo;
	for (
		iterSafePathInfo = platSafePathInfo.begin();
		iterSafePathInfo != platSafePathInfo.end();
		++iterSafePathInfo
		)
	{
		/*
			std::wstring
				m_sLabel, // label that can be used in the rule name and/or description
				m_sPath;  // the file system path
		*/
		os
			<< iterSafePathInfo->m_sLabel << szDelim
			<< iterSafePathInfo->m_sPath << std::endl;
	}
	os << std::endl;

	return true;
}

bool SerializeFileDetails(const FileDetailsCollection_t& fileDetails, std::wostream& os)
{
	os 
		// Header for this section
		<< szHeader_FileDetails << std::endl;
	os
		// CSV headers for the coming data
		<< L"AppLabel" << szDelim
		<< L"IsSafeDir" << szDelim
		<< L"FileType" << szDelim
		<< L"FilePath" << szDelim
		<< L"VerProductName" << szDelim
		<< L"VerFileDescription" << szDelim
		<< L"X500CertSigner" << szDelim
		<< L"ALPublisherName" << szDelim
		<< L"ALProductName" << szDelim
		<< L"ALBinaryName" << szDelim
		<< L"ALBinaryVersion" << szDelim
		<< L"ALHash" << szDelim
		<< L"FileSize" << szDelim
		<< L"SigningTimestamp" << szDelim
		<< L"PEFileLinkDate" << szDelim
		<< L"CreateTime" << szDelim
		<< L"LastWriteTime" << std::endl;

	FileDetailsCollection_t::const_iterator iterFileDetails;
	for (
		iterFileDetails = fileDetails.begin();
		iterFileDetails != fileDetails.end();
		++iterFileDetails
		)
	{
		/*
			// Determined from outside the file
			std::wstring m_sAppLabel;                    // Information that can be used in rule name/description
			bool m_bIsSafeDir;                           // Safe dir can use path rules; unsafe requires publisher or hash rules
			// Determined from the file itself
			AppLockerFileDetails_ftype_t m_fileType;    // determines which rule collection to use
			std::wstring m_sFilePath;                    // full path to the file
			std::wstring m_sVerProductName;              // Product name from version resource (for information only, not for AppLocker publisher rule)
			std::wstring m_sVerFileDescription;          // File description from version resource
			std::wstring m_sX500CertSigner;              // For a signed file, the full subject name in X.500 form
			std::wstring m_ALPublisherName;              // For a signed file, publisher name for AppLocker rule
			std::wstring m_ALProductName;                // For a signed file, product name for AppLocker rule
			std::wstring m_ALBinaryName;                 // For a signed file, binary name for AppLocker rule
			std::wstring m_ALBinaryVersion;              // For a signed file, binary version for AppLocker rule
			std::wstring m_ALHash;                       // Hash value for hash rules
			std::wstring m_fileSize;                     // File size (can be used in hash rule)
			std::wstring m_sSigningTimestamp;            // Date/time of signing, if file is signed and timestamped
			std::wstring m_sPEFileLinkDate;              // Date/time file was linked, if file is a PE file and not a repeatable build (in which the field is not a link date)
			std::wstring m_ftCreateTime;                 // File creation time according to the file system
			std::wstring m_ftLastWriteTime;              // File last write time according to the file system
		*/
		os
			<< iterFileDetails->m_sAppLabel << szDelim
			<< Bool2Str(iterFileDetails->m_bIsSafeDir) << szDelim
			<< FType2Str(iterFileDetails->m_fileType) << szDelim
			<< iterFileDetails->m_sFilePath << szDelim
			<< iterFileDetails->m_sVerProductName << szDelim
			<< iterFileDetails->m_sVerFileDescription << szDelim
			<< iterFileDetails->m_sX500CertSigner << szDelim
			<< iterFileDetails->m_ALPublisherName << szDelim
			<< iterFileDetails->m_ALProductName << szDelim
			<< iterFileDetails->m_ALBinaryName << szDelim
			<< iterFileDetails->m_ALBinaryVersion << szDelim
			<< iterFileDetails->m_ALHash << szDelim
			<< iterFileDetails->m_fileSize << szDelim
			<< iterFileDetails->m_sSigningTimestamp << szDelim
			<< iterFileDetails->m_sPEFileLinkDate << szDelim
			<< iterFileDetails->m_ftCreateTime << szDelim
			<< iterFileDetails->m_ftLastWriteTime << std::endl;
	}
	os << std::endl;

	return true;
}

bool SerializePackagedAppInfo(const PackagedAppInfoCollection_t& pkgInfoCollection, std::wostream& os)
{
	// Section header
	os << szHeader_PackagedAppInfo << std::endl;

	os
		<< L"Name" << szDelim
		<< L"FullName" << szDelim
		<< L"DisplayName" << szDelim
		<< L"Publisher" << szDelim
		<< L"PublisherDisplayName" << szDelim
		<< L"Version" << szDelim
		<< L"SignatureKind" << szDelim
		<< L"InstallLocation" << szDelim
		<< L"Architecture" << std::endl;

	for (
		PackagedAppInfoCollection_t::const_iterator iter = pkgInfoCollection.begin();
		iter != pkgInfoCollection.end();
		iter++
		)
	{
		os
			<< iter->Name << szDelim
			<< iter->FullName << szDelim
			<< iter->DisplayName << szDelim
			<< iter->Publisher << szDelim
			<< iter->PublisherDisplayName << szDelim
			<< iter->Version << szDelim
			<< iter->SignatureKind << szDelim
			<< iter->InstallLocation << szDelim
			<< iter->Architecture << std::endl;
	}

	os << std::endl;

	return true;
}

bool SerializeShellLinks(const ShellLinkDataContextCollection_t& shellLinks, std::wostream& os, bool bIncludeHeader)
{
	if (bIncludeHeader)
	{
		os << szHeader_ShellLinks << std::endl;
	}

	os
		<< L"Link name" << szDelim
		<< L"Localized" << szDelim
		<< L"App path" << szDelim
		<< L"Arguments" << szDelim
		<< L"Description" << szDelim
		<< L"Link path" << szDelim
		<< L"Link base location" << szDelim
		<< L"Link relative path"
		<< std::endl;

	ShellLinkDataContextCollection_t::const_iterator iterLinkData;
	for (
		iterLinkData = shellLinks.begin();
		iterLinkData != shellLinks.end();
		++iterLinkData
		)
	{
		os
			<< iterLinkData->sLinkName << szDelim
			<< iterLinkData->sLocalizedName << szDelim
			<< iterLinkData->sFileSystemPath << szDelim
			<< iterLinkData->sArguments << szDelim
			<< iterLinkData->sDescription << szDelim
			<< iterLinkData->sFullLinkPath << szDelim
			<< LinkLocation2Str(iterLinkData->linkLocation) << szDelim
			<< iterLinkData->sLinkRelativeSubdir
			<< std::endl;
	}

	if (bIncludeHeader)
	{
		os << std::endl;
	}

	return true;
}

