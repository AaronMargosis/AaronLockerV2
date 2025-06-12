// Interface for deserializing a full- or one-directory-scan from a file.

#include "pch.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "../AaronLocker_CommonUtils/Utf8FileUtility.h"
#include "../AaronLocker_CommonUtils/StringUtils.h"
#include "AaronLockerDeserializer.h"
#include "CommonDefs.h"



AaronLockerDeserializer::AaronLockerDeserializer()
	: m_scantype(scantype_t::Unknown)
{
}

// The whole thing in one function.
bool AaronLockerDeserializer::Deserialize(const wchar_t* szFilename, std::wstring& sErrorInfo)
{
	if (NULL == szFilename)
	{
		sErrorInfo = L"Bad parameter: null pointer";
		return false;
	}

	std::wifstream fs;
	if (!Utf8FileUtility::OpenForReadingWithLocale(fs, szFilename))
	{
		sErrorInfo = L"Error - cannot open file ";
		sErrorInfo += szFilename;
		return false;
	}

	bool retval = true;
	sErrorInfo.clear();

	std::wstringstream strProcessingError;

	// Iterate through looking for defined headers, then process what's under the header until hit a blank line.
	// Note that this makes some assumptions about a well-formed file and doesn't perform as many checks as it
	// could, but at no point should a malformed file cause unexpected code execution. In particular, if the lines
	// after a recognized header don't have the expected number of delimited fields, there's no significant
	// error checking at this time, nor (for the most part) for any other content validation.

	while (fs.good())
	{
		std::wstring sLine;
		StdGetlineCRLF(fs, sLine);
		if (sLine == szHeader_ScanTypeFull)
		{
			// This file represents a full scan
			m_scantype = scantype_t::FullScan;
		}
		else if (sLine == szHeader_ScanTypeDirectory)
		{
			// This file represents a one-directory scan: get the directory and app name on subsequent lines.
			m_scantype = scantype_t::OneDirectoryScan;
			StdGetlineCRLF(fs, m_sOneDirScan_Directory);
			StdGetlineCRLF(fs, m_sOneDirScan_AppName);
		}
		else if (StartsWith(sLine, szHeader_ComputerName, true))
		{
			// ComputerName header followed by the computer name
			m_sComputerName = sLine.substr(wcslen(szHeader_ComputerName));
		}
		else if (StartsWith(sLine, szHeader_ScanStarted, true))
		{
			// ScanStart header followed by the scan's start time (as a string, not parsed further)
			m_sStartTime = sLine.substr(wcslen(szHeader_ScanStarted));
		}
		else if (StartsWith(sLine, szHeader_ScanEnded, true))
		{
			// ScanEnd header followed by the scan's end time (as a string, not parsed further)
			m_sEndTime = sLine.substr(wcslen(szHeader_ScanEnded));
		}
		else if (sLine == szHeader_WindowsDirectories)
		{
			// WindowsDirectories header, followed by the scanned system's system drive, Windows and Program Files directories.
			StdGetlineCRLF(fs, m_sSystemDrive);
			StdGetlineCRLF(fs, m_sWindowsDir);
			StdGetlineCRLF(fs, m_sProgramFilesDir);
			StdGetlineCRLF(fs, m_sProgramFilesX86Dir);
		}
		else if (sLine == szHeader_ErrorInfo)
		{
			// Error information, zero or more lines.
			std::wstringstream strErrorInfo;
			bool bFirstLine = true;
			while (StdGetlineCRLF(fs, sLine).good() && sLine.length() > 0)
			{
				// If there was a previous line, insert an EOL before adding in the new line.
				if (!bFirstLine)
					strErrorInfo << std::endl;
				strErrorInfo << sLine;
				bFirstLine = false;
			}
			m_sErrorInfo = strErrorInfo.str();
		}
		else if (sLine == szHeader_UnsafeDirectoriesWindows)
		{
			// Unsafe directories under the Windows directory.
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine); 
			while (sLine.length() > 0 && fs.good())
			{
				// Each line is expected to have three delimited fields
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				if (3 == vStrings.size())
				{
					m_unsafeWindowsSubdirs.push_back(
						UnsafeDirectoryInfo_t(
							vStrings[0],
							Str2Bool(vStrings[1]),
							vStrings[2]
						)
					);
				}
			}
		}
		else if (sLine == szHeader_UnsafeDirectoriesProgramFiles)
		{
			// Unsafe directories under the Program Files directories.
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine);
			while (sLine.length() > 0 && fs.good())
			{
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				// Each line is expected to have three delimited fields
				if (3 == vStrings.size())
				{
					m_unsafeProgFilesSubdirs.push_back(
						UnsafeDirectoryInfo_t(
							vStrings[0],
							Str2Bool(vStrings[1]),
							vStrings[2]
						)
					);
				}
			}
		}
		else if (sLine == szHeader_PubInfoWindowsDirExclusions)
		{
			// Publisher information of EXE files to exclude under the Windows directory.
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine);
			while (sLine.length() > 0 && fs.good())
			{
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				if (3 == vStrings.size())
				{
					m_PubInfoForWindowsExclusions.push_back(
						PubInfoForExclusions_t(
							vStrings[0],
							vStrings[1],
							vStrings[2]
						)
					);
				}
			}
		}
		else if (sLine == szHeader_PlatformSafePathInfo)
		{
			// Information about known safe paths outside of the Windows/PF directories (e.g., AV files under ProgramData)
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine);
			while (sLine.length() > 0 && fs.good())
			{
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				if (2 == vStrings.size())
				{
					// Two fields: app name/label, and directory path.
					m_PlatformSafePathInfo.push_back(
						SafePathInfo_t(
							vStrings[0],
							vStrings[1]
						)
					);
				}
			}
		}
		else if (sLine == szHeader_FileDetails)
		{
			// AppLocker-relevant details about files to consider creating rules for.
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine);
			while (sLine.length() > 0 && fs.good())
			{
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				if (17 == vStrings.size())
				{
					FileDetails_t fileDetails;
					size_t ix = 0;
					fileDetails.m_sAppLabel = vStrings[ix++];
					fileDetails.m_bIsSafeDir = Str2Bool(vStrings[ix++]);
					fileDetails.m_fileType = Str2FType(vStrings[ix++]);
					fileDetails.m_sFilePath = vStrings[ix++];
					fileDetails.m_sVerProductName = vStrings[ix++];
					fileDetails.m_sVerFileDescription = vStrings[ix++];
					fileDetails.m_sX500CertSigner = vStrings[ix++];
					fileDetails.m_ALPublisherName = vStrings[ix++];
					fileDetails.m_ALProductName = vStrings[ix++];
					fileDetails.m_ALBinaryName = vStrings[ix++];
					fileDetails.m_ALBinaryVersion = vStrings[ix++];
					fileDetails.m_ALHash = vStrings[ix++];
					fileDetails.m_fileSize = vStrings[ix++];
					fileDetails.m_sSigningTimestamp = vStrings[ix++];
					fileDetails.m_sPEFileLinkDate = vStrings[ix++];
					fileDetails.m_ftCreateTime = vStrings[ix++];
					fileDetails.m_ftLastWriteTime = vStrings[ix++];
					m_FileDetails.push_back(fileDetails);
				}
			}
		}
		else if (sLine == szHeader_PackagedAppInfo)
		{
			// Information about all installed packaged apps on the endpoint (Win8.1/WS2012R2 and newer)
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine);
			while (sLine.length() > 0 && fs.good())
			{
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				if (9 == vStrings.size())
				{
					PackagedAppInfo_t data;
					size_t ix = 0;
					data.Name = vStrings[ix++];
					data.FullName = vStrings[ix++];
					data.DisplayName = vStrings[ix++];
					data.Publisher = vStrings[ix++];
					data.PublisherDisplayName = vStrings[ix++];
					data.Version = vStrings[ix++];
					data.SignatureKind = vStrings[ix++];
					data.InstallLocation = vStrings[ix++];
					data.Architecture = vStrings[ix++];
					m_PackagedAppInfo.push_back(data);
				}
			}
		}
		else if (sLine == szHeader_ShellLinks)
		{
			// Information gathered from shortcut files to help map file locations to app names
			// Throw away the CSV headers
			StdGetlineCRLF(fs, sLine);
			while (sLine.length() > 0 && fs.good())
			{
				StdGetlineCRLF(fs, sLine);
				std::vector<std::wstring> vStrings;
				SplitStringToVector(sLine, chrDelim, vStrings);
				if (8 == vStrings.size())
				{
					ShellLinkDataContext_t data;
					size_t ix = 0;
					data.sLinkName = vStrings[ix++];
					data.sLocalizedName = vStrings[ix++];
					data.sFileSystemPath = vStrings[ix++];
					data.sArguments = vStrings[ix++];
					data.sDescription = vStrings[ix++];
					data.sFullLinkPath = vStrings[ix++];
					data.linkLocation = Str2LinkLocation(vStrings[ix++]);
					data.sLinkRelativeSubdir = vStrings[ix++];
					m_ShellLinks.push_back(data);
				}
			}
		}
		else if (0 == sLine.length())
		{
			// Extraneous blank line - ignore.
		}
		else
		{
			strProcessingError << L"Unexpected line: " << sLine << std::endl;
			retval = false;
		}
	}

	fs.close();

	//TODO: Now perform some validation, e.g., did we pick up a scan type 

	sErrorInfo = strProcessingError.str();
	return retval;
}

