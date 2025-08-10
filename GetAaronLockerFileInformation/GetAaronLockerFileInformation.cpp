// AaronLocker test utility function: GetAaronLockerFileInformation

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <io.h>
#include <fcntl.h>
#include "../AppLockerFunctionality/AppLockerFunctionality.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Structs.h"

static bool SerializeFileDetailsTable(const FileDetailsCollection_t& fileDetails, std::wostream& os);
static bool SerializeFileDetailsList(const FileDetailsCollection_t& fileDetails, std::wostream& os);

/// <summary>
/// Write command-line syntax to stderr and then exit.
/// </summary>
/// <param name="szError">Caller-supplied error text</param>
/// <param name="argv0">The program's argv[0] value</param>
static void Usage(const wchar_t* szError, const wchar_t* argv0)
{
	std::wstring sExe = GetFileNameFromFilePath(argv0);
	if (szError)
		std::wcerr << szError << std::endl;
	std::wcerr
		<< std::endl
		<< L"Usage:" << std::endl
		<< std::endl
		<< L"    " << sExe << L" -file filepath... [-table] [-out outputFilename]" << std::endl
		<< L" or" << std::endl
		<< L"    " << sExe << L" -link filepath... [-table] [-out outputFilename]" << std::endl
		<< std::endl
		<< L"You can specify multiple filepaths; each must be preceded by \"-file\" or \"-link\"." << std::endl
		<< L"\"filepath\" can include wildcard characters." << std::endl
		<< std::endl;
	exit(-1);
}

int wmain(int argc, wchar_t** argv)
{
	// Set output mode to UTF8.
	if (_setmode(_fileno(stdout), _O_U8TEXT) == -1 || _setmode(_fileno(stderr), _O_U8TEXT) == -1)
	{
		std::wcerr << L"Unable to set stdout and/or stderr modes to UTF8." << std::endl;
	}

	std::vector<std::wstring> fileSpecs, files;
	std::wstring sOutFile;
	bool bFileMode = false;
	bool bLinkMode = false;
	bool bOutToFile = false;
	bool bTableView = false;

	// Parse command line options
	int ixArg = 1;
	while (ixArg < argc)
	{
		if (0 == StringCompareCaseInsensitive(L"-file", argv[ixArg]))
		{
			bFileMode = true;
			if (bLinkMode)
				Usage(L"Cannot use both -file and -link", argv[0]);
			if (++ixArg >= argc)
				Usage(L"Missing arg for -file", argv[0]);
			fileSpecs.push_back(argv[ixArg]);
		}
		else if (0 == StringCompareCaseInsensitive(L"-link", argv[ixArg]))
		{
			bLinkMode = true;
			if (bFileMode)
				Usage(L"Cannot use both -file and -link", argv[0]);
			if (++ixArg >= argc)
				Usage(L"Missing arg for -link", argv[0]);
			fileSpecs.push_back(argv[ixArg]);
		}
		// Output to file
		else if (0 == StringCompareCaseInsensitive(L"-out", argv[ixArg]))
		{
			bOutToFile = true;
			if (++ixArg >= argc)
				Usage(L"Missing arg for -out", argv[0]);
			sOutFile = argv[ixArg];
		}
		else if (0 == StringCompareCaseInsensitive(L"-table", argv[ixArg]))
		{
			bTableView = true;
		}
		else
		{
			Usage(L"Unrecognized command-line option", argv[0]);
		}
		++ixArg;
	}

	std::vector<std::wstring>::const_iterator iterFileSpecs;
	for (
		iterFileSpecs = fileSpecs.begin();
		iterFileSpecs != fileSpecs.end();
		++iterFileSpecs
		)
	{
		std::wstring sDirectoryPath = GetDirectoryNameFromFilePath(*iterFileSpecs);
		if (sDirectoryPath.length() > 0)
			sDirectoryPath += L"\\";
		WIN32_FIND_DATAW FindFileData = { 0 };
		Wow64FsRedirection fsRedir;
		fsRedir.Disable();
		HANDLE hFileSearch = FindFirstFileEx_ExtendedPath(
			iterFileSpecs->c_str(),
			FINDEX_INFO_LEVELS::FindExInfoBasic, // Optimize - no need to get short names
			&FindFileData,
			FINDEX_SEARCH_OPS::FindExSearchNameMatch,
			FIND_FIRST_EX_LARGE_FETCH); // optimization, according to the documentation
		fsRedir.Revert();
		if (INVALID_HANDLE_VALUE == hFileSearch)
		{
			std::wcerr << L"File(s) not found: " << *iterFileSpecs << std::endl;
		}
		else
		{
			do {
				// If the returned name is not a subdirectory or a reparse point, add it to the collection.
				const DWORD dwUngoodFileAttributes =
					FILE_ATTRIBUTE_DIRECTORY | 
					FILE_ATTRIBUTE_REPARSE_POINT |
					FILE_ATTRIBUTE_OFFLINE | 
					FILE_ATTRIBUTE_RECALL_ON_OPEN | 
					FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
				if (0 == (FindFileData.dwFileAttributes & dwUngoodFileAttributes))
				{
					// Full path
					files.push_back(
						sDirectoryPath + FindFileData.cFileName
					);
				}
				// Get the next one
			} while (FindNextFileW(hFileSearch, &FindFileData));
			// Search complete, close the handle.
			FindClose(hFileSearch);
		}
	}

	if (files.size() == 0)
	{
		Usage(L"No files specified.", argv[0]);
	}

	// Define a wostream output; create a wofstream if sOutFile defined; point it to std::wcout otherwise.
	// Do that now before performing the scan in case there's a problem with the output file.

	// pStream points to whatever ostream we're writing to.
	// Default to writing to stdout/wcout.
	// If -out specified, open an fstream for writing.
	std::wostream* pStream = &std::wcout;
	std::wofstream fs;
	if (bOutToFile)
	{
		pStream = &fs;
		fs.open(sOutFile, std::ios_base::out);
		if (fs.fail())
		{
			// If opening the file for output fails, quit now.
			std::wcerr << L"Cannot open output file " << sOutFile << std::endl;
			Usage(NULL, argv[0]);
		}

		// Ensure that output is UTF-8, with BOM if writing to file.
		pStream->imbue(bOutToFile ? Utf8FileUtility::LocaleForWritingUtf8File() : Utf8FileUtility::LocaleForWritingUtf8NoHeader());
	}

	if (bLinkMode)
	{
		ShellLinkInfo sli;
		if (!sli.Ready())
		{
			std::wcerr << L"ShellLinkInfo can't be initialized" << std::endl;
		}
		else
		{
			const wchar_t* const szDelim = L"\t";;
			if (bTableView)
			{
				*pStream
					<< L"Link name" << szDelim
					<< L"Localized" << szDelim
					<< L"App path" << szDelim
					<< L"Arguments" << szDelim
					<< L"Description" << szDelim
					<< L"Link path"
					<< std::endl;
			}
			std::vector<std::wstring>::const_iterator iterFiles;
			for (
				iterFiles = files.begin();
				iterFiles != files.end();
				++iterFiles
				)
			{
				ShellLinkData_t data;
				if (sli.Get(*iterFiles, data))
				{
					if (bTableView)
					{
						*pStream
							<< data.sLinkName << szDelim
							<< data.sLocalizedName << szDelim
							<< data.sFileSystemPath << szDelim
							<< data.sArguments << szDelim
							<< data.sDescription << szDelim
							<< data.sFullLinkPath
							<< std::endl;
					}
					else
					{
						const size_t nLabelWidth = 13;
						*pStream
							<< std::left
							<< std::setw(nLabelWidth) << L"Link name" << data.sLinkName << std::endl
							<< std::setw(nLabelWidth) << L"Localized" << data.sLocalizedName << std::endl
							<< std::setw(nLabelWidth) << L"App path" << data.sFileSystemPath << std::endl
							<< std::setw(nLabelWidth) << L"Arguments" << data.sArguments << std::endl
							<< std::setw(nLabelWidth) << L"Description" << data.sDescription << std::endl
							<< std::setw(nLabelWidth) << L"Link path" << data.sFullLinkPath << std::endl
							<< std::endl;
					}
				}
			}
		}
	}
	else
	{	//std::wstring sAppLabel = GetFileNameFromFilePath(argv[0]);
		FileDetailsCollection_t m_FileDetails;

		std::vector<std::wstring>::const_iterator iterFiles;
		for (
			iterFiles = files.begin();
			iterFiles != files.end();
			++iterFiles
			)
		{
			// Determine whether the file is AppLocker-relevant
			const wchar_t* szFilename = iterFiles->c_str();
			AppLockerFileDetails alfd(szFilename);
			if (!alfd.FileExistsFullyPresent())
			{
				std::wcerr << L"File does not exist: " << alfd.FilePath() << std::endl;
			}
			else
			{
				PEFileInfo peFileInfo;
				DWORD dwApiError;
				AppLockerFileDetails_ftype_t ftype = alfd.GetFileType(peFileInfo, true, dwApiError);
				bool bAddThisFile = false;
				switch (ftype)
				{
					// AppLocker-relevant file types
				case AppLockerFileDetails_ftype_t::ft_EXE:
				case AppLockerFileDetails_ftype_t::ft_DLL:
				case AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL:
				case AppLockerFileDetails_ftype_t::ft_MSI:
				case AppLockerFileDetails_ftype_t::ft_Script:
					bAddThisFile = true;
					break;

					// See whether "unknown" because we couldn't inspect content.
				case AppLockerFileDetails_ftype_t::ft_Unknown:
					if (0 != dwApiError)
					{
						std::wcerr << L"Couldn't inspect " << szFilename << L": " << SysErrorMessage(dwApiError) << std::endl;
					}
					break;

					// Do nothing with files of these types
				case AppLockerFileDetails_ftype_t::ft_KnownNonCodeExtension:
				case AppLockerFileDetails_ftype_t::ft_ScriptJS:
				case AppLockerFileDetails_ftype_t::ft_Appx:
				default:
					break;
				}

				// Prepare a file-details structure about this file
				// See FileDetails_t declaration for documentation about all its attributes
				FileDetails_t fileDetails;

				AppLockerFileInformation alfi(szFilename);
				// GetHash256Info returns the filename portion of the file path to include in an AppLocker rule.
				// Ignoring what it returns because we can reconstitute it again later from the full path.
				std::wstring sFilenameIgnored;
				alfi.GetHash256Info(fileDetails.m_ALHash, fileDetails.m_FlatFileHash, sFilenameIgnored, fileDetails.m_fileSize, dwApiError);
				if (0 != dwApiError)
				{
					std::wcerr << L"Failure getting hash info from " << szFilename << L": " << SysErrorMessage(dwApiError) << std::endl;
				}

				//fileDetails.m_sAppLabel = sAppLabel;
				//fileDetails.m_bIsSafeDir = IsThisDirectorySafe(*iterFiles, bIsSafeDirChecked, bIsSafeDir, pvUnsafeDirectoryInfo);
				fileDetails.m_fileType = ftype;
				fileDetails.m_sFilePath = *iterFiles;
				if (peFileInfo.m_bIsPEFile)
				{
					fileDetails.m_PEImageFileMachineType = peFileInfo.ImageFileMachineString();
				}
				dwApiError = 0;
				if (AppLockerFileDetails_ftype_t::ft_MSI != ftype)
				{
					// Using alfi instead of szFilename returns the extended-path name if needed.
					VersionInfo vi(alfi.FileDetails().FilePath().c_str());
					fileDetails.m_sVerProductName = vi.ProductName();
					fileDetails.m_sVerFileDescription = vi.FileDescription();
					alfi.GetPublisherInfo(fileDetails.m_ALPublisherName, fileDetails.m_ALProductName, fileDetails.m_ALBinaryName, fileDetails.m_ALBinaryVersion, fileDetails.m_sX500CertSigner, fileDetails.m_sSigningTimestamp, dwApiError);
					peFileInfo.LinkTimestamp(fileDetails.m_sPEFileLinkDate);
				}
				else
				{
					MsiFileInfo_t msiFileInfo;
					bool gpiRet = alfi.GetPublisherInfo(fileDetails.m_ALPublisherName, fileDetails.m_sX500CertSigner, fileDetails.m_sSigningTimestamp, msiFileInfo, dwApiError);
					fileDetails.m_sVerProductName = msiFileInfo.sProductName;
					if (gpiRet)
					{
						fileDetails.m_ALProductName = msiFileInfo.sALProductName;
						fileDetails.m_ALBinaryName = msiFileInfo.sALBinaryName;
						fileDetails.m_ALBinaryVersion = msiFileInfo.sALBinaryVersion;
					}
				}

				if (0 != dwApiError)
				{
					std::wcerr << L"Failure getting publisher info from " << szFilename << L": " << SysErrorMessage(dwApiError) << std::endl;
				}

				std::wstring sAltName;
				Wow64FsRedirection fsRedir;
				fsRedir.Disable();
				HANDLE hFile = OpenExistingFile_ExtendedPath(szFilename, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, dwApiError, sAltName);
				fsRedir.Revert();
				if (INVALID_HANDLE_VALUE != hFile)
				{
					// Visual Studio compiler keeps reporting warning C6001 "Using uninitialized memory '*hFile'" 
					// for the GetFileTime call on the next line. I have no idea why. hFile is *always* assigned 
					// the return value of CreateFileW before it gets here. Reported VS bug to Microsoft Jan 3 2021.
					FILETIME ftCreateTime, ftLastAccessTime, ftLastWriteTime; // Last-access-time is useless to us.
					if (GetFileTime(hFile, &ftCreateTime, &ftLastAccessTime, &ftLastWriteTime))
					{
						fileDetails.m_ftCreateTime = FileTimeToWString(ftCreateTime);
						fileDetails.m_ftLastWriteTime = FileTimeToWString(ftLastWriteTime);
					}
					CloseHandle(hFile);
				}
				else
				{
					std::wcerr << L"Failure getting file system times from " << szFilename << L": " << SysErrorMessage(dwApiError) << std::endl;
				}
				// Add the file details to the results collection
				m_FileDetails.push_back(fileDetails);
			}
		}

		if (bTableView)
			SerializeFileDetailsTable(m_FileDetails, *pStream);
		else
			SerializeFileDetailsList(m_FileDetails, *pStream);
	}

	// Close the output file, if specified.
	if (bOutToFile)
	{
		fs.close();
	}

	return 0;
}

static const wchar_t* const szTrue = L"True";
static const wchar_t* const szFalse = L"False";

const wchar_t* Bool2Str(bool b)
{
	return (b ? szTrue : szFalse);
}

bool Str2Bool(const wchar_t* szBool)
{
	return (NULL != szBool && (0 == StringCompareCaseInsensitive(szTrue, szBool)));
}

bool Str2Bool(const std::wstring& sBool)
{
	return Str2Bool(sBool.c_str());
}

// --------------------------------------------------------------------------------
static const wchar_t* const szUnknown = L"Unknown";
static const wchar_t* const szKnownNonCodeExtension = L"KnownNonCodeExtension";
static const wchar_t* const szEXE = L"EXE";
static const wchar_t* const szDLL = L"DLL";
static const wchar_t* const szResourceOnlyDLL = L"ResourceOnlyDLL";
static const wchar_t* const szMSI = L"MSI";
static const wchar_t* const szScript = L"Script";
static const wchar_t* const szScriptJS = L"ScriptJS";
static const wchar_t* const szAppx = L"Appx";
static const wchar_t* const szUNDEFINED = L"[UNDEFINED]";

struct FType2Str_t
{
	AppLockerFileDetails_ftype_t ftype;
	const wchar_t* szType;
};

FType2Str_t Ftype2StrMap[] = {
	{ AppLockerFileDetails_ftype_t::ft_Unknown,               szUnknown },
	{ AppLockerFileDetails_ftype_t::ft_KnownNonCodeExtension, szKnownNonCodeExtension },
	{ AppLockerFileDetails_ftype_t::ft_EXE,                   szEXE },
	{ AppLockerFileDetails_ftype_t::ft_DLL,                   szDLL },
	{ AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL,       szResourceOnlyDLL },
	{ AppLockerFileDetails_ftype_t::ft_MSI,                   szMSI },
	{ AppLockerFileDetails_ftype_t::ft_Script,                szScript },
	{ AppLockerFileDetails_ftype_t::ft_ScriptJS,              szScriptJS },
	{ AppLockerFileDetails_ftype_t::ft_Appx,                  szAppx },
};
const size_t nFtype2StrMap = sizeof(Ftype2StrMap) / sizeof(Ftype2StrMap[0]);

// Reimplementing as a couple of std::unordered_map collections might squeeze a few more cycles.

const wchar_t* FType2Str(AppLockerFileDetails_ftype_t ftype)
{
	for (size_t ix = 0; ix < nFtype2StrMap; ++ix)
	{
		if (ftype == Ftype2StrMap[ix].ftype)
			return Ftype2StrMap[ix].szType;
	}
	return szUNDEFINED;
}


bool SerializeFileDetailsTable(const FileDetailsCollection_t& fileDetails, std::wostream& os)
{
	const wchar_t* const szDelim = L"\t";;
	os
		// CSV headers for the coming data
		//<< L"AppLabel" << szDelim
		//<< L"IsSafeDir" << szDelim
		<< L"FilePath" << szDelim
		<< L"FileType" << szDelim
		<< L"VerProductName" << szDelim
		<< L"VerFileDescription" << szDelim
		<< L"X500CertSigner" << szDelim
		<< L"ALPublisherName" << szDelim
		<< L"ALProductName" << szDelim
		<< L"ALBinaryName" << szDelim
		<< L"ALBinaryVersion" << szDelim
		<< L"ALHash" << szDelim
		<< L"SHA256Hash" << szDelim
		<< L"FileSize" << szDelim
		<< L"PEImageFileMachineType" << szDelim
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
		os
			//<< iterFileDetails->m_sAppLabel << szDelim
			//<< Bool2Str(iterFileDetails->m_bIsSafeDir) << szDelim
			<< iterFileDetails->m_sFilePath << szDelim
			<< FType2Str(iterFileDetails->m_fileType) << szDelim
			<< iterFileDetails->m_sVerProductName << szDelim
			<< iterFileDetails->m_sVerFileDescription << szDelim
			<< iterFileDetails->m_sX500CertSigner << szDelim
			<< iterFileDetails->m_ALPublisherName << szDelim
			<< iterFileDetails->m_ALProductName << szDelim
			<< iterFileDetails->m_ALBinaryName << szDelim
			<< iterFileDetails->m_ALBinaryVersion << szDelim
			<< iterFileDetails->m_ALHash << szDelim
			<< iterFileDetails->m_FlatFileHash << szDelim
			<< iterFileDetails->m_fileSize << szDelim
			<< iterFileDetails->m_PEImageFileMachineType << szDelim
			<< iterFileDetails->m_sSigningTimestamp << szDelim
			<< iterFileDetails->m_sPEFileLinkDate << szDelim
			<< iterFileDetails->m_ftCreateTime << szDelim
			<< iterFileDetails->m_ftLastWriteTime << std::endl;
	}
	os << std::endl;

	return true;
}

bool SerializeFileDetailsList(const FileDetailsCollection_t& fileDetails, std::wostream& os)
{
	const size_t nLabelWidth = 19;

	FileDetailsCollection_t::const_iterator iterFileDetails;
	for (
		iterFileDetails = fileDetails.begin();
		iterFileDetails != fileDetails.end();
		++iterFileDetails
		)
	{
		os
			<< std::left
			//<< L"AppLabel" << 	//<< iterFileDetails->m_sAppLabel << std::endl
			//<< L"IsSafeDir" << 	//<< Bool2Str(iterFileDetails->m_bIsSafeDir) << std::endl
			<< std::setw(nLabelWidth) << L"FilePath" << iterFileDetails->m_sFilePath << std::endl
			<< std::setw(nLabelWidth) << L"FileType" << FType2Str(iterFileDetails->m_fileType) << std::endl
			<< std::setw(nLabelWidth) << L"VerProductName" << iterFileDetails->m_sVerProductName << std::endl
			<< std::setw(nLabelWidth) << L"VerFileDescription" << iterFileDetails->m_sVerFileDescription << std::endl
			<< std::setw(nLabelWidth) << L"X500CertSigner" << iterFileDetails->m_sX500CertSigner << std::endl
			<< std::setw(nLabelWidth) << L"ALPublisherName" << iterFileDetails->m_ALPublisherName << std::endl
			<< std::setw(nLabelWidth) << L"ALProductName" << iterFileDetails->m_ALProductName << std::endl
			<< std::setw(nLabelWidth) << L"ALBinaryName" << iterFileDetails->m_ALBinaryName << std::endl
			<< std::setw(nLabelWidth) << L"ALBinaryVersion" << iterFileDetails->m_ALBinaryVersion << std::endl
			<< std::setw(nLabelWidth) << L"ALHash" << iterFileDetails->m_ALHash << std::endl
			<< std::setw(nLabelWidth) << L"SHA256" << iterFileDetails->m_FlatFileHash << std::endl
			<< std::setw(nLabelWidth) << L"FileSize" << iterFileDetails->m_fileSize << std::endl
			<< std::setw(nLabelWidth) << L"PEMachineType" << iterFileDetails->m_PEImageFileMachineType << std::endl
			<< std::setw(nLabelWidth) << L"SigningTimestamp" << iterFileDetails->m_sSigningTimestamp << std::endl
			<< std::setw(nLabelWidth) << L"PEFileLinkDate" << iterFileDetails->m_sPEFileLinkDate << std::endl
			<< std::setw(nLabelWidth) << L"CreateTime" << iterFileDetails->m_ftCreateTime << std::endl
			<< std::setw(nLabelWidth) << L"LastWriteTime" << iterFileDetails->m_ftLastWriteTime << std::endl
			<< std::endl;
	}
	os << std::endl;

	return true;
}
