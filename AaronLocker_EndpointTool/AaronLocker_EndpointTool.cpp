// AaronLocker_EndpointTool.cpp
//
// Command-line tool to perform AaronLocker endpoint full scans and single-directory scans.
//

#include <Windows.h>
#include <iostream>
#include <fstream>

#include "../AppLockerFunctionality/AppLockerFunctionality.h"
#include "../DirectorySafetyFunctions/DirectorySafetyFunctions.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "../AaronLocker_EndpointScanLogic/AaronLocker_EndpointScanLogic.h"

#include "../AaronLocker_Serialization/AaronLockerSerializer.h"

/// <summary>
/// Write command-line syntax to stderr and then exit.
/// </summary>
/// <param name="szError">Caller-supplied error text</param>
/// <param name="argv0">The program's argv[0] value</param>
void Usage(const wchar_t* szError, const wchar_t* argv0)
{
	std::wstring sExe = GetFileNameFromFilePath(argv0);
	if (szError)
		std::wcerr << szError << std::endl;
	std::wcerr
		<< std::endl
		<< L"Usage:" << std::endl
		<< std::endl
		<< L"  Full endpoint scan:" << std::endl
		<< L"    " << sExe << L" -full [-out filename]" << std::endl
		<< std::endl
		<< L"  One-directory scan:" << std::endl
		<< L"    " << sExe << L" -dir dirname [-label appname] [-out filename]" << std::endl
		<< std::endl
		<< L"  Shortcuts/links scan:" << std::endl
		<< L"    " << sExe << L" -links [-out filename]" << std::endl
		<< std::endl
		<< L"  -out   : specifies output filename. If not specified, writes to stdout." << std::endl
		<< L"  -dir   : \"dirname\" specifies directory to scan." << std::endl
		<< L"  -label : optional app name to associate with files under the directory." << std::endl
		<< std::endl;

		// Possibly later:
		// * Multi-directory scan (dir/app names), output file
		// * Configurability for SidsToIgnore, Windows file exclusions
		// * Handle URL-encoded parameters

	exit(-1);
}

int wmain(int argc, wchar_t** argv)
{
	//{
	//	std::wcout << L"argc/argv params:" << std::endl;
	//	for (int i = 0; i < argc; ++i)
	//	{
	//		std::wcout << i << L" |" << argv[i] << L"|" << std::endl;
	//	}
	//	std::wcout << std::endl;
	//}
	int exitCode = 0;
	bool bFullScan = false, bOneDirScan = false, bLinksScan = false, bLabel = false, bOutToFile = false;
	std::wstring sDirname, sAppname, sOutFile;

	// Parse command line options
	int ixArg = 1;
	while (ixArg < argc)
	{
		// Full scan
		if (0 == StringCompareCaseInsensitive(L"-full", argv[ixArg]))
		{
			bFullScan = true;
		}
		// One-directory scan; must be followed by directory name to scan
		else if (0 == StringCompareCaseInsensitive(L"-dir", argv[ixArg]))
		{
			// If already specified, can't specify it again
			if (bOneDirScan)
				Usage(L"-dir specified more than once", argv[0]);
			bOneDirScan = true;
			if (++ixArg >= argc)
				Usage(L"Missing arg for -dir", argv[0]);
			sDirname = argv[ixArg];
			// If the name ends with '\' (because PowerShell does that), remove the backslash;
			// PowerShell also does weird things with command line params that contain spaces and end in backslash
			while (EndsWith(sDirname, L'\\') || EndsWith(sDirname, L'"'))
				sDirname = sDirname.substr(0, sDirname.length() - 1);
		}
		// Shortcuts/links scan
		else if (0 == StringCompareCaseInsensitive(L"-links", argv[ixArg]))
		{
			bLinksScan = true;
		}
		// Appname label for one-directory scan; must be followed by app name
		else if (0 == StringCompareCaseInsensitive(L"-label", argv[ixArg]))
		{
			// If already specified, can't specify it again
			if (bLabel)
				Usage(L"-label specified more than once", argv[0]);
			bLabel = true;
			if (++ixArg >= argc)
				Usage(L"Missing arg for -label", argv[0]);
			sAppname = argv[ixArg];
		}
		// Output to file
		else if (0 == StringCompareCaseInsensitive(L"-out", argv[ixArg]))
		{
			bOutToFile = true;
			if (++ixArg >= argc)
				Usage(L"Missing arg for -out", argv[0]);
			sOutFile = argv[ixArg];
		}
		else
		{
			Usage(L"Unrecognized command-line option", argv[0]);
		}
		++ixArg;
	}
	// Parameter validation:
	// * Must have selected one scan type
	int nScanTypes = 0;
	if (bFullScan) nScanTypes++;
	if (bOneDirScan) nScanTypes++;
	if (bLinksScan) nScanTypes++;
	if (1 != nScanTypes)
		Usage(L"Must select a scan type (-full, -dir, -links)", argv[0]);
	// * Can use label only with one-dir scan
	if (bLabel && !bOneDirScan)
		Usage(L"Can use -label only with one-directory scan", argv[0]);

	// Validation of sDirName can be handled by the scan.
	// Validation of sOutFile (if set) will be handled before the scan

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
	}
	// Ensure that output is UTF-8.
	pStream->imbue(Utf8FileUtility::LocaleForWritingUtf8File());

	if (bLinksScan)
	{
		// For links-only scan, output file is just tab-delimited data; error info written to stderr.
		EndpointScan_Links scan;
		std::wstring sErrorInfo;
		scan.PerformFullScan(sErrorInfo);
		AaronLockerSerializer::Serialize(scan, *pStream);
		if (sErrorInfo.length() > 0)
		{
			std::wcerr << sErrorInfo << std::endl;
		}
	}
	else
	{	// The SIDs to ignore in security descriptors. Eventually provide a way to add more SIDs to this collection.
		SidsToFilter sidsToFilter;
		if (bFullScan)
		{
			// Perform a full scan, then serialize results to the selected output stream.
			EndpointFullScan scan(sidsToFilter);
			/*bool ret = */
			scan.PerformFullScan();
			AaronLockerSerializer::Serialize(scan, *pStream);
		}
		else
		{
			// Scan the specified directory, then serialize results to the selected output stream.
			EndpointOneDirectoryScan scan(sidsToFilter);
			bool bScanGood = scan.ScanDirectory(sDirname.c_str(), sAppname.c_str());
			AaronLockerSerializer::Serialize(scan, sDirname, sAppname, *pStream);
			if (!bScanGood)
			{
				exitCode = -1;
				std::wcerr << scan.ErrorInfo() << std::endl;
			}
		}
	}

	// Close the output file, if specified.
	if (bOutToFile)
	{
		fs.close();
	}

	return exitCode;
}

