// PathToAppNameTool.cpp
//
// Command-line tool to map file paths to localized application names.
//

#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Links.h"
#include "../AaronLocker_EndpointScanLogic/PathToAppNameMap.h"

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
		<< L"    " << sExe << L" itemToTranslate [...] [-out filename]" << std::endl
		<< std::endl
		<< L"  Each \"itemToTranslate\" can be a full path to a directory or file to be mapped." << std::endl
		<< L"  If \"itemToTranslate\" begins with \"@\" it is a text file containing one or more file paths to map," << std::endl
		<< L"  one per line." << std::endl
		<< std::endl
		<< L"  If -out is specified, output is written to UTF8-encoded filename, one result per line. Otherwise," << std::endl
		<< L"  output is written to stdout." << std::endl
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

	//{
	//	std::wcout << L"argc/argv params:" << std::endl;
	//	for (int i = 0; i < argc; ++i)
	//	{
	//		std::wcout << i << L" |" << argv[i] << L"|" << std::endl;
	//	}
	//	std::wcout << std::endl;
	//}

	int exitCode = 0;

	std::vector<std::wstring> vPathsToMap;
	bool bOutToFile = false;
	std::wstring sOutFile;

	// No params: show usage
	if (1 == argc)
		Usage(NULL, argv[0]);

	// Parse command line options
	int ixArg = 1;
	while (ixArg < argc)
	{
		// Output to file
		if (0 == StringCompareCaseInsensitive(L"-out", argv[ixArg]))
		{
			bOutToFile = true;
			if (++ixArg >= argc)
				Usage(L"Missing arg for -out", argv[0]);
			sOutFile = argv[ixArg];
		}
		// Any other attempted command-line switches, show usage
		else if (L'-' == argv[ixArg][0] || L'/' == argv[ixArg][0])
		{
			Usage(NULL, argv[0]);
		}
		// File containing paths to try to map, one per line
		else if (L'@' == argv[ixArg][0])
		{
			std::wifstream fs;
			const wchar_t* szFilename = &(argv[ixArg][1]);
			if (!Utf8FileUtility::OpenForReadingWithLocale(fs, szFilename))
			{
				std::wstringstream strError;
				strError << L"Error - cannot open file " << szFilename << std::endl;
				Usage(strError.str().c_str(), argv[0]);
			}
			while (fs.good())
			{
				std::wstring sFilePath;
				StdGetlineCRLF(fs, sFilePath);
				if (sFilePath.length() > 0)
				{
					vPathsToMap.push_back(sFilePath);
				}
			}
			fs.close();
		}
		// Path to try to map
		else
		{
			vPathsToMap.push_back(argv[ixArg]);
		}

		++ixArg;
	}

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
		// Ensure that file output is UTF-8.
		pStream->imbue(Utf8FileUtility::LocaleForWritingUtf8File());
	}


	EndpointScan_Links linkScanner;
	std::wstring sErrorInfo;
	if (!linkScanner.PerformFullScan(sErrorInfo))
	{
		std::wcerr << L"Scan failed: " << sErrorInfo << std::endl;
		return -1;
	}

	PathToAppMap pathToAppMap;
	pathToAppMap.AddEntries(linkScanner.ScanResults());

	std::vector<std::wstring>::const_iterator iterPaths;
	for (
		iterPaths = vPathsToMap.begin();
		iterPaths != vPathsToMap.end();
		++iterPaths
		)
	{
		std::wstring sAppName;
		if (pathToAppMap.FindEntry(*iterPaths, sAppName))
		{
			*pStream << *iterPaths << L"\t" << sAppName << std::endl;
		}
		else
		{
			*pStream << *iterPaths << L"\t" << L"[[[not mapped]]]" << std::endl;
		}
	}

	// Close the output file, if specified.
	if (bOutToFile)
	{
		fs.close();
	}

	return exitCode;
}

