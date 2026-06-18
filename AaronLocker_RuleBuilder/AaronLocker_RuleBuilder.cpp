// AaronLocker_RuleBuilder.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


//TODO: Add an option to remove store app rules
//TODO: Consider making the command-line switches case sensitive, and then distinguishing -r R -rr -RR.
//TODO: Offer +r and +rr. Exclusive choice between -r/-rr (which remove rules) and +r/+rr (which add rules). Can use one pattern or the other. +r/+rr means include only the named rule sets; -r/-rr means include all except the named rule sets.
//TODO: Figure out how to create a rule so that this doesn't get blocked:
/*
	Location      : Packaged app
	GenericPath   : 34791E63.CanonPrintAssistant
	GenericDir    : 34791E63.CanonPrintAssistant
	OriginalPath  : 34791E63.CanonPrintAssistant
	FileName      : 34791E63.CanonPrintAssistant
	FileExt       :
	FileType      : APPX
	PublisherName : CN=41BAE105-1234-432C-A39C-1B7D1C24232B
	ProductName   : 34791E63.CANONPRINTASSISTANT
	BinaryName    : APPX
	FileVersion   : 1.0.45.00
	Hash          : N/A
	UserSID       : S-1-5-18
	UserName      : NT AUTHORITY\SYSTEM
	MachineName   : DESKTOP-9C7URV8
	EventTime     : 2026-06-18T01:11:58.6002740
	EventTimeXL   : 2026-06-18 01:11:58
	PID           : 25392
	EventType     : Error
*/

#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <set>
#include "../RuleBuilding/RuleBuilding.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "../AaronLocker_Serialization/AaronLockerDeserializer.h"

/// <summary>
/// Structure to define the available +o predefined per-app rule component options
/// </summary>
struct PredefAppRules_t
{
	const wchar_t* szCmdLineOption;
	const wchar_t* szLabel;
	const wchar_t* szDescription;
	const PublisherRuleCollection_t& ruleCollection;
};

/// <summary>
/// Structure to define the available +w options to decline excluding built-in Windows executables.
/// </summary>
struct WindowsExeExcl_t
{
	const wchar_t* szCmdLineOption;
	const wchar_t* szDescription;
};

PredefAppRules_t PredefAppRules[] = {
	{
		L"ChromeM",
		L"Google Chrome (machine-wide)",
		L"For machine-wide install of Google Chrome (enables its user-profile binaries)",
		BuiltInRules::GoogleChromeMachinewideInstallRules()
	},
	{
		L"ChromeU",
		L"All Google apps",
		L"Enables per-user install of Google Chrome and everything signed by Google",
		BuiltInRules::GoogleChromePerUserInstallRules()
	},
	{
		L"Firefox",
		L"Mozilla Firefox",
		L"Allows users to install and run Mozilla Firefox from unsafe directories",
		BuiltInRules::MozillaRules()
	},
	{
		L"Teams",
		L"Microsoft Teams",
		L"Allows users to install and run Microsoft Teams from unsafe directories",
		BuiltInRules::MicrosoftTeamsRules()
	},
	{
		L"Zoom",
		L"Zoom",
		L"Allows users to install and run Zoom from unsafe directories",
		BuiltInRules::ZoomRules()
	},
	{
		L"WebEx",
		L"WebEx",
		L"Allows users to install and run WebEx from unsafe directories",
		BuiltInRules::WebExRules()
	},
	{
		L"Slack",
		L"Slack",
		L"Allows users to install and run Slack from unsafe directories",
		BuiltInRules::SlackRules()
	},
	{
		L"Flash",
		L"Chromium Flash Player",
		L"Allows Flash player in Chromium-based browsers",
		BuiltInRules::ChromiumBrowserFlashPlayerRules()
	},
	{
		L"Intuit",
		L"Intuit installers",
		L"Allows Intuit products to run per-user data updaters, such as for TurboTax",
		BuiltInRules::IntuitDataUpdaterRules()
	},
	{
		L"StoreAll",
		L"All signed packaged apps",
		L"Allows users to download and run all apps from the Microsoft Store app",
		BuiltInRules::AllStoreApps()
	},
	{
		L"StoreMS",
		L"All Microsoft-signed packaged apps",
		L"Allows users to download and run Microsoft-signed apps from the Microsoft Store app",
		BuiltInRules::MsSignedStoreApps()
	},
	{
		L"MSDLLs",
		L"All Microsoft DLLs (DISCOURAGED)",
		L"Allows users to load any Microsoft-signed DLLs (DISCOURAGED, only as last resort)",
		BuiltInRules::AllMicrosoftDLLs()
	}
};
const size_t nPredefAppRules = sizeof(PredefAppRules) / sizeof(PredefAppRules[0]);

WindowsExeExcl_t WindowsExeExcl[] = {
	{ L"Cipher", L"Allow non-admin execution of Cipher.exe (File Encryption Utility)" },
	{ L"Runas",  L"Allow non-admin execution of Runas.exe (Run As Utility)" },
	{ L"Mshta",  L"Allow non-admin execution of Mshta.exe (Microsoft (R) HTML Application host)" },
	{ L"WMIC",   L"Allow non-admin execution of WMIC.exe (WMI Commandline Utility)" },
};
const size_t nWindowsExeExcl = sizeof(WindowsExeExcl) / sizeof(WindowsExeExcl[0]);


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
		<< L"  " << sExe << L" +s scanFilePath... [+o appRuleOption...] [+w windowsExeOption...] [-r ruleSetToRemove...] [-rr ruleSetsToRemove...] [+out filename | +x XmlOutputDirectory]" << std::endl
		<< std::endl
		<< L"    +s:  import a serialized endpoint scan file (full scan or one-directory scan)." << std::endl
		<< L"         You can specify \"+s scanFilePath\" multiple times on the command line." << std::endl
		<< L"         You must specify at least one full scan file." << std::endl
		<< std::endl
		<< L"    +o:  apply predefined per-app rules. appRuleOption must be one of:" << std::endl
		<< std::left;
	for (size_t ixOpt = 0; ixOpt < nPredefAppRules; ++ixOpt)
	{
		std::wcerr << L"           " << std::setw(7) << PredefAppRules[ixOpt].szCmdLineOption << L" - " << PredefAppRules[ixOpt].szDescription << std::endl;
	}
	std::wcerr
		<< L"         You can specify \"+o appRuleOption\" multiple times on the command line." << std::endl
		<< std::endl
		<< L"    +w:  don't exclude built-in Windows executable that will otherwise be blocked by default:" << std::endl
		<< std::left;
	for (size_t ixOpt = 0; ixOpt < nWindowsExeExcl; ++ixOpt)
	{
		std::wcerr << L"           " << std::setw(7) << WindowsExeExcl[ixOpt].szCmdLineOption << L" - " << WindowsExeExcl[ixOpt].szDescription << std::endl;
	}
	std::wcerr
		<< L"         You can specify \"+w windowsExeOption\" multiple times on the command line." << std::endl
		<< std::endl
		<< L"    +winTemp:  create rules for files found under the \\Windows\\Temp directory." << std::endl
		<< L"         By default these files are ignored for rule-building." << std::endl
		<< std::endl
		<< L"    -r:  remove a proposed rule set by name prior to export." << std::endl
		<< L"         You can specify \"-r ruleSetToRemove\" multiple times." << std::endl
		<< std::endl
		<< L"    -rr: remove all proposed rule sets with names beginning with the specified name prior to export." << std::endl
		<< L"         (Unlike with the -r option, the -rr specification is case-insensitive.)" << std::endl
		<< L"         For example, \"-rr Symbol\" will remove all proposed rule sets with names beginning with \"Symbol\"." << std::endl
		<< L"         You can specify \"-rr ruleSetsToRemove\" multiple times." << std::endl
		<< std::endl
		<< L"    +out: Write detailed proposed rule set information to \"filename\" for further analysis." << std::endl
		<< std::endl
		<< L"    +x:  Export XML policy files to XmlOutputDirectory." << std::endl
		<< std::endl
		<< L"    If you do not specify +x to export XML files, " << sExe << L" lists rule set names and the" << std::endl
		<< L"    proposed rules associated with each." << std::endl
		<< std::endl
		<< L"Examples:" << std::endl
		<< std::endl
		<< L"  " << sExe << L" +o ChromeM +o Zoom +s fullscan.txt +s JoesApp.txt" << std::endl
		<< L"    Enables predefined rules for two apps, imports two scans; outputs proposed rules to stdout." << std::endl
		<< std::endl
		<< L"  " << sExe << L" +o ChromeM +o Zoom +s fullscan.txt +s JoesApp.txt -r \"Utils (Non-default root directory)\"" << std::endl
		<< L"    Enables predefined rules for two apps, imports two scans; outputs proposed rules (after removing one rule set) to stdout." << std::endl
		<< std::endl
		<< L"  " << sExe << L" +o ChromeM +o Zoom +s fullscan.txt +s JoesApp.txt -rr Utils +x C:\\AaronLocker" << std::endl
		<< L"    Enables predefined rules for two apps, imports two scans; writes AppLocker Enforce and Audit policy XML files to the" << std::endl
		<< L"    C:\\AaronLocker directory after removing all rule sets that have names beginning with \"Utils\"." << std::endl
		<< std::endl
		;

	exit(-1);
}

typedef std::set<std::wstring> sortedStrings;

static void Helper_AddProposedRuleSummaryToSet(
	const std::wstring& sRuleInfo,
	RuleItem::Collection_t collection,
	sortedStrings& exeRules,
	sortedStrings& dllRules,
	sortedStrings& msiRules,
	sortedStrings& scriptRules
	)
{
	switch (collection)
	{
	case RuleItem::Collection_t::Exe:
		exeRules.insert(sRuleInfo);
		break;
	case RuleItem::Collection_t::Dll:
		dllRules.insert(sRuleInfo);
		break;
	case RuleItem::Collection_t::Msi:
		msiRules.insert(sRuleInfo);
		break;
	case RuleItem::Collection_t::Script:
		scriptRules.insert(sRuleInfo);
		break;
	case RuleItem::Collection_t::All:
		exeRules.insert(sRuleInfo);
		dllRules.insert(sRuleInfo);
		msiRules.insert(sRuleInfo);
		scriptRules.insert(sRuleInfo);
		break;
	}
}

static void Helper_WriteProposedRuleSetSummary(RuleItem::Collection_t collection, const sortedStrings& rules, std::wostream& oStream)
{
	if (rules.size() > 0)
	{
		oStream << L"    " << RuleItem::Collection2Str(collection) << std::endl;
		for (
			sortedStrings::const_iterator iterRules = rules.begin();
			iterRules != rules.end();
			++iterRules
			)
		{
			oStream << L"      " << *iterRules << std::endl;
		}
	}
}

static void Helper_WriteProposedRuleSetSummaries(
	const sortedStrings& exeRules,
	const sortedStrings& dllRules,
	const sortedStrings& msiRules,
	const sortedStrings& scriptRules,
	std::wostream& oStream
)
{
	Helper_WriteProposedRuleSetSummary(RuleItem::Collection_t::Exe, exeRules, oStream);
	Helper_WriteProposedRuleSetSummary(RuleItem::Collection_t::Dll, dllRules, oStream);
	Helper_WriteProposedRuleSetSummary(RuleItem::Collection_t::Msi, msiRules, oStream);
	Helper_WriteProposedRuleSetSummary(RuleItem::Collection_t::Script, scriptRules, oStream);
}

/// <summary>
/// Output information about proposed rule sets for review to stdout.
/// </summary>
/// <param name="ruleAnalyzer"></param>
static void WriteProposedRuleSetSummary(const RuleAnalyzer& ruleAnalyzer)
{

	// Output information about proposed rule sets for review to stdout.
	// Assumed that AppX rules are always publisher rules, and a rule set that contains an Appx rule contains only that one rule

	std::vector<std::wstring> proposedRuleSetNames;
	size_t nRuleSets = ruleAnalyzer.GetProposedRuleSetNames(proposedRuleSetNames);
	if (nRuleSets > 0)
	{
		std::wstringstream strAppxRules;

		for (
			std::vector<std::wstring>::const_iterator iterNames = proposedRuleSetNames.begin();
			iterNames != proposedRuleSetNames.end();
			++iterNames
			)
		{
			const RuleSet_t* pRuleSet = NULL;
			if (ruleAnalyzer.GetProposedRuleSet(*iterNames, &pRuleSet))
			{
				bool bItemsToReport = false;

				std::wstringstream strRuleSetInfo;
				strRuleSetInfo
					<< L"============= Rule set =============" << std::endl
					<< *iterNames << std::endl
					<< std::endl;

				// Output path rules, publisher rules, hash rules.
				if (0 != pRuleSet->m_PathRules.size())
				{
					bItemsToReport = true;

					strRuleSetInfo << L"  Path rules: " << pRuleSet->m_PathRules.size() << std::endl;

					sortedStrings exeRules, dllRules, msiRules, scriptRules;

					PathRuleCollection_t::const_iterator iterRules;
					for (
						iterRules = pRuleSet->m_PathRules.begin();
						iterRules != pRuleSet->m_PathRules.end();
						++iterRules
						)
					{
						std::wstring sRuleInfo = iterRules->m_sPath;
						Helper_AddProposedRuleSummaryToSet(sRuleInfo, iterRules->m_collection, exeRules, dllRules, msiRules, scriptRules);
					}
					Helper_WriteProposedRuleSetSummaries(exeRules, dllRules, msiRules, scriptRules, strRuleSetInfo);
				}
				if (0 != pRuleSet->m_PublisherRules.size())
				{
					strRuleSetInfo << L"  Publisher rules: " << pRuleSet->m_PublisherRules.size() << std::endl;

					sortedStrings exeRules, dllRules, msiRules, scriptRules;

					PublisherRuleCollection_t::const_iterator iterRules;
					for (
						iterRules = pRuleSet->m_PublisherRules.begin();
						iterRules != pRuleSet->m_PublisherRules.end();
						++iterRules
						)
					{
						if (RuleItem::Collection_t::Appx != iterRules->m_collection)
						{
							bItemsToReport = true;
							std::wstring sRuleInfo = iterRules->m_sPublisher + L" \\ " + iterRules->m_sProduct + L" \\ " + iterRules->m_sBinaryName;
							Helper_AddProposedRuleSummaryToSet(sRuleInfo, iterRules->m_collection, exeRules, dllRules, msiRules, scriptRules);
						}
						else
						{
							strAppxRules << L"  " << iterRules->m_sName << std::endl;
						}
					}
					Helper_WriteProposedRuleSetSummaries(exeRules, dllRules, msiRules, scriptRules, strRuleSetInfo);
				}
				if (0 != pRuleSet->m_HashRules.size())
				{
					bItemsToReport = true;

					strRuleSetInfo << L"  Hash rules: " << pRuleSet->m_HashRules.size() << std::endl;

					sortedStrings exeRules, dllRules, msiRules, scriptRules;

					HashRuleCollection_t::const_iterator iterRules;
					size_t longestFnameLength = 0;
					for (
						iterRules = pRuleSet->m_HashRules.begin();
						iterRules != pRuleSet->m_HashRules.end();
						++iterRules
						)
					{
						if (iterRules->m_sFilename.length() > longestFnameLength)
							longestFnameLength = iterRules->m_sFilename.length();
					}
					for (
						iterRules = pRuleSet->m_HashRules.begin();
						iterRules != pRuleSet->m_HashRules.end();
						++iterRules
						)
					{
						std::wstringstream strRuleInfo;
						strRuleInfo << std::left << std::setw(longestFnameLength + 2) << iterRules->m_sFilename << replaceStringAll(iterRules->m_sDescription, L"\r\n", L"");
						Helper_AddProposedRuleSummaryToSet(strRuleInfo.str(), iterRules->m_collection, exeRules, dllRules, msiRules, scriptRules);
					}
					Helper_WriteProposedRuleSetSummaries(exeRules, dllRules, msiRules, scriptRules, strRuleSetInfo);
				}

				if (bItemsToReport)
				{
					std::wcout << strRuleSetInfo.str() << std::endl;
				}
			}

		}

		if (strAppxRules.str().length() > 0)
		{
			std::wcout
				<< L"============= APPX RULES =============" << std::endl
				<< strAppxRules.str();
		}
	}
}

static void WriteProposedRuleSetsForAnalysis(const RuleAnalyzer& ruleAnalyzer, const std::wstring& sCommentSelectedOptions, std::wostream& strOut)
{
	// Output detailed information about proposed rule sets for analysis to input stream.

	std::vector<std::wstring> proposedRuleSetNames;
	std::wstringstream strRuleBuilderOptions, strProposedPathRules, strProposedPublisherRules, strProposedHashRules;
	const wchar_t* szTab = L"\t";
	strRuleBuilderOptions
		<< L":::: RULE BUILDER OPTIONS" << std::endl
		<< sCommentSelectedOptions << std::endl;
	strProposedPathRules
		<< L":::: PROPOSED PATH RULES" << std::endl
		<< L"RuleSetName\tCollection\tName\tDescription\tPath" << std::endl;
	strProposedPublisherRules
		<< L":::: PROPOSED PUBLISHER RULES" << std::endl
		<< L"RuleSetName\tCollection\tName\tDescription\tPublisher\tProduct\tBinaryName" << std::endl;
	strProposedHashRules
		<< L":::: PROPOSED HASH RULES" << std::endl
		<< L"RuleSetName\tCollection\tName\tDescription\tFilename\tFileLength\tHash" << std::endl;
	size_t nRuleSets = ruleAnalyzer.GetProposedRuleSetNames(proposedRuleSetNames);
	if (nRuleSets > 0)
	{
		for (
			std::vector<std::wstring>::const_iterator iterNames = proposedRuleSetNames.begin();
			iterNames != proposedRuleSetNames.end();
			++iterNames
			)
		{
			const std::wstring& sRuleSetName = *iterNames;

			const RuleSet_t* pRuleSet = NULL;
			if (ruleAnalyzer.GetProposedRuleSet(*iterNames, &pRuleSet))
			{
				for (
					PathRuleCollection_t::const_iterator iterRules = pRuleSet->m_PathRules.begin();
					iterRules != pRuleSet->m_PathRules.end();
					++iterRules
					)
				{
					strProposedPathRules
						<< sRuleSetName << szTab
						<< RuleItem::Collection2Str(iterRules->m_collection) << szTab
						<< iterRules->m_sName << szTab
						<< replaceStringAll(iterRules->m_sDescription, L"\r\n", L"") << szTab
						<< iterRules->m_sPath << std::endl;
				}
					
				for (
					PublisherRuleCollection_t::const_iterator iterRules = pRuleSet->m_PublisherRules.begin();
					iterRules != pRuleSet->m_PublisherRules.end();
					++iterRules
					)
				{
					strProposedPublisherRules
						<< sRuleSetName << szTab
						<< RuleItem::Collection2Str(iterRules->m_collection) << szTab
						<< iterRules->m_sName << szTab
						<< replaceStringAll(iterRules->m_sDescription, L"\r\n", L"") << szTab
						<< iterRules->m_sPublisher << szTab
						<< iterRules->m_sProduct << szTab
						<< iterRules->m_sBinaryName << std::endl;
				}
					
				for (
					HashRuleCollection_t::const_iterator iterRules = pRuleSet->m_HashRules.begin();
					iterRules != pRuleSet->m_HashRules.end();
					++iterRules
					)
				{
					strProposedHashRules
						<< sRuleSetName << szTab
						<< RuleItem::Collection2Str(iterRules->m_collection) << szTab
						<< iterRules->m_sName << szTab
						<< replaceStringAll(iterRules->m_sDescription, L"\r\n", L"") << szTab
						<< iterRules->m_sFilename << szTab
						<< iterRules->m_sFileLength << szTab
						<< iterRules->m_sHashData << std::endl;
				}
			}
		}
	}

	strOut
		<< strRuleBuilderOptions.str()
		<< std::endl
		<< strProposedPathRules.str()
		<< std::endl
		<< strProposedPublisherRules.str()
		<< std::endl
		<< strProposedHashRules.str()
		;
}


int wmain(int argc, wchar_t** argv)
{
	// Set output mode to UTF8.
	if (_setmode(_fileno(stdout), _O_U8TEXT) == -1 || _setmode(_fileno(stderr), _O_U8TEXT) == -1)
	{
		std::wcerr << L"Unable to set stdout and/or stderr modes to UTF8." << std::endl;
	}

	RuleAnalyzer ruleAnalyzer;
	std::vector<std::wstring> scanfiles, rulesetsToRemove, rulesetNamePrefixesToRemove;
	CaseInsensitiveStringLookup windowsExesNotToExclude;
	bool bIncludeWindowsTempFiles = false;
	std::vector<AaronLockerDeserializer> scans;
	std::wstring sAnalysisFile, sPolicyFileDirectory;
	std::wstringstream strCommentSelectedOptions;

	// Parse command line options
	int ixArg = 1;
	while (ixArg < argc)
	{
		if (0 == wcscmp(L"+o", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for +o", argv[0]);
			const wchar_t* szOption = argv[ixArg];
			bool bMatched = false;
			for (size_t ixOpt = 0; ixOpt < nPredefAppRules; ++ixOpt)
			{
				if (0 == StringCompareCaseInsensitive(PredefAppRules[ixOpt].szCmdLineOption, szOption))
				{
					bMatched = true;
					ruleAnalyzer.AddToBaseRules(PredefAppRules[ixOpt].ruleCollection);
					strCommentSelectedOptions << L" +o " << szOption;
					break;
				}
			}
			if (!bMatched)
				Usage(L"Unrecognized +o option", argv[0]);
		}
		// Allow non-admin execution of Windows exe that will otherwise be blocked by default
		else if (0 == wcscmp(L"+w", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for +w", argv[0]);
			const wchar_t* szOption = argv[ixArg];
			bool bMatched = false;
			for (size_t ixOpt = 0; ixOpt < nWindowsExeExcl; ++ixOpt)
			{
				if (0 == StringCompareCaseInsensitive(WindowsExeExcl[ixOpt].szCmdLineOption, szOption))
				{
					bMatched = true;
					std::wstring sArgU = szOption;
					std::wstring sExeName = sArgU + L".exe";
					windowsExesNotToExclude.Add(sExeName);
					strCommentSelectedOptions << L" +w " << sArgU;
					break;
				}
			}
			if (!bMatched)
				Usage(L"Unrecognized +w option", argv[0]);
		}
		// Specify scan files
		else if (0 == wcscmp(L"+s", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for +s", argv[0]);
			std::wstring sArgU = argv[ixArg];
			scanfiles.push_back(sArgU);
			strCommentSelectedOptions << L" +s " << sArgU;
		}
		// Proposed rule set to remove
		else if (0 == wcscmp(L"-r", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for -r", argv[0]);
			std::wstring sArgU = argv[ixArg];
			rulesetsToRemove.push_back(sArgU);
			strCommentSelectedOptions << L" -r " << sArgU;
		}
		// Proposed rule set to remove
		else if (0 == wcscmp(L"-rr", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for -rr", argv[0]);
			std::wstring sArgU = argv[ixArg];
			rulesetNamePrefixesToRemove.push_back(sArgU);
			strCommentSelectedOptions << L" -rr " << sArgU;
		}
		// Whether to include files in the Windows Temp directory (make this check case-insensitive)
		else if (0 == _wcsicmp(L"+winTemp", argv[ixArg]))
		{
			bIncludeWindowsTempFiles = true;
			strCommentSelectedOptions << L" +winTemp ";
		}
		else if (0 == wcscmp(L"+out", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for +out", argv[0]);
			sAnalysisFile = argv[ixArg];
		}
		else if (0 == wcscmp(L"+x", argv[ixArg]))
		{
			if (++ixArg >= argc)
				Usage(L"Missing arg for +x", argv[0]);
			sPolicyFileDirectory = argv[ixArg];
		}
		else
		{
			Usage(L"Unrecognized command-line option", argv[0]);
		}
		++ixArg;
	}

	// Parameter validation:
	// Must have at least one scan file.
	// if sPolicyFileDirectory specified, must be a valid directory

	if (0 == scanfiles.size())
	{
		Usage(L"No scan files specified", argv[0]);
	}

	if (sAnalysisFile.length() > 0 && sPolicyFileDirectory.length() > 0)
	{
		Usage(L"Can't specify +out and +x", argv[0]);
	}

	if (sPolicyFileDirectory.length() > 0)
	{
		// Remove trailing path separator if it has one. (PowerShell autocomplete likes to append them, helpfully...)
		while (EndsWith(sPolicyFileDirectory, L'\\') || EndsWith(sPolicyFileDirectory, L'/'))
			sPolicyFileDirectory = sPolicyFileDirectory.substr(0, sPolicyFileDirectory.length() - 1);

		// This directory test is Windows dependent. Note that std::filesystem requires C++17 which breaks other stuff.
		DWORD dwFileAttributes = GetFileAttributesW(sPolicyFileDirectory.c_str());
		if (INVALID_FILE_ATTRIBUTES == dwFileAttributes || (0 == (FILE_ATTRIBUTE_DIRECTORY & dwFileAttributes)))
		{
			Usage(L"Invalid directory specified with +x", argv[0]);
		}
	}

	std::wstring sErrorInfo;

	// Read in the serialized scan files
	for (
		std::vector<std::wstring>::const_iterator iterFiles = scanfiles.begin();
		iterFiles != scanfiles.end();
		++iterFiles
		)
	{
		AaronLockerDeserializer scan;
		if (!scan.Deserialize(iterFiles->c_str(), sErrorInfo))
		{
			std::wcerr
				<< L"Error deserializing " << *iterFiles << L":" << std::endl
				<< sErrorInfo << std::endl
				<< std::endl;
			exit(-2);
		}
		else
		{
			scans.push_back(scan);
		}
	}

	// Process the scan files
	if (!ruleAnalyzer.ProcessScans(scans, windowsExesNotToExclude, bIncludeWindowsTempFiles, sErrorInfo))
	{
		std::wcerr
			<< L"Error processing scans:" << std::endl
			<< sErrorInfo << std::endl
			<< std::endl;
		Usage(NULL, argv[0]);
	}

	//TODO: one of these is case-sensitive, the other isn't. Maybe offer explicit options: -r -R -rr -RR
	// Remove proposed rule sets
	for (
		std::vector<std::wstring>::const_iterator iterNames = rulesetsToRemove.begin();
		iterNames != rulesetsToRemove.end();
		++iterNames
		)
	{
		if (!ruleAnalyzer.DeleteProposedRuleSet(*iterNames))
		{
			std::wcerr
				<< L"Rule set " << *iterNames << L" not found" << std::endl
				<< std::endl;
			Usage(NULL, argv[0]);
		}
	}
	for (
		std::vector<std::wstring>::const_iterator iterNames = rulesetNamePrefixesToRemove.begin();
		iterNames != rulesetNamePrefixesToRemove.end();
		++iterNames
		)
	{
		if (0 == ruleAnalyzer.DeleteProposedRuleSetBeginningWithName(*iterNames))
		{
			std::wcerr
				<< L"No rule sets beginning with \"" << *iterNames << L"\" found" << std::endl
				<< std::endl;
			Usage(NULL, argv[0]);
		}
	}

	if (sAnalysisFile.length() > 0)
	{
		std::wofstream fs;
		fs.open(sAnalysisFile, std::ios_base::out);
		if (fs.fail())
		{
			// If opening the file for output fails, quit now.
			std::wcerr << L"Cannot open output file " << sAnalysisFile << std::endl;
			Usage(NULL, argv[0]);
		}
		// Ensure that file output is UTF-8.
		fs.imbue(Utf8FileUtility::LocaleForWritingUtf8File());

		WriteProposedRuleSetsForAnalysis(ruleAnalyzer, strCommentSelectedOptions.str(), fs);

		fs.close();
	}
	// If +x not specified, show the proposed rule sets
	else if (sPolicyFileDirectory.length() == 0)
	{
		WriteProposedRuleSetSummary(ruleAnalyzer);
	}
	else // +x specified. Build the XML policies and write them to disk.
	{
		CommentRuleCollection_t comments;
		CommentRule comment;
		comment.SetComment(L"RuleBuilder options", strCommentSelectedOptions.str());
		comments.push_back(comment);
		if (!ruleAnalyzer.CreatePolicies(comments, sErrorInfo))
		{
			std::wcerr
				<< L"Error creating policies:" << std::endl
				<< sErrorInfo << std::endl
				<< std::endl;
			Usage(NULL, argv[0]);
		}

		// Define the policy file names.
		// Use forward slash as the path separator so it works on all platforms.
		// (Microsoft documentation for the primary file-creation API says "You may use either forward slashes (/) or backslashes (\) in this name."
		// https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew )
		const std::wstring sFnameBase = sPolicyFileDirectory + L"/AaronLocker-" + ruleAnalyzer.TimestampForFilename();
		std::wstring sEnforceXml = sFnameBase + L"-Enforce.xml";
		std::wstring sAuditXml = sFnameBase + L"-Audit.xml";
		bool bBothWritten = true;
		if (!ruleAnalyzer.SavePolicy(sEnforceXml.c_str(), true, sErrorInfo))
		{
			bBothWritten = false;
			std::wcerr << L"Error writing enforce policy XML to " << sEnforceXml << L": " << sErrorInfo << std::endl;
		}
		if (!ruleAnalyzer.SavePolicy(sAuditXml.c_str(), false, sErrorInfo))
		{
			bBothWritten = false;
			std::wcerr << L"Error writing audit policy XML to " << sAuditXml << L": " << sErrorInfo << std::endl;
		}
		if (bBothWritten)
		{
			// Output paths to the two files, and the unique identifier for the enforce/audit policy pair (from the timestamp pseudo-rule).
			std::wcout << L"Enforce XML    : " << sEnforceXml << std::endl;
			std::wcout << L"Audit XML      : " << sAuditXml << std::endl;
			std::wcout << L"Timestamp GUID : " << ruleAnalyzer.TimestampGuid() << std::endl;
		}
		else
		{
			return -1;
		}
	}

	return 0;
}
