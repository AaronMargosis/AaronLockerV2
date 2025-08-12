// OfficeMacroControlTool.cpp

#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>
#include <iomanip>
#include "../AaronLocker_CommonUtils/FileSystemUtils.h"
#include "../AaronLocker_CommonUtils/StringUtils.h"
#include "../AaronLocker_CommonUtils/SysErrorMessage.h"

#include "../OfficeMacroControl/OfficeMacroControl.h"

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
		<< L"    " << sExe << L" [options...]" << std::endl
		<< std::endl
		<< L"Options include:" << std::endl
		<< std::endl
		<< L"  -ASR         : Set Attack Surface Reduction rules to Not Configured" << std::endl
		<< L"  +ASR:block   : Set Attack Surface Reduction rules to BLOCK mode" << std::endl
		<< L"  +ASR:audit   : Set Attack Surface Reduction rules to AUDIT mode" << std::endl
		<< L"  +ASR:warn    : Set Attack Surface Reduction rules to WARN mode" << std::endl
		<< L"  -DUM         : Set \"Disable All Unsigned Macros\" to Not Configured" << std::endl
		<< L"  +DUM:basic   : Set \"Disable All Unsigned Macros\" to basic restrictions" << std::endl
		<< L"                 Configures \"VBA Macro Notification Settings\" to \"Disable all except digitally signed macros\"" << std::endl
		<< L"  +DUM:trusted : +DUM:basic plus \"Require macros to be signed by a trusted publisher\"" << std::endl
		<< L"  +DUM:strict  : +DUM:trusted plus \"Block certificates from trusted publishers that are only installed in the current" << std::endl
		<< L"                 user certificate store\" and \"Require Extended Key Usage (EKU) for certificates from trusted publishers\"" << std::endl
		<< L"  +BM, -BM     : Configure/unconfigure \"Block macros from running in Office files from the internet\"" << std::endl
		<< L"  +VAdd, -VAdd : Configure/unconfigure \"Disable unsigned VBA addins\"" << std::endl
		<< L"                 For Excel and PowerPoint: \"Require that application add-ins are signed by Trusted Publisher\"" << std::endl
		<< L"  +DTL, -DTL   : Configure/unconfigure \"Disable all trusted locations\"" << std::endl
		<< L"  +LFB, -LFB   : Configure/unconfigure \"Legacy File Block\"" << std::endl
		<< L"  +SEM, -SEM   : Configure/unconfigure \"Scan encrypted macros\"" << std::endl
		<< L"  +DVBA, -DVBA : Configure/unconfigure \"Disable all VBA\"" << std::endl
		<< std::endl
		<< L"  +LHF         : Configure all the low-hanging fruit; equivalent to" << std::endl
		<< L"                     +ASR:audit +BM +VAdd +DTL +SEM" << std::endl
		<< L"  +MHF         : Configure all the medium-hanging fruit; equivalent to" << std::endl
		<< L"                     +ASR:block +BM +VAdd +DTL +LFB +SEM" << std::endl
		<< L"  +Max         : Configure strict settings (all but \"Disable all VBA\"); equivalent to" << std::endl
		<< L"                     +ASR:block +DUM:strict +BM +VAdd +DTL +LFB +SEM" << std::endl
		<< std::endl
		<< L"  +NC          : Explicitly revert all unspecified options to Not Configured" << std::endl
		<< L"                 (If used without any other options, reverts all the above options to Not Configured.)" << std::endl
		<< L"  -WhatIf      : List what would be changed without making changes" << std::endl
		<< L"  -Verify      : Verify selected settings against current local policy" << std::endl
		<< std::endl
		<< L"If options conflict, the last one specified takes precedence." << std::endl
		<< std::endl;
	exit(-1);
}

/// <summary>
/// true/false, or not specified
/// </summary>
enum class config_t { eFalse, eTrue, eNotSpecified };

int wmain(int argc, wchar_t** argv)
{
	if (1 == argc)
	{
		Usage(NULL, argv[0]);
	}

	// Set output mode to UTF8.
	if (_setmode(_fileno(stdout), _O_U8TEXT) == -1 || _setmode(_fileno(stderr), _O_U8TEXT) == -1)
	{
		std::wcerr << L"Unable to set stdout and/or stderr modes to UTF8." << std::endl;
	}

	// Variables corresponding to command-line option selections.
	bool bWhatIf = false;
	bool bVerify = false;
	// bASR and bUnsignedMacro get set true if corresponding option actually specified
	bool bASR = false;
	bool bUnsignedMacro = false;
	OfficeMacroControl::eASR_options_t Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eNotConfigured;
	OfficeMacroControl::eUnsignedMacro_options_t Configure_DisableAllUnsignedMacros = OfficeMacroControl::eUnsignedMacro_options_t::eNotConfigured;
	config_t Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eNotSpecified;
	config_t Configure_DisableUnsignedVbaAddins = config_t::eNotSpecified;
	config_t Configure_DisableAllTrustedLocations = config_t::eNotSpecified;
	config_t Configure_LegacyFileBlock = config_t::eNotSpecified;
	config_t Configure_ScanEncryptedMacros = config_t::eNotSpecified;
	config_t Configure_DisableAllVBA = config_t::eNotSpecified;
	bool bForceNotConfigured = false;

	// Parse command line options
	int ixArg = 1;
	while (ixArg < argc)
	{
		if (0 == StringCompareCaseInsensitive(L"-ASR", argv[ixArg]))
		{
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eNotConfigured;
			bASR = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+ASR:block", argv[ixArg]))
		{
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eBlock;
			bASR = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+ASR:audit", argv[ixArg]))
		{
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eAudit;
			bASR = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+ASR:warn", argv[ixArg]))
		{
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eWarn;
			bASR = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"-DUM", argv[ixArg]))
		{
			Configure_DisableAllUnsignedMacros = OfficeMacroControl::eUnsignedMacro_options_t::eNotConfigured;
			bUnsignedMacro = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+DUM:basic", argv[ixArg]))
		{
			Configure_DisableAllUnsignedMacros = OfficeMacroControl::eUnsignedMacro_options_t::eBasic;
			bUnsignedMacro = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+DUM:trusted", argv[ixArg]))
		{
			Configure_DisableAllUnsignedMacros = OfficeMacroControl::eUnsignedMacro_options_t::eReqTrustedPublisher;
			bUnsignedMacro = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+DUM:strict", argv[ixArg]))
		{
			Configure_DisableAllUnsignedMacros = OfficeMacroControl::eUnsignedMacro_options_t::eStrict;
			bUnsignedMacro = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"+BM", argv[ixArg]))
		{
			Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"-BM", argv[ixArg]))
		{
			Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eFalse;
		}
		else if (0 == StringCompareCaseInsensitive(L"+VAdd", argv[ixArg]))
		{
			Configure_DisableUnsignedVbaAddins = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"-VAdd", argv[ixArg]))
		{
			Configure_DisableUnsignedVbaAddins = config_t::eFalse;
		}
		else if (0 == StringCompareCaseInsensitive(L"+DTL", argv[ixArg]))
		{
			Configure_DisableAllTrustedLocations = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"-DTL", argv[ixArg]))
		{
			Configure_DisableAllTrustedLocations = config_t::eFalse;
		}
		else if (0 == StringCompareCaseInsensitive(L"+LFB", argv[ixArg]))
		{
			Configure_LegacyFileBlock = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"-LFB", argv[ixArg]))
		{
			Configure_LegacyFileBlock = config_t::eFalse;
		}
		else if (0 == StringCompareCaseInsensitive(L"+SEM", argv[ixArg]))
		{
			Configure_ScanEncryptedMacros = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"-SEM", argv[ixArg]))
		{
			Configure_ScanEncryptedMacros = config_t::eFalse;
		}
		else if (0 == StringCompareCaseInsensitive(L"+DVBA", argv[ixArg]))
		{
			Configure_DisableAllVBA = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"-DVBA", argv[ixArg]))
		{
			Configure_DisableAllVBA = config_t::eFalse;
		}
		else if (0 == StringCompareCaseInsensitive(L"+LHF", argv[ixArg]))
		{
			// low-hanging fruit
			bASR = true;
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eAudit;
			Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eTrue;
			Configure_DisableUnsignedVbaAddins = config_t::eTrue;
			Configure_DisableAllTrustedLocations = config_t::eTrue;
			Configure_ScanEncryptedMacros = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"+MHF", argv[ixArg]))
		{
			// medium-hanging fruit
			bASR = true;
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eBlock;
			Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eTrue;
			Configure_DisableUnsignedVbaAddins = config_t::eTrue;
			Configure_DisableAllTrustedLocations = config_t::eTrue;
			Configure_LegacyFileBlock = config_t::eTrue;
			Configure_ScanEncryptedMacros = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"+Max", argv[ixArg]))
		{
			// max strict (except for disabling all VBA)
			bASR = true;
			bUnsignedMacro = true;
			Configure_AttackSurfaceReduction = OfficeMacroControl::eASR_options_t::eBlock;
			Configure_DisableAllUnsignedMacros = OfficeMacroControl::eUnsignedMacro_options_t::eStrict;
			Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eTrue;
			Configure_DisableUnsignedVbaAddins = config_t::eTrue;
			Configure_DisableAllTrustedLocations = config_t::eTrue;
			Configure_LegacyFileBlock = config_t::eTrue;
			Configure_ScanEncryptedMacros = config_t::eTrue;
		}
		else if (0 == StringCompareCaseInsensitive(L"+NC", argv[ixArg]))
		{
			// Anything not explicitly configured gets reverted to Not Configured
			bForceNotConfigured = true;
		}
		else if (0 == StringCompareCaseInsensitive(L"-WhatIf", argv[ixArg]))
		{
			// Show proposed changes, don't make changes
			// WhatIf and Verify are mutually exclusive
			bWhatIf = true;
			bVerify = false;
		}
		else if (0 == StringCompareCaseInsensitive(L"-Verify", argv[ixArg]))
		{
			// Read and report settings against selected settings (don't make changes)
			// WhatIf and Verify are mutually exclusive
			bWhatIf = false;
			bVerify = true;
		}
		else
		{
			std::wcerr << L"Unrecognized command-line option: " << argv[ixArg] << std::endl;
			Usage(NULL, argv[0]);
		}

		++ixArg;
	}

	if (bForceNotConfigured)
	{
		// Anything not explicitly specified on the command line gets reverted to Not Configured.

		bASR = bUnsignedMacro = true;

		if (config_t::eNotSpecified == Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet)
			Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = config_t::eFalse;

		if (config_t::eNotSpecified == Configure_DisableUnsignedVbaAddins)
			Configure_DisableUnsignedVbaAddins = config_t::eFalse;

		if (config_t::eNotSpecified == Configure_DisableAllTrustedLocations)
			Configure_DisableAllTrustedLocations = config_t::eFalse;

		if (config_t::eNotSpecified == Configure_LegacyFileBlock)
			Configure_LegacyFileBlock = config_t::eFalse;

		if (config_t::eNotSpecified == Configure_ScanEncryptedMacros)
			Configure_ScanEncryptedMacros = config_t::eFalse;

		if (config_t::eNotSpecified == Configure_DisableAllVBA)
			Configure_DisableAllVBA = config_t::eFalse;
	}

	//std::wcout << L"bASR = " << bASR << std::endl;
	//std::wcout << L"Configure_AttackSurfaceReduction = " << (int)Configure_AttackSurfaceReduction << std::endl;
	//std::wcout << L"bUnsignedMacro " << bUnsignedMacro << std::endl;
	//std::wcout << L"Configure_DisableAllUnsignedMacros = " << (int)Configure_DisableAllUnsignedMacros << std::endl;
	//std::wcout << L"Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet = " << (int)Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet << std::endl;
	//std::wcout << L"Configure_DisableUnsignedVbaAddins = " << (int)Configure_DisableUnsignedVbaAddins << std::endl;
	//std::wcout << L"Configure_DisableAllTrustedLocations = " << (int)Configure_DisableAllTrustedLocations << std::endl;
	//std::wcout << L"Configure_LegacyFileBlock = " << (int)Configure_LegacyFileBlock << std::endl;
	//std::wcout << L"Configure_ScanEncryptedMacros = " << (int)Configure_ScanEncryptedMacros << std::endl;
	//std::wcout << L"Configure_DisableAllVBA = " << (int)Configure_DisableAllVBA << std::endl;
	//std::wcout << L"bForceNotConfigured = " << (int)bForceNotConfigured << std::endl;
	//std::wcout << std::endl;

	if (bWhatIf)
	{
		// Output tab-delimited output to stdout
		// Report the GP paths/names and the registry key/values.
		// Output a header line first:
		std::wcout << L"GPO path\tGPO setting name\tRegistry Key\tRegistry Value Name\tDesired GPO setting\tDesired Reg Value" << std::endl;

		if (bASR)
			OfficeMacroControl::Report_AttackSurfaceReduction(Configure_AttackSurfaceReduction, std::wcout);

		if (bUnsignedMacro)
			OfficeMacroControl::Report_DisableAllUnsignedMacros(Configure_DisableAllUnsignedMacros, std::wcout);

		config_t eCfg;
		eCfg = Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet;
		if (config_t::eNotSpecified != eCfg)
			OfficeMacroControl::Report_BlockMacrosFromRunningInOfficeFilesFromTheInternet((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_DisableUnsignedVbaAddins;
		if (config_t::eNotSpecified != eCfg)
			OfficeMacroControl::Report_DisableUnsignedVbaAddins((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_DisableAllTrustedLocations;
		if (config_t::eNotSpecified != eCfg)
			OfficeMacroControl::Report_DisableAllTrustedLocations((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_LegacyFileBlock;
		if (config_t::eNotSpecified != eCfg)
			OfficeMacroControl::Report_LegacyFileBlock((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_ScanEncryptedMacros;
		if (config_t::eNotSpecified != eCfg)
			OfficeMacroControl::Report_ScanEncryptedMacros((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_DisableAllVBA;
		if (config_t::eNotSpecified != eCfg)
			OfficeMacroControl::Report_DisableAllVBA((config_t::eTrue == eCfg), std::wcout);

		return 0;
	}
	else if (bVerify)
	{
		// Read-only view of local GPO (doesn't require administrative rights)
		OfficeMacroControl omc(true);
		std::wstring sErrorInfo = omc.ErrorInfo();
		if (sErrorInfo.length() > 0)
		{
			std::wcerr << sErrorInfo << std::endl;
			return -5;
		}

		// Output tab-delimited output to stdout
		// Report the GP paths/names and the registry key/values.
		// Output a header line first:
		std::wcout << L"GPO path\tGPO setting name\tRegistry Key\tRegistry Value Name\tDesired GPO setting\tDesired Reg Value\tActual Reg Value" << std::endl;

		if (bASR)
			omc.Verify_AttackSurfaceReduction(Configure_AttackSurfaceReduction, std::wcout);

		if (bUnsignedMacro)
			omc.Verify_DisableAllUnsignedMacros(Configure_DisableAllUnsignedMacros, std::wcout);

		config_t eCfg;
		eCfg = Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet;
		if (config_t::eNotSpecified != eCfg)
			omc.Verify_BlockMacrosFromRunningInOfficeFilesFromTheInternet((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_DisableUnsignedVbaAddins;
		if (config_t::eNotSpecified != eCfg)
			omc.Verify_DisableUnsignedVbaAddins((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_DisableAllTrustedLocations;
		if (config_t::eNotSpecified != eCfg)
			omc.Verify_DisableAllTrustedLocations((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_LegacyFileBlock;
		if (config_t::eNotSpecified != eCfg)
			omc.Verify_LegacyFileBlock((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_ScanEncryptedMacros;
		if (config_t::eNotSpecified != eCfg)
			omc.Verify_ScanEncryptedMacros((config_t::eTrue == eCfg), std::wcout);

		eCfg = Configure_DisableAllVBA;
		if (config_t::eNotSpecified != eCfg)
			omc.Verify_DisableAllVBA((config_t::eTrue == eCfg), std::wcout);

		sErrorInfo = omc.ErrorInfo();
		if (sErrorInfo.length() > 0)
		{
			std::wcerr
				<< L"Error information:" << std::endl
				<< sErrorInfo << std::endl;
		}

		return 0;
	}
	else
	{
		// Make specified changes to local GPO
		OfficeMacroControl omc;
		std::wstring sErrorInfo = omc.ErrorInfo();
		if (sErrorInfo.length() > 0)
		{
			std::wcerr << sErrorInfo << std::endl;
			return -5;
		}

		if (bASR)
			omc.Enforce_AttackSurfaceReduction(Configure_AttackSurfaceReduction);

		if (bUnsignedMacro)
			omc.Enforce_DisableAllUnsignedMacros(Configure_DisableAllUnsignedMacros);

		if (config_t::eNotSpecified != Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet)
			omc.Enforce_BlockMacrosFromRunningInOfficeFilesFromTheInternet(config_t::eFalse != Configure_BlockMacrosFromRunningInOfficeFilesFromTheInternet);

		if (config_t::eNotSpecified != Configure_DisableUnsignedVbaAddins)
			omc.Enforce_DisableUnsignedVbaAddins(config_t::eFalse != Configure_DisableUnsignedVbaAddins);

		if (config_t::eNotSpecified != Configure_DisableAllTrustedLocations)
			omc.Enforce_DisableAllTrustedLocations(config_t::eFalse != Configure_DisableAllTrustedLocations);

		if (config_t::eNotSpecified != Configure_LegacyFileBlock)
			omc.Enforce_LegacyFileBlock(config_t::eFalse != Configure_LegacyFileBlock);

		if (config_t::eNotSpecified != Configure_ScanEncryptedMacros)
			omc.Enforce_ScanEncryptedMacros(config_t::eFalse != Configure_ScanEncryptedMacros);

		if (config_t::eNotSpecified != Configure_DisableAllVBA)
			omc.Enforce_DisableAllVBA(config_t::eFalse != Configure_DisableAllVBA);

		sErrorInfo = omc.ErrorInfo();
		if (sErrorInfo.length() > 0)
		{
			std::wcerr
				<< L"Error information:" << std::endl
				<< sErrorInfo << std::endl;
		}

		omc.CleanUpEmptyKeys();

		HRESULT hr = omc.CommitChanges();
		std::wcout << SysErrorMessage(hr) << std::endl;

		return (int)hr;
	}
}