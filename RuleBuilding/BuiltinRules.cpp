#include "pch.h"
#include "RuleItemCollectionOps.h"
#include "BuiltinRules.h"


// Implemented so that the "static initialization order fiasco" doesn't happen.
// https://isocpp.org/wiki/faq/ctors#static-init-order
// I.e., it works even if another compilation unit's static initialization depends on methods in this
// compilation unit and happens before this compilation unit's static initialization.

// ------------------------------------------------------------------------------------------
// Private implementation for this compilation unit, created and fully initialized on first use.
class BuiltInRules_SingletonImpl
{
public:
	// Access to these instance variables guaranteed to take place after initialization.
	PathRuleCollection_t
		DefaultPathRules,
		DefaultAdminPathRules,
		BuiltInDllFilesToExcludeByPath
		;
	PublisherRuleCollection_t 
		DefaultPublisherRules,
		BuiltInExeFilesToExcludeByPublisher,
		BuiltInDllFilesToExcludeByPublisher,
		GoogleChromeMachinewideInstallRules,
		GoogleChromePerUserInstallRules,
		MozillaRules,
		MicrosoftTeamsRules,
		ZoomRules,
		WebExRules,
		SlackRules,
		ChromiumBrowserFlashPlayerRules,
		IntuitDataUpdaterRules,
		AllStoreApps,
		MsSignedStoreApps,
		AllMicrosoftDLLs
		;

public:
	/// <summary>
	/// The only way to get access to the member variables is through this singleton accessor
	/// method which returns a reference to the singleton instance, created and initialized on
	/// first access.
	/// </summary>
	static const BuiltInRules_SingletonImpl& Get()
	{
		if (NULL == pInstance)
		{
			pInstance = new BuiltInRules_SingletonImpl();
		}
		return *pInstance;
	}
private:
	// Internal reference to singleton instance
	static BuiltInRules_SingletonImpl* pInstance;
	// Constructor accessible only to the static Get() method.
	BuiltInRules_SingletonImpl() { Initialize(); }
	~BuiltInRules_SingletonImpl() = default;
	// One-time initialization of the singleton instance.
	void Initialize();

private:
	// Not implemented
	BuiltInRules_SingletonImpl(const BuiltInRules_SingletonImpl&) = delete;
	BuiltInRules_SingletonImpl& operator = (const BuiltInRules_SingletonImpl&) = delete;
};

// Private static member that points to the singleton instance
BuiltInRules_SingletonImpl* BuiltInRules_SingletonImpl::pInstance = NULL;

// ------------------------------------------------------------------------------------------
// Public accessors

/// <summary>
/// Built-in/hardcoded logic about files not to build rules for.
/// </summary>
/// <param name="fd">Input: information about the file to consider</param>
/// <returns>true if the rule-builder should not bother creating a rule for this file</returns>
bool BuiltInRules::IgnoreFile(const FileDetails_t& fd)
{
	// Right now the only file we're ignoring is OneDrive's CollectSyncLogs.bat script.
	// It is unsigned and therefore requires a hash rule, for a hash that can change every time OneDrive
	// is updated.
	// CollectSyncLogs.bat is designed to be executed by an end user to gather a bunch of sensitive data
	// into a .cab file on the user's desktop for the user to send to Microsoft support engineers for analysis.
	// IMO, the likelihood of a user ever needing to execute it is very low. Take this out and it should (soon) be
	// possible to allow OneDrive to run without any custom rules.
	// Match on it if it's an unsigned script file in an unsafe directory, and ...
	if (
		false == fd.m_bIsSafeDir &&
		AppLockerFileDetails_ftype_t::ft_Script == fd.m_fileType &&
		0 == fd.m_ALPublisherName.length())
	{
		// ... partial directory name matches and file name matches (case-insensitive compare).
		// Case-insensitive inspection of file path by converting to lowercase.
		// Not doing that string manipulation unless the quick safedir and filetype checks don't match.
		// Take the file path, convert to lowercase for case-insensitive comparison.
		std::wstring sFilePathLC = fd.m_sFilePath;
		WString_To_Lower(sFilePathLC);
		if (
			std::wstring::npos != sFilePathLC.find(L"\\appdata\\local\\microsoft\\onedrive\\") &&
			GetFileNameFromFilePath(sFilePathLC) == L"collectsynclogs.bat"
			)
		{
			return true;
		}
	}
	return false;
}

const PathRuleCollection_t& BuiltInRules::DefaultPathRules()
{
	return BuiltInRules_SingletonImpl::Get().DefaultPathRules;
}

const PathRuleCollection_t& BuiltInRules::DefaultAdminPathRules()
{
	return BuiltInRules_SingletonImpl::Get().DefaultAdminPathRules;
}

const PublisherRuleCollection_t& BuiltInRules::DefaultPublisherRules()
{
	return BuiltInRules_SingletonImpl::Get().DefaultPublisherRules;
}

const PublisherRuleCollection_t& BuiltInRules::GoogleChromeMachinewideInstallRules()
{
	return BuiltInRules_SingletonImpl::Get().GoogleChromeMachinewideInstallRules;
}

const PublisherRuleCollection_t& BuiltInRules::GoogleChromePerUserInstallRules()
{
	return BuiltInRules_SingletonImpl::Get().GoogleChromePerUserInstallRules;
}

const PublisherRuleCollection_t& BuiltInRules::MozillaRules()
{
	return BuiltInRules_SingletonImpl::Get().MozillaRules;
}

const PublisherRuleCollection_t& BuiltInRules::MicrosoftTeamsRules()
{
	return BuiltInRules_SingletonImpl::Get().MicrosoftTeamsRules;
}

const PublisherRuleCollection_t& BuiltInRules::ZoomRules()
{
	return BuiltInRules_SingletonImpl::Get().ZoomRules;
}

const PublisherRuleCollection_t& BuiltInRules::WebExRules()
{
	return BuiltInRules_SingletonImpl::Get().WebExRules;
}

const PublisherRuleCollection_t& BuiltInRules::SlackRules()
{
	return BuiltInRules_SingletonImpl::Get().SlackRules;
}

const PublisherRuleCollection_t& BuiltInRules::ChromiumBrowserFlashPlayerRules()
{
	return BuiltInRules_SingletonImpl::Get().ChromiumBrowserFlashPlayerRules;
}

const PublisherRuleCollection_t& BuiltInRules::IntuitDataUpdaterRules()
{
	return BuiltInRules_SingletonImpl::Get().IntuitDataUpdaterRules;
}

const PublisherRuleCollection_t& BuiltInRules::AllStoreApps()
{
	return BuiltInRules_SingletonImpl::Get().AllStoreApps;
}

const PublisherRuleCollection_t& BuiltInRules::MsSignedStoreApps()
{
	return BuiltInRules_SingletonImpl::Get().MsSignedStoreApps;
}

const PublisherRuleCollection_t& BuiltInRules::AllMicrosoftDLLs()
{
	return BuiltInRules_SingletonImpl::Get().AllMicrosoftDLLs;
}

const PublisherRuleCollection_t& BuiltInRules::BuiltInExeFilesToExcludeByPublisher()
{
	return BuiltInRules_SingletonImpl::Get().BuiltInExeFilesToExcludeByPublisher;
}

const PublisherRuleCollection_t& BuiltInRules::BuiltInDllFilesToExcludeByPublisher()
{
	return BuiltInRules_SingletonImpl::Get().BuiltInDllFilesToExcludeByPublisher;
}

const PathRuleCollection_t& BuiltInRules::BuiltInDllFilesToExcludeByPath()
{
	return BuiltInRules_SingletonImpl::Get().BuiltInDllFilesToExcludeByPath;
}

// ------------------------------------------------------------------------------------------
// Some strings that show up a few times

static const wchar_t* const szProdNameMSWindowsOS = L"MICROSOFT® WINDOWS® OPERATING SYSTEM";
static const wchar_t* const szProdNameMSNetFx     = L"MICROSOFT® .NET FRAMEWORK";
static const wchar_t* const szMSDefaultSupportDLLs = L"Microsoft common support DLLs";

// ------------------------------------------------------------------------------------------

/// <summary>
/// One-time initialization of the singleton instance.
/// </summary>
void BuiltInRules_SingletonImpl::Initialize()
{
	// --------------------------------------------------------------------------------
	// Rules that can be applied for well-known/common apps.

	// WebEx used to sign everything with a "CISCO WEBEX" certificate, but as of March 9 2022 it's now a "CISCO SYSTEMS" cert.
	const wchar_t* const szCiscoSystemsPublisher = L"O=CISCO SYSTEMS, INC., L=SAN JOSE, S=CALIFORNIA, C=US";
	const wchar_t* const szWebExLabel = L"WebEx";

	WebExRules = {
		//
		// Older versions
		//
		PublisherRuleItem(
			szWebExLabel,
			L"O=CISCO WEBEX LLC, L=SAN JOSE, S=CALIFORNIA, C=US"
		),
		//PublisherRuleItem(
		//	szWebExLabel,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"ONNXRUNTIME.DLL",
		//	RuleItem::Collection_t::Dll
		//),
		PublisherRuleItem(
			szWebExLabel,
			L"O=INTEL CORPORATION, L=SANTA CLARA, S=CA, C=US",
			L"INTEL(R) THREADING BUILDING BLOCKS FOR WINDOWS",
			L"TBB.DLL",
			RuleItem::Collection_t::Dll
		),
		//
		// Versions as of March 9 2022
		//
		// MSI
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"WEBEX",
			RuleItem::Collection_t::Msi
		),
		// DLL
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			RuleItem::Collection_t::Dll
		),
		// EXE
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"WEBEX",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"CISCO WEBEX MEETING",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"WEBEX FOR WINDOWS HOST",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"CISCO WEBEX MEETINGS",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"VXME-AGENT",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			szWebExLabel,
			szCiscoSystemsPublisher,
			L"WEBEX MEETING",
			RuleItem::Collection_t::Exe
		)
	};

	ZoomRules = {
		PublisherRuleItem(
			L"Zoom",
			L"O=ZOOM VIDEO COMMUNICATIONS, INC., L=SAN JOSE, S=CALIFORNIA, C=US"
		)
	};

	SlackRules = {
		// Exe, Dll, Msi, Script:
		PublisherRuleItem(
			L"Slack",
			L"O=SLACK TECHNOLOGIES, INC., L=SAN FRANCISCO, S=CALIFORNIA, C=US"
		),
		// Store app
		PublisherRuleItem(
			L"Slack, from Slack Technologies Inc.",
			L"CN=B25A2379-D5D0-455B-826A-BFFC7EBB5713",
			L"91750D7E.Slack",
			RuleItem::Collection_t::Appx
		)
	};

	MicrosoftTeamsRules = {
		// Allow Microsoft Teams to run from unsafe directories:
		PublisherRuleItem(
			L"Microsoft Teams",
			MicrosoftPublisher(),
			L"MICROSOFT TEAMS"
		),
		PublisherRuleItem(
			L"Microsoft Teams",
			MicrosoftPublisher(),
			L"MICROSOFT TEAMS UPDATE"
		)
	};

	GoogleChromeMachinewideInstallRules = {
		// Enable these rules if Google Chrome is installed to ProgramFiles.
		// Google Chrome runs some code in the user profile even when Chrome is installed to Program Files.
		// This creates publisher rules that allow those components to run.
		// Note that Google's PublisherNames can use either "S=CA" or "S=CALIFORNIA" so we have to cover both.
		// In the past the ESET publisher has incorporated "S=SLOVAKIA" but not lately.
		PublisherRuleItem(
			L"Google Chrome (user-profile files in machine-wide install)",
			L"O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CA, C=US",
			L"SOFTWARE REPORTER TOOL",
			L"SOFTWARE_REPORTER_TOOL.EXE",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			L"Google Chrome (user-profile files in machine-wide install)",
			L"O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US",
			L"SOFTWARE REPORTER TOOL",
			L"SOFTWARE_REPORTER_TOOL.EXE",
			RuleItem::Collection_t::Exe
		),
		PublisherRuleItem(
			L"Google Chrome (user-profile files in machine-wide install)",
			L"O=ESET, SPOL. S R.O., L=BRATISLAVA, C=SK",
			L"CHROME CLEANUP",
			RuleItem::Collection_t::Dll
		),
		PublisherRuleItem(
			L"Google Chrome (user-profile files in machine-wide install)",
			L"O=ESET, SPOL. S R.O., L=BRATISLAVA, C=SK",
			L"CHROME PROTECTOR",
			RuleItem::Collection_t::Dll
		)
	};

	// Enable per-user install of Google Chrome (NOT THE GREATEST IDEA - requires allowing anything by Google)
	GoogleChromePerUserInstallRules = {
		PublisherRuleItem(
			L"Google Chrome per-user install",
			L"O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CA, C=US"
		),
		PublisherRuleItem(
			L"Google Chrome per-user install",
			L"O=GOOGLE LLC, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US"
		)
	};

	// Enable Mozilla Firefox
	MozillaRules = {
		// Exe, Dll, Msi, Script
		PublisherRuleItem(
			L"Mozilla Firefox",
			L"O=MOZILLA CORPORATION, L=MOUNTAIN VIEW, S=CALIFORNIA, C=US"
		),
		// Store app
		PublisherRuleItem(
			L"Mozilla Firefox, from Mozilla",
			L"CN=082E9164-EE6C-4EC8-B62C-441FAE7BEFA1",
			L"Mozilla.Firefox",
			RuleItem::Collection_t::Appx
		)
	};

	// Enable to allow Flash player in Google Chrome and/or Chromium-based Microsoft Edge:
	ChromiumBrowserFlashPlayerRules = {
		PublisherRuleItem(
			L"Flash Player for Chromium browsers",
			L"O=ADOBE INC., L=SAN JOSE, S=CA, C=US",
			L"SHOCKWAVE FLASH",
			L"PEPFLASHPLAYER.DLL",
			RuleItem::Collection_t::Dll
		)
	};

	// Enable Intuit-signed MSI files to execute; e.g., for TurboTax data updates.
	// (Windows makes it possible for non-admins to apply MSI patches to admin-installed apps if the
	// .msp patch is signed by the same signer as the original .msi.)
	IntuitDataUpdaterRules = {
		PublisherRuleItem(
			L"Intuit data updaters",
			L"O=INTUIT, INC., L=SAN DIEGO, S=CALIFORNIA, C=US",
			RuleItem::Collection_t::Msi
		),
		PublisherRuleItem(
			L"Intuit data updaters",
			L"O=INTUIT INC., L=SAN DIEGO, S=CALIFORNIA, C=US",
			RuleItem::Collection_t::Msi
		)
	};

	// Enable all signed Store apps (a.k.a., packaged apps).
	AllStoreApps = {
		PublisherRuleItem(
			L"Allow all signed packaged apps",
			sStar(),
			sStar(),
			sStar(),
			L"Allows Everyone to run packaged apps that are signed.",
			RuleItem::Collection_t::Appx
		)
	};

	// Enable Microsoft-signed Store apps (a.k.a., packaged apps).
	MsSignedStoreApps = {
		PublisherRuleItem(
			L"Allow Microsoft-signed packaged apps",
			MicrosoftAppxPublisher(),
			sStar(),
			sStar(),
			L"Allows Everyone to run packaged apps that are signed by Microsoft.",
			RuleItem::Collection_t::Appx
		),
		PublisherRuleItem(
			L"Allow Microsoft-signed Clipchamp",
			L"CN=33F0F141-36F3-4EC2-A77D-51B53D0BA0E4",
			L"Clipchamp.Clipchamp",
			sStar(),
			L"Allows Everyone to run Clipchamp signed by Microsoft.",
			RuleItem::Collection_t::Appx
		),
		//PublisherRuleItem(
		//	L"Allow Microsoft-signed Skype (Win8.1/Win10)", // Retired in May 2025
		//	L"CN=Skype Software Sarl, O=Microsoft Corporation, L=Luxembourg, S=Luxembourg, C=LU",
		//	L"Microsoft.SkypeApp",
		//	sStar(),
		//	L"Allows Everyone to run Skype signed by Microsoft.",
		//	RuleItem::Collection_t::Appx
		//),
	};

	// --------------------------------------------------------------------------------
	// Allows all Microsoft-signed DLLs. Last resort, discouraged, but might be needed 
	// for some crap, such as OneDrive's nonsense.
	// Note that if this is applied, PowerShell v2 signed DLLs are explicitly blocked for everyone.
	// By default, the path rule allowing non-admin execution in the Windows directory has specific 
	// exceptions for the PSv2 DLLs, which still allows admins to load those DLLs. Allowing all
	// MS-signed DLLs would then allow non-admins to load those PSv2 DLLs too, so to compensate we apply
	// a deny rule for everyone for those DLLs.

	{
		// Create a deny rule blocking everyone from loading the signed PowerShell v2 DLLs:
		// Observed in 
		// C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
		PublisherRuleItem ruleDenyPSv2DLLs;
		ruleDenyPSv2DLLs.m_sName = L"Block signed PowerShell v2 DLLs";
		ruleDenyPSv2DLLs.m_sDescription = L"Signed PowerShell v2 DLLs explicitly denied for all users to compensate for allowing all Microsoft-signed DLLs.";
		ruleDenyPSv2DLLs.m_bAllow = false;
		ruleDenyPSv2DLLs.m_collection = RuleItem::Collection_t::Dll;
		ruleDenyPSv2DLLs.m_sPublisher = MicrosoftPublisher();
		// Note that this DLL has a different string for product name from most Windows OS files
		ruleDenyPSv2DLLs.m_sProduct = L"MICROSOFT (R) WINDOWS (R) OPERATING SYSTEM";
		ruleDenyPSv2DLLs.m_sBinaryName = L"SYSTEM.MANAGEMENT.AUTOMATION.DLL";
		// Disallow anything lower than 10.x.
		ruleDenyPSv2DLLs.m_sBinaryVersionHigh = L"9.9.9.9";
		ruleDenyPSv2DLLs.m_sBinaryVersionLow = sStar();

		// Initialize the AllMicrosoftDLLs collection
		AllMicrosoftDLLs = {
			// Allow all Microsoft-signed DLL files
			PublisherRuleItem(
				L"Microsoft-signed DLLs",
				MicrosoftPublisher(),
				RuleItem::Collection_t::Dll
			),

			// And deny signed PowerShell v2 DLLs.
			ruleDenyPSv2DLLs
		};
	}

	// --------------------------------------------------------------------------------
	// Initialization of data that is needed only for RuleAnalyzer's internal use.
	// Default rules that should always be used.

	// --------------------------------------------------------------------------------
	// DefaultPublisherRules

	// Build this collection in pieces:
	DefaultPublisherRules = {
		// Allow Microsoft-signed MSI files (e.g., Office per-user initialization)
		PublisherRuleItem(
			L"Microsoft-signed MSI files",
			MicrosoftPublisher(),
			RuleItem::Collection_t::Msi
		),
		// Windows' built-in troubleshooting often involves running Microsoft-signed scripts in the user's profile
		PublisherRuleItem(
			L"Microsoft-signed script files",
			MicrosoftPublisher(),
			RuleItem::Collection_t::Script
		),
		// Microsoft-signed DLLs that are built as part of the Windows product 
		// (note that AppLocker cannot distinguish between the Windows code-signing cert and other Microsoft certs)
		PublisherRuleItem(
			szMSDefaultSupportDLLs,
			MicrosoftPublisher(),
			szProdNameMSWindowsOS,
			RuleItem::Collection_t::Dll
		),
		//// During Windows upgrade, setup loads %OSDRIVE%\$WINDOWS.~BT\SOURCES\GENERALTEL.DLL, which loads two other DLLs in the same directory
		//PublisherRuleItem(
		//	szMSDefaultSupportDLLs,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"GENERALTEL.DLL",
		//	L"Allow selected files from %OSDRIVE%\\$WINDOWS.~BT\\SOURCES during Windows upgrade",
		//	RuleItem::Collection_t::Dll
		//),
		//PublisherRuleItem(
		//	szMSDefaultSupportDLLs,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"WDSCORE.DLL",
		//	L"Allow selected files from %OSDRIVE%\\$WINDOWS.~BT\\SOURCES during Windows upgrade",
		//	RuleItem::Collection_t::Dll
		//),
		//PublisherRuleItem(
		//	szMSDefaultSupportDLLs,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"AEINV.DLL",
		//	L"Allow selected files from %OSDRIVE%\\$WINDOWS.~BT\\SOURCES during Windows upgrade",
		//	RuleItem::Collection_t::Dll
		//),
		// Allow protected content to run in MS Edge
		PublisherRuleItem(
			szMSDefaultSupportDLLs,
			MicrosoftPublisher(),
			L"WIDEVINE CONTENT DECRYPTION MODULE",
			L"MS Edge content protection",
			RuleItem::Collection_t::Dll
		),
		//##########################################################################
		// Windows Universal CRT, API sets, redists
		//##########################################################################
		//PublisherRuleItem(
		//	szMSDefaultSupportDLLs,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"APISETSTUB",
		//	L"MS Windows API set (api-ms-win-*.dll)",
		//	RuleItem::Collection_t::Dll
		//),
		//PublisherRuleItem(
		//	szMSDefaultSupportDLLs,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"D3DCOMPILER_47.DLL",
		//	L"MS Direct3D HLSL Compiler for Redistribution",
		//	RuleItem::Collection_t::Dll
		//),
		//PublisherRuleItem(
		//	szMSDefaultSupportDLLs,
		//	MicrosoftPublisher(),
		//	szProdNameMSWindowsOS,
		//	L"UCRTBASE.DLL",
		//	L"MS UCRT runtime DLL",
		//	RuleItem::Collection_t::Dll
		//),
	};
	
	//
	// Continue adding to DefaultPublisherRules...
	//
	
	// OneDrive
	const std::wstring sOneDrive = L"Microsoft OneDrive";
	const wchar_t* const szStar = L"*";
	// OneDrive Exe files
	typedef struct { const wchar_t* szProd; const wchar_t* szBinName; } prodbinname_t;
	const prodbinname_t OneDriveExes[] = {
		{
			L"MICROSOFT ONEDRIVE",
			szStar
		},
		{
			L"MICROSOFT LIST SYNC",
			L"MICROSOFTLISTSYNC.EXE"
		},
		{
			L"MICROSOFT LIST SYNC NATIVE MESSAGING CLIENT",
			L"MICROSOFTLISTSYNCNATIVEMESSAGING.EXE"
		},
		{
			L"MICROSOFT NUCLEUS",
			L"MICROSOFT.NUCLEUS.EXE"
		},
		{
			L"MICROSOFT NUCLEUS NATIVE MESSAGING CLIENT",
			L"MICROSOFT.NUCLEUS.NATIVEMESSAGING.EXE"
		},
		{
			L"MICROSOFT SHAREPOINT",
			L"MICROSOFT.SHAREPOINT.EXE"
		},
		{
			L"MICROSOFT SHAREPOINT NATIVE MESSAGING CLIENT",
			L"MICROSOFT.SHAREPOINT.NATIVEMESSAGING.EXE"
		}
	};
	const size_t nOneDriveExes = sizeof(OneDriveExes) / sizeof(OneDriveExes[0]);
	for (size_t ix = 0; ix < nOneDriveExes; ++ix)
	{
		DefaultPublisherRules.push_back(
			PublisherRuleItem(
				sOneDrive,
				MicrosoftPublisher(),
				OneDriveExes[ix].szProd,
				OneDriveExes[ix].szBinName,
				RuleItem::Collection_t::Exe
			)
		);
	}
	// OneDrive Dll files
	const prodbinname_t OneDriveDlls[] = {
		{
			L"GLIB",
			szStar
		},
		{
			L"MIP SDK",
			szStar
		},
		{
			L"QT5",
			szStar
		},
		{
			L"MICROSOFT ONEDRIVE",
			szStar
		},
		{
			L"MICROSOFT AD RMS",
			szStar
		},
		{
			L"THE OPENSSL TOOLKIT",
			szStar
		},
		{
			L"MICROSOFT© ADAL",
			L"ADAL.DLL"
		},
		{
			L"MICROSOFT OFFICE",
			L"FLOODGATECLIENTLIBRARYDLLWIN32CLIENT.DLL"
		},
		{
			L"LIBEGL",
			L"LIBEGL.DLL"
		},
		{
			L"LIBGLESV2",
			L"LIBGLESV2.DLL"
		},
		{
			L"MICROSOFT LIST SYNC",
			L"MICROSOFTLISTSYNC.DLL"
		},
		{
			L"MICROSOFT.OFFICE.IRM.MSOPROTECTOR",
			L"MICROSOFT.OFFICE.IRM.MSOPROTECTOR.DLL"
		},
		{
			L"MICROSOFT.OFFICE.IRM.OFCPROTECTOR",
			L"MICROSOFT.OFFICE.IRM.OFCPROTECTOR.DLL"
		},
		{
			L"MICROSOFT.OFFICE.IRM.PDFPROTECTOR",
			L"MICROSOFT.OFFICE.IRM.PDFPROTECTOR.DLL"
		},
		{
			L"MICROSOFT NUCLEUS",
			L"MICROSOFT.NUCLEUS.DLL"
		},
		{
			L"MICROSOFT SHAREPOINT",
			L"MICROSOFT.SHAREPOINT.DLL"
		},
		{
			L"MICROSOFT SHAREPOINT CALC LIBRARY",
			L"MICROSOFT.SHAREPOINT.CALC.DLL"
		},
		{
			L"MICROSOFT SHAREPOINT HTTP SERVER",
			L"MICROSOFT.SHAREPOINT.HTTPSVR.DLL"
		},
		{
			L"MICROSOFT SHAREPOINT WEB SOCKET CLIENT",
			L"MICROSOFT.SHAREPOINT.WEBSOCKETCLIENT.DLL"
		},
		{
			L"MICROSOFT EDGE EMBEDDED BROWSER WEBVIEW LOADER", 
			L"WEBVIEW2LOADER.DLL"
		},
		{
			L"MICROSOFT.AIP.PDFPROTECTOR", 
			L"MICROSOFT.AIP.PDFPROTECTOR.DLL"
		},
		{
			L"MICROSOFT EDGE DOMAIN ACTIONS COMPONENT",
			szStar
		},
		{
			L"MICROSOFT EDGE",
			szStar
		},
		// Several resource-only DLLs that have a product name but no binary name
		{ L"CONCRT140 FORWARDER", szStar },
		{ L"MSVCP140_1 FORWARDER", szStar },
		{ L"MSVCP140_2 FORWARDER", szStar },
		{ L"MSVCP140 FORWARDER", szStar },
		{ L"VCAMP140 FORWARDER", szStar },
		{ L"VCCORLIB140 FORWARDER", szStar },
		{ L"VCOMP140 FORWARDER", szStar },
		{ L"VCRUNTIME140_1 FORWARDER", szStar },
		{ L"VCRUNTIME140 FORWARDER", szStar },
	};
	const size_t nOneDriveDlls = sizeof(OneDriveDlls) / sizeof(OneDriveDlls[0]);
	for (size_t ix = 0; ix < nOneDriveDlls; ++ix)
	{
		DefaultPublisherRules.push_back(
			PublisherRuleItem(
				sOneDrive,
				MicrosoftPublisher(),
				OneDriveDlls[ix].szProd,
				OneDriveDlls[ix].szBinName,
				RuleItem::Collection_t::Dll
			)
		);
	}

	/*
	//
	// Add MSVC redist DLLs to DefaultPublisherRules...
	//
	Supports the creation of publisher rules for observed Microsoft redistributable DLL files.
	There are already MSVC*, MFC* and other redistributable DLLs in Windows - this code also allows redistributable DLLs that often ship with
	other products and are installed into user-writable directories.
	This output allows any version of signed MS redist DLLs that shipped with a known version of Visual Studio.
	This is not the same as allowing everything signed by Microsoft or that is part of Visual Studio - just the redistributable runtime library support DLLs.

	This set can be updated as additional MSVC* and MFC* DLLs appear in event logs when observed executing from user-writable directories.
	Add more files as they are identified.
	*/
	const std::wstring sMsvcRedistDlls = L"MSVC redistrib DLLs";
	const prodbinname_t MsvcRedistDlls[] =
	{
		//##########################################################################
		// Visual Studio 2005
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2005",
		L"MSVCP80.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2005",
		L"MSVCR80.DLL"
		},

		//##########################################################################
		// Visual Studio 2008
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2008",
		L"MFC90U.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2008",
		L"MSVCP90.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2008",
		L"MSVCR90.DLL"
		},

		//##########################################################################
		// Visual Studio 2010
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2010",
		L"MSVCP100.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2010",
		L"MSVCR100_CLR0400.DLL"
		},

		//##########################################################################
		// Visual Studio 2012
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2012",
		L"MFC110.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2012",
		L"MSVCP110.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2012",
		L"MSVCR110.DLL"
		},

		//##########################################################################
		// Visual Studio 2013
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2013",
		L"MFC120.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2013",
		L"MFC120U.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2013",
		L"MSVCP120.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2013",
		L"MSVCR120.DLL"
		},

		//##########################################################################
		// Visual Studio 2015
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2015",
		L"CONCRT140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2015",
		L"MSVCP140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2015",
		L"VCCORLIB140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2015",
		L"VCRUNTIME140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2015",
		L"MFC140U.DLL"
		},

		//##########################################################################
		// Visual Studio 2017
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"CONCRT140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"MFC140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"MSVCP140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"MSVCP140_1.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"MSVCP140_2.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"VCCORLIB140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO® 2017",
		L"VCRUNTIME140.DLL"
		},

		//##########################################################################
		// Visual Studio 10
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO® 10",
		L"MFC100U.DLL"
		},

		//##########################################################################
		// Visual Studio (unspecified)
		//##########################################################################
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"CONCRT140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MFC140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MFC140U.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MSVCP140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MSVCP140_1.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MSVCP140_2.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MSVCP140_ATOMIC_WAIT.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"MSVCP140_CODECVT_IDS.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"VCCORLIB140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"VCRUNTIME140.DLL"
		},
		{
		L"MICROSOFT® VISUAL STUDIO®",
		L"VCRUNTIME140_1.DLL"
		},
	};
	const size_t nMsvcRedistDlls = sizeof(MsvcRedistDlls) / sizeof(MsvcRedistDlls[0]);
	for (size_t ix = 0; ix < nMsvcRedistDlls; ++ix)
	{
		DefaultPublisherRules.push_back(
			PublisherRuleItem(
				szMSDefaultSupportDLLs,
				MicrosoftPublisher(),
				MsvcRedistDlls[ix].szProd,
				MsvcRedistDlls[ix].szBinName,
				sMsvcRedistDlls,
				RuleItem::Collection_t::Dll
			)
		);
	}

	// Add allow-all Windows-signed Appx rule to DefaultPublisherRules
	{
		PublisherRuleItem rule;
		rule.m_bAllow = true; // Allow rule
		rule.m_sName = L"Allow all Windows-signed packaged apps";
		rule.m_sDescription = L"Allows everyone to run packaged apps that are part of Windows.";
		rule.m_collection = RuleItem::Collection_t::Appx;
		rule.m_sPublisher = MicrosoftWindowsAppxPublisher();
		rule.m_sProduct = sStar();
		rule.m_sBinaryName = sStar();
		rule.m_sBinaryVersionHigh = sStar();
		rule.m_sBinaryVersionLow = sStar();
		// rule.m_sUserOrGroupSid - default value;
		DefaultPublisherRules.push_back(rule);
	}

	//
	// Add Deny rule(s) to DefaultPublisherRules
	//
	// Disallow BgInfo 4.25 and earlier
	{
		PublisherRuleItem rule;
		rule.m_bAllow = false; // Deny rule
		rule.m_sName = L"BgInfo: Disallow old versions of Sysinternals Bginfo.exe";
		rule.m_sDescription = L"Disallow Sysinternals Bginfo.exe versions 4.25 and earlier that aren't AppLocker-aware";
		rule.m_collection = RuleItem::Collection_t::Exe;
		rule.m_sPublisher = MicrosoftPublisher();
		rule.m_sProduct = L"BGINFO";
		rule.m_sBinaryName = L"BGINFO.EXE";
		rule.m_sBinaryVersionHigh = L"4.25.0.0";
		rule.m_sBinaryVersionLow = sStar();
		// rule.m_sUserOrGroupSid - default value;
		DefaultPublisherRules.push_back(rule);
	}


	// --------------------------------------------------------------------------------
	// Initialize DefaultPathRules: default path rules that should always be used

	// Allow selected Windows Installer files, by path
	const std::wstring sAllowSelectedMSIs = L"Allow selected Windows Installer files";
	{
		// Two path rules, mostly the same
		PathRuleItem rule;
		rule.m_bAllow = true; // Allow rule
		rule.m_collection = RuleItem::Collection_t::Msi;
		rule.m_sName = sAllowSelectedMSIs;
		rule.m_sDescription = L"Allows everyone to run installer files in the SCCM cache (%windir%\\ccmcache).";
		rule.m_sPath = L"%WINDIR%\\ccmcache\\*";
		// rule.m_sUserOrGroupSid - default value;
		DefaultPathRules.push_back(rule);

		rule.m_sDescription = L"Allows everyone to run all Windows Installer files located in %systemdrive%\\Windows\\Installer.";
		rule.m_sPath = L"%WINDIR%\\Installer\\*";
		DefaultPathRules.push_back(rule);
	}

	// --------------------------------------------------------------------------------
	// Initialize DefaultAdminPathRules
	{
		// Four path rules, mostly the same
		const std::wstring sAdminsAllowAll = L"Administrators: allow all";
		PathRuleItem rule;
		rule.m_bAllow = true; // Allow rule
		rule.m_sName = sAdminsAllowAll;
		rule.m_sPath = L"*";
		rule.m_sUserOrGroupSid = SidAdministrators();

		rule.m_collection = RuleItem::Collection_t::Exe;
		rule.m_sDescription = L"Allows members of the local Administrators group to run all exe files.";
		DefaultAdminPathRules.push_back(rule);
		rule.m_collection = RuleItem::Collection_t::Dll;
		rule.m_sDescription = L"Allows members of the local Administrators group to load all DLLs.";
		DefaultAdminPathRules.push_back(rule);
		rule.m_collection = RuleItem::Collection_t::Msi;
		rule.m_sDescription = L"Allows members of the local Administrators group to run all Windows Installer files.";
		DefaultAdminPathRules.push_back(rule);
		rule.m_collection = RuleItem::Collection_t::Script;
		rule.m_sDescription = L"Allows members of the local Administrators group to run all scripts.";
		DefaultAdminPathRules.push_back(rule);
	}

	// --------------------------------------------------------------------------------
	// Initialize the exclusions for the Windows path rules: files installed by Windows under %WINDIR% to
	// exclude from the path rules that allow non-admins to execute anything under %WINDIR%. This is a hardcoded
	// list rather than an endpoint scan result because some of the content changes across different Windows versions
	// so no single scan will get them all, and we want to exclude them all. 
	{
		// Built-in Windows executables that non-admins usually don't need to run and that can be used for
		// AppLocker bypass or for nefarious activities (e.g., Cipher.exe used by ransomware to encrypt
		// files).
		// This array specifies files to be excluded by product name and binary name:
		const prodbinname_t BuiltInExesToExcludeByPubBinary[] =
		{
			// Note that PresentationHost.exe has been observed with the .NET Fx (Win7) and Windows OS product names (Win8.1+)
			{ L"INTERNET EXPLORER",  L"MSHTA.EXE" },
			{ szProdNameMSNetFx,     L"ADDINPROCESS.EXE" },
			{ szProdNameMSNetFx,     L"ADDINPROCESS32.EXE" },
			{ szProdNameMSNetFx,     L"ADDINUTIL.EXE" },
			{ szProdNameMSNetFx,     L"ASPNET_COMPILER.EXE" },
			{ szProdNameMSNetFx,     L"IEEXEC.EXE" },
			{ szProdNameMSNetFx,     L"INSTALLUTIL.EXE" },
			{ szProdNameMSNetFx,     L"MICROSOFT.WORKFLOW.COMPILER.EXE" },
			{ szProdNameMSNetFx,     L"MSBUILD.EXE" },
			{ szProdNameMSNetFx,     L"PRESENTATIONHOST.EXE" },
			{ szProdNameMSNetFx,     L"REGASM.EXE" },
			{ szProdNameMSNetFx,     L"REGSVCS.EXE" },
			{ szProdNameMSWindowsOS, L"CIPHER.EXE" },
			{ szProdNameMSWindowsOS, L"PRESENTATIONHOST.EXE" },
			{ szProdNameMSWindowsOS, L"RUNAS.EXE" },
			{ szProdNameMSWindowsOS, L"WMIC.EXE" },
		};
		for (size_t ix = 0; ix < sizeof(BuiltInExesToExcludeByPubBinary) / sizeof(BuiltInExesToExcludeByPubBinary[0]); ++ix)
		{
			BuiltInExeFilesToExcludeByPublisher.push_back(
				PublisherRuleItem(
					L"", // No need for label on exception
					MicrosoftPublisher(),
					BuiltInExesToExcludeByPubBinary[ix].szProd,
					BuiltInExesToExcludeByPubBinary[ix].szBinName,
					RuleItem::Collection_t::Exe
				)
			);
		}

		// On Windows 7 and Windows 8.1 (and corresponding Windows Server editions), exclude the built-in
		// PowerShell executables for non-admin execution, but allow them for non-admin execution if an
		// AppLocker-aware version (PS v5.x, binary version 10.x or newer) is installed.
		// This does not prevent admins from running any version of PowerShell.
		// Did some testing with latest version of PowerShell Core 7. It adheres to AppLocker awareness
		// rules of Windows PowerShell v5.1. The rule here won't affect PowerShell Core because its
		// product name is PowerShell, not Windows.
		{
			// Create exceptions for PowerShell.exe and PowerShell_ISE.
			PublisherRuleItem rule;
			rule.m_sPublisher = MicrosoftPublisher();
			rule.m_sProduct = szProdNameMSWindowsOS;
			rule.m_sBinaryName = L"POWERSHELL.EXE";
			rule.m_sBinaryVersionHigh = L"9.9.9.9";
			rule.m_sBinaryVersionLow = sStar();
			BuiltInExeFilesToExcludeByPublisher.push_back(rule);
			rule.m_sBinaryName = L"POWERSHELL_ISE.EXE";
			BuiltInExeFilesToExcludeByPublisher.push_back(rule);
		}

		// Block PowerShell v2 for non-admin use to prevent "powershell.exe -version 2.0" to get to a PowerShell 
		// interface that is not AppLocker-aware.
		// Implemented with a publisher exception for the signed System.Management.Automation.dll, and two path rules
		// for specific JIT-compiled System.Management DLLs.
		{
			// Observed in 
			// C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
			PublisherRuleItem rule;
			rule.m_sPublisher = MicrosoftPublisher();
			// Note that this DLL has a different string for product name from most Windows OS files
			rule.m_sProduct = L"MICROSOFT (R) WINDOWS (R) OPERATING SYSTEM";
			rule.m_sBinaryName = L"SYSTEM.MANAGEMENT.AUTOMATION.DLL";
			// Exception for anything lower than 10.x.
			rule.m_sBinaryVersionHigh = L"9.9.9.9";
			rule.m_sBinaryVersionLow = sStar();
			BuiltInDllFilesToExcludeByPublisher.push_back(rule);
		}

		{
			// Two path rules, identical except for the path.
			PathRuleItem rule;
			rule.m_sPath = L"%WINDIR%\\assembly\\NativeImages_v2.0.50727_32\\System.Management.A#\\*";
			BuiltInDllFilesToExcludeByPath.push_back(rule);

			rule.m_sPath = L"%WINDIR%\\assembly\\NativeImages_v2.0.50727_64\\System.Management.A#\\*";
			BuiltInDllFilesToExcludeByPath.push_back(rule);
		}
	}
}
