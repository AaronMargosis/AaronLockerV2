#include "pch.h"
#include "../AaronLocker_CommonUtils/StringUtils.h"
#include "CommonDefs.h"

extern const wchar_t chrDelim = L'\t';
const wchar_t* const szTab = L"\t";
const wchar_t* const szDelim = szTab;
#define HEADER_CHARS L":::: "
#define UNSAFE_DIRS  L"UNSAFE DIRECTORIES UNDER "
const wchar_t* const szHeader_ScanTypeFull                  = HEADER_CHARS L"SCAN TYPE: FULL";
const wchar_t* const szHeader_ScanTypeDirectory             = HEADER_CHARS L"SCAN TYPE: DIRECTORY";
const wchar_t* const szHeader_ComputerName                  = HEADER_CHARS L"COMPUTER NAME: ";
const wchar_t* const szHeader_ScanStarted                   = HEADER_CHARS L"SCAN STARTED: ";
const wchar_t* const szHeader_ScanEnded                     = HEADER_CHARS L"SCAN ENDED  : ";
const wchar_t* const szHeader_WindowsDirectories            = HEADER_CHARS L"WINDOWS DIRECTORIES:";
const wchar_t* const szHeader_ErrorInfo                     = HEADER_CHARS L"ERROR INFO:";
const wchar_t* const szHeader_UnsafeDirectoriesWindows      = HEADER_CHARS UNSAFE_DIRS L"WINDOWS:";
const wchar_t* const szHeader_UnsafeDirectoriesProgramFiles = HEADER_CHARS UNSAFE_DIRS L"PROGRAM FILES:";
const wchar_t* const szHeader_PubInfoWindowsDirExclusions   = HEADER_CHARS L"PUBLISHER INFO FOR WINDOWS DIRECTORY EXCLUSIONS:";
const wchar_t* const szHeader_PlatformSafePathInfo          = HEADER_CHARS L"PLATFORM SAFE PATH INFO:";
const wchar_t* const szHeader_FileDetails                   = HEADER_CHARS L"FILE DETAILS:";
const wchar_t* const szHeader_PackagedAppInfo               = HEADER_CHARS L"INSTALLED PACKAGED APPS:";
const wchar_t* const szHeader_ShellLinks                    = HEADER_CHARS L"SHELL LINKS:";

// --------------------------------------------------------------------------------
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
static const wchar_t* const szUnknown               = L"Unknown";
static const wchar_t* const szKnownNonCodeExtension = L"KnownNonCodeExtension";
static const wchar_t* const szEXE                   = L"EXE";
static const wchar_t* const szDLL                   = L"DLL";
static const wchar_t* const szResourceOnlyDLL       = L"ResourceOnlyDLL";
static const wchar_t* const szMSI                   = L"MSI";
static const wchar_t* const szScript                = L"Script";
static const wchar_t* const szScriptJS              = L"ScriptJS";
static const wchar_t* const szAppx                  = L"Appx";
static const wchar_t* const szUNDEFINED             = L"[UNDEFINED]";

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

AppLockerFileDetails_ftype_t Str2FType(const wchar_t* szType)
{
	for (size_t ix = 0; ix < nFtype2StrMap; ++ix)
	{
		if (0 == StringCompareCaseInsensitive(szType, Ftype2StrMap[ix].szType))
			return Ftype2StrMap[ix].ftype;
	}
	return AppLockerFileDetails_ftype_t::ft_Unknown;
}

AppLockerFileDetails_ftype_t Str2FType(const std::wstring& sType)
{
	return Str2FType(sType.c_str());
}


// --------------------------------------------------------------------------------

struct LinkLoc2Str_t
{
	ShellLinkDataContext_t::LinkLocation_t loc;
	const wchar_t* szLoc;
};

LinkLoc2Str_t LinkLoc2StrMap[] = {
	{ ShellLinkDataContext_t::LinkLocation_t::AllUsersStartMenu, L"AllUsersStartMenu" },
	{ ShellLinkDataContext_t::LinkLocation_t::AllUsersDesktop,   L"AllUsersDesktop" },
	{ ShellLinkDataContext_t::LinkLocation_t::PerUserStartMenu,  L"PerUserStartMenu" },
	{ ShellLinkDataContext_t::LinkLocation_t::PerUserDesktop,    L"PerUserDesktop" },
	{ ShellLinkDataContext_t::LinkLocation_t::Other,             L"Other" },
};
const size_t nLinkLoc2StrMap = sizeof(LinkLoc2StrMap) / sizeof(LinkLoc2StrMap[0]);

const wchar_t* LinkLocation2Str(ShellLinkDataContext_t::LinkLocation_t loc)
{
	for (size_t ix = 0; ix < nLinkLoc2StrMap; ++ix)
	{
		if (loc == LinkLoc2StrMap[ix].loc)
			return LinkLoc2StrMap[ix].szLoc;
	}
	return L"";
}

ShellLinkDataContext_t::LinkLocation_t Str2LinkLocation(const wchar_t* szLoc)
{
	for (size_t ix = 0; ix < nLinkLoc2StrMap; ++ix)
	{
		if (0 == StringCompareCaseInsensitive(szLoc, LinkLoc2StrMap[ix].szLoc))
			return LinkLoc2StrMap[ix].loc;
	}
	return ShellLinkDataContext_t::LinkLocation_t::Other;
}

ShellLinkDataContext_t::LinkLocation_t Str2LinkLocation(const std::wstring& sLoc)
{
	return Str2LinkLocation(sLoc.c_str());
}

// --------------------------------------------------------------------------------

