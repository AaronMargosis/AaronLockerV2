// Definitions common to AaronLockerSerializer and AaronLockerDeserializer.

#pragma once

#include "../AppLockerFunctionality/AppLockerFileDetails_ftype.h"
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Structs.h"

extern const wchar_t chrDelim;
extern const wchar_t* const szTab;
extern const wchar_t* const szDelim;

extern const wchar_t* const szHeader_ScanTypeFull;
extern const wchar_t* const szHeader_ScanTypeDirectory;
extern const wchar_t* const szHeader_ComputerName;
extern const wchar_t* const szHeader_ScanStarted;
extern const wchar_t* const szHeader_ScanEnded;
extern const wchar_t* const szHeader_WindowsDirectories;
extern const wchar_t* const szHeader_ErrorInfo;
extern const wchar_t* const szHeader_UnsafeDirectoriesWindows;
extern const wchar_t* const szHeader_UnsafeDirectoriesProgramFiles;
extern const wchar_t* const szHeader_PubInfoWindowsDirExclusions;
extern const wchar_t* const szHeader_PlatformSafePathInfo;
extern const wchar_t* const szHeader_FileDetails;
extern const wchar_t* const szHeader_PackagedAppInfo;
extern const wchar_t* const szHeader_ShellLinks;

const wchar_t* Bool2Str(bool b);
bool Str2Bool(const wchar_t* szBool);
bool Str2Bool(const std::wstring& sBool);

const wchar_t* FType2Str(AppLockerFileDetails_ftype_t ftype);
AppLockerFileDetails_ftype_t Str2FType(const wchar_t* szType);
AppLockerFileDetails_ftype_t Str2FType(const std::wstring& sType);

const wchar_t* LinkLocation2Str(ShellLinkDataContext_t::LinkLocation_t loc);
ShellLinkDataContext_t::LinkLocation_t Str2LinkLocation(const wchar_t* szLoc);
ShellLinkDataContext_t::LinkLocation_t Str2LinkLocation(const std::wstring& sLoc);
