// OfficeMacroControl.cpp
// Implementation of interface to apply groups of related GPO settings as cohesive units to control execution of Microsoft Office macros.

#include <Windows.h>
#include <strsafe.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "OfficeMacroGpoData.h"
#include "OfficeMacroControl.h"


// ------------------------------------------------------------------------------------------
// Local helper functions

static const wchar_t* const szTab = L"\t";

/// <summary>
/// Local function to configure an array of GpoItem_t settings to local group policy.
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="lgpo">Object to interface with local GPO</param>
/// <param name="strErrorInfo">Stream to write error information into</param>
/// <returns>true if successful</returns>
static bool ConfigureGpoItems(const GpoItem_t* pGpoItems, LocalGPO& lgpo, std::wstringstream& strErrorInfo);

/// <summary>
/// Local function to revert settings to Not Configured (delete registry values from local policy store).
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="lgpo">Object to interface with local GPO</param>
/// <param name="strErrorInfo">Stream to write error information into</param>
/// <returns>true if successful</returns>
static bool UnconfigureGpoItems(const GpoItem_t* pGpoItems, LocalGPO& lgpo, std::wstringstream& strErrorInfo);

/// <summary>
/// Local function to report GP editor paths/names or registry key/values for an array of GpoItem_t settings as tab-delimited data.
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="bConfigure">true to report changes if applying settings; false to report changes if reverting settings to Not Configured.</param>
/// <param name="strOutput">Output stream</param>
static void ReportGpoItems(const GpoItem_t* pGpoItems, bool bConfigure, std::wostream& strOutput);

/// <summary>
/// Local function to report GP editor paths/names and registry keys/values and the corresponding configured GPO registry value for an array of 
/// GpoItem_t settings as tab-delimited data.
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="bConfigure">true if desired value is configured, false if desired value is Not Configured</param>
/// <param name="lgpo">Object to interface with local GPO (needs only read-only access)</param>
/// <param name="strOutput">Output stream</param>
static void VerifyGpoItems(const GpoItem_t* pGpoItems, bool bConfigure, LocalGPO& lgpo, std::wostream& strOutput);

// ------------------------------------------------------------------------------------------

OfficeMacroControl::OfficeMacroControl(bool bLgpoReadOnly /*= false*/)
{
	// Initialize LGPO object for use.
	HRESULT hr = m_lgpo.Init(bLgpoReadOnly);
	if (FAILED(hr))
	{
		m_strErrorInfo << L"Failure initializing LGPO object: " << SysErrorMessageWithCode(hr) << std::endl;
	}
}

OfficeMacroControl::~OfficeMacroControl()
{
}

/// <summary>
/// Commit all policy changes made through the Enforce_ methods.
/// </summary>
/// <returns>HRESULT from the save/commit operation.</returns>
HRESULT OfficeMacroControl::CommitChanges()
{
	return m_lgpo.Save();
}

/// <summary>
/// Aggregated error information beginning from instantiation.
/// </summary>
/// <returns>Aggregated error information</returns>
std::wstring OfficeMacroControl::ErrorInfo()
{
	return m_strErrorInfo.str();
}

// --------------------------------------------------------------------------------------------------------------

bool OfficeMacroControl::Enforce_AttackSurfaceReduction(eASR_options_t option)
{
	switch (option)
	{
	case eASR_options_t::eNotConfigured:
		return UnconfigureGpoItems(ASR_Block, m_lgpo, m_strErrorInfo);
	case eASR_options_t::eAudit:
		return ConfigureGpoItems(ASR_Audit, m_lgpo, m_strErrorInfo);
	case eASR_options_t::eBlock:
		return ConfigureGpoItems(ASR_Block, m_lgpo, m_strErrorInfo);
	case eASR_options_t::eWarn:
		return ConfigureGpoItems(ASR_Warn, m_lgpo, m_strErrorInfo);
	case eASR_options_t::eOff:
		return ConfigureGpoItems(ASR_Off, m_lgpo, m_strErrorInfo);
	default:
		m_strErrorInfo << L"OfficeMacroControl::Enforce_AttackSurfaceReduction invalid option: " << (int)option << std::endl;
		return false;
	}
}

bool OfficeMacroControl::Enforce_BlockMacrosFromRunningInOfficeFilesFromTheInternet(bool bConfigure)
{
	return bConfigure ?
		ConfigureGpoItems(BlockMacrosFromRunningInOfficeFilesFromTheInternet, m_lgpo, m_strErrorInfo) :
		UnconfigureGpoItems(BlockMacrosFromRunningInOfficeFilesFromTheInternet, m_lgpo, m_strErrorInfo);
}

bool OfficeMacroControl::Enforce_DisableAllUnsignedMacros(eUnsignedMacro_options_t option)
{
	switch (option)
	{
	case eUnsignedMacro_options_t::eNotConfigured:
		return UnconfigureGpoItems(DisableAllUnsignedMacros_basic, m_lgpo, m_strErrorInfo);
	case eUnsignedMacro_options_t::eBasic:
		return ConfigureGpoItems(DisableAllUnsignedMacros_basic, m_lgpo, m_strErrorInfo);
	case eUnsignedMacro_options_t::eReqTrustedPublisher:
		return ConfigureGpoItems(DisableAllUnsignedMacros_reqTrustedPub, m_lgpo, m_strErrorInfo);
	case eUnsignedMacro_options_t::eStrict:
		return ConfigureGpoItems(DisableAllUnsignedMacros_strict, m_lgpo, m_strErrorInfo);
	default:
		m_strErrorInfo << L"OfficeMacroControl::Enforce_DisableAllUnsignedMacros invalid option: " << (int)option << std::endl;
		return false;
	}
}

bool OfficeMacroControl::Enforce_DisableUnsignedVbaAddins(bool bConfigure)
{
	return bConfigure ?
		ConfigureGpoItems(DisableUnsignedVbaAddins, m_lgpo, m_strErrorInfo) :
		UnconfigureGpoItems(DisableUnsignedVbaAddins, m_lgpo, m_strErrorInfo);
}

bool OfficeMacroControl::Enforce_DisableAllTrustedLocations(bool bConfigure)
{
	return bConfigure ?
		ConfigureGpoItems(DisableAllTrustedLocations, m_lgpo, m_strErrorInfo) :
		UnconfigureGpoItems(DisableAllTrustedLocations, m_lgpo, m_strErrorInfo);
}

bool OfficeMacroControl::Enforce_DisableAllVBA(bool bConfigure)
{
	return bConfigure ?
		ConfigureGpoItems(DisableAllVBA, m_lgpo, m_strErrorInfo) :
		UnconfigureGpoItems(DisableAllVBA, m_lgpo, m_strErrorInfo);
}

bool OfficeMacroControl::Enforce_LegacyFileBlock(bool bConfigure)
{
	return bConfigure ?
		ConfigureGpoItems(LegacyFileBlock, m_lgpo, m_strErrorInfo) :
		UnconfigureGpoItems(LegacyFileBlock, m_lgpo, m_strErrorInfo);
}

bool OfficeMacroControl::Enforce_ScanEncryptedMacros(bool bConfigure)
{
	return bConfigure ?
		ConfigureGpoItems(ScanEncryptedMacros, m_lgpo, m_strErrorInfo) :
		UnconfigureGpoItems(ScanEncryptedMacros, m_lgpo, m_strErrorInfo);
}

// --------------------------------------------------------------------------------------------------------------

void OfficeMacroControl::Report_AttackSurfaceReduction(eASR_options_t option, std::wostream& strOutput)
{
	switch (option)
	{
	case eASR_options_t::eNotConfigured:
		ReportGpoItems(ASR_Block, false, strOutput);
		return;
	case eASR_options_t::eAudit:
		ReportGpoItems(ASR_Audit, true, strOutput);
		return;
	case eASR_options_t::eBlock:
		ReportGpoItems(ASR_Block, true, strOutput);
		return;
	case eASR_options_t::eWarn:
		ReportGpoItems(ASR_Warn, true, strOutput);
		return;
	case eASR_options_t::eOff:
		ReportGpoItems(ASR_Off, true, strOutput);
		return;
	//default:
	//	m_strErrorInfo << L"OfficeMacroControl::Enforce_AttackSurfaceReduction invalid option: " << (int)option << std::endl;
	//	return false;
	}
}

void OfficeMacroControl::Report_BlockMacrosFromRunningInOfficeFilesFromTheInternet(bool bConfigure, std::wostream& strOutput)
{
	ReportGpoItems(BlockMacrosFromRunningInOfficeFilesFromTheInternet, bConfigure, strOutput);
}

void OfficeMacroControl::Report_DisableAllUnsignedMacros(eUnsignedMacro_options_t option, std::wostream& strOutput)
{
	switch (option)
	{
	case eUnsignedMacro_options_t::eNotConfigured:
		ReportGpoItems(DisableAllUnsignedMacros_basic, false, strOutput);
		return;
	case eUnsignedMacro_options_t::eBasic:
		ReportGpoItems(DisableAllUnsignedMacros_basic, true, strOutput);
		return;
	case eUnsignedMacro_options_t::eReqTrustedPublisher:
		ReportGpoItems(DisableAllUnsignedMacros_reqTrustedPub, true, strOutput);
		return;
	case eUnsignedMacro_options_t::eStrict:
		ReportGpoItems(DisableAllUnsignedMacros_strict, true, strOutput);
		return;
	//default:
	//	m_strErrorInfo << L"OfficeMacroControl::Enforce_DisableAllUnsignedMacros invalid option: " << (int)option << std::endl;
	//	return false;
	}
}

void OfficeMacroControl::Report_DisableUnsignedVbaAddins(bool bConfigure, std::wostream& strOutput)
{
	ReportGpoItems(DisableUnsignedVbaAddins, bConfigure, strOutput);
}

void OfficeMacroControl::Report_DisableAllTrustedLocations(bool bConfigure, std::wostream& strOutput)
{
	ReportGpoItems(DisableAllTrustedLocations, bConfigure, strOutput);
}

void OfficeMacroControl::Report_DisableAllVBA(bool bConfigure, std::wostream& strOutput)
{
	ReportGpoItems(DisableAllVBA, bConfigure, strOutput);
}

void OfficeMacroControl::Report_LegacyFileBlock(bool bConfigure, std::wostream& strOutput)
{
	ReportGpoItems(LegacyFileBlock, bConfigure, strOutput);
}

void OfficeMacroControl::Report_ScanEncryptedMacros(bool bConfigure, std::wostream& strOutput)
{
	ReportGpoItems(ScanEncryptedMacros, bConfigure, strOutput);
}

// --------------------------------------------------------------------------------------------------------------

void OfficeMacroControl::Verify_AttackSurfaceReduction(eASR_options_t option, std::wostream& strOutput)
{
	switch (option)
	{
	case eASR_options_t::eNotConfigured:
		VerifyGpoItems(ASR_Block, false, m_lgpo, strOutput);
		return;
	case eASR_options_t::eAudit:
		VerifyGpoItems(ASR_Audit, true, m_lgpo, strOutput);
		return;
	case eASR_options_t::eBlock:
		VerifyGpoItems(ASR_Block, true, m_lgpo, strOutput);
		return;
	case eASR_options_t::eWarn:
		VerifyGpoItems(ASR_Warn, true, m_lgpo, strOutput);
		return;
	case eASR_options_t::eOff:
		VerifyGpoItems(ASR_Off, true, m_lgpo, strOutput);
		return;
	//default:
	//	Error
	}
}

void OfficeMacroControl::Verify_BlockMacrosFromRunningInOfficeFilesFromTheInternet(bool bConfigure, std::wostream& strOutput)
{
	VerifyGpoItems(BlockMacrosFromRunningInOfficeFilesFromTheInternet, bConfigure, m_lgpo, strOutput);
}

void OfficeMacroControl::Verify_DisableAllUnsignedMacros(eUnsignedMacro_options_t option, std::wostream& strOutput)
{
	switch (option)
	{
	case eUnsignedMacro_options_t::eNotConfigured:
		VerifyGpoItems(DisableAllUnsignedMacros_basic, false, m_lgpo, strOutput);
		return;
	case eUnsignedMacro_options_t::eBasic:
		VerifyGpoItems(DisableAllUnsignedMacros_basic, true, m_lgpo, strOutput);
		return;
	case eUnsignedMacro_options_t::eReqTrustedPublisher:
		VerifyGpoItems(DisableAllUnsignedMacros_reqTrustedPub, true, m_lgpo, strOutput);
		return;
	case eUnsignedMacro_options_t::eStrict:
		VerifyGpoItems(DisableAllUnsignedMacros_strict, true, m_lgpo, strOutput);
		return;
	//default:
	//	Error
	}
}

void OfficeMacroControl::Verify_DisableUnsignedVbaAddins(bool bConfigure, std::wostream& strOutput)
{
	VerifyGpoItems(DisableUnsignedVbaAddins, bConfigure, m_lgpo, strOutput);
}

void OfficeMacroControl::Verify_DisableAllTrustedLocations(bool bConfigure, std::wostream& strOutput)
{
	VerifyGpoItems(DisableAllTrustedLocations, bConfigure, m_lgpo, strOutput);
}

void OfficeMacroControl::Verify_DisableAllVBA(bool bConfigure, std::wostream& strOutput)
{
	VerifyGpoItems(DisableAllVBA, bConfigure, m_lgpo, strOutput);
}

void OfficeMacroControl::Verify_LegacyFileBlock(bool bConfigure, std::wostream& strOutput)
{
	VerifyGpoItems(LegacyFileBlock, bConfigure, m_lgpo, strOutput);
}

void OfficeMacroControl::Verify_ScanEncryptedMacros(bool bConfigure, std::wostream& strOutput)
{
	VerifyGpoItems(ScanEncryptedMacros, bConfigure, m_lgpo, strOutput);
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Local function to configure an array of GpoItem_t settings to local group policy.
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="lgpo">Object to interface with local GPO</param>
/// <param name="strErrorInfo">Stream to write error information into</param>
/// <returns>true if successful</returns>
static bool ConfigureGpoItems(const GpoItem_t* pGpoItems, LocalGPO& lgpo, std::wstringstream& strErrorInfo)
{
	bool retval = true;
	for (const GpoItem_t* pGpoItem = pGpoItems; NULL != pGpoItem->gpoDefn.szRegKey; pGpoItem++)
	{
		LSTATUS lstat;
		// LGPO Computer Configuration or User Configuration
		HKEY hBaseKey = pGpoItem->gpoDefn.bIsMachine ? lgpo.ComputerKey() : lgpo.UserKey();
		HKEY hKeyResult = NULL;
		lstat = RegCreateKeyExW(hBaseKey, pGpoItem->gpoDefn.szRegKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKeyResult, NULL);
		if (ERROR_SUCCESS == lstat)
		{
			// Registry type and data. Note that because ALL of the registry data currently used by this code to
			// control Office macro execution is either a REG_DWORD or a DWORD value represented as a REG_SZ,
			// dwRegData here can be a DWORD, and we don't need to get into the complexity of a union or
			// a class hierarchy.
			DWORD dwRegType = pGpoItem->gpoItemChoice.dwRegType;
			const BYTE* pData = NULL;
			DWORD dwData = pGpoItem->gpoItemChoice.dwRegData;
			// Buffer in case value needs to be represented as REG_SZ.
			const size_t cchBufSize = 16;
			wchar_t szData[cchBufSize] = { 0 };
			DWORD cbData = 0;
			switch (dwRegType)
			{
			case REG_DWORD:
				pData = (const BYTE*)&dwData;
				cbData = sizeof(DWORD);
				break;
			case REG_SZ:
				// Represent DWORD value as REG_SZ
				StringCchPrintfW(szData, cchBufSize, L"%u", dwData);
				pData = (const BYTE*)szData;
#pragma warning(push)
#pragma warning(disable:4267) // Warning affects 64-bit builds, but real-world string length will not actually be a data-loss problem here: '=': conversion from 'size_t' to 'DWORD', possible loss of data
				cbData = (wcslen(szData) + 1) * sizeof(wchar_t);
#pragma warning(pop)
				break;
			default:
				// No other data types supported
				strErrorInfo << L"Invalid GPO item registry type" << std::endl;
				retval = false;
				break;
			}
			if (pData)
			{
				lstat = RegSetValueExW(hKeyResult, pGpoItem->gpoDefn.szRegValName, 0, pGpoItem->gpoItemChoice.dwRegType, pData, cbData);
				if (ERROR_SUCCESS != lstat)
				{
					strErrorInfo << L"Error setting registry value for LGPO: " << SysErrorMessageWithCode(lstat) << std::endl;
					retval = false;
				}
			}

			RegCloseKey(hKeyResult);
		}
		else
		{
			strErrorInfo << L"Error creating/opening policy key for LGPO: " << SysErrorMessageWithCode(lstat) << std::endl;
			retval = false;
		}
	}

	return retval;
}

/// <summary>
/// Local function to revert settings to Not Configured (delete registry values from local policy store).
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="lgpo">Object to interface with local GPO</param>
/// <param name="strErrorInfo">Stream to write error information into</param>
/// <returns>true if successful</returns>
static bool UnconfigureGpoItems(const GpoItem_t* pGpoItems, LocalGPO& lgpo, std::wstringstream& strErrorInfo)
{
	bool retval = true;
	for (const GpoItem_t* pGpoItem = pGpoItems; NULL != pGpoItem->gpoDefn.szRegKey; pGpoItem++)
	{
		LSTATUS lstat;
		HKEY hBaseKey = pGpoItem->gpoDefn.bIsMachine ? lgpo.ComputerKey() : lgpo.UserKey();
		HKEY hKeyResult = NULL;
		// If key doesn't exist, we're already done. Nothing to delete.
		lstat = RegOpenKeyExW(hBaseKey, pGpoItem->gpoDefn.szRegKey, 0, KEY_SET_VALUE, &hKeyResult);
		if (ERROR_SUCCESS == lstat)
		{
			// Not an error if the value doesn't exist.
			lstat = RegDeleteValueW(hKeyResult, pGpoItem->gpoDefn.szRegValName);
			if (ERROR_SUCCESS != lstat && ERROR_FILE_NOT_FOUND != lstat)
			{
				strErrorInfo << L"Error deleting registry value for LGPO: " << SysErrorMessageWithCode(lstat) << std::endl;
				retval = false;
			}

			RegCloseKey(hKeyResult);
		}
		// Not a problem if the key is not there
		else if (ERROR_FILE_NOT_FOUND != lstat)
		{
			strErrorInfo << L"Error creating/opening policy key for LGPO: " << SysErrorMessageWithCode(lstat) << std::endl;
			retval = false;
		}
	}

	return retval;
}

/// <summary>
/// Local function to report GP editor paths/names or registry key/values for an array of GpoItem_t settings as tab-delimited data.
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="bConfigure">true to report changes if applying settings; false to report changes if reverting settings to Not Configured.</param>
/// <param name="strOutput">Output stream</param>
void ReportGpoItems(const GpoItem_t* pGpoItems, bool bConfigure, std::wostream& strOutput)
{
	for (const GpoItem_t* pGpoItem = pGpoItems; NULL != pGpoItem->gpoDefn.szRegKey; pGpoItem++)
	{

		strOutput
			<< (pGpoItem->gpoDefn.bIsMachine ? L"Computer Configuration" : L"User Configuration") << L"\\Windows Components\\" << pGpoItem->gpoDefn.szGpoEditorPath << szTab
			<< pGpoItem->gpoDefn.szGpoSettingName << szTab
			<< (pGpoItem->gpoDefn.bIsMachine ? L"HKLM\\" : L"HKCU\\") << pGpoItem->gpoDefn.szRegKey << szTab
			<< pGpoItem->gpoDefn.szRegValName << szTab;
		if (bConfigure)
		{
			strOutput
				<< pGpoItem->gpoItemChoice.szGpoSettingChoice << szTab
				// ASSUMPTION here that settings are all either DWORD or SZ
				<< (pGpoItem->gpoItemChoice.dwRegType == REG_DWORD ? L"REG_DWORD: " : L"REG_SZ: ") << pGpoItem->gpoItemChoice.dwRegData << std::endl;
		}
		else
		{
			strOutput
				<< L"Not Configured" << szTab
				<< L"DELETE" << std::endl;
		}
	}
}

/// <summary>
/// Local function to report GP editor paths/names and registry keys/values and the corresponding configured GPO registry value for an array of 
/// GpoItem_t settings as tab-delimited data.
/// </summary>
/// <param name="pGpoItems">Pointer to first element in array; last element in array contains NULL pointers.</param>
/// <param name="bConfigure">true if desired value is configured, false if desired value is Not Configured</param>
/// <param name="lgpo">Object to interface with local GPO (needs only read-only access)</param>
/// <param name="strOutput">Output stream</param>
void VerifyGpoItems(const GpoItem_t* pGpoItems, bool bConfigure, LocalGPO& lgpo, std::wostream& strOutput)
{
	const wchar_t* szNotSet = L"[NOT SET]";

	for (const GpoItem_t* pGpoItem = pGpoItems; NULL != pGpoItem->gpoDefn.szRegKey; pGpoItem++)
	{
		// For each item, output GP editor path/setting, registry key/value name...
		strOutput
			<< (pGpoItem->gpoDefn.bIsMachine ? L"Computer Configuration" : L"User Configuration") << L"\\Windows Components\\" << pGpoItem->gpoDefn.szGpoEditorPath << szTab
			<< pGpoItem->gpoDefn.szGpoSettingName << szTab
			<< (pGpoItem->gpoDefn.bIsMachine ? L"HKLM\\" : L"HKCU\\") << pGpoItem->gpoDefn.szRegKey << szTab
			<< pGpoItem->gpoDefn.szRegValName << szTab;
		// If desired value is configured, output the choice name and registry type/value
		// Otherwise, "Not Configured" and "[NOT SET]"...
		if (bConfigure)
		{
			strOutput 
				<< pGpoItem->gpoItemChoice.szGpoSettingChoice << szTab
				// ASSUMPTION here that settings are all either DWORD or SZ
				<< (pGpoItem->gpoItemChoice.dwRegType == REG_DWORD ? L"REG_DWORD: " : L"REG_SZ: ") << pGpoItem->gpoItemChoice.dwRegData << szTab;
		}
		else
		{
			strOutput
				<< L"Not Configured" << szTab
				<< szNotSet << szTab;
		}

		// Read actual value from local GPO; if the value is found and is of the registry type expected for the setting, output it;
		// Otherwise, output "[NOT SET]"
		bool bValueSet = false;
		LSTATUS lstat;
		HKEY hBaseKey = pGpoItem->gpoDefn.bIsMachine ? lgpo.ComputerKey() : lgpo.UserKey();
		HKEY hKeyResult = NULL;
		// If key doesn't exist, we're already done. Nothing there.
		lstat = RegOpenKeyExW(hBaseKey, pGpoItem->gpoDefn.szRegKey, 0, KEY_READ, &hKeyResult);
		if (ERROR_SUCCESS == lstat)
		{
			// Data can be REG_DWORD or REG_SZ. Define a union that can handle either; 
			// if it's a string value, 16 characters should be way more than enough for these settings.
			union { DWORD dwData; wchar_t szData[16]; } uData = { 0 };
			DWORD dwType, cbData = sizeof(uData);
			lstat = RegQueryValueExW(hKeyResult, pGpoItem->gpoDefn.szRegValName, NULL, &dwType, (LPBYTE)&uData, &cbData);
			// Make sure that the data type is the expected type for the setting.
			// Treat it as "not set" if the data type doesn't match expected. (Although any given component might or might not verify registry type before using the retrieved data.)
			if (ERROR_SUCCESS == lstat && pGpoItem->gpoItemChoice.dwRegType == dwType)
			{
				switch (dwType)
				{
				case REG_DWORD:
					bValueSet = true;
					strOutput << L"REG_DWORD: " << uData.dwData;
					break;
				case REG_SZ:
					bValueSet = true;
					strOutput << L"REG_SZ: " << uData.szData;
					break;
				}
			}

			RegCloseKey(hKeyResult);
		}
		// If the value wasn't found and reported, report "[NOT SET]".
		if (!bValueSet)
			strOutput << szNotSet;
		// End of the line
		strOutput << std::endl;
	}
}