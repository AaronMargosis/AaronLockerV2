#include <windows.h>
#include <GPEdit.h>
#include "LocalGPO.h"

// Class to encapsulate group policy processing.
//TODO: Prior to save, delete any empty registry keys (or at least offer the option) - note that
// Windows creates some empty keys through policy (e.g., SystemCertificates) - don't delete those.
// Possibly implement by offering helper functions to delete values; those functions could then work their way up
// the key hierarchy and delete any empty keys.

// Constructor
LocalGPO::LocalGPO()
: m_UserKey(NULL), m_ComputerKey(NULL), m_pLGPO(NULL)
{
}

// Initialization
HRESULT LocalGPO::Init(bool bReadOnly /*= false*/)
{
	// Initialize COM
	// Note: this MUST be apartment threaded. COINIT_MULTITHREADED increases likelihood of crashing.
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if ( FAILED(hr) )
	{
		return hr;
	}

	// Create an instance of IGroupPolicyObject:  
	// https://docs.microsoft.com/en-us/windows/win32/api/gpedit/nn-gpedit-igrouppolicyobject
	hr = CoCreateInstance(CLSID_GroupPolicyObject, NULL, CLSCTX_INPROC_SERVER, IID_IGroupPolicyObject, (void**)&m_pLGPO);
	if ( FAILED(hr) )
	{
		return hr;
	}

	// Access local group policy on this computer, optionally with read-only permission.
	DWORD dwFlags = GPO_OPEN_LOAD_REGISTRY | (bReadOnly ? GPO_OPEN_READ_ONLY : 0);
	hr = m_pLGPO->OpenLocalMachineGPO(dwFlags);
	if ( FAILED(hr) )
	{
		return hr;
	}

	// Retain references to machine and user policy keys.
	hr = m_pLGPO->GetRegistryKey(GPO_SECTION_MACHINE, &m_ComputerKey);
	if ( FAILED(hr) )
	{
		return hr;
	}

	hr = m_pLGPO->GetRegistryKey(GPO_SECTION_USER, &m_UserKey);
	if ( FAILED(hr) )
	{
		return hr;
	}

	return S_OK;
}

// Destructor
LocalGPO::~LocalGPO()
{
	if ( m_UserKey )
		RegCloseKey(m_UserKey);
	if ( m_ComputerKey )
		RegCloseKey(m_ComputerKey);
	if ( m_pLGPO )
		m_pLGPO->Release();
	CoUninitialize();
}

// Save policy changes, with automatic retries if necessary.
HRESULT LocalGPO::Save()
{
	if (!m_pLGPO)
		return E_POINTER;

	HRESULT hrComputer = S_OK, hrUser = S_OK;

	// Save machine and user config with standard extension GUID
	GUID RegistryId = REGISTRY_EXTENSION_GUID;
	hrComputer = SaveWithRetries(TRUE, &RegistryId);
	hrUser = SaveWithRetries(FALSE, &RegistryId);

	// If either failed, return that failure code
	if (FAILED(hrComputer))
		return hrComputer;
	else
		return hrUser;
}

HRESULT LocalGPO::RegisterMachineCSE(GUID* pGuidExtension)
{
	return SaveWithRetries(TRUE, pGuidExtension);
}

HRESULT LocalGPO::RegisterUserCSE(GUID* pGuidExtension)
{
	return SaveWithRetries(FALSE, pGuidExtension);
}

HRESULT LocalGPO::SaveWithRetries(BOOL bComputer, GUID* pGuidExtension)
{
	// Re ThisAdminToolGuid...
	// From the IGroupPolicyObject::Save documentation:
	// "Specifies the GUID that identifies the MMC snap-in used to edit this policy. The snap-in 
	// can be a Microsoft snap-in or a third-party snap-in."
	// I.e., it's supposed to represent the tool that's editing the policy - it doesn't need to be
	// (and probably shouldn't be) someone else's GUID.
	// GUIDGen.exe tool provides this native formatting; no need to translate a string to a GUID
	// {586343C6-F45A-4A1C-BA32-70E09609EDC1}
	static GUID ThisAdminToolGuid =
	{ 0x586343c6, 0xf45a, 0x4a1c, { 0xba, 0x32, 0x70, 0xe0, 0x96, 0x9, 0xed, 0xc1 } };

	// I've observed that occasionally the Save operation will fail on a transient sharing 
	// violation condition that is overcome simply by trying again.
	// On sharing violation, retry every half second for up to 10 seconds.
	constexpr HRESULT hrSharingViolation = HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION);
	const int retries = 20;
	const DWORD retryDelay_ms = 500;

	HRESULT hr = m_pLGPO->Save(bComputer, TRUE, pGuidExtension, &ThisAdminToolGuid);
	if (hrSharingViolation == hr)
	{
		for (int retry = 0; retry < retries; ++retry)
		{
			Sleep(retryDelay_ms);
			hr = m_pLGPO->Save(bComputer, TRUE, pGuidExtension, &ThisAdminToolGuid);
			if (hrSharingViolation != hr)
				break;
		}
	}
	return hr;
}

