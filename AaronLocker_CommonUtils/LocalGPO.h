#pragma once

#include <Windows.h>
#include <initguid.h>
#include <GPEdit.h>

/// <summary>
/// Class to encapsulate group policy processing.
/// </summary>
class LocalGPO
{
public:
	LocalGPO();
	~LocalGPO();

	//TODO: Add an "apply" function that copies registry values from policy repository to target registry locations, including one or more user hives. (For domain-joined, force registry update in case DC isn't available; won't work correctly if policy requires a CSE.)

	/// <summary>
	/// Init must be called prior to other operations, and should be called only once on the object.
	/// </summary>
	/// <param name="bReadOnly">Input: true for read-only operations, which do not require administrative rights. False (default) for read/write.</param>
	/// <returns>S_OK on success; a failure HRESULT otherwise</returns>
	HRESULT Init(bool bReadOnly = false);

	// Get registry keys corresponding to user and machine policy.

	/// <summary>
	/// Returns registry key corresponding to user policy.
	/// </summary>
	HKEY UserKey() const { return m_UserKey; }
	/// <summary>
	/// Returns registry key corresponding to machine policy.
	/// </summary>
	HKEY ComputerKey() const { return m_ComputerKey; }

	/// <summary>
	/// Save policy changes, with automatic retries if necessary.
	/// </summary>
	/// <returns>Success or failure HRESULT.</returns>
	HRESULT Save();

	/// <summary>
	/// Register a group policy client side extension (CSE) for machine-policy processing.
	/// Automatically retries if necessary.
	/// </summary>
	/// <param name="pGuidExtension">GUID of the CSE</param>
	/// <returns>Success or failure HRESULT</returns>
	HRESULT RegisterMachineCSE(GUID* pGuidExtension);

	/// <summary>
	/// Register a group policy client side extension (CSE) for user-policy processing.
	/// Automatically retries if necessary.
	/// </summary>
	/// <param name="pGuidExtension">GUID of the CSE</param>
	/// <returns>Success or failure HRESULT</returns>
	HRESULT RegisterUserCSE(GUID* pGuidExtension);

private:
	// Data
	HKEY m_UserKey, m_ComputerKey;
	IGroupPolicyObject* m_pLGPO;

	/// <summary>
	/// Internal function for saving machine or user policies with automatic retries if necessary.
	/// </summary>
	/// <param name="bComputer">true for machine policy, false for user policy</param>
	/// <param name="pGuidExtension">GUID of CSE; should be REGISTRY_EXTENSION_GUID for normal registry policy CSE.</param>
	/// <returns>Success or failure HRESULT</returns>
	HRESULT SaveWithRetries(BOOL bComputer, GUID* pGuidExtension);

private:
	// Not implemented
	LocalGPO(const LocalGPO &) = delete;
	LocalGPO & operator = (const LocalGPO &) = delete;
};
