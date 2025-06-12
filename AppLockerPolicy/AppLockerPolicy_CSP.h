#pragma once

/*
AppLocker configuration via WMI bridge to MDM/CSP interfaces.
Microsoft's documentation is incomplete (to put it nicely).
CSP interfaces:
  https://docs.microsoft.com/en-us/windows/client-management/mdm/applocker-csp
WMI bridge interfaces to them:
  https://docs.microsoft.com/en-us/windows/win32/dmwmibridgeprov/mdm-bridge-wmi-provider-portal
I believe these interfaces require Windows 10 and are not available on earlier Windows versions.

IMPORTANT to note that this code must run as Local System. Admin isn't enough.
And failure tends to be silent as admin - no access-denied errors. Listing just sees nothing.

These are the AppLocker classes of interest in this code:
  MDM_AppLocker_ApplicationLaunchRestrictions01_EXE03
  MDM_AppLocker_DLL03
  MDM_AppLocker_MSI03
  MDM_AppLocker_Script03
  MDM_AppLocker_ApplicationLaunchRestrictions01_StoreApps03

These AppLocker-related classes are also defined, but this code doesn't use them:
  MDM_AppLocker_CodeIntegrity03
  MDM_AppLocker_EnterpriseDataProtection01_EXE03
  MDM_AppLocker_EnterpriseDataProtection01_StoreApps03


Tech notes on CSP/MDM/AppLocker (and [L]GPO):
* You can define multiple rule sets under different group names. It appears to me that execution of a
  file is allowed only if it is allowed by every rule set.
  This is different from what seems to happen with AppLocker rule sets in GPO, where rule sets in AD
  GPO are merged together and with any in local GPO. Overlapping sets of allow rules in GPO are therefore
  more likely to lead to more permissive results, while overlapping sets of allow rules in CSP/MDM are
  more likely to lead to more restrictive results.

* If different policies are applied through CSP/MDM and through [L]GPO, it appears that execution of a
  file is allowed only if it is allowed by both CSP/MDM and [L]GPO evaluations.

* It doesn't seem possible in AppLocker/CSP/MDM to set a rule collection to "NotConfigured" and no rules - 
  seems to be the equivalent of "allow nothing."

* The MDM_AppLocker_* classes appear to work on all *recent* Windows 10 SKUs I tried, including Home and Pro.
  However, it doesn't work on Windows 10 v10240 - the original 2015 release. I don't know in which Win10
  version it was introduced.

*/
#include <string>
#define _WIN32_DCOM
#include <comdef.h>
#include <Wbemidl.h>
#include <map>

/// <summary>
/// Structure for retrieving AppLocker policy from machine's CSP/MDM interfaces from
/// the AppLockerPolicy_CSP class' GetPolicies member function.
/// Use the Policy() function to get the actual policy XML, not the m_ruleCollections member.
/// </summary>
struct AppLockerPolicy_t {
	std::wstring m_ruleCollections;

	std::wstring Policy() const;
} ;
/// <summary>
/// Collection of AppLocker policies, each with a name.
/// It is possible to have multiple AppLocker policies defined at the same time via CSP/MDM.
/// </summary>
typedef std::map<std::wstring, AppLockerPolicy_t> AppLockerPolicies_t;

// ------------------------------------------------------------------------------------------

/// <summary>
/// Class to manage AppLocker policy via WMI bridge to MDM/CSP interfaces.
/// Note that every function in this class needs to be executed as Local System to work correctly.
/// Running as a member of the Administrators group is insufficient.
/// </summary>
class AppLockerPolicy_CSP
{
public:
	/// <summary>
	/// Constructor. Initializes the object (if possible) for subsequent operations.
	/// Call the StatusOK function to determine whether initialization was successful.
	/// </summary>
	AppLockerPolicy_CSP();
	// Destructor
	~AppLockerPolicy_CSP();
	
	/// <summary>
	/// Returns true if the COM and WMI interfaces initialized correctly.
	/// E.g., initialization will fail if the necessary WMI namespace for
	/// AppLocker management doesn't exist on the target system. (I think
	/// it requires Win10...)
	/// </summary>
	/// <param name="psErrorInfo">Optional, output: string to get additional information about initialization failure</param>
	/// <returns>true if initialization successful; false otherwise.</returns>
	bool StatusOK(std::wstring* psErrorInfo = 0) const;

	/// <summary>
	/// Retrieves the AppLocker policies configured through CSP/MDM, and the
	/// names under which they are configured.
	/// </summary>
	/// <param name="policies">Output: collection through which results are returned</param>
	/// <returns>true if successful (even if no policies found), false otherwise.</returns>
	bool GetPolicies(AppLockerPolicies_t& policies);

	/// <summary>
	/// Sets AppLocker policy from the supplied AppLocker policy XML string.
	/// </summary>
	/// <param name="sPolicyXml">Input: AppLocker policy XML</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	bool SetPolicyFromString(const std::wstring& sPolicyXml, std::wstring& sErrorInfo);

	/// <summary>
	/// Sets AppLocker policy from the supplied AppLocker policy XML UTF8-encoded file.
	/// </summary>
	/// <param name="sXmlPolicyFile">Input: path to UTF8-encoded file containing AppLocker policy XML.</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	bool SetPolicyFromFile(const std::wstring& sXmlPolicyFile, std::wstring& sErrorInfo);

	// Making these interfaces public for the moment to make it possible to experiment with multiple policy sets
	bool SetPolicyFromString(const std::wstring& sPolicyXml, const std::wstring& sGroupName, std::wstring& sErrorInfo);
	bool SetPolicyFromFile(const std::wstring& sXmlPolicyFile, const std::wstring& sGroupName, std::wstring& sErrorInfo);

	/// <summary>
	/// Deletes ALL AppLocker policies that are configured on the system through CSP/MDM.
	/// "ALL" means all instances of these five classes under ROOT\CIMV2\mdm\dmmap:
	///   MDM_AppLocker_ApplicationLaunchRestrictions01_EXE03
	///   MDM_AppLocker_DLL03
	///   MDM_AppLocker_MSI03
	///   MDM_AppLocker_Script03
	///   MDM_AppLocker_ApplicationLaunchRestrictions01_StoreApps03
	/// TODO: create an interface to delete policies by name instead of all of them.
	/// </summary>
	/// <param name="bPoliciesDeleted">Output: true if one or more policies deleted.</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	bool DeleteAllPolicies(bool& bPoliciesDeleted, std::wstring& sErrorInfo);

private:
	// Internal functions to initialize and uninitialize COM/WMI interfaces
	bool Initialize();
	void Uninitialize();

	// Helper functions for the public functions.
	void GetPolicyProperties(const wchar_t* szMdmClass, AppLockerPolicies_t& policies);
	HRESULT DeleteAllPolicyInstances(const wchar_t* szMdmClass, bool& bPoliciesDeleted, std::wstringstream& strErrorInfo);

	HRESULT CreatePolicyInstance(
		const wchar_t* szMdmClass,
		const std::wstring& sGroupParentId,
		const wchar_t* szInstanceId,
		const std::wstring& sPolicyPiece,
		std::wstringstream& strErrorInfo);

private:
	// COM member pointers
	IWbemLocator* m_pLocator;
	IWbemServices* m_pServices;
	// final result from Initialize operations.
	HRESULT m_hrInit;

private:
	// Not implemented
	AppLockerPolicy_CSP(const AppLockerPolicy_CSP&) = delete;
	AppLockerPolicy_CSP& operator = (const AppLockerPolicy_CSP&) = delete;
};

