#pragma once

#include <string>

// Note that this doesn't configure AppIdSvc.

/// <summary>
/// Class to manage AppLocker policy via local GPO (group policy objects)
/// </summary>
class AppLockerPolicy_LGPO
{
public:
	/// <summary>
	/// Retrieve XML document representing LGPO-configured AppLocker policy.
	/// Does not require administrative rights.
	/// </summary>
	/// <param name="sAppLockerPolicyXml">Output: AppLocker policy XML</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool GetLocalPolicy(std::wstring& sAppLockerPolicyXml, std::wstring& sErrorInfo);

	/// <summary>
	/// Retrieve XML document representing effective GPO-configured AppLocker policy,
	/// based on evidence in the registry. Effective AppLocker policy can be the merged 
	/// results from Active Directory policies and local GPO.
	/// Does not require administrative rights.
	/// </summary>
	/// <param name="sAppLockerPolicyXml">Output: AppLocker policy XML</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool GetEffectivePolicy(std::wstring& sAppLockerPolicyXml, std::wstring& sErrorInfo);

	/// <summary>
	/// Clears (deletes) any AppLocker policy configured through LGPO.
	/// Requires administrative rights.
	/// </summary>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool ClearPolicy(std::wstring& sErrorInfo);

	/// <summary>
	/// Sets AppLocker policy from the supplied AppLocker policy XML string.
	/// </summary>
	/// <param name="sPolicyXml">Input: AppLocker policy XML</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool SetPolicyFromString(const std::wstring& sPolicyXml, std::wstring& sErrorInfo);

	/// <summary>
	/// Sets AppLocker policy from the supplied AppLocker policy XML UTF8-encoded file.
	/// </summary>
	/// <param name="sXmlPolicyFile">Input: path to UTF8-encoded file containing AppLocker policy XML.</param>
	/// <param name="sErrorInfo">Output: error information</param>
	/// <returns>true if successful, false otherwise</returns>
	static bool SetPolicyFromFile(const std::wstring& sXmlPolicyFile, std::wstring& sErrorInfo);
};

