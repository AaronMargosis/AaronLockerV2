/// Custom XML parser specifically for AppLocker policy XML documents and the purposes of applying policy through Group Policy or CSP/MDM.
/// Note that it's not a strict XML parser and assumes for the most part that the input document is well-formed.
//
#pragma once

#include <string>
#include <vector>

/// <summary>
/// Structure used for Group Policy rendering
/// </summary>
struct RuleInfo_t
{
	std::wstring sGuid;
	std::wstring sXml;
};
typedef std::vector<RuleInfo_t> RuleInfoCollection_t;

/// <summary>
/// Custom XML parser specifically for AppLocker policy XML documents and the purposes of applying policy through Group Policy or CSP/MDM.
/// Note that it's not a strict XML parser and assumes for the most part that the input document is well-formed.
/// </summary>
class AppLockerXmlParser
{
public:
	/// <summary>
	/// L"AppLockerPolicy" - the root element of an AppLocker policy XML document 
	/// </summary>
	static const wchar_t* const szPolicyRootTagname;

	// Extracts out the separate rule collections from the policy document.

	/// <summary>
	/// Given AppLocker policy XML, extract out each RuleCollection 
	/// </summary>
	/// <param name="sPolicyXml">Input: string representing the full AppLocker policy XML</param>
	/// <param name="sExePolicy">Output: the XML representing the EXE rule collection</param>
	/// <param name="sDllPolicy">Output: the XML representing the DLL rule collection</param>
	/// <param name="sMsiPolicy">Output: the XML representing the MSI rule collection</param>
	/// <param name="sScriptPolicy">Output: the XML representing the Script rule collection</param>
	/// <param name="sAppxPolicy">Output: the XML representing the Appx (Store apps) rule collection</param>
	/// <returns>true if successful, false on any parsing error</returns>
	static bool ParseRuleCollections(
		const std::wstring& sPolicyXml,
		std::wstring& sExePolicy,
		std::wstring& sDllPolicy,
		std::wstring& sMsiPolicy,
		std::wstring& sScriptPolicy,
		std::wstring& sAppxPolicy);

	/// <summary>
	/// Given a RuleCollection XML, extract the separate rules into a RuleInfoCollection_t.
	/// </summary>
	/// <param name="sRuleCollectionXml">Input: the XML representing a rule collection</param>
	/// <param name="dwEnforcementMode">Output: an integer corresponding to the collection's enforcement mode: 1 for Enforce, 0 for Audit</param>
	/// <param name="rules">A collection of structures containing the XML for each rule and the GUID ID.
	/// Note: returns rule info only if enforcement mode is Enforce or Audit; returns nothing if enforcement mode is "not configured".</param>
	/// <returns>true if successful (even if no rules returned), false on any parsing error.</returns>
	static bool ParseRuleCollection(
		const std::wstring& sRuleCollectionXml, 
		unsigned long& dwEnforcementMode, 
		RuleInfoCollection_t& rules);

private:
	/// <summary>
	/// Internal method used by ParseRuleCollection to extract path, publisher, and hash rules separately. 
	/// </summary>
	/// <param name="sRuleCollectionXml">Input: the XML representing a rule collection</param>
	/// <param name="szRuleName">The XML element name for the rule type; e.g., "FilePathRule"</param>
	/// <param name="rules">A collection of structures containing the XML for each rule and the GUID ID.</param>
	/// <returns>true if successful, false on any parsing error.</returns>
	static bool ParseRules(const std::wstring& sRuleCollectionXml, const wchar_t* szRuleName, RuleInfoCollection_t& rules);

};

