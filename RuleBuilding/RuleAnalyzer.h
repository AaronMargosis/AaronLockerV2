#pragma once
#include <map>
#include <set>
#include "../AaronLocker_Serialization/AaronLockerDeserializer.h"
#include "../RuleBuilding/RuleItems.h"
#include "../RuleBuilding/BuiltinRules.h"


/// <summary>
/// Keyed/sorted collection of RuleSet_t
/// </summary>
typedef std::map<std::wstring, RuleSet_t> RuleSetCollection_t;

/// <summary>
/// Class that takes deserialized endpoint scan files and other input and builds a complete
/// set of AppLocker rules.
/// 
/// Intended sequence:
/// 1. Instantiate RuleAnalyzer
/// 2. Add optional built-in rules by calling AddToBaseRules, passing in values from BuiltInRules.
/// 3. Pass deserialized scans to ProcessScans (at least one must be a full scan), and an optional set
///    of built-in EXE files not to exclude that are otherwise excluded by default).
/// 4. Review proposed rules through GetProposedRuleSetNames and GetProposedRuleSet.
/// 5. Remove unwanted proposed rules through DeleteProposedRuleSet.
/// 6. Build the XML by calling CreatePolicies and SavePolicy.
/// 
/// TODO: Need to support add-ons; e.g., turn proposed rules into a format that can be persisted, perhaps XML fragments to merge in, perhaps some text-based format like the original solution used that get converted into rules.
/// </summary>
class RuleAnalyzer
{
public:
	RuleAnalyzer();
	~RuleAnalyzer() = default;

	/// <summary>
	/// Add predefined rules to the base set. (See the BuiltInRules class.)
	/// </summary>
	void AddToBaseRules(const PublisherRuleCollection_t& publisherRules);

	/// <summary>
	/// Takes one or more deserialized scans (at least one must be a full scan) and an
	/// optional set of built-in EXEs not to exclude, and prepares rules.
	/// TODO: Add an option not to build rules for resource-only DLLs. (Except that "resource-only" doesn't mean that apps don't use LoadLibrary without the resource-only flag to load them...)
	/// </summary>
	/// <param name="scans"></param>
	/// <param name="windowsExesNotToExclude"></param>
	/// <param name="sErrorInfo"></param>
	/// <returns>true if successful, false otherwise (see sErrorInfo for error information)</returns>
	bool ProcessScans(const std::vector<AaronLockerDeserializer>& scans, const CaseInsensitiveStringLookup& windowsExesNotToExclude, std::wstring& sErrorInfo);

	/// <summary>
	/// Returns the set of app names of proposed rule sets from the scans' file details.
	/// </summary>
	/// <returns>The number of app names returned.</returns>
	size_t GetProposedRuleSetNames(std::vector<std::wstring>& names) const;

	/// <summary>
	/// Returns a pointer to a proposed rule set associated with the name provided.
	/// </summary>
	/// <param name="sName">Input: the app name</param>
	/// <param name="ppRuleSet">Output: a pointer to the proposed rule set associated with the app name, or NULL if not found.</param>
	/// <returns>true if the proposed rule set is returned; false if the name wasn't found.</returns>
	bool GetProposedRuleSet(const std::wstring& sName, const RuleSet_t** ppRuleSet) const;

	//TODO: One of these is case-sensitive, the other isn't. Maybe offer explicit options.
	/// <summary>
	/// Removes a proposed rule set
	/// </summary>
	/// <param name="sName">Name of the rule set to remove</param>
	/// <returns>true if removed; false if name not found.</returns>
	bool DeleteProposedRuleSet(const std::wstring& sName);

	/// <summary>
	/// Removes all proposed rule sets beginning with the input name, with optional case sensitivity
	/// </summary>
	/// <param name="sName">Beginning of the name of the rule sets to remove</param>
	/// <param name="bCaseSensitive">true if comparison should be case-sensitive</param>
	/// <returns>Number of rule sets removed</returns>
	size_t DeleteProposedRuleSetBeginningWithName(const std::wstring& sName, bool bCaseSensitive = false);

	/// <summary>
	/// Creates Enforce and Audit mode AppLocker policies from all the captured data, along
	/// with optional comments.
	/// </summary>
	/// <param name="comments">Input: Zero or more inert comment rules to add to the rule set.</param>
	/// <param name="sErrorInfo">Output: any error information from processing</param>
	/// <returns>true if successful (always returns true)</returns>
	bool CreatePolicies(const CommentRuleCollection_t& comments, std::wstring& sErrorInfo);

	/// <summary>
	/// Writes Enforce or Audit AppLocker XML policy to a UTF-8 encoded file.
	/// </summary>
	/// <param name="szFilename">Input: path to output file</param>
	/// <param name="bEnforcePolicy">Input: true for Enforce policy XML, false for Audit policy XML</param>
	/// <param name="sErrorInfo">Output: error information on failure</param>
	/// <returns>true if successful, false otherwise</returns>
	bool SavePolicy(const wchar_t* szFilename, bool bEnforcePolicy, std::wstring& sErrorInfo) const;

	/// <summary>
	/// Timestamp string from timestamp pseudo-rule that can be used in a filename.
	/// Valid after CreatePolicies succeeds.
	/// </summary>
	const std::wstring& TimestampForFilename() const;

	/// <summary>
	/// GUID from timestamp pseudo-rule that uniquely identifies this enforce/audit pair of policies.
	/// Valid after CreatePolicies succeeds.
	/// </summary>
	const std::wstring& TimestampGuid() const;

	/*
	TODO: Evaluate need to map actual paths to AppLocker's pseudo-env-vars, and be able to compare against them.
	*/

private:
	// Helper functions for ProcessScans
	void InitializeWindirProgFilesPathRules();
	void ProcessWindirProgFilesPathRuleExceptions(const AaronLockerDeserializer& scan, const CaseInsensitiveStringLookup& windowsExesNotToExclude);
	void SetWindirProgFilesPathRuleExceptions();
	void IncorporatePlatformSafePathRulesToBaseRules(const SafePathInfoCollection_t& safePathInfo);
	bool ProposeRulesFromFileDetails(const FileDetailsCollection_t& vFileDetails, const std::wstring& sComputerName);
	bool AddRulesForInstalledPackagedApps(const PackagedAppInfoCollection_t& vPackagedApps, const std::wstring& sComputerName);

	// Data
	// The base rules including all the default rules, selected predefined BuiltInRules collections
	RuleSet_t           m_baseRules;
	// Proposed rules from reviewing all the FileDetailsCollections.
	RuleSetCollection_t m_proposedAppRules;

	// Helper functions for ProposeRulesFromFileDetails
	void CreatePathRuleProposal(
		const FileDetails_t& fileDetails,
		const PathRuleCollection_t& vExistingPathRules);
	void AddPublisherRuleProposal(
		const PublisherRuleItem& rule,
		const PublisherRuleCollection_t& vExistingPublisherRules);
	void CreateHashRuleProposal(
		const FileDetails_t& fileDetails,
		const HashRuleCollection_t& vExistingHashRules,
		const std::wstring& sComputerName,
		const std::wstring& sOptionalInfo);

private:
	// Data

	// Distinct Exe, Dll, and Script path rule items for the 
	// Windows and ProgramFiles directories.
	PathRuleItemWithExceptions 
	    m_windirRuleExe, m_windirRuleDll, m_windirRuleScript, 
	    m_PFRuleExe, m_PFRuleDll, m_PFRuleScript;
	// Used to get sorted/uniquefied Windir/PF exceptions across multiple scans
	// Reason for a lookup and a corresponding set is to make sure there's no more
	// than one of any given path, but retaining the original case for the output
	// results.
	CaseInsensitiveStringLookup m_WindirLookup, m_PFLookup;
	std::set<std::wstring> m_WindirPathExceptions, m_PFPathExceptions;
	// Assume that Windir Exe Publisher exceptions are all upper-case, so no need for a separate lookup
	std::set<std::wstring> m_WindirPubExceptions;

	// Properties from timestamp rule
	std::wstring m_sTimestampForFilename, m_sTimestampGuid;

	std::wstring m_sEnforcePolicyXml, m_sAuditPolicyXml;

private:
	// Not implemented
	RuleAnalyzer(const RuleAnalyzer&) = delete;
	RuleAnalyzer& operator = (const RuleAnalyzer&) = delete;
};

