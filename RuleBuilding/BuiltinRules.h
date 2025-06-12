#pragma once

#include "../RuleBuilding/RuleItemCollectionOps.h"

/// <summary>
/// BuiltInRules encapsulates predefined groups of AppLocker rules that can be
/// implemented.
/// </summary>
class BuiltInRules
{
public:
	// --------------------------------------------------------------------------------
	// Rules that can be applied for well-known/common apps.

	/// <summary>
	/// GoogleChromeMachinewideInstallRules:
	/// Enable these rules if Google Chrome is installed to ProgramFiles.
	/// Google Chrome runs some code in the user profile even when Chrome is installed to Program Files.
	/// </summary>
	static const PublisherRuleCollection_t& GoogleChromeMachinewideInstallRules();
	/// <summary>
	/// GoogleChromePerUserInstallRules:
	/// Enables per-user install of Google Chrome. Note that to do so, need to allow
	/// anything signed by Google, not just Chrome.
	/// </summary>
	static const PublisherRuleCollection_t& GoogleChromePerUserInstallRules();
	/// <summary>
	/// MozillaRules:
	/// Enables per-user install and use of Mozilla Firefox.
	/// </summary>
	static const PublisherRuleCollection_t& MozillaRules();
	/// <summary>
	/// MicrosoftTeamsRules:
	/// Allow users to install and run Microsoft Teams from unsafe directories
	/// </summary>
	static const PublisherRuleCollection_t& MicrosoftTeamsRules();
	/// <summary>
	/// ZoomRules:
	/// Allow users to install and run Zoom from unsafe directories
	/// </summary>
	static const PublisherRuleCollection_t& ZoomRules();
	/// <summary>
	/// WebExRules:
	/// Allow users to install and run WebEx from unsafe directories
	/// </summary>
	/// <returns></returns>
	static const PublisherRuleCollection_t& WebExRules();
	/// <summary>
	/// SlackRules:
	/// Allow users to install and run Slack from unsafe directories
	/// </summary>
	/// <returns></returns>
	static const PublisherRuleCollection_t& SlackRules();
	/// <summary>
	/// ChromiumBrowserFlashPlayerRules:
	/// Enable to allow Flash player in Google Chrome and/or Chromium-based Microsoft Edge
	/// </summary>
	static const PublisherRuleCollection_t& ChromiumBrowserFlashPlayerRules();
	/// <summary>
	/// IntuitDataUpdaterRules:
	/// Enable Intuit products to run per-user data updaters, such as for TurboTax.
	/// </summary>
	static const PublisherRuleCollection_t& IntuitDataUpdaterRules();
	/// <summary>
	/// AllStoreApps:
	/// Allow all signed Store apps (a.k.a, AppX, packaged apps)
	/// </summary>
	/// <returns></returns>
	static const PublisherRuleCollection_t& AllStoreApps();
	/// <summary>
	/// MsStoreApps:
	/// Allow Microsoft-signed Store apps (a.k.a, AppX, packaged apps)
	/// </summary>
	/// <returns></returns>
	static const PublisherRuleCollection_t& MsSignedStoreApps();
	/// <summary>
	/// STRONGLY DISCOURAGED. LAST RESORT ONLY.
	/// AllMicroosftDLLs:
	/// Allows all Microsoft-signed DLLs.
	/// (Might be needed as a last resort for some crap, such as OneDrive's nonsense.)
	/// </summary>
	/// <returns></returns>
	static const PublisherRuleCollection_t& AllMicrosoftDLLs();
	// --------------------------------------------------------------------------------

	/// <summary>
	/// Built-in/hardcoded logic about files not to build rules for.
	/// </summary>
	/// <param name="fd">Input: information about the file to consider</param>
	/// <returns>true if the rule-builder should not bother creating a rule for this file</returns>
	static bool IgnoreFile(const FileDetails_t& fd);

	// --------------------------------------------------------------------------------
	// The remaining functions are for the RuleAnalyzer class' internal use only.
	static const PathRuleCollection_t& DefaultPathRules();
	static const PublisherRuleCollection_t& DefaultPublisherRules();
	static const PathRuleCollection_t& DefaultAdminPathRules();
	static const PublisherRuleCollection_t& BuiltInExeFilesToExcludeByPublisher();
	static const PublisherRuleCollection_t& BuiltInDllFilesToExcludeByPublisher();
	static const PathRuleCollection_t& BuiltInDllFilesToExcludeByPath();
};

