
#include "pch.h"
#include <stdio.h>
#include <sstream>
#include <fstream>
#include <set>
#include <list>
#include "../AaronLocker_CommonUtils/Utf8FileUtility.h"
#include "RuleAnalyzer.h"

// ------------------------------------------------------------------------------------------

/// <summary>
/// Default constructor. Initializes base rules with default base rules.
/// </summary>
RuleAnalyzer::RuleAnalyzer()
{
    MergeToRuleCollection<PathRuleCollection_t, PathRuleCollection_t::const_iterator, PathRuleItem>(m_baseRules.m_PathRules, BuiltInRules::DefaultAdminPathRules());
    MergeToRuleCollection<PublisherRuleCollection_t, PublisherRuleCollection_t::const_iterator, PublisherRuleItem>(m_baseRules.m_PublisherRules, BuiltInRules::DefaultPublisherRules());
    MergeToRuleCollection<PathRuleCollection_t, PathRuleCollection_t::const_iterator, PathRuleItem>(m_baseRules.m_PathRules, BuiltInRules::DefaultPathRules());
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Add predefined rules to the base set. (See the BuiltInRules class.)
/// Doesn't add any rules that are redundant.
/// </summary>
void RuleAnalyzer::AddToBaseRules(const PublisherRuleCollection_t& publisherRules)
{
    MergeToRuleCollection<PublisherRuleCollection_t, PublisherRuleCollection_t::const_iterator, PublisherRuleItem>(m_baseRules.m_PublisherRules, publisherRules);
}

/// <summary>
/// Takes one or more deserialized scans (at least one must be a full scan) and an
/// optional set of built-in EXEs not to exclude, and prepares rules.
/// </summary>
/// <returns>true if successful, false otherwise (see sErrorInfo for error information)</returns>
bool RuleAnalyzer::ProcessScans(
    const std::vector<AaronLockerDeserializer>& scans,
    const CaseInsensitiveStringLookup& windowsExesNotToExclude,
    std::wstring& sErrorInfo)
{
    // Verify that at least one scan is a full scan.
    // Build all PathRuleItemWithExceptions for Windir and PF, incorporating unsafe dirs and known-exe exceptions
    // 
    // For all scans, get computer name and FileDetails, ProposeRules and incorporate computer name into Details

    sErrorInfo.clear();

    // Initialize the path rules for the Windows and ProgramFiles directories, and prepare to add exceptions
    InitializeWindirProgFilesPathRules();

    // Iterate through the scans, looking only at full scans on first pass
    bool bGotFullScan = false;
    std::vector<AaronLockerDeserializer>::const_iterator iterScans;
    for (
        iterScans = scans.begin();
        iterScans != scans.end();
        ++iterScans
        )
    {
        if (AaronLockerDeserializer::scantype_t::FullScan == iterScans->m_scantype)
        {
            bGotFullScan = true;

            // Gether information for path-rule exceptions for the Windows and ProgramFiles directories.
            ProcessWindirProgFilesPathRuleExceptions(*iterScans, windowsExesNotToExclude);

            // Incorporate rules for safe paths (primarily for AV putting its code under ProgramData)
            IncorporatePlatformSafePathRulesToBaseRules(iterScans->m_PlatformSafePathInfo);

            // Add rules for installed packaged apps:
            AddRulesForInstalledPackagedApps(iterScans->m_PackagedAppInfo, iterScans->m_sComputerName);
        }
    }

    // If no full scans, get out
    if (!bGotFullScan)
    {
        sErrorInfo = L"At least one of the scans must be a full scan.";
        return false;
    }

    // Incorporate path rule exceptions from information gathered from full scans.
    SetWindirProgFilesPathRuleExceptions();

    // Go through all the scans and process the data about files for which custom per-app rules might be needed.
    for (
        iterScans = scans.begin();
        iterScans != scans.end();
        ++iterScans
        )
    {
        ProposeRulesFromFileDetails(iterScans->m_FileDetails, iterScans->m_sComputerName);
    }

    return true;
}

// Initialize path rule information for the Windows and ProgramFiles directories.
void RuleAnalyzer::InitializeWindirProgFilesPathRules()
{
    // Initialize lookups and collections
    m_WindirLookup.clear();
    m_PFLookup.clear();
    m_WindirPathExceptions.clear();
    m_WindirPubExceptions.clear();
    m_PFPathExceptions.clear();

    // Allow
    m_windirRuleExe.m_bAllow =
        m_windirRuleDll.m_bAllow =
        m_windirRuleScript.m_bAllow =
        m_PFRuleExe.m_bAllow =
        m_PFRuleDll.m_bAllow =
        m_PFRuleScript.m_bAllow = true;
    // Everyone
    m_windirRuleExe.m_sUserOrGroupSid =
        m_windirRuleDll.m_sUserOrGroupSid =
        m_windirRuleScript.m_sUserOrGroupSid =
        m_PFRuleExe.m_sUserOrGroupSid =
        m_PFRuleDll.m_sUserOrGroupSid =
        m_PFRuleScript.m_sUserOrGroupSid = SidEveryone();

    m_windirRuleExe.m_sName = m_windirRuleDll.m_sName = m_windirRuleScript.m_sName =
        L"Allow files in the Windows directory (excluding user-writable subdirectories)";
    m_windirRuleExe.m_sPath = m_windirRuleDll.m_sPath = m_windirRuleScript.m_sPath =
        L"%WINDIR%\\*";
    m_windirRuleExe.m_collection = RuleItem::Collection_t::Exe;
    m_windirRuleDll.m_collection = RuleItem::Collection_t::Dll;
    m_windirRuleScript.m_collection = RuleItem::Collection_t::Script;
    m_windirRuleExe.m_sDescription = L"Allows everyone to run most .exe files in/under the Windows directory.";
    m_windirRuleDll.m_sDescription = L"Allows everyone to load DLLs located in the Windows folder.";
    m_windirRuleScript.m_sDescription = L"Allows everyone to run scripts that are in the Windows directory.";

    m_PFRuleExe.m_sName = m_PFRuleDll.m_sName = m_PFRuleScript.m_sName =
        L"Allow files in the Program Files directories (excluding user-writable subdirectories)";
    m_PFRuleExe.m_sPath = m_PFRuleDll.m_sPath = m_PFRuleScript.m_sPath =
        L"%PROGRAMFILES%\\*";
    m_PFRuleExe.m_collection = RuleItem::Collection_t::Exe;
    m_PFRuleDll.m_collection = RuleItem::Collection_t::Dll;
    m_PFRuleScript.m_collection = RuleItem::Collection_t::Script;
    m_PFRuleExe.m_sDescription = L"Allows everyone to run .exe files in safe Program Files directories.";
    m_PFRuleDll.m_sDescription = L"Allows everyone to load DLLs that are located in the Program Files directories.";
    m_PFRuleScript.m_sDescription = L"Allows everyone to run scripts in safe Program Files directories.";

    // Clear the exceptions in case processing was invoked more than once.
    m_windirRuleExe.clearExceptions();
    m_windirRuleDll.clearExceptions();
    m_windirRuleScript.clearExceptions();
    m_PFRuleExe.clearExceptions();
    m_PFRuleDll.clearExceptions();
    m_PFRuleScript.clearExceptions();

    // Add exception for SYSTEM32\AppLocker\*. The directory is normally a safe directory, but there's
    // an apparent bug in which the security descriptor on some files in that directory grant ownership
    // and full control to the interactive user who logged on. Without this exception, that user could 
    // overwrite those files with executable content (e.g., copy a DLL over them) and then execute them.
    // Described here: https://oddvar.moe/2019/05/29/a-small-discovery-about-applocker/
    // and confirmed in Aaron Margosis' testing.
    m_WindirPathExceptions.insert(L"%SYSTEM32%\\AppLocker\\*");
}

// Helper function used by ProcessWindirProgFilesPathRuleExceptions.
// If sPath begins with sPathStart, change sFullPath so that it begins with sEnvVar instead
// Returns true if sFullPath modified, false otherwise
static bool ReplacePathWithPseudoEnvVar(std::wstring& sFullPath, const std::wstring& sPathStart, const std::wstring& sEnvVar)
{
    if (PathStartsWithDirectory(sFullPath, sPathStart))
    {
        // If PathStartsWithDirectory returns true, it guarantees that sFullPath.length() >= sPathStart.length()
        sFullPath =
            sEnvVar +
            sFullPath.substr(sPathStart.length());
        return true;
    }
    else
        return false;
}

// Get information for path-rule exceptions for the Windows and ProgramFiles directories for this scan.
void RuleAnalyzer::ProcessWindirProgFilesPathRuleExceptions(const AaronLockerDeserializer& scan, const CaseInsensitiveStringLookup& windowsExesNotToExclude)
{
    // Process exceptions for unsafe Windows subdirectories.
    // Need to change "C:\Windows\System32\..." etc to %SYSTEM32% etc.
    // The paths to look for and the pseudo-envvars to replace them with
    const std::wstring sWindir = scan.m_sWindowsDir;
    const std::wstring sSystem32 = scan.m_sWindowsDir + L"\\System32";
    const std::wstring sSysWow64 = scan.m_sWindowsDir + L"\\SysWOW64";
    const std::wstring sEnvVarWindir = L"%WINDIR%";
    const std::wstring sEnvVarSys32 = L"%SYSTEM32%";
    UnsafeDirectoryCollection_t::const_iterator iterUnsafeDirs;
    for (
        iterUnsafeDirs = scan.m_unsafeWindowsSubdirs.begin();
        iterUnsafeDirs != scan.m_unsafeWindowsSubdirs.end();
        ++iterUnsafeDirs
        )
    {
        std::wstring sPath = iterUnsafeDirs->m_sFileSystemPath;
        // Have to do System32/SysWow64 before Windir
        ReplacePathWithPseudoEnvVar(sPath, sSystem32, sEnvVarSys32);
        ReplacePathWithPseudoEnvVar(sPath, sSysWow64, sEnvVarSys32);
        ReplacePathWithPseudoEnvVar(sPath, sWindir, sEnvVarWindir);
        // the path followed by "\*"
        std::wstring sPath1 = sPath + sBackslashStar();
        // Add path only if not in the set already
        if (m_WindirLookup.Add(sPath1))
            m_WindirPathExceptions.insert(sPath1);
        if (iterUnsafeDirs->m_bNeedsAltDataStreamExclusion)
        {
            // If the directory's alternate data streams need an additional
            // exclusion, add it
            sPath1 = sPath + L":*";
            if (m_WindirLookup.Add(sPath1))
                m_WindirPathExceptions.insert(sPath1);
        }
    }

    // Process exceptions for unsafe ProgramFiles subdirectories.
    // The paths to look for and the pseudo-envvars to replace them with
    const std::wstring sPF = scan.m_sProgramFilesDir;
    const std::wstring sPFx86 = scan.m_sProgramFilesX86Dir;
    const std::wstring sEnvVarPF = L"%PROGRAMFILES%";
    for (
        iterUnsafeDirs = scan.m_unsafeProgFilesSubdirs.begin();
        iterUnsafeDirs != scan.m_unsafeProgFilesSubdirs.end();
        ++iterUnsafeDirs
        )
    {
        std::wstring sPath = iterUnsafeDirs->m_sFileSystemPath;
        // Have to do PFx86 before PF if it exists.
        if (sPFx86.length() > 0)
            ReplacePathWithPseudoEnvVar(sPath, sPFx86, sEnvVarPF);
        ReplacePathWithPseudoEnvVar(sPath, sPF, sEnvVarPF);
        // the path followed by "\*"
        std::wstring sPath1 = sPath + sBackslashStar();
        // Add path only if not in the set already
        if (m_PFLookup.Add(sPath1))
            m_PFPathExceptions.insert(sPath1);
        if (iterUnsafeDirs->m_bNeedsAltDataStreamExclusion)
        {
            // If the directory's alternate data streams need an additional
            // exclusion, add it
            sPath1 = sPath + L":*";
            if (m_PFLookup.Add(sPath1))
                m_PFPathExceptions.insert(sPath1);
        }
    }

    // Now process exceptions for problematic built-in Windows files.
    // Merge directly into the exceptions lists. Doesn't incorporate duplicate/redundant rules.
    // First review EXE files that non-admins shouldn't be allowed to execute.
    for (
        PublisherRuleCollection_t::const_iterator iterPubInfo = BuiltInRules::BuiltInExeFilesToExcludeByPublisher().begin();
        iterPubInfo != BuiltInRules::BuiltInExeFilesToExcludeByPublisher().end();
        ++iterPubInfo
        )
    {
        // Exceptions to the exception list. E.g., if rule creator wants to allow non-admins to be able to execute WMIC.exe,
        // don't add it to the exceptions list.
        if (!windowsExesNotToExclude.IsInSet(iterPubInfo->m_sBinaryName))
        {
            MergeToRuleCollection<PublisherRuleCollection_t, PublisherRuleCollection_t::const_iterator, PublisherRuleItem>(
                m_windirRuleExe.m_exceptions.m_PublisherRules, *iterPubInfo
                );
        }
    }

    // Exceptions to disallow non-admin execution of built-in DLLs (e.g., don't allow PowerShell v2 downgrade).
    MergeToRuleCollection<PublisherRuleCollection_t, PublisherRuleCollection_t::const_iterator, PublisherRuleItem>(
        m_windirRuleDll.m_exceptions.m_PublisherRules, BuiltInRules::BuiltInDllFilesToExcludeByPublisher()
        );
    MergeToRuleCollection<PathRuleCollection_t, PathRuleCollection_t::const_iterator, PathRuleItem>(
        m_windirRuleDll.m_exceptions.m_PathRules, BuiltInRules::BuiltInDllFilesToExcludeByPath()
        );

}

// Now that the sorted/uniquefied set of exceptions are established, now apply them.
void RuleAnalyzer::SetWindirProgFilesPathRuleExceptions()
{
    for (
        std::set<std::wstring>::const_iterator iterPaths = m_WindirPathExceptions.begin();
        iterPaths != m_WindirPathExceptions.end();
        ++iterPaths
        )
    {
        PathRuleItem rule;
        rule.m_sPath = *iterPaths;
        m_windirRuleExe.m_exceptions.m_PathRules.push_back(rule);
        m_windirRuleDll.m_exceptions.m_PathRules.push_back(rule);
        m_windirRuleScript.m_exceptions.m_PathRules.push_back(rule);
    }

    for (
        std::set<std::wstring>::const_iterator iterPaths = m_PFPathExceptions.begin();
        iterPaths != m_PFPathExceptions.end();
        ++iterPaths
        )
    {
        PathRuleItem rule;
        rule.m_sPath = *iterPaths;
        m_PFRuleExe.m_exceptions.m_PathRules.push_back(rule);
        m_PFRuleDll.m_exceptions.m_PathRules.push_back(rule);
        m_PFRuleScript.m_exceptions.m_PathRules.push_back(rule);
    }
}

// Incorporate rules for safe paths (primarily for AV putting its code under ProgramData)
void RuleAnalyzer::IncorporatePlatformSafePathRulesToBaseRules(const SafePathInfoCollection_t& safePathInfo)
{
    for (
        SafePathInfoCollection_t::const_iterator iterSafePathInfo = safePathInfo.begin();
        iterSafePathInfo != safePathInfo.end();
        ++iterSafePathInfo
        )
    {
        PathRuleItem rule;
        // rule.m_bAllow - default value
        rule.m_sName = iterSafePathInfo->m_sLabel;
        rule.m_sPath = iterSafePathInfo->m_sPath;
        rule.m_collection = RuleItem::Collection_t::All;
        //TODO: populate this if not already set: rule.m_sDescription;
        // rule.m_sUserOrGroupSid - default value

        MergeToRuleCollection<PathRuleCollection_t, PathRuleCollection_t::const_iterator, PathRuleItem>(m_baseRules.m_PathRules, rule);
    }
}

// ------------------------------------------------------------------------------------------

// Review data about files for which custom per-app rules might be needed and build proposed rules.
bool RuleAnalyzer::ProposeRulesFromFileDetails(
    const FileDetailsCollection_t& vFileDetails, const std::wstring& sComputerName)
{
    bool retval = true;

    // Create proposed path and hash rules as we see each file, dropping redundant rules as we see them.
    // Microsoft-signed files get one rule per product/binaryname combination.
    // Other signed files get aggregated first, as we can coalesce publisher rules into a smaller set.

    // Redundancy of a proposed rule is measured against existing base rules (defined in these three rule collections),
    // and then previously-defined per-app rules.
    const PathRuleCollection_t& vExistingPathRules = m_baseRules.m_PathRules;
    const PublisherRuleCollection_t& vExistingPublisherRules = m_baseRules.m_PublisherRules;
    const HashRuleCollection_t& vExistingHashRules = m_baseRules.m_HashRules;

    // Typedef a keyed set of groups of file details:
    typedef std::unordered_map<std::wstring, FileDetailsCollection_t> FileAggregator_t;

    // Collection of signed files, grouped by file type (rule collection) + publisher
    FileAggregator_t signedFilesAggregator;
    FileAggregator_t::iterator iterSFA;

    // Iterate through all the files
    FileDetailsCollection_t::const_iterator iterFD;
    for (
        iterFD = vFileDetails.begin();
        iterFD != vFileDetails.end();
        ++iterFD
        )
    {
        if (BuiltInRules::IgnoreFile(*iterFD))
        {
            // Do nothing
        }
        else if (iterFD->m_bIsSafeDir)
        {
            // File in a safe directory --> path rule
            CreatePathRuleProposal(*iterFD, vExistingPathRules);
        }
        else if (iterFD->m_ALPublisherName.length() == 0)
        {
            // Unsigned file --> hash rule
            CreateHashRuleProposal(*iterFD, vExistingHashRules, sComputerName, std::wstring());
        }
        else // Signed files
        {
            // If the file is already covered by any existing publisher rules, skip it.
            if (!Match <PublisherRuleCollection_t, PublisherRuleCollection_t::const_iterator>(vExistingPublisherRules, *iterFD))
            {
                // Microsoft-signed files must have product name + binary name, or they get hash rules.
                if (MicrosoftPublisher() == iterFD->m_ALPublisherName)
                {
                    if (iterFD->m_ALProductName.length() == 0 || iterFD->m_ALBinaryName.length() == 0)
                    {
                        // Rule description will include that the file is Microsoft-signed but is missing version information.
                        CreateHashRuleProposal(*iterFD, vExistingHashRules, sComputerName, L"File is Microsoft-signed but missing version resource information.");
                    }
                    else
                    {
                        // Rule for Microsoft-signed file not already covered by existing rules must be a granular rule,
                        // including product name and binary file name.
                        PublisherRuleItem rule;
                        // default rule.m_bAllow;
                        rule.m_collection = RuleItem::FromFType(iterFD->m_fileType);
                        rule.m_sBinaryName = iterFD->m_ALBinaryName;
                        // default - rule.m_sBinaryVersionHigh;
                        // default - rule.m_sBinaryVersionLow;
                        //TODO: populate this if not already set: rule.m_sDescription;
                        rule.m_sName = iterFD->m_sAppLabel;
                        rule.m_sProduct = iterFD->m_ALProductName;
                        rule.m_sPublisher = iterFD->m_ALPublisherName;
                        // default - rule.m_sUserOrGroupSid;

                        AddPublisherRuleProposal(rule, vExistingPublisherRules);
                    }
                }
                else
                {
                    // All other signed files get file details aggregrated into the signedFilesAggregator collection, grouped 
                    // by RuleCollection+Publisher. That collection will be processed after we iterate through
                    // all the files.
                    RuleItem::Collection_t collection = RuleItem::FromFType(iterFD->m_fileType);
                    // No file that shows up in a file details collection should map to "no collection" but check anyway.
                    if (RuleItem::Collection_t::NotSet != collection)
                    {
                        // Build the key for the collection from the rule collection and the publisher name.
                        std::wstring sKey = RuleItem::Collection2Str(collection) + L"|" + iterFD->m_ALPublisherName;

                        // If this key isn't in the set yet, add a new entry
                        iterSFA = signedFilesAggregator.find(sKey);
                        if (signedFilesAggregator.end() == iterSFA)
                        {
                            // New collection, with this one new element.
                            FileDetailsCollection_t collPubCollection;
                            collPubCollection.push_back(*iterFD);
                            signedFilesAggregator[sKey] = collPubCollection;
                        }
                        else
                        {
                            // This key is in the set already; add this file to the file details collection
                            // associated with that key.
                            iterSFA->second.push_back(*iterFD);
                        }
                    }
                }
            }
        }
    }

    // Now go through the non-Microsoft signed files and build a sensible set of rules for them.
    // Iterate through each keyed set.
    for (
        iterSFA = signedFilesAggregator.begin();
        iterSFA != signedFilesAggregator.end();
        ++iterSFA
        )
    {
        // Each item under this key has the same collection and publisher. Rather than try to extract them from
        // the key, just get them from the first item in the FileDetailsCollection.
        // Assume for now that app label is the same for all of them too
        const FileDetailsCollection_t& collPubCollection = iterSFA->second;
        RuleItem::Collection_t collection = RuleItem::FromFType(collPubCollection[0].m_fileType);
        const std::wstring& sPublisher = collPubCollection[0].m_ALPublisherName;
        const std::wstring& sAppLabel = collPubCollection[0].m_sAppLabel;

        // Now group these files by product (productAggregator). 
        // If any are missing product name, or if there are more than 5 product names associated with this publisher, create a single publisher-only
        // rule for this collection/publisher, allowing everything by this publisher.
        // Otherwise, create a rule for each product. If a product has only one file, include the binary name in the rule.
        FileAggregator_t productAggregator;
        FileAggregator_t::iterator iterProdFA;
        FileDetailsCollection_t::const_iterator iterCollPublisher;
        bool bBlankProduct = false;
        for (
            iterCollPublisher = collPubCollection.begin();
            !bBlankProduct && iterCollPublisher != collPubCollection.end();
            ++iterCollPublisher
            )
        {
            const std::wstring& sProduct = iterCollPublisher->m_ALProductName;
            if (sProduct.length() == 0)
            {
                // Blank product name; quit this one and build a single rule with publisher only
                bBlankProduct = true;
            }
            else
            {
                // Seen this product name yet? Create element, or add to existing item.
                iterProdFA = productAggregator.find(sProduct);
                if (productAggregator.end() == iterProdFA)
                {
                    FileDetailsCollection_t fdc;
                    fdc.push_back(*iterCollPublisher);
                    productAggregator[sProduct] = fdc;
                }
                else
                {
                    iterProdFA->second.push_back(*iterCollPublisher);
                }
            }
        }

        // Finished aggregating by product. If any had blank product or there were more than 5 products,
        // create one rule with just the publisher name
        if (bBlankProduct || productAggregator.size() > 5)
        {
            PublisherRuleItem rule;
            // default rule.m_bAllow;
            rule.m_collection = collection;
            //TODO: populate this if not already set:  rule.m_sDescription;
            rule.m_sName = sAppLabel;
            rule.m_sPublisher = sPublisher;
            // default rule.m_sUserOrGroupSid;

            AddPublisherRuleProposal(rule, vExistingPublisherRules);
        }
        else
        {
            // Otherwise, create a rule for each product. If a product has only one file, include the binary name in the rule.
            for (
                iterProdFA = productAggregator.begin();
                iterProdFA != productAggregator.end();
                ++iterProdFA
                )
            {
                const FileDetailsCollection_t& prodCollection = iterProdFA->second;
                PublisherRuleItem rule;
                // default rule.m_bAllow;
                rule.m_collection = collection;
                //TODO: populate this if not already set:  rule.m_sDescription;
                rule.m_sName = sAppLabel;
                rule.m_sPublisher = sPublisher;
                rule.m_sProduct = prodCollection[0].m_ALProductName;
                // default rule.m_sUserOrGroupSid;
                if (prodCollection.size() == 1 && prodCollection[0].m_ALBinaryName.length() > 0)
                {
                    rule.m_sBinaryName = prodCollection[0].m_ALBinaryName;
                }

                AddPublisherRuleProposal(rule, vExistingPublisherRules);
            }
        }
    }

    return retval;
}

bool RuleAnalyzer::AddRulesForInstalledPackagedApps(const PackagedAppInfoCollection_t& vPackagedApps, const std::wstring& sComputerName)
{
    for (
        PackagedAppInfoCollection_t::const_iterator iter = vPackagedApps.begin();
        iter != vPackagedApps.end();
        ++iter
        )
    {
        std::wstring sProdName = (iter->DisplayName.empty() ? iter->Name : iter->DisplayName);
        std::wstring sPubName = (iter->PublisherDisplayName.empty() ? iter->Publisher : iter->PublisherDisplayName);
        PublisherRuleItem rule;
        // default rule.m_bAllow;
        rule.m_collection = RuleItem::Collection_t::Appx;
        rule.m_sPublisher = iter->Publisher;
        rule.m_sProduct = iter->Name;
        rule.m_sName = sProdName + L", from " + sPubName;
        rule.m_sDescription = iter->FullName + L" version " + iter->Version + L" observed on " + sComputerName + L" in " + iter->InstallLocation;
        // default rule.m_sUserOrGroupSid;
        // Add to collection if not redundant (e.g., not Windows-signed)
        AddPublisherRuleProposal(rule, m_baseRules.m_PublisherRules);
    }

    return true;
}

// Helper function to create a new safe-directory path rule for all collections and add it to the proposed rule set if it's not redundant.
void RuleAnalyzer::CreatePathRuleProposal(const FileDetails_t& fileDetails, const PathRuleCollection_t& vExistingPathRules)
{
    PathRuleItem rule;
    // default rule.m_bAllow;
    rule.m_collection = RuleItem::Collection_t::All;
    //TODO: populate this if not already set:  rule.m_sDescription;
    rule.m_sName = fileDetails.m_sAppLabel;
    rule.m_sPath = GetDirectoryNameFromFilePath(fileDetails.m_sFilePath) + L"\\*";
    // default rule.m_sUserOrGroupSid;

    // Check whether an existing base rule makes it redundant. (Not removing any base rules even if the new one supersedes them.)
    RuleItem::Redundancy_t redundancy = RedundancyCheck<PathRuleCollection_t, PathRuleCollection_t::const_iterator, PathRuleItem>(vExistingPathRules, rule);
    if (RuleItem::Redundancy_t::ProposedIsRedundant != redundancy)
    {
        // If not redundant with base rules, check the proposed app rules so far for this app.
        RuleSetCollection_t::iterator iterAppRuleSet = m_proposedAppRules.find(fileDetails.m_sAppLabel);
        // Add to proposed rule set unless proposed rule set has something better
        if (m_proposedAppRules.end() != iterAppRuleSet)
        {
            // Add to the proposed rule set if not redundant, removing any rules from the set that it supersedes.
            AddRuleToCollectionWithCleanup<PathRuleCollection_t, PathRuleCollection_t::iterator, PathRuleItem>(iterAppRuleSet->second.m_PathRules, rule);
        }
        else
        {
            // New app rule set
            RuleSet_t appRuleSet;
            appRuleSet.m_PathRules.push_back(rule);
            m_proposedAppRules[fileDetails.m_sAppLabel] = appRuleSet;
        }
    }
}

// Helper function to add a publisher rule to the proposed rule set if it's not redundant.
void RuleAnalyzer::AddPublisherRuleProposal(const PublisherRuleItem& rule, const PublisherRuleCollection_t& vExistingPublisherRules)
{
    // Look at base rules first (not removing any base rules)
    RuleItem::Redundancy_t redundancy = RedundancyCheck<PublisherRuleCollection_t, PublisherRuleCollection_t::const_iterator, PublisherRuleItem>(vExistingPublisherRules, rule);
    if (RuleItem::Redundancy_t::ProposedIsRedundant != redundancy)
    {
        // If not redundant with base rules, check the proposed app rules so far for this app.
        RuleSetCollection_t::iterator iterAppRuleSet = m_proposedAppRules.find(rule.m_sName);
        // Add to proposed rule set unless proposed rule set has something better
        if (m_proposedAppRules.end() != iterAppRuleSet)
        {
            // Add to the proposed rule set if not redundant, removing any rules from the set that it supersedes.
            AddRuleToCollectionWithCleanup<PublisherRuleCollection_t, PublisherRuleCollection_t::iterator, PublisherRuleItem>(iterAppRuleSet->second.m_PublisherRules, rule);
        }
        else
        {
            // New app rule set
            RuleSet_t appRuleSet;
            appRuleSet.m_PublisherRules.push_back(rule);
            m_proposedAppRules[rule.m_sName] = appRuleSet;
        }
    }
}

// Helper function to create a new hash rule and add it to the proposed rule set if it's not redundant.
void RuleAnalyzer::CreateHashRuleProposal(
    const FileDetails_t& fileDetails, 
    const HashRuleCollection_t& vExistingHashRules,
    const std::wstring& sComputerName,
    const std::wstring& sOptionalInfo)
{
    HashRuleItem rule;
    // default rule.m_bAllow;
    rule.m_collection = RuleItem::FromFType(fileDetails.m_fileType);
    if (sOptionalInfo.length() > 0)
    {
        rule.m_sDescription = sOptionalInfo + L" \r\n";
    }
    rule.m_sDescription += std::wstring(L"Observed in ") + fileDetails.m_sFilePath + L" on " + sComputerName;
    rule.m_sFileLength = fileDetails.m_fileSize;
    rule.m_sFilename = GetFileNameFromFilePath(fileDetails.m_sFilePath);
    rule.m_sHashData = fileDetails.m_ALHash;
    rule.m_sName = fileDetails.m_sAppLabel;
    // default rule.m_sUserOrGroupSid;

    // Look at base rules first (not removing any base rules)
    RuleItem::Redundancy_t redundancy = RedundancyCheck<HashRuleCollection_t, HashRuleCollection_t::const_iterator, HashRuleItem>(vExistingHashRules, rule);
    if (RuleItem::Redundancy_t::ProposedIsRedundant != redundancy)
    {
        // If not redundant with base rules, check the proposed app rules so far for this app.
        RuleSetCollection_t::iterator iterAppRuleSet = m_proposedAppRules.find(fileDetails.m_sAppLabel);
        // Add to proposed rule set unless proposed rule set has something better
        if (m_proposedAppRules.end() != iterAppRuleSet)
        {
            // Add to the proposed rule set if not redundant, removing any rules from the set that it supersedes.
            AddRuleToCollectionWithCleanup<HashRuleCollection_t, HashRuleCollection_t::iterator, HashRuleItem>(iterAppRuleSet->second.m_HashRules, rule);
        }
        else
        {
            // New app rule set
            RuleSet_t appRuleSet;
            appRuleSet.m_HashRules.push_back(rule);
            m_proposedAppRules[fileDetails.m_sAppLabel] = appRuleSet;
        }
    }
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Returns the set of app names of proposed rule sets from the scans' file details.
/// </summary>
/// <returns>The number of app names returned.</returns>
size_t RuleAnalyzer::GetProposedRuleSetNames(std::vector<std::wstring>& names) const
{
    size_t retval = 0;
    names.clear();
    for (
        RuleSetCollection_t::const_iterator iterRuleSet = m_proposedAppRules.begin();
        iterRuleSet != m_proposedAppRules.end();
        ++iterRuleSet
        )
    {
        names.push_back(iterRuleSet->first);
        ++retval;
    }
    return retval;
}

/// <summary>
/// Returns a pointer to a proposed rule set associated with the name provided.
/// </summary>
/// <param name="sName">Input: the app name</param>
/// <param name="ppRuleSet">Output: a pointer to the proposed rule set associated with the app name, or NULL if not found.</param>
/// <returns>true if the proposed rule set is returned; false if the name wasn't found.</returns>
bool RuleAnalyzer::GetProposedRuleSet(const std::wstring& sName, const RuleSet_t** ppRuleSet) const
{
    *ppRuleSet = NULL;
    RuleSetCollection_t::const_iterator iterRuleSet = m_proposedAppRules.find(sName);
    if (m_proposedAppRules.end() == iterRuleSet)
        return false;
    *ppRuleSet = &iterRuleSet->second;
    return true;
}

/// <summary>
/// Removes a proposed rule set
/// </summary>
/// <param name="sName">Name of the rule set to remove</param>
/// <returns>true if removed; false if name not found.</returns>
bool RuleAnalyzer::DeleteProposedRuleSet(const std::wstring& sName)
{
    return (0 != m_proposedAppRules.erase(sName));
}

/// <summary>
/// Removes all proposed rule sets beginning with the input name, with optional case sensitivity
/// </summary>
/// <param name="sName">Beginning of the name of the rule sets to remove</param>
/// <param name="bCaseSensitive">true if comparison should be case-sensitive</param>
/// <returns>Number of rule sets removed</returns>
size_t RuleAnalyzer::DeleteProposedRuleSetBeginningWithName(const std::wstring& sName, bool bCaseSensitive /*= false*/)
{
    // Get the list of matching names
    std::list<std::wstring> listOfNamesToRemove;
    for (
        RuleSetCollection_t::const_iterator iterRuleSet = m_proposedAppRules.begin();
        iterRuleSet != m_proposedAppRules.end();
        ++iterRuleSet
        )
    {
        if (StartsWith(iterRuleSet->first, sName, bCaseSensitive))
        {
            listOfNamesToRemove.push_back(iterRuleSet->first);
        }
    }
    // Delete those entries. (Can't do that while iterating through the rule set collection)
    for (
        std::list<std::wstring>::const_iterator iterNames = listOfNamesToRemove.begin();
        iterNames != listOfNamesToRemove.end();
        ++iterNames
        )
    {
        m_proposedAppRules.erase(*iterNames);
    }
    return listOfNamesToRemove.size();
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

// Helper function that writes a rule item's XML to the correct rule collection stream
static inline void WriteRuleToXml(const RuleItem& rule,
    std::wostream& strExeRuleCollection,
    std::wostream& strDllRuleCollection,
    std::wostream& strMsiRuleCollection,
    std::wostream& strScriptRuleCollection,
    std::wostream& strAppxRuleCollection)
{
    switch (rule.m_collection)
    {
    case RuleItem::Collection_t::Exe:
        rule.ToXml(strExeRuleCollection);
        break;
    case RuleItem::Collection_t::Dll:
        rule.ToXml(strDllRuleCollection);
        break;
    case RuleItem::Collection_t::Msi:
        rule.ToXml(strMsiRuleCollection);
        break;
    case RuleItem::Collection_t::Script:
        rule.ToXml(strScriptRuleCollection);
        break;
    case RuleItem::Collection_t::Appx:
        rule.ToXml(strAppxRuleCollection);
        break;
    case RuleItem::Collection_t::All:
        rule.ToXml(strExeRuleCollection);
        rule.ToXml(strDllRuleCollection, true);
        rule.ToXml(strMsiRuleCollection, true);
        rule.ToXml(strScriptRuleCollection, true);
        break;
    }
}

// Helper function that writes a rule set's items' XML to the correct rule collection streams
static inline void WriteRuleSetToXml(const RuleSet_t& ruleSet,
    std::wostream& strExeRuleCollection,
    std::wostream& strDllRuleCollection,
    std::wostream& strMsiRuleCollection,
    std::wostream& strScriptRuleCollection,
    std::wostream& strAppxRuleCollection)
{
    PathRuleCollection_t::const_iterator iterPathRules;
    PublisherRuleCollection_t::const_iterator iterPublisherRules;
    HashRuleCollection_t::const_iterator iterHashRules;
    RuleSetCollection_t::const_iterator iterRuleSetColl;
    for (
        iterPathRules = ruleSet.m_PathRules.begin();
        iterPathRules != ruleSet.m_PathRules.end();
        ++iterPathRules
        )
    {
        WriteRuleToXml(*iterPathRules,
            strExeRuleCollection,
            strDllRuleCollection,
            strMsiRuleCollection,
            strScriptRuleCollection,
            strAppxRuleCollection);
    }
    for (
        iterPublisherRules = ruleSet.m_PublisherRules.begin();
        iterPublisherRules != ruleSet.m_PublisherRules.end();
        ++iterPublisherRules
        )
    {
        WriteRuleToXml(*iterPublisherRules,
            strExeRuleCollection,
            strDllRuleCollection,
            strMsiRuleCollection,
            strScriptRuleCollection,
            strAppxRuleCollection);
    }
    for (
        iterHashRules = ruleSet.m_HashRules.begin();
        iterHashRules != ruleSet.m_HashRules.end();
        ++iterHashRules
        )
    {
        WriteRuleToXml(*iterHashRules,
            strExeRuleCollection,
            strDllRuleCollection,
            strMsiRuleCollection,
            strScriptRuleCollection,
            strAppxRuleCollection);
    }
}

/// <summary>
/// Creates Enforce and Audit mode AppLocker policies from all the captured data.
/// </summary>
/// <returns>true if successful (always returns true)</returns>
bool RuleAnalyzer::CreatePolicies(const CommentRuleCollection_t& comments, std::wstring& sErrorInfo)
{
    //TODO: Low priority, but might be nice to order rules within each rule collection starting with admin rules and then the Windir/PF rules.

    bool retval = false;
    sErrorInfo.clear();

    // Create a string stream for each rule collection
    std::wstringstream
        strExeRuleCollection,
        strDllRuleCollection,
        strMsiRuleCollection,
        strScriptRuleCollection,
        strAppxRuleCollection;

    // Write each base rule's XML to the appropriate rule collection stream
    WriteRuleSetToXml(m_baseRules,
        strExeRuleCollection,
        strDllRuleCollection,
        strMsiRuleCollection,
        strScriptRuleCollection,
        strAppxRuleCollection);

    // Write each Windows/ProgramFiles path rules' XML to the appropriate rule collection streams.
    m_windirRuleExe.ToXml(strExeRuleCollection);
    m_windirRuleDll.ToXml(strDllRuleCollection);
    m_windirRuleScript.ToXml(strScriptRuleCollection);
    m_PFRuleExe.ToXml(strExeRuleCollection);
    m_PFRuleDll.ToXml(strDllRuleCollection);
    m_PFRuleScript.ToXml(strScriptRuleCollection);

    // Iterate through all the proposed app rules and write their XML to the appropriate rule collection streams.
    RuleSetCollection_t::const_iterator iterRuleSetColl;
    for (
        iterRuleSetColl = m_proposedAppRules.begin();
        iterRuleSetColl != m_proposedAppRules.end();
        ++iterRuleSetColl
        )
    {
        WriteRuleSetToXml(iterRuleSetColl->second, 
            strExeRuleCollection,
            strDllRuleCollection,
            strMsiRuleCollection,
            strScriptRuleCollection,
            strAppxRuleCollection);
    }

    // If any comment rules supplied, add them in to the EXE rule collection
    for (
        CommentRuleCollection_t::const_iterator iterComments = comments.begin();
        iterComments != comments.end();
        ++iterComments
        )
    {
        iterComments->ToXml(strExeRuleCollection);
    }

    // Create a TimestampRule item and add its XML to the EXE rule collection.
    // Also capture a version of the timestamp that can be used as part of file names.
    TimestampRule timestamp;
    timestamp.ToXml(strExeRuleCollection);
    m_sTimestampForFilename = timestamp.m_sTimestampForFilename;
    m_sTimestampGuid = timestamp.Guid();

    // Some constants I'll need
    const wchar_t* szAppLockerPolicy = L"AppLockerPolicy";
    const wchar_t* szRuleCollectionOpen = L"<RuleCollection Type=";
    const wchar_t* szRuleCollectionClose = L"</RuleCollection>";
    const wchar_t* szEnforceMode = L" EnforcementMode=\"Enabled\"";
    const wchar_t* szAuditMode = L" EnforcementMode=\"AuditOnly\"";

    // Create a string stream to write the full policy into.
    std::wstringstream strPolicy;
    // Write the policy into the stream - start with the Enforce-mode policy.
    strPolicy
        << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        << L"<" << szAppLockerPolicy << L" Version=\"1\">" 
        << std::endl
        << szRuleCollectionOpen << L"\"Exe\"" << szEnforceMode << L">"
        << strExeRuleCollection.str()
        << szRuleCollectionClose
        << std::endl
        << szRuleCollectionOpen << L"\"Dll\"" << szEnforceMode << L">"
        << strDllRuleCollection.str()
        << szRuleCollectionClose
        << std::endl
        << szRuleCollectionOpen << L"\"Msi\"" << szEnforceMode << L">"
        << strMsiRuleCollection.str()
        << szRuleCollectionClose
        << std::endl
        << szRuleCollectionOpen << L"\"Script\"" << szEnforceMode << L">"
        << strScriptRuleCollection.str()
        << szRuleCollectionClose
        << std::endl
        << szRuleCollectionOpen << L"\"Appx\"" << szEnforceMode << L">"
        << strAppxRuleCollection.str()
        << szRuleCollectionClose
        << std::endl
        << L"</" << szAppLockerPolicy << L">"
        ;

    // Set the internal enforce policy XML string
    m_sEnforcePolicyXml = strPolicy.str();
    // Globally replace enforce-mode with audit mode and assign that to the internal audit policy XML string.
    m_sAuditPolicyXml = replaceStringAll(m_sEnforcePolicyXml, szEnforceMode, szAuditMode);

    retval = true;

    return retval;
}

/// <summary>
/// Writes Enforce or Audit AppLocker XML policy to a UTF-8 encoded file.
/// </summary>
/// <param name="szFilename">Input: path to output file</param>
/// <param name="bEnforcePolicy">Input: true for Enforce policy XML, false for Audit policy XML</param>
/// <param name="sErrorInfo">Output: error information on failure</param>
/// <returns>true if successful, false otherwise</returns>
bool RuleAnalyzer::SavePolicy(const wchar_t* szFilename, bool bEnforcePolicy, std::wstring& sErrorInfo) const
{
    std::wofstream fs;
    fs.open(szFilename, std::ios_base::out);
    if (fs.fail())
    {
        sErrorInfo = L"Couldn't open file for writing";
        return false;
    }
    fs.imbue(Utf8FileUtility::LocaleForWritingUtf8File());
    if (bEnforcePolicy)
        fs << m_sEnforcePolicyXml;
    else
        fs << m_sAuditPolicyXml;
    fs.close();

    return true;
}

/// <summary>
/// Timestamp string from timestamp pseudo-rule that can be used in a filename.
/// Valid after CreatePolicies succeeds.
/// </summary>
const std::wstring& RuleAnalyzer::TimestampForFilename() const
{
    return m_sTimestampForFilename;
}

/// <summary>
/// GUID from timestamp pseudo-rule that uniquely identifies this enforce/audit pair of policies.
/// Valid after CreatePolicies succeeds.
/// </summary>
const std::wstring& RuleAnalyzer::TimestampGuid() const
{
    return m_sTimestampGuid;
}

// ------------------------------------------------------------------------------------------
