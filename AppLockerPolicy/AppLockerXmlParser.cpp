#include "pch.h"
#include "AppLockerXmlParser.h"

/// L"AppLockerPolicy" - the root element of an AppLocker policy XML document 
//static
const wchar_t* const AppLockerXmlParser::szPolicyRootTagname = L"AppLockerPolicy";

/// <summary>
/// Given AppLocker policy XML, extract out each RuleCollection 
/// </summary>
/// <param name="sPolicyXml">Input: string representing the full AppLocker policy XML</param>
/// <param name="sExePolicy">Output: the XML representing the EXE rule collection</param>
/// <param name="sDllPolicy">Output: the XML representing the DLL rule collection</param>
/// <param name="sMsiPolicy">Output: the XML representing the MSI rule collection</param>
/// <param name="sScriptPolicy">Output: the XML representing the Script rule collection</param>
/// <param name="sAppxPolicy">Output: the XML representing the Appx ("Store apps," "Packaged apps") rule collection</param>
/// <returns>true if successful, false on any parsing error</returns>
bool AppLockerXmlParser::ParseRuleCollections(const std::wstring& sPolicyXml, std::wstring& sExePolicy, std::wstring& sDllPolicy, std::wstring& sMsiPolicy, std::wstring& sScriptPolicy, std::wstring& sAppxPolicy)
{
    // NOT a robust XML parse here; mostly assumes well-formed AppLocker policy XML.
    sExePolicy.clear();
    sDllPolicy.clear();
    sMsiPolicy.clear();
    sScriptPolicy.clear();
    sAppxPolicy.clear();

    // Verify that the AppLocker policy root element appears to be in this string.
    // It's not invalid to have that and then no rule collections. But have to have that root element.
    if (std::wstring::npos == sPolicyXml.find(std::wstring(L"<") + szPolicyRootTagname))
        return false;

    // Limited parsing validation
    bool bParseOK = true;
    // ixRC is index pointing to the next rule collection or the starting point for the next search.
    size_t ixRC = 0;
    // Quit when there are no more rule collections or we hit a parsing problem.
    while (std::wstring::npos != ixRC && bParseOK)
    {
        // Find the next rule collection
        ixRC = sPolicyXml.find(L"<RuleCollection ", ixRC);
        if (std::wstring::npos != ixRC)
        {
            // Determine what rule collection this is - get the opening dquote following the next "Type" attribute
            bParseOK = false;
            size_t ixType = sPolicyXml.find(L"Type", ixRC);
            if (std::wstring::npos != ixType)
            {
                size_t ixDQ = sPolicyXml.find(L'"', ixType);
                if (std::wstring::npos != ixDQ)
                {
                    // Get three characters of the "Type" attribute's text.
                    // (Could get the entire text up to the next dquote, but this will work well enough)
                    std::wstring sType = sPolicyXml.substr(ixDQ + 1, 3);
                    // Find the rule collection's ending element
                    // The RuleCollection element can have child elements representing one or more rules,
                    // or it might be empty. So the RuleCollection can end with "</RuleCollection>" or it
                    // might end with "/>". In the latter case, we'd find a "/>" before we see another "<".
                    // Look for that first, and if we don't find that, then look for the full closing tag.
                    std::wstring sEndRC = L"/>";
                    size_t ixNextLT = sPolicyXml.find(L"<", ixDQ);
                    size_t ixEndRC = sPolicyXml.find(sEndRC, ixDQ);
                    if (std::wstring::npos == ixEndRC || (std::wstring::npos != ixNextLT && ixNextLT < ixEndRC))
                    {
                        sEndRC = L"</RuleCollection>";
                        ixEndRC = sPolicyXml.find(sEndRC, ixDQ);
                    }
                    if (std::wstring::npos != ixEndRC)
                    {
                        bParseOK = true;
                        // Write the rule collection substring to the output parameter corresponding to
                        // the collection type. Note that we're looking at only three characters of the
                        // type name in this case (e.g., "Scr" instead of "Script").
                        size_t substrLen = ixEndRC + sEndRC.length() - ixRC;
                        if (sType == L"Exe") { sExePolicy = sPolicyXml.substr(ixRC, substrLen); }
                        else if (sType == L"Dll") { sDllPolicy = sPolicyXml.substr(ixRC, substrLen); }
                        else if (sType == L"Msi") { sMsiPolicy = sPolicyXml.substr(ixRC, substrLen); }
                        else if (sType == L"Scr") { sScriptPolicy = sPolicyXml.substr(ixRC, substrLen); }
                        else if (sType == L"App") { sAppxPolicy = sPolicyXml.substr(ixRC, substrLen); }
                        else {
                            bParseOK = false;
                        }
                        // Move up to begin search for next rule collection.
                        ixRC += substrLen;
                    }
                }
            }
        }
    }

    return bParseOK;
}

/// <summary>
/// Given a RuleCollection XML, extract the separate rules into a RuleInfoCollection_t.
/// </summary>
/// <param name="sRuleCollectionXml">Input: the XML representing a rule collection</param>
/// <param name="dwEnforcementMode">Output: an integer corresponding to the collection's enforcement mode: 1 for Enforce, 0 for Audit</param>
/// <param name="rules">A collection of structures containing the XML for each rule and the GUID ID.
/// Note: returns rule info only if enforcement mode is Enforce or Audit; returns nothing if enforcement mode is "not configured".</param>
/// <returns>true if successful (even if no rules returned), false on any parsing error.</returns>
bool AppLockerXmlParser::ParseRuleCollection(const std::wstring& sRuleCollectionXml, unsigned long& dwEnforcementMode, RuleInfoCollection_t& rules)
{
    // Initialize output parameters
    dwEnforcementMode = 0;
    rules.clear();

    // Looking at attributes within the opening RuleCollection element - look for closing '>'
    size_t ixFirstGT = sRuleCollectionXml.find(L'>');
    if (std::wstring::npos == ixFirstGT)
        return false;

    std::wstring sRuleCollectionElement = sRuleCollectionXml.substr(0, ixFirstGT);
    // Find the EnforcementMode attribute within the RuleCollection element
    size_t ixEnforce = sRuleCollectionElement.find(L"EnforcementMode");
    // Error if not found
    if (std::wstring::npos == ixEnforce)
        return false;
    // Search for subsequent text for usual values:
    // OK if Not Configured, but quit - not returning rules in this case
    if (std::wstring::npos != sRuleCollectionElement.find(L"NotConfigured", ixEnforce))
        return true;
    // "Enabled" means Enforce mode
    if (std::wstring::npos != sRuleCollectionElement.find(L"Enabled", ixEnforce))
        dwEnforcementMode = 1;
    else if (std::wstring::npos != sRuleCollectionElement.find(L"AuditOnly", ixEnforce))
        dwEnforcementMode = 0;
    else
        return false;

    // Now separately go get the path, publisher, and hash rules and add them to "rules"
    if (!ParseRules(sRuleCollectionXml, L"FilePathRule", rules))
        return false;
    if (!ParseRules(sRuleCollectionXml, L"FilePublisherRule", rules))
        return false;
    if (!ParseRules(sRuleCollectionXml, L"FileHashRule", rules))
        return false;

    return true;
}

/// <summary>
/// Internal method used by ParseRuleCollection to extract path, publisher, and hash rules separately. 
/// </summary>
/// <param name="sRuleCollectionXml">Input: the XML representing a rule collection</param>
/// <param name="szRuleName">The XML element name for the rule type; e.g., "FilePathRule"</param>
/// <param name="rules">A collection of structures containing the XML for each rule and the GUID ID.</param>
/// <returns>true if successful, false on any parsing error.</returns>
bool AppLockerXmlParser::ParseRules(const std::wstring& sRuleCollectionXml, const wchar_t* szRuleName, RuleInfoCollection_t& rules)
{
    // Create strings representing text to find the opening and correspondng closing elements
    // for this rule.
    const std::wstring sRuleStartElem = std::wstring(L"<") + szRuleName;
    const std::wstring sRuleEndElem = std::wstring(L"</") + szRuleName;
    size_t ixRuleStart = 0;
    while (std::wstring::npos != ixRuleStart)
    {
        // Find the next instance of the rule
        ixRuleStart = sRuleCollectionXml.find(sRuleStartElem, ixRuleStart);
        if (std::wstring::npos != ixRuleStart)
        {
            // Find the next instance of the rule ending following this rule start
            size_t ixRuleEnd = sRuleCollectionXml.find(sRuleEndElem, ixRuleStart);
            if (std::wstring::npos == ixRuleEnd)
                return false;
            // Find the next closing '>' after the ending element text (could be whitespace between the end of the name and the '>')
            ixRuleEnd = sRuleCollectionXml.find(L">", ixRuleEnd);
            if (std::wstring::npos == ixRuleEnd)
                return false;
            // Create a new RuleInfo_t and get the substring representing the rule into .sXml.
            RuleInfo_t ruleInfo;
            ruleInfo.sXml = sRuleCollectionXml.substr(ixRuleStart, ixRuleEnd + 1 - ixRuleStart);
            // Find the "Id" attribute within this rule
            size_t ixId = ruleInfo.sXml.find(L"Id");
            if (std::wstring::npos == ixId)
                return false;
            // Get the text in between the next two dquotes -- that's the GUID.
            size_t ixDQ = ruleInfo.sXml.find(L'"', ixId);
            if (std::wstring::npos == ixDQ)
                return false;
            size_t ixGuidStart = ixDQ + 1;
            ixDQ = ruleInfo.sXml.find(L'"', ixGuidStart);
            if (std::wstring::npos == ixDQ)
                return false;
            ruleInfo.sGuid = ruleInfo.sXml.substr(ixGuidStart, ixDQ - ixGuidStart);
            // Add it to the collection.
            rules.push_back(ruleInfo);
            // Move up the index before searching for the next rule
            ixRuleStart += ruleInfo.sXml.length();
        }
    }

    return true;
}
