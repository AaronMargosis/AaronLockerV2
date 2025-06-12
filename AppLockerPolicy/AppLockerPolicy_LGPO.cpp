#include "pch.h"

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "AppLockerXmlParser.h"
#include "AppLockerPolicy_LGPO.h"

// ------------------------------------------------------------------------------------------
// String constants
// 

static const std::wstring sParseErrorText = L"Unable to parse AppLocker policy XML";
static const std::wstring sKeyPathBase = L"Software\\Policies\\Microsoft\\Windows\\SrpV2";
static const wchar_t* const szEnforcementMode = L"EnforcementMode";
static const wchar_t* const szAllowWindows = L"AllowWindows";
static const wchar_t* const szValue = L"Value";
// Rule collections
static const wchar_t* const szExe = L"Exe";
static const wchar_t* const szDll = L"Dll";
static const wchar_t* const szMsi = L"Msi";
static const wchar_t* const szScript = L"Script";
static const wchar_t* const szAppx = L"Appx";


// ------------------------------------------------------------------------------------------

// Declare local helper functions (defined later in this file)
static bool IngestRuleCollection(
    HKEY hGpoKey,
    const std::wstring& sKeyName,
    std::wstringstream& strPolicyXml,
    std::wstring& sErrorInfo);

static bool ApplyRuleCollection(
    HKEY hGpoKey,
    const std::wstring& sKeyName,
    const std::wstring& sRuleCollectionXml,
    std::wstring& sErrorInfo);

// ------------------------------------------------------------------------------------------

/// <summary>
/// Internal function that retrieves AppLocker XML policy from the registry. Can be used to
/// get effective policy from HKLM policies, or from an LGPO processor that creates a
/// local GPO replica in a temporary subkey under the caller's HKCU.
/// </summary>
/// <param name="hKey">Input: base key above sKeyPathBase to inspect - typically HKLM or a LocalGPO ComputerKey</param>
/// <param name="sAppLockerPolicyXml">Output: AppLocker policy XML</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
static bool GetPolicy(
    HKEY hKey,
    std::wstring& sAppLockerPolicyXml,
    std::wstring& sErrorInfo)
{
    // Initialize output parameters
    sAppLockerPolicyXml.clear();
    sErrorInfo.clear();

    // Stream text into strPolicy to create the AppLocker policy XML document,
    // starting with XML declaration and root element.
    std::wstringstream strPolicy;
    strPolicy
        << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>" << std::endl
        << L"<" << AppLockerXmlParser::szPolicyRootTagname << L" Version=\"1\">" << std::endl
        ;

    // Get rule collection information one rule collection at a time; streaming each into strPolicy.
    if (
        !IngestRuleCollection(hKey, szExe, strPolicy, sErrorInfo) ||
        !IngestRuleCollection(hKey, szDll, strPolicy, sErrorInfo) ||
        !IngestRuleCollection(hKey, szMsi, strPolicy, sErrorInfo) ||
        !IngestRuleCollection(hKey, szScript, strPolicy, sErrorInfo) ||
        !IngestRuleCollection(hKey, szAppx, strPolicy, sErrorInfo)
        )
    {
        // On failure, sErrorInfo is the only output parameter that receives data.
        return false;
    }

    // Close the root element.
    strPolicy
        << L"</" << AppLockerXmlParser::szPolicyRootTagname << L">"
        ;

    // Write result to output parameter
    sAppLockerPolicyXml = strPolicy.str();

    return true;
}


/// <summary>
/// Retrieve XML document representing LGPO-configured AppLocker policy.
/// Does not require administrative rights.
/// </summary>
/// <param name="sAppLockerPolicyXml">Output: AppLocker policy XML</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_LGPO::GetLocalPolicy(std::wstring& sAppLockerPolicyXml, std::wstring& sErrorInfo)
{
    // Create LocalGPO object with read-only access (doesn't require administrative rights)
    LocalGPO lgpo;
    HRESULT hr = lgpo.Init(true);
    if (FAILED(hr))
    {
        sErrorInfo = std::wstring(L"Could not initialize Local GPO: ") + SysErrorMessage(hr);
        return false;
    }

    return GetPolicy(lgpo.ComputerKey(), sAppLockerPolicyXml, sErrorInfo);
}


/// <summary>
/// Retrieve XML document representing effective GPO-configured AppLocker policy,
/// based on evidence in the registry. Effective AppLocker policy can be the merged 
/// results from Active Directory policies and local GPO.
/// Does not require administrative rights.
/// </summary>
/// <param name="sAppLockerPolicyXml">Output: AppLocker policy XML</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_LGPO::GetEffectivePolicy(std::wstring& sAppLockerPolicyXml, std::wstring& sErrorInfo)
{
    return GetPolicy(HKEY_LOCAL_MACHINE, sAppLockerPolicyXml, sErrorInfo);
}


/// <summary>
/// Clears (deletes) any AppLocker policy configured through LGPO.
/// Requires administrative rights.
/// </summary>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_LGPO::ClearPolicy(std::wstring& sErrorInfo)
{
    // Create LocalGPO object, delete the stuff under ComputerKey + sKeyPathBase.
    sErrorInfo.clear();

    // Local GPO object with read/write access
    LocalGPO lgpo;
    HRESULT hr = lgpo.Init();
    if (FAILED(hr))
    {
        sErrorInfo = std::wstring(L"Could not initialize Local GPO: ") + SysErrorMessage(hr);
        return false;
    }

    // Delete the top key where AppLocker policy is placed into the registry and everything below it.
    LSTATUS regStatus = RegDeleteTreeW(lgpo.ComputerKey(), sKeyPathBase.c_str());

    // If registry key not found, there's no AppLocker policy in Local GPO. Still return success.
    if (ERROR_FILE_NOT_FOUND == regStatus)
    {
        sErrorInfo = L"No AppLocker policy found in Local GPO.";
        return true;
    }

    // Anything else goes wrong is an error.
    if (ERROR_SUCCESS != regStatus)
    {
        sErrorInfo = std::wstring(L"Registry error deleting Local GPO content: ") + SysErrorMessage(regStatus);
        return false;
    }

    // Save the results back into local GPO.
    hr = lgpo.Save();
    if (FAILED(hr))
    {
        sErrorInfo = std::wstring(L"Could not save changes to Local GPO: ") + SysErrorMessage(hr);
        return false;
    }
    return true;
}

/// <summary>
/// Sets AppLocker policy from the supplied AppLocker policy XML string.
/// </summary>
/// <param name="sPolicyXml">Input: AppLocker policy XML</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_LGPO::SetPolicyFromString(const std::wstring& sPolicyXml, std::wstring& sErrorInfo)
{
    // Start by removing any existing AppLocker policy from LGPO.
    // The input policy will be the complete policy, with no artifacts of previous policy left behind.
    if (!ClearPolicy(sErrorInfo))
    {
        return false;
    }

    // Don't bring the error info forward from successful ClearPolicy call.
    sErrorInfo.clear();

    // Local GPO object with read/write access
    LocalGPO lgpo;
    HRESULT hr = lgpo.Init();
    if (FAILED(hr))
    {
        sErrorInfo = std::wstring(L"Could not initialize Local GPO: ") + SysErrorMessage(hr);
        return false;
    }

    // Break out each rule collection separately.
    std::wstring sExePolicy, sDllPolicy, sMsiPolicy, sScriptPolicy, sAppxPolicy;
    if (!AppLockerXmlParser::ParseRuleCollections(sPolicyXml, sExePolicy, sDllPolicy, sMsiPolicy, sScriptPolicy, sAppxPolicy))
    {
        sErrorInfo = sParseErrorText;
        return false;
    }

    HKEY hKey = lgpo.ComputerKey();

    // Create policy for each rule collection in turn
    if (
        !ApplyRuleCollection(hKey, szExe, sExePolicy, sErrorInfo) ||
        !ApplyRuleCollection(hKey, szDll, sDllPolicy, sErrorInfo) ||
        !ApplyRuleCollection(hKey, szMsi, sMsiPolicy, sErrorInfo) ||
        !ApplyRuleCollection(hKey, szScript, sScriptPolicy, sErrorInfo) ||
        !ApplyRuleCollection(hKey, szAppx, sAppxPolicy, sErrorInfo)
        )
    {
        return false;
    }

    // Save the results back into local GPO.
    hr = lgpo.Save();
    if (FAILED(hr))
    {
        sErrorInfo = std::wstring(L"Could not save Local GPO: ") + SysErrorMessage(hr);
        return false;
    }
    return true;
}

/// <summary>
/// Sets AppLocker policy from the supplied AppLocker policy XML UTF8-encoded file.
/// </summary>
/// <param name="sXmlPolicyFile">Input: path to UTF8-encoded file containing AppLocker policy XML.</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_LGPO::SetPolicyFromFile(const std::wstring& sXmlPolicyFile, std::wstring& sErrorInfo)
{
    std::wifstream fs;
    if (!Utf8FileUtility::OpenForReadingWithLocale(fs, sXmlPolicyFile.c_str()))
    {
        sErrorInfo = L"Error - cannot open file ";
        sErrorInfo += sXmlPolicyFile;
        return false;
    }

    sErrorInfo.clear();

    // Read the full content of the file into sPolicy
    std::wstring sPolicy((std::istreambuf_iterator<wchar_t>(fs)), (std::istreambuf_iterator<wchar_t>()));
    // Close the file
    fs.close();

    // Set the policy from the retrieved data
    return SetPolicyFromString(sPolicy, sErrorInfo);
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Local helper function that converts pieces of AppLocker representation in local GPO registry into XML
/// </summary>
/// <param name="hGpoKey">Input: registry key temporarily holding machine local group policy</param>
/// <param name="sKeyName">Input: AppLocker policy subkey name to read information from</param>
/// <param name="strPolicyXml">Output: function appends XML fragments to this stream</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise.</returns>
static bool IngestRuleCollection(
    HKEY hGpoKey,
    const std::wstring& sKeyName,
    std::wstringstream& strPolicyXml,
    std::wstring& sErrorInfo)
{
    // No real errors possible - if the data is not there, there's just no policy
    UNREFERENCED_PARAMETER(sErrorInfo);

    // Full registry path (relative under GPO key) to read data from
    const std::wstring sKeyPath = sKeyPathBase + L"\\" + sKeyName;

    HKEY hSubkey = NULL;
    LSTATUS regStatus;
    regStatus = RegOpenKeyExW(hGpoKey, sKeyPath.c_str(), 0, KEY_READ, &hSubkey);
    if (ERROR_SUCCESS == regStatus)
    {
        // Key exists for this rule collection, so start creating a RuleCollection element and child elements.
        strPolicyXml << L"<RuleCollection Type=\"" << sKeyName << L"\" EnforcementMode=\"";

        // Absence of EnforcementMode value means "NotConfigured"; otherwise AuditOnly or Enabled. (Invalid value treated here as NotConfigured.)
        DWORD dwType = 0, dwEnforcementMode = 0, cbEnforcementMode = sizeof(dwEnforcementMode);
        regStatus = RegQueryValueExW(hSubkey, szEnforcementMode, 0, &dwType, (BYTE*)&dwEnforcementMode, &cbEnforcementMode);
        const wchar_t* szMode = L"NotConfigured";
        if (ERROR_SUCCESS == regStatus)
        {
            switch (dwEnforcementMode)
            {
            case 0:
                szMode = L"AuditOnly";
                break;
            case 1:
                szMode = L"Enabled";
                break;
            }
        }
        strPolicyXml << szMode << L"\">" << std::endl;

        // Specific rules are in GUID-named subkeys. Iterate through the subkeys
        DWORD dwIx = 0;
        regStatus = ERROR_SUCCESS;
        while (ERROR_SUCCESS == regStatus)
        {
            wchar_t szGuidSubkeyName[64] = { 0 };
            DWORD cchGuidSubkeyName = sizeof(szGuidSubkeyName) / sizeof(szGuidSubkeyName[0]);
            regStatus = RegEnumKeyExW(hSubkey, dwIx++, szGuidSubkeyName, &cchGuidSubkeyName, NULL, NULL, NULL, NULL);
            if (ERROR_SUCCESS == regStatus)
            {
                // And open each of them...
                HKEY hRuleKey = NULL;
                regStatus = RegOpenKeyExW(hSubkey, szGuidSubkeyName, 0, KEY_READ, &hRuleKey);
                if (ERROR_SUCCESS == regStatus)
                {
                    // And read the "Value" value, containing the XML for a specific rule.
                    DWORD cbData = 0;
                    regStatus = RegQueryValueExW(hRuleKey, szValue, NULL, &dwType, NULL, &cbData);
                    if ((ERROR_SUCCESS == regStatus || ERROR_MORE_DATA == regStatus) && cbData > 0 && REG_SZ == dwType)
                    {
                        byte* pBuffer = new byte[cbData];
                        regStatus = RegQueryValueExW(hRuleKey, szValue, NULL, &dwType, pBuffer, &cbData);
                        if (ERROR_SUCCESS == regStatus)
                        {
                            // And append it to the output stream
                            strPolicyXml << (const wchar_t*)pBuffer; // << std::endl;
                        }
                        delete[] pBuffer;
                    }
                    RegCloseKey(hRuleKey);
                }
            }
        }
        // Close the RuleCollection element.
        strPolicyXml << L"</RuleCollection>" << std::endl;

        RegCloseKey(hSubkey);
    }

    return true;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Local helper function for converting AppLocker policy XML for a rule collection to registry representation for local GPO.
/// </summary>
/// <param name="hGpoKey">Input: registry key temporarily holding machine local group policy</param>
/// <param name="sKeyName">Input: rule-collection-specific subkey name to write information into (e.g., "Exe")</param>
/// <param name="sRuleCollectionXml">Input: XML fragment for one rule collection</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
static bool ApplyRuleCollection(
    HKEY hGpoKey,
    const std::wstring& sKeyName,
    const std::wstring& sRuleCollectionXml,
    std::wstring& sErrorInfo)
{
    // If input rule collection XML is empty, do nothing
    if (0 == sRuleCollectionXml.length())
        return true;

    // Parse the rule collection XML into the pieces we need
    RuleInfoCollection_t rules;
    DWORD dwEnforcementMode = 0;
    if (!AppLockerXmlParser::ParseRuleCollection(sRuleCollectionXml, dwEnforcementMode, rules))
    {
        sErrorInfo = sParseErrorText;
        return false;
    }

    // Full registry path (relative under GPO key) to write data into
    const std::wstring sKeyPath = sKeyPathBase + L"\\" + sKeyName;

    // Create the subkey for this rule collection
    HKEY hSubkey = NULL;
    DWORD dwDisposition = 0;
    LSTATUS regStatus;
    regStatus = RegCreateKeyExW(hGpoKey, sKeyPath.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &hSubkey, &dwDisposition);
    if (ERROR_SUCCESS == regStatus)
    {
        // Write the EnforcementMode value into this key
        regStatus = RegSetValueExW(hSubkey, szEnforcementMode, 0, REG_DWORD, (const BYTE*)&dwEnforcementMode, sizeof(dwEnforcementMode));
        if (ERROR_SUCCESS == regStatus)
        {
            // Write the "AllowWindows" value into this key - set to 0
            DWORD zero = 0;
            regStatus = RegSetValueExW(hSubkey, szAllowWindows, 0, REG_DWORD, (const BYTE*)&zero, sizeof(zero));
            if (ERROR_SUCCESS == regStatus)
            {
                // Go through each rule in the rule collection one by one...
                for (
                    RuleInfoCollection_t::const_iterator iterRules = rules.begin();
                    ERROR_SUCCESS == regStatus && iterRules != rules.end();
                    ++iterRules
                    )
                {
                    // Create the GUID subkey for this rule...
                    HKEY hRuleKey = NULL;
                    regStatus = RegCreateKeyExW(hSubkey, iterRules->sGuid.c_str(), 0, NULL, 0, KEY_SET_VALUE, NULL, &hRuleKey, &dwDisposition);
                    if (ERROR_SUCCESS == regStatus)
                    {
                        // ... and create the "Value" value and set it to the rule's XML
                        DWORD cbRuleText = (DWORD)((iterRules->sXml.length() + 1) * sizeof(wchar_t));
                        regStatus = RegSetValueExW(hRuleKey, szValue, 0, REG_SZ, (const BYTE*)iterRules->sXml.c_str(), cbRuleText);
                        RegCloseKey(hRuleKey);
                    }
                }
            }
        }
        RegCloseKey(hSubkey);
    }

    if (ERROR_SUCCESS != regStatus)
    {
        sErrorInfo = std::wstring(L"Registry write error while creating GPO content: ") + SysErrorMessage(regStatus);
        return false;
    }
    return true;
}

