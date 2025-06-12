#include "pch.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "AppLockerXmlParser.h"
#include "AppLockerPolicy_CSP.h"
#pragma comment(lib, "wbemuuid.lib")


// ------------------------------------------------------------------------------------------
// String constants

const wchar_t* const szWmiNamespace     = L"root\\cimv2\\mdm\\dmmap";
// MDM classes (accessed through CSP interfaces)
const wchar_t* const szMdmClassExe      = L"MDM_AppLocker_ApplicationLaunchRestrictions01_EXE03";
const wchar_t* const szMdmClassDll      = L"MDM_AppLocker_DLL03";
const wchar_t* const szMdmClassMsi      = L"MDM_AppLocker_MSI03";
const wchar_t* const szMdmClassScript   = L"MDM_AppLocker_Script03";
const wchar_t* const szMdmClassAppx     = L"MDM_AppLocker_ApplicationLaunchRestrictions01_StoreApps03";
// MDM instance ID values (accessed through CSP interfaces)
const wchar_t* const szInstanceIdExe    = L"EXE";
const wchar_t* const szInstanceIdDll    = L"DLL";
const wchar_t* const szInstanceIdMsi    = L"MSI";
const wchar_t* const szInstanceIdScript = L"Script";
const wchar_t* const szInstanceIdAppx   = L"StoreApps";
// MDM parent ID base - add custom group name
const std::wstring sParentIdBase        = L"./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/";
// MDM properties for the MDM AppLocker classes
const wchar_t* const szPropParentId     = L"ParentID";
const wchar_t* const szPropInstanceId   = L"InstanceID";
const wchar_t* const szPropPolicy       = L"Policy";
const wchar_t* const szPropSysPath      = L"__PATH";

/// <summary>
/// The ParentId property for instances of these classes is 
/// "./Vendor/MSFT/AppLocker/ApplicationLaunchRestrictions/" plus a custom "Grouping" name. It's possible
/// to have multiple instances of the CSP/MDM AppLocker classes under different ParentId values.
/// Need to experiment and research what the effect is of having multiple rules defined.
/// In the meantime, putting all rules under a single ParentId value.
/// </summary>
const std::wstring sDefaultPolicyGroupName = L"AaronLocker";
const std::wstring sDefaultPolicyGroupParentId = sParentIdBase + sDefaultPolicyGroupName;

// ------------------------------------------------------------------------------------------

/// <summary>
/// Function for the AppLockerPolicy_t struct that returns a full AppLocker policy XML document.
/// The m_rulecollections member combines the policy's rule collections into a single string.
/// This function produces the full document with the XML declaration and the root
/// AppLockerPolicy element.
/// </summary>
std::wstring AppLockerPolicy_t::Policy() const
{
    std::wstringstream strPolicy;
    // Write the policy into the stream - start with the Enforce-mode policy.
    strPolicy
        << L"<?xml version=\"1.0\" encoding=\"utf-8\"?>" << std::endl
        << L"<" << AppLockerXmlParser::szPolicyRootTagname << L" Version=\"1\">" << std::endl
        << m_ruleCollections
        //<< std::endl
        << L"</" << AppLockerXmlParser::szPolicyRootTagname << L">"
        ;
    return strPolicy.str();
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Constructor. Initializes the object (if possible) for subsequent operations.
/// Call the StatusOK function to determine whether initialization was successful.
/// </summary>
AppLockerPolicy_CSP::AppLockerPolicy_CSP()
    :
    m_pLocator(NULL), m_pServices(NULL)
{
    Initialize();
}

// Destructor
AppLockerPolicy_CSP::~AppLockerPolicy_CSP()
{
    Uninitialize();
}

/// <summary>
/// Returns true if the COM and WMI interfaces initialized correctly.
/// E.g., initialization will fail if the necessary WMI namespace for
/// AppLocker management doesn't exist on the target system. (I think
/// it requires Win10...)
/// </summary>
/// <param name="psErrorInfo">Optional, output: string to get additional information about initialization failure</param>
/// <returns>true if initialization successful; false otherwise.</returns>
bool AppLockerPolicy_CSP::StatusOK(std::wstring* psErrorInfo /* = NULL*/) const
{
    if (NULL != m_pLocator && NULL != m_pServices)
    {
        // Good. Clear the error string if provided
        if (psErrorInfo)
            psErrorInfo->clear();
        return true;
    }
    else
    {
        // Not good. Convert initialization result into error text.
        if (psErrorInfo)
            *psErrorInfo = SysErrorMessage(m_hrInit);
        return false;
    }
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Retrieves the AppLocker policies configured through CSP/MDM, and the
/// names under which they are configured.
/// </summary>
/// <param name="policies">Output: collection through which results are returned</param>
/// <returns>true if successful (even if no policies found), false otherwise.</returns>
bool AppLockerPolicy_CSP::GetPolicies(AppLockerPolicies_t& policies)
{
    policies.clear();

    if (!StatusOK())
        return false;

    // Retrieve instances of each CSP/MDM AppLocker class in turn and retrieve policy info from them.
    GetPolicyProperties(szMdmClassExe, policies);
    GetPolicyProperties(szMdmClassDll, policies);
    GetPolicyProperties(szMdmClassMsi, policies);
    GetPolicyProperties(szMdmClassScript, policies);
    GetPolicyProperties(szMdmClassAppx, policies);

    return true;
}

/// <summary>
/// Sets AppLocker policy from the supplied AppLocker policy XML string.
/// </summary>
/// <param name="sPolicyXml">Input: AppLocker policy XML</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_CSP::SetPolicyFromString(const std::wstring& sPolicyXml, std::wstring& sErrorInfo)
{
    return SetPolicyFromString(sPolicyXml, sDefaultPolicyGroupName, sErrorInfo);
}

/// <summary>
/// Sets AppLocker policy from the supplied AppLocker policy XML UTF8-encoded file.
/// </summary>
/// <param name="sXmlPolicyFile">Input: path to UTF8-encoded file containing AppLocker policy XML.</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_CSP::SetPolicyFromFile(const std::wstring& sXmlPolicyFile, std::wstring& sErrorInfo)
{
    return SetPolicyFromFile(sXmlPolicyFile, sDefaultPolicyGroupName, sErrorInfo);
}

/// <summary>
/// Sets AppLocker policy from the supplied AppLocker policy XML string.
/// </summary>
/// <param name="sPolicyXml">Input: AppLocker policy XML</param>
/// <param name="sGroupName">Input: group name for the policy set; goes into the Parent ID</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_CSP::SetPolicyFromString(const std::wstring& sPolicyXml, const std::wstring& sGroupName, std::wstring& sErrorInfo)
{
    std::wstring sGroupParentId;
    if (sGroupName.length() > 0)
    {
        sGroupParentId = sParentIdBase + sGroupName;
    }
    else
    {
        sGroupParentId = sDefaultPolicyGroupParentId;
    }

    if (!StatusOK())
    {
        sErrorInfo = L"Can't access CSP/MDM.";
        return false;
    }

    // Break out each rule collection separately.
    std::wstring sExePolicy, sDllPolicy, sMsiPolicy, sScriptPolicy, sAppxPolicy;
    if (!AppLockerXmlParser::ParseRuleCollections(sPolicyXml, sExePolicy, sDllPolicy, sMsiPolicy, sScriptPolicy, sAppxPolicy))
    {
        sErrorInfo = L"Invalid policy XML";
        return false;
    }

    // Create an CSP/MDM AppLocker policy class instance for each rule collection.
    bool retval = false;
    sErrorInfo.clear();
    std::wstringstream strError;
    HRESULT hr;
    if (
        SUCCEEDED(hr = CreatePolicyInstance(szMdmClassExe, sGroupParentId, szInstanceIdExe, sExePolicy, strError)) &&
        SUCCEEDED(hr = CreatePolicyInstance(szMdmClassDll, sGroupParentId, szInstanceIdDll, sDllPolicy, strError)) &&
        SUCCEEDED(hr = CreatePolicyInstance(szMdmClassMsi, sGroupParentId, szInstanceIdMsi, sMsiPolicy, strError)) &&
        SUCCEEDED(hr = CreatePolicyInstance(szMdmClassScript, sGroupParentId, szInstanceIdScript, sScriptPolicy, strError)) &&
        SUCCEEDED(hr = CreatePolicyInstance(szMdmClassAppx, sGroupParentId, szInstanceIdAppx, sAppxPolicy, strError))
        )
    {
        retval = true;
    }
    else
    {
        //WBEM_E_FAILED;
        sErrorInfo = L"Failure creating CSP/MDM policy instances: ";
        sErrorInfo += SysErrorMessage(hr) + L"; ";
        sErrorInfo += strError.str();
    }
    return retval;
}

/// <summary>
/// Sets AppLocker policy from the supplied AppLocker policy XML UTF8-encoded file.
/// </summary>
/// <param name="sXmlPolicyFile">Input: path to UTF8-encoded file containing AppLocker policy XML.</param>
/// <param name="sGroupName">Input: group name for the policy set; goes into the Parent ID</param>
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_CSP::SetPolicyFromFile(const std::wstring& sXmlPolicyFile, const std::wstring& sGroupName, std::wstring& sErrorInfo)
{
    if (!StatusOK())
    {
        sErrorInfo = L"Can't access CSP/MDM.";
        return false;
    }

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
    return SetPolicyFromString(sPolicy, sGroupName, sErrorInfo);
}


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
/// <param name="sErrorInfo">Output: error information</param>
/// <returns>true if successful, false otherwise</returns>
bool AppLockerPolicy_CSP::DeleteAllPolicies(bool& bPoliciesDeleted, std::wstring& sErrorInfo)
{
    bPoliciesDeleted = false;

    if (!StatusOK())
        return false;

    // Delete all instances of each CSP/MDM AppLocker class in turn.
    std::wstringstream strErrorInfo;
    HRESULT hr1 = DeleteAllPolicyInstances(szMdmClassExe, bPoliciesDeleted, strErrorInfo);
    HRESULT hr2 = DeleteAllPolicyInstances(szMdmClassDll, bPoliciesDeleted, strErrorInfo);
    HRESULT hr3 = DeleteAllPolicyInstances(szMdmClassMsi, bPoliciesDeleted, strErrorInfo);
    HRESULT hr4 = DeleteAllPolicyInstances(szMdmClassScript, bPoliciesDeleted, strErrorInfo);
    HRESULT hr5 = DeleteAllPolicyInstances(szMdmClassAppx, bPoliciesDeleted, strErrorInfo);
    if (FAILED(hr1))
        strErrorInfo << SysErrorMessage(hr1) << std::endl;
    if (FAILED(hr2))
        strErrorInfo << SysErrorMessage(hr2) << std::endl;
    if (FAILED(hr3))
        strErrorInfo << SysErrorMessage(hr3) << std::endl;
    if (FAILED(hr4))
        strErrorInfo << SysErrorMessage(hr4) << std::endl;
    if (FAILED(hr5))
        strErrorInfo << SysErrorMessage(hr5) << std::endl;
    sErrorInfo = strErrorInfo.str();
    return true;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Local helper function to retrieve a string property from an object instance.
/// </summary>
/// <param name="pClassObject">Input: Pointer to the class instance</param>
/// <param name="szProperty">Input: Name of the property to retrieve</param>
/// <param name="sValue">Output: retrieved value</param>
/// <returns>true if successful, false otherwise</returns>
static bool GetStringProperty(IWbemClassObject* pClassObject, const wchar_t* szProperty, std::wstring& sValue)
{
    bool retval = false;
    VARIANT vtProp;
    VariantInit(&vtProp);
    HRESULT hr = pClassObject->Get(szProperty, 0, &vtProp, NULL, NULL);
    // Verify that it's a string value
    if (SUCCEEDED(hr) && VT_BSTR == vtProp.vt)
    {
        sValue = vtProp.bstrVal;
        retval = true;
    }
    // VariantClear necessary to release any memory allocated by the Get operation.
    VariantClear(&vtProp);
    return retval;
}

/// <summary>
/// Helper function to retrieve AppLocker policies for a specific CSP/MDM AppLocker class.
/// </summary>
/// <param name="szMdmClass">Input: Name of the MDM AppLocker class to retrieve instances and read data from; e.g., szMdmClassExe</param>
/// <param name="policies">Output: collection to append retrieved data to</param>
void AppLockerPolicy_CSP::GetPolicyProperties(const wchar_t* szMdmClass, AppLockerPolicies_t& policies)
{
    // Check just in case. No null-pointer dereferences here!
    if (NULL == m_pServices)
        return;

    // WQL query to retrieve all instances of the input class
    std::wstring sQuery = std::wstring(L"SELECT * FROM ") + szMdmClass;
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = m_pServices->ExecQuery(
        bstr_t(L"WQL"),
        bstr_t(sQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY, // | WBEM_FLAG_USE_AMENDED_QUALIFIERS,
        NULL,
        &pEnumerator);
    if (FAILED(hr) || (NULL == pEnumerator))
        return;

    IWbemClassObject* pClassObject;
    ULONG uReturn = 0;

    // Retrieve and process class instances one at a time until no more to retrieve
    do {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        if (uReturn > 0)
        {
            // Get the ParentId and Policy properties from this class instance.
            // The last part of the ParentId is the custom grouping name which will be assigned to sPolicyName;
            // The Policy property contains the rule collection XML for the class instance.
            std::wstring sParentId, sPolicy, sPolicyName;
            if (GetStringProperty(pClassObject, szPropParentId, sParentId))
            {
                if (GetStringProperty(pClassObject, szPropPolicy, sPolicy))
                {
                    // Split the ParentId on '/' and get the substring following the last one - that's the policy name
                    std::vector<std::wstring> sParentParts;
                    SplitStringToVector(sParentId, L'/', sParentParts);
                    sPolicyName = sParentParts[sParentParts.size() - 1];
                    // Does the collection already have anything under this policy name?
                    AppLockerPolicies_t::iterator pPolicy = policies.find(sPolicyName);
                    if (policies.end() == pPolicy)
                    {
                        // No existing items under this name. Create a new one
                        AppLockerPolicy_t policy;
                        policy.m_ruleCollections = sPolicy + L"\n";
                        policies[sPolicyName] = policy;
                    }
                    else
                    {
                        // Add to the existing rule collections string.
                        pPolicy->second.m_ruleCollections += (sPolicy + L"\n");
                    }
                }
            }
            pClassObject->Release();
        }
    } while (0 != uReturn);

    pEnumerator->Release();
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Delete all instances of the specified class.
/// </summary>
/// <param name="szMdmClass">Input: Name of the MDM AppLocker class to delete instances of; e.g., szMdmClassExe</param>
/// <param name="strErrorInfo">Output: error information</param>
/// <returns>HRESULT value from last operation performed.</returns>
HRESULT AppLockerPolicy_CSP::DeleteAllPolicyInstances(const wchar_t* szMdmClass, bool& bPoliciesDeleted, std::wstringstream& strErrorInfo)
{
    // As it turns out, it's kinda hard to get any useful information for failures here.
    UNREFERENCED_PARAMETER(strErrorInfo);

    // No null-pointer dereferences please!
    if (NULL == m_pServices)
        return E_POINTER;

    // WQL query to retrieve all instances of the input class
    std::wstring sQuery = std::wstring(L"SELECT * FROM ") + szMdmClass;
    IEnumWbemClassObject* pEnumerator = NULL;
    HRESULT hr = m_pServices->ExecQuery(
        bstr_t(L"WQL"),
        bstr_t(sQuery.c_str()),
        WBEM_FLAG_FORWARD_ONLY, // | WBEM_FLAG_USE_AMENDED_QUALIFIERS,
        NULL,
        &pEnumerator);
    //strErrorInfo << L"m_pServices->ExecQuery " << HEX(hr, 8, true, true) << L"; ";
    if (FAILED(hr) || (NULL == pEnumerator))
        return hr;

    IWbemClassObject* pClassObject;
    ULONG uReturn = 0;

    do {
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
        //strErrorInfo << L"pEnumerator->Next " << HEX(hr, 8, true, true) << L", uReturn " << uReturn << L"; ";
        if (uReturn > 0)
        {
            //// Diagnostic info
            //std::wstring sInfo;
            //strErrorInfo << L"-------------------" << std::endl;
            //if (GetStringProperty(pClassObject, szPropInstanceId, sInfo))
            //    strErrorInfo << szPropInstanceId << L": " << sInfo << std::endl;
            //if (GetStringProperty(pClassObject, szPropParentId, sInfo))
            //    strErrorInfo << szPropParentId << L": " << sInfo << std::endl;
            //if (GetStringProperty(pClassObject, szPropPolicy, sInfo))
            //    strErrorInfo << szPropPolicy << L": " << sInfo << std::endl;

            std::wstring sInstancePath;
            if (GetStringProperty(pClassObject, szPropSysPath, sInstancePath))
            {
                _bstr_t bstrInstancePath(sInstancePath.c_str());
                hr = m_pServices->DeleteInstance(bstrInstancePath, 0, NULL, NULL);
                // strErrorInfo << L"m_pServices->DeleteInstance " << HEX(hr, 8, true, true) << L": " << sInstancePath << std::endl;
                if (SUCCEEDED(hr))
                {
                    bPoliciesDeleted = true;
                }
            }
            pClassObject->Release();
        }
    } while (0 != uReturn);

    pEnumerator->Release();

    return S_OK;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Create an CSP/MDM AppLocker class instance of a specified class and corresponding instance ID, with
/// data representing an AppLocker rule collection.
/// </summary>
/// <param name="szMdmClass">Input: name of class instance to create; e.g., szMdmClassDll ("MDM_AppLocker_DLL03")</param>
/// <param name="sGroupParentId">Input: parent ID string</param>
/// <param name="szInstanceId">Input: instance ID string; e.g., szInstanceIdDll ("DLL")</param>
/// <param name="sPolicyPiece">Input: rule collection XML</param>
/// <param name="strErrorInfo">Output: error information</param>
/// <returns>HRESULT of the last operation performed</returns>
HRESULT AppLockerPolicy_CSP::CreatePolicyInstance(const wchar_t* szMdmClass, const std::wstring& sGroupParentId, const wchar_t* szInstanceId, const std::wstring& sPolicyPiece, std::wstringstream& strErrorInfo)
{
    IWbemClassObject* pNewInstance = 0;
    IWbemClassObject* pClassDefinition = 0;

    // Retrieve the class definition.
    HRESULT hr = m_pServices->GetObject(_bstr_t(szMdmClass), 0, NULL, &pClassDefinition, NULL);
    if (FAILED(hr))
    {
        strErrorInfo << L"Can't get class definition for " << szMdmClass << L" " << szInstanceId;
        return hr;
    }

    // Create a new instance of the class.
    hr = pClassDefinition->SpawnInstance(0, &pNewInstance);
    pClassDefinition->Release();  // Don't need the class any more
    pClassDefinition = NULL;
    if (FAILED(hr))
    {
        strErrorInfo << L"Can't spawn new instance of " << szMdmClass << L" " << szInstanceId;
        return hr;
    }

    // Create objects that can be passed to COM interfaces with property values to put into the new object
    _bstr_t bstrParentID(sGroupParentId.c_str());
    _bstr_t bstrInstanceID(szInstanceId);
    // The XML policy needs to be encoded (e.g., "<" becomes "&lt;")
    std::wstring sPolicyEncoded = EncodeForXml(sPolicyPiece.c_str());
    _bstr_t bstrPolicy(sPolicyEncoded.c_str());
    // Put these BSTR values into COM Variant objects.
    VARIANT vParentId, vInstanceId, vPolicy;
    vParentId.vt = vInstanceId.vt = vPolicy.vt = VT_BSTR;
    vParentId.bstrVal = bstrParentID;
    vInstanceId.bstrVal = bstrInstanceID;
    vPolicy.bstrVal = bstrPolicy;

    // Set the ParentId, InstanceId, and Policy values into the new instance.
    if (
        SUCCEEDED(hr = pNewInstance->Put(szPropParentId, 0, &vParentId, 0)) &&
        SUCCEEDED(hr = pNewInstance->Put(szPropInstanceId, 0, &vInstanceId, 0)) &&
        SUCCEEDED(hr = pNewInstance->Put(szPropPolicy, 0, &vPolicy, 0))
        )
    {
        // Other properties acquire the 'default' value specified
        // in the class definition unless otherwise modified here.
        // Write the instance to WMI. 
        hr = m_pServices->PutInstance(pNewInstance, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
        if (FAILED(hr))
        {
            strErrorInfo << L"Can't create/update instance of " << szMdmClass << L" " << szInstanceId;
        }
    }
    else
    {
        strErrorInfo << L"Can't apply property to new class instance of " << szMdmClass << L" " << szInstanceId;
    }
    pNewInstance->Release();
    return hr;
}

// ------------------------------------------------------------------------------------------

/// <summary>
/// Initialization of COM/WMI interfaces. Uninitializes on failure.
/// </summary>
/// <returns>true if successful, false otherwise.</returns>
bool AppLockerPolicy_CSP::Initialize()
{
    bool retval = false;
    // Initialize COM. Doesn't matter whether apartment-threaded or multithreaded.
    m_hrInit = CoInitAnyThreaded();
    if (SUCCEEDED(m_hrInit))
    {
        m_hrInit = CoInitializeSecurity(
            NULL,
            -1,      // COM negotiates service                  
            NULL,    // Authentication services
            NULL,    // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
            RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
            NULL,             // Authentication info 
            EOAC_NONE,        // Additional capabilities
            NULL              // Reserved
        );
        if (SUCCEEDED(m_hrInit))
        {
            // WMI
            m_hrInit = CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&m_pLocator);
            if (SUCCEEDED(m_hrInit))
            {
                // Connect to the WMI namespace where the AppLocker classes are defined.
                m_hrInit = m_pLocator->ConnectServer(
                    _bstr_t(szWmiNamespace), // WMI namespace
                    NULL,                    // User name
                    NULL,                    // User password
                    0,                       // Locale
                    NULL,                    // Security flags                 
                    0,                       // Authority       
                    0,                       // Context object
                    &m_pServices             // IWbemServices proxy
                );
                if (SUCCEEDED(m_hrInit))
                {
                    m_hrInit = CoSetProxyBlanket(
                        m_pServices,                  // the proxy to set
                        RPC_C_AUTHN_WINNT,            // authentication service
                        RPC_C_AUTHZ_NONE,             // authorization service
                        NULL,                         // Server principal name
                        RPC_C_AUTHN_LEVEL_CALL,       // authentication level
                        RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
                        NULL,                         // client identity 
                        EOAC_NONE                     // proxy capabilities     
                    );
                    if (SUCCEEDED(m_hrInit))
                    {
                        // If we get here, we're good.
                        retval = true;
                    }
                }
            }
        }
    }

    if (!retval)
    {
        // If we didn't make it all the way through, clean up what we did.
        Uninitialize();
    }

    return retval;
}

/// <summary>
/// Release any COM/WMI that was allocated
/// </summary>
void AppLockerPolicy_CSP::Uninitialize()
{
    if (m_pServices)
        m_pServices->Release();
    m_pServices = NULL;
    if (m_pLocator)
        m_pLocator->Release();
    m_pLocator = NULL;
    CoUninitialize();
}

// ------------------------------------------------------------------------------------------


