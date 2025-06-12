#include "ShellLinkInfo.h"
#include "Wow64FsRedirection.h"
#include "CoInit.h"
#include "../AaronLocker_CommonUtils/FileSystemUtils.h"
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include <ObjIdl.h>
#include <ShlObj.h>


static const int cchTempBufferSize = INFOTIPSIZE;

ShellLinkInfo::ShellLinkInfo()
	: m_pShellLink(NULL), m_pPersistFile(NULL)
{
    // Large buffer for string data, not on the stack.
    m_pszTempBuffer = new wchar_t[cchTempBufferSize];

    // Initialize COM. Doesn't matter whether apartment-threaded or multithreaded.
    HRESULT hr = CoInitAnyThreaded();
    // If COM initialization failed, we can't proceeed
    m_bComInitialized = SUCCEEDED(hr);
    if (m_bComInitialized)
    {
        // Initialize COM pointers.
        hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&m_pShellLink);
        if (SUCCEEDED(hr))
        {
            hr = m_pShellLink->QueryInterface(IID_IPersistFile, (void**)&m_pPersistFile);
        }
    }
}

ShellLinkInfo::~ShellLinkInfo()
{
    delete[] m_pszTempBuffer;
    if (m_pPersistFile)
        m_pPersistFile->Release();
    if (m_pShellLink)
        m_pShellLink->Release();
    if (m_bComInitialized)
        CoUninitialize();
}

bool ShellLinkInfo::Ready() const
{
    // If this is non-NULL, the other things must all be ready as well.
    return NULL != m_pPersistFile;
}


/// <summary>
/// Because of an "interesting" feature in 64-bit Windows, shell links that point to locations under "Program Files" 
/// can return paths pointing to "Program Files (x86)" when queried by a 32-bit process.
/// The workaround (supplied to Aaron Margosis in an email from Microsoft's Raymond Chen) is to rewrite the
/// link into a temporary memory buffer with the SLDF_DISABLE_KNOWNFOLDER_RELATIVE_TRACKING flag set, and then
/// load that version of the link.
/// </summary>
/// <param name="pShellLink">Pointer to shell link interface to update</param>
/// <returns>HRESULT of last update operation performed</returns>
static HRESULT UpdateShellLink(IShellLink* pShellLink)
{
    IShellLinkDataList* pShellLinkDataList = NULL;
    IPersistStream* pPersistStream = NULL;
    IStream* pStream = NULL;
    DWORD dwDataListFlags = 0;
    HRESULT hr;

    if (FAILED(hr = pShellLink->QueryInterface(IID_IShellLinkDataList, (void**)&pShellLinkDataList)))
        goto UpdateShellLink_Done;
    if (FAILED(hr = pShellLinkDataList->GetFlags(&dwDataListFlags)))
        goto UpdateShellLink_Done;
    dwDataListFlags |= SLDF_DISABLE_KNOWNFOLDER_RELATIVE_TRACKING;
    if (FAILED(hr = pShellLinkDataList->SetFlags(dwDataListFlags)))
        goto UpdateShellLink_Done;
    if (FAILED(hr = pShellLink->QueryInterface(IID_IPersistStream, (void**)&pPersistStream)))
        goto UpdateShellLink_Done;
    if (FAILED(hr = CreateStreamOnHGlobal(NULL, TRUE, &pStream)))
        goto UpdateShellLink_Done;
    if (FAILED(hr = pPersistStream->Save(pStream, TRUE)))
        goto UpdateShellLink_Done;
    if (FAILED(hr = pStream->Seek({ 0 }, 0, NULL)))
        goto UpdateShellLink_Done;
    if (FAILED(hr = pPersistStream->Load(pStream)))
        goto UpdateShellLink_Done;

UpdateShellLink_Done:
    if (pStream)
        pStream->Release();
    if (pPersistStream)
        pPersistStream->Release();
    if (pShellLinkDataList)
        pShellLinkDataList->Release();
    return hr;
}

bool ShellLinkInfo::Get(const std::wstring& sLnkFilePath, ShellLinkData_t& data)
{
    data.clear();

    bool retval = false;
    if (Ready())
    {
        data.sFullLinkPath = sLnkFilePath;
        data.sLinkName = GetFileNameWithoutExtensionFromFilePath(sLnkFilePath);

        HRESULT hr;
        // No need to turn off WOW64 FS redir here, as there will be no need to look at 
        // shortcut files in/under System32.
        hr = m_pPersistFile->Load(sLnkFilePath.c_str(), STGM_READ);
        if (SUCCEEDED(hr))
        {
            // See description of UpdateShellLink above for the purpose of this workaround.
            hr = UpdateShellLink(m_pShellLink);
            if (SUCCEEDED(hr))
            {
                hr = m_pShellLink->Resolve(NULL, SLR_NO_UI | SLR_NOUPDATE);
                if (SUCCEEDED(hr))
                {
                    retval = true;
                    // Get the link's target path
                    hr = m_pShellLink->GetPath(m_pszTempBuffer, cchTempBufferSize, NULL, 0);
                    if (SUCCEEDED(hr))
                    {
                        data.sFileSystemPath = m_pszTempBuffer;
                    }
                    // Get any command-line arguments in the link
                    hr = m_pShellLink->GetArguments(m_pszTempBuffer, cchTempBufferSize);
                    if (SUCCEEDED(hr))
                    {
                        data.sArguments = m_pszTempBuffer;
                    }
                    // Get the link's description, if present
                    hr = m_pShellLink->GetDescription(m_pszTempBuffer, cchTempBufferSize);
                    if (SUCCEEDED(hr))
                    {
                        data.sDescription = m_pszTempBuffer;
                    }
                    // See whether there is a desktop.ini in the same directory with this *.lnk file that
                    // has a localized name for this link.
                    std::wstring sLnkFileName = GetFileNameFromFilePath(sLnkFilePath);
                    std::wstring sDesktopIniPath = GetDirectoryNameFromFilePath(sLnkFilePath) + L"\\desktop.ini";
                    DWORD dwGPPSret = GetPrivateProfileStringW(
                        L"LocalizedFileNames",
                        sLnkFileName.c_str(),
                        NULL,
                        m_pszTempBuffer,
                        cchTempBufferSize,
                        sDesktopIniPath.c_str());
                    if (dwGPPSret > 0)
                    {
                        // If the value in the desktop.ini begins with '@', it's an indirect string in a resource DLL
                        if (L'@' == m_pszTempBuffer[0])
                        {
                            // Turn off file system redirection before looking up the indirect string
                            Wow64FsRedirection wow64FSRedir(true);
                            hr = SHLoadIndirectString(m_pszTempBuffer, m_pszTempBuffer, cchTempBufferSize, NULL);
                            wow64FSRedir.Revert();
                            // if successful, set the localized name value
                            if (SUCCEEDED(hr))
                            {
                                data.sLocalizedName = m_pszTempBuffer;
                            }
                        }
                        else
                        {
                            // Not in the format for an indirect string; just return whatever was in the desktop.ini.
                            data.sLocalizedName = m_pszTempBuffer;
                        }
                    }
                }
            }
        }
    }
    return retval;
}

