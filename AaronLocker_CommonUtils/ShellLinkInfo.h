// Class to extract information from a Windows shortcut (*.lnk) file
#pragma once

#include <Windows.h>
#include <ShObjIdl.h>
#include <ShlGuid.h>
#include <string>
#include "../AaronLocker_CommonUtils/ShellLinkInfo_Struct.h"


/// <summary>
/// Class to retrieve information from Windows shortcut files (designed for apps that execute files)
/// </summary>
class ShellLinkInfo
{
public:
    ShellLinkInfo();
    ~ShellLinkInfo();

    /// <summary>
    /// Gather information from a link file.
    /// </summary>
    /// <param name="sLnkFilePath">Input: Path to the shortcut file</param>
    /// <param name="data">Output: data retrieved from the shortcut</param>
    /// <returns>true if successful, false otherwise</returns>
    bool Get(const std::wstring& sLnkFilePath, ShellLinkData_t& data);

    /// <summary>
    /// Indicates whether the ShellLinkInfo instance initialized successfully.
    /// </summary>
    bool Ready() const;

private:
    bool m_bComInitialized;
    IShellLinkW* m_pShellLink;
    IPersistFile* m_pPersistFile;
    wchar_t* m_pszTempBuffer;

private:
    ShellLinkInfo(const ShellLinkInfo&) = delete;
    ShellLinkInfo& operator = (const ShellLinkInfo&) = delete;
};



