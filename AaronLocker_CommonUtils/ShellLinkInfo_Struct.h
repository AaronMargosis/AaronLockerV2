// Data structure representing data extracted from a Windows shortcut (*.lnk) file
#pragma once

#include <string>
#include <vector>

/// <summary>
/// Data that can be captured from a shortcut that points to an app
/// </summary>
struct ShellLinkData_t
{
    std::wstring
        sFullLinkPath,
        sLinkName,
        sLocalizedName,
        sDescription,
        sFileSystemPath,
        sArguments;

    void clear()
    {
        sFullLinkPath.clear();
        sLinkName.clear();
        sLocalizedName.clear();
        sDescription.clear();
        sFileSystemPath.clear();
        sArguments.clear();
    }
};


