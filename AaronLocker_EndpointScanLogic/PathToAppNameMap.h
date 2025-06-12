// Map arbitrary file paths to application display names, based on Start Menu and Desktop shortcuts

#pragma once

#include <map>
#include <string>
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Links.h"

/// <summary>
/// Class to enable mapping arbitrary file paths to application display names, based on shortcuts
/// in Start Menus and Desktops.
/// See the implementation file for the logic used to create the mapping.
/// </summary>
class PathToAppMap : public std::map<std::wstring, std::wstring>
{
public:
	PathToAppMap();
	~PathToAppMap() = default;
	PathToAppMap(const PathToAppMap&) = default;
	PathToAppMap& operator = (const PathToAppMap&) = default;

	/// <summary>
	/// Add entries to the map from information gathered from shortcuts.
	/// </summary>
	/// <param name="shellLinks">Input: information collected from shell links</param>
	void AddEntries(const ShellLinkDataContextCollection_t& shellLinks);

	/// <summary>
	/// Look up an application name based on an input file path. Looks for the input file/directory,
	/// then its parent directories until a match is found or can't search any further.
	/// </summary>
	/// <param name="sPath">Input: path to a file or directory</param>
	/// <param name="sAppName">Output: application display name, if mapping found for the input path</param>
	/// <returns>true if mapping found, false otherwise</returns>
	bool FindEntry(const std::wstring& sPath, std::wstring& sAppName);

private:
	/// <summary>
	/// Internal method to add a specially-processed path and an application display name to the map.
	/// The entry is not added if a pre-existing entry overrides it.
	/// </summary>
	bool AddEntry(const std::wstring& sPath, const std::wstring& sAppName);

	/// <summary>
	/// Internal method to add default paths during map initialization.
	/// </summary>
	void AddDefaultEntries();
};
