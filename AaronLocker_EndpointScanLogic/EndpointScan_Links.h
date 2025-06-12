// Interface to scan an endpoint's shortcut files to support mapping file paths to application display names
#pragma once

#include <vector>
#include "../AaronLocker_CommonUtils/ShellLinkInfo.h"
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Structs.h"


/// <summary>
/// Interface to scan an endpoint's shortcut files to support mapping file paths to application display names
/// </summary>
class EndpointScan_Links // No need at this time to inherit from EndpointScan_Base
{
public:

	EndpointScan_Links();
	~EndpointScan_Links();

	/// <summary>
	/// Retrieve data from shortcut files in system-wide Start Menu and Desktop, 
	/// and the Start Menus and Desktops of each user profile
	/// </summary>
	/// <param name="sErrorInfo">Output: info about any errors during the scan</param>
	/// <returns>true if successful, false otherwise</returns>
	bool PerformFullScan(std::wstring& sErrorInfo);

	/// <summary>
	/// Returns the results from the previous PerformFullScan.
	/// </summary>
	const ShellLinkDataContextCollection_t& ScanResults() const;

private:
	ShellLinkDataContextCollection_t m_ShellLinkDataCollection;

private:
	// Not implemented
	EndpointScan_Links(const EndpointScan_Links&) = delete;
	EndpointScan_Links& operator = (const EndpointScan_Links&) = delete;
};

