// Interface for serializing full- or one-directory-scans to an output stream.

#pragma once
#include <iostream>
#include "../DirectorySafetyFunctions/DirectorySafetyStructs.h"
#include "../AaronLocker_EndpointScanLogic/AaronLocker_EndpointScanLogic.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"

/// <summary>
/// Class for serializing EndpointFullScan and EndpointOneDirectoryScan to an output stream.
/// </summary>
class AaronLockerSerializer
{
public:
	/// <summary>
	/// Serializes an EndpointFullScan to an output stream.
	/// </summary>
	static bool Serialize(
		const EndpointFullScan& scan, 
		std::wostream& os);

	/// <summary>
	/// Serializes an EndpointOneDirectoryScan to an output stream,
	/// along with the directory name and the app name associated with the scan.
	/// </summary>
	static bool Serialize(
		const EndpointOneDirectoryScan& scan, 
		const std::wstring& sDirectoryName,
		const std::wstring& sAppname, 
		std::wostream& os);

	/// <summary>
	/// Serializes the results of an Endpoint "links" scan to a stream.
	/// </summary>
	static bool Serialize(
		const EndpointScan_Links& scan,
		std::wostream& os);
};


