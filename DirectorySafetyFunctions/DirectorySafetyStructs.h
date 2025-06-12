#pragma once

#include <string>
#include <vector>

/// <summary>
/// Structure to report information about unsafe directories:
/// * Directory path
/// * Whether the directory's ADSes need exclusions
/// * The SIDs of nonadmin entities that have write access to the directory.
/// </summary>
struct UnsafeDirectoryInfo_t {
	std::wstring m_sFileSystemPath;
	bool         m_bNeedsAltDataStreamExclusion;
	std::wstring m_nonadminSids;
	// Implementation note: original implementation was that this structure had a vector<CSid>, but that
	// wasn't good for serialization/deserialization. wstring is better for that, and the information is
	// informational only, so strings are good. Plus, the CSid class depends on Windows interfaces.
	// Some SIDs can be converted to names ONLY on the machine where they're defined; some SIDs require
	// network traffic to be translated. Using CSid::toDomainAndUserNameIfNoNetworkNeeded to try to strike
	// the right balance.

	/// <summary>
	/// Constructor that takes a string (e.g., for deserialization or copying)
	/// </summary>
	UnsafeDirectoryInfo_t(
		const std::wstring& sFileSystemPath,
		bool bNeedsAltDataStreamExclusion,
		const std::wstring& sNonadminSids
	) :
		m_sFileSystemPath(sFileSystemPath),
		m_bNeedsAltDataStreamExclusion(bNeedsAltDataStreamExclusion),
		m_nonadminSids(sNonadminSids)
	{}

	//TODO: Undo the removing from this struct because CSid has dependencies on Windows interfaces.
	///// <summary>
	///// Constructor that takes a vector of CSids. Converts local accounts to names.
	///// </summary>
	//UnsafeDirectoryInfo_t(
	//	const std::wstring& sFileSystemPath,
	//	bool bNeedsAltDataStreamExclusion,
	//	const std::vector<CSid>& nonadminSids
	//) :
	//	m_sFileSystemPath(sFileSystemPath),
	//	m_bNeedsAltDataStreamExclusion(bNeedsAltDataStreamExclusion)
	//{
	//	std::wstringstream str;
	//	for (
	//		std::vector<CSid>::const_iterator iterSids = nonadminSids.begin();
	//		iterSids != nonadminSids.end();
	//		++iterSids
	//		)
	//	{
	//		if (iterSids->IsMachineLocal())
	//			str << iterSids->toDomainAndUsername() << L"; ";
	//		else
	//			str << iterSids->toSidString() << L"; ";
	//	}
	//	m_nonadminSids = str.str();
	//}
};

typedef std::vector<UnsafeDirectoryInfo_t> UnsafeDirectoryCollection_t;

