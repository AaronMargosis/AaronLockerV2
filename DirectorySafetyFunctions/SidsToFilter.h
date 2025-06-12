#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <ostream>
#include "../AaronLocker_CommonUtils/CSid.h"

// ------------------------------------------------------------------------------------------
/// <summary>
/// Class represents a collection of SIDs to ignore in file system security descriptors when 
/// determining "safe" vs. "unsafe" (non-admin-writable).
/// </summary>
class SidsToFilter
{
public:
	/// <summary>
	/// Class constructor; sets up the default set of SIDs to ignore in file system security
	/// descriptors when determining "safe" vs. "unsafe" (non-admin-writable).
	/// </summary>
	SidsToFilter();
	// Dtor
	~SidsToFilter();

	// Add a SID to the list 
	// (e.g., a custom domain account that appears in security descriptors and that is not
	// in the built-in Admins group.

	/// <summary>
	/// Add a SID to the collection of SIDs to ignore.
	/// For example, a custom domain account that is considered admin-equivalent that
	/// appears in security descriptors and that is not in the built-in Admins group.
	/// </summary>
	/// <param name="pSid">The SID to ignore, in binary form</param>
	void AddSidToFilter(PSID pSid);
	/// <summary>
	/// Add a SID to the collection of SIDs to ignore.
	/// For example, a custom domain account that is considered admin-equivalent that
	/// appears in security descriptors and that is not in the built-in Admins group.
	/// </summary>
	/// <param name="szSid">The SID to ignore, in string form</param>
	void AddSidToFilter(const wchar_t* szSid);

	/// <summary>
	/// Determine whether the specified SID should be ignored in security descriptors.
	/// Returns true if the SID is in the collection or is an NT SERVICE SID (S-1-5-80-*)
	/// </summary>
	/// <param name="pSid">The SID to evaluate, in binary form.</param>
	/// <returns>Returns true if the SID is in the collection or is an NT SERVICE SID (S-1-5-80-*)</returns>
	bool FilterThisSid(PSID pSid) const;

	/// <summary>
	/// For diagnostic purposes: dump the collection of SIDs, and names where possible
	/// </summary>
	/// <param name="os">stream to dump output into</param>
	void DumpList(std::wostream& os) const;

private:
	// Returns true if the SID is explicitly in the list
	bool SidIsInSet(PSID pSid) const;

private:
	// It's a vector, so determining whether a SID is in the set requires iterating through the set
	// each time and calling the EqualSid API on each until found or the end of the vector.
	// I considered using std::unordered_set, but that would require writing a reliable hash function
	// and verifying that it didn't turn out to be more expensive. To that end, I tested another 
	// implementation using std::unordered_set<std::wstring> and using string representations of the
	// SIDs, trading off the benefit of hash lookups for the cost of SID-to-string conversions.
	// In a release build, that implementation was about 1000 times more expensive than iterating
	// through the vector and calling EqualSid.
	std::vector<CSid> m_SidSet;

private:
	// Not implemented
	SidsToFilter(const SidsToFilter&) = delete;
	SidsToFilter& operator = (const SidsToFilter&) = delete;
};

