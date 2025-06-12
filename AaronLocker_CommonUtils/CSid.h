#pragma once

#include <Windows.h>
#include <string>

// ------------------------------------------------------------------------------------------
/// <summary>
/// Class to represent a SID and manage its memory
/// </summary>
class CSid
{
public:
	// (Considered adding a constructor that would build the machine SID but didn't
	// want to make it the default constructor, and other options like "CSid(bool)" weren't
	// appealing enough. Leaving MachineSid as a separate class.)

	/// <summary>
	/// Default constructor
	/// </summary>
	CSid();
	/// <summary>
	/// Constructor from pointer to SID
	/// </summary>
	CSid(PSID pSid);
	/// <summary>
	/// Constructor from a string representation of a SID
	/// TODO: Be able to take an SDDL representation such as SY, BU, etc:
	/// Change this signature to CSid(const wchar_t* szSid, bool bIsSDDL = false);
	/// </summary>
	CSid(const wchar_t* szSid);
	// Destructor
	~CSid();
	// Copy constructor
	CSid(const CSid& other);
	// assignment operator
	CSid& operator = (const CSid& other);
	// equality operators
	bool operator == (PSID pSid) const;
	bool operator == (const CSid& other) const;

	// Conversion to raw type
	operator PSID() const;
	// Explicit conversion to raw type
	PSID psid() const;

	/// <summary>
	/// Conversion to wstring representation of the SID
	/// </summary>
	/// <returns></returns>
	std::wstring toSidString() const;
	// Conversion to name (if possible)
	
	/// <summary>
	/// Lookup and conversion to "DOMAIN\USERNAME", if possible, with option to return string SID on failure.
	/// </summary>
	/// <param name="bReturnSidOnFailure">if name lookup fails: if true, return SID as string; if false, return empty string.</param>
	/// <returns>"DOMAIN\USERNAME" associated with the SID; empty string or SID string if conversion not possible</returns>
	std::wstring toDomainAndUsername(bool bReturnSidOnFailure = false) const;

	/// <summary>
	/// Lookup and conversion to username (without domain), if possible.
	/// </summary>
	/// <returns>Username associated with the SID; empty string if conversion not possible</returns>
	std::wstring toUsername() const;

	/// <summary>
	/// Lookup and conversion to DOMAIN\USERNAME if it can be resolved without network traffic.
	/// </summary>
	/// <returns>DOMAIN\USERNAME or SID in string form.</returns>
	std::wstring toDomainAndUserNameIfNoNetworkNeeded() const;

	/// <summary>
	/// Returns true if this SID represents a local entity - i.e., has the same base SID as the machine SID.
	/// Note that if local, name lookup for this SID can be performed successfully ONLY on this machine, and
	/// doing so WILL NOT result in network traffic to retrieve it.
	/// </summary>
	/// <returns>true if this SID has the same base SID as the local machine's SID</returns>
	bool IsMachineLocal() const;

	/// <summary>
	/// Reports whether the SID is an NT SERVICE SID (begins with S-1-5-80-) or RESTRICTED SERVICES SID (begins with S-1-5-99-)
	/// </summary>
	/// <param name="pSid">SID to inspect</param>
	/// <returns>true if the SID is an NT SERVICE or RESTRICTED SERVICES SID; false otherwise</returns>
	static bool IsNtServiceSid(PSID pSid);

	/// <summary>
	/// Reports whether the SID is an NT SERVICE SID (begins with S-1-5-80-) or RESTRICTED SERVICES SID (begins with S-1-5-99-)
	/// </summary>
	/// <returns>true if the SID is an NT SERVICE or RESTRICTED SERVICES SID; false otherwise</returns>
	bool IsNtServiceSid() const;

private:
	/// <summary>
	/// Reports whether the SID is an NT AUTHORITY SID (S-1-5-) with a specific base RID (S-1-5-XX).
	/// </summary>
	/// <param name="pSid"></param>
	/// <param name="dwRid"></param>
	/// <returns></returns>
	static bool TestNtAuthorityBaseRID(PSID pSid, DWORD dwRid);

	// Conversion to domain\name strings
	bool Lookup(std::wstring& sDomainName, std::wstring& sUserName) const;

private:
	void ClearBuffer();
	void SetBuffer(PSID pSid);
	byte* m_pBuf;
};

