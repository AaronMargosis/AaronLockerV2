// Interface to get information about the current running security context.


#include <Windows.h>
#include "CSid.h"

/// <summary>
/// Information about the current process token.
/// Could be enhanced if needed to query current thread token, if present.
/// </summary>
class WhoAmI
{
public:
	WhoAmI();
	virtual ~WhoAmI();

	const CSid& GetUserCSid() const { return m_userSid; }

	/// <summary>
	/// Returns true if current process running as Local System
	/// </summary>
	bool IsSystem() const;

	// If needed, can add "is running with admin rights," "is a member of admins (whether elevated or not)," "has a linked token," maybe "get linked token" ...

	/// <summary>
	/// Raw token access.
	/// </summary>
	HANDLE HToken() const { return m_hToken; }

private:
	/// <summary>
	/// Returns current user SID as a CSid
	/// </summary>
	/// <param name="userSid">Output: CSid representing process user</param>
	/// <returns>true if successful; false otherwise</returns>
	bool GetUserCSid(CSid& userSid) const;

private:
	HANDLE m_hToken;
	CSid m_userSid;

private:
	// Not implemented
	WhoAmI(const WhoAmI&) = delete;
	WhoAmI& operator = (const WhoAmI&) = delete;
};
