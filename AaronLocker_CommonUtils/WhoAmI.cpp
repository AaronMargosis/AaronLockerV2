
#include "SidStrings.h"
#include "WhoAmI.h"

WhoAmI::WhoAmI()
{
	// Note that GetCurrentProcessToken() is not available on Win7
	// Request query and query-source; if that fails, try to get query only
	if (
		OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &m_hToken) ||
		OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &m_hToken)
		)
	{
		GetUserCSid(m_userSid);
	}
}

WhoAmI::~WhoAmI()
{
	CloseHandle(m_hToken);
}

bool WhoAmI::IsSystem() const
{
	static const CSid sidSystem(SidString::NtAuthSystem);

	return (sidSystem == GetUserCSid());
}

bool WhoAmI::GetUserCSid(CSid& userSid) const
{
	bool retval = false;
	DWORD dwLength = 0;
	GetTokenInformation(m_hToken, TokenUser, NULL, 0, &dwLength);
	if (ERROR_INSUFFICIENT_BUFFER == GetLastError() && dwLength > 0)
	{
		byte* buffer = new byte[dwLength];
		PTOKEN_USER pUser = (PTOKEN_USER)buffer;
		if (GetTokenInformation(m_hToken, TokenUser, pUser, dwLength, &dwLength))
		{
			retval = true;
			userSid = pUser->User.Sid;
		}
		delete[] buffer;
	}
	return retval;
}

