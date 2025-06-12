#include <Windows.h>
#include <sddl.h>
#include "MachineSid.h"
#include "CSid.h"


// ------------------------------------------------------------------------------------------
// Create a local singleton instance of MachineSid for later comparisons
static MachineSid machineSid;

// ------------------------------------------------------------------------------------------

CSid::CSid() : m_pBuf(NULL)
{
}

CSid::CSid(PSID pSid) : m_pBuf(NULL)
{
	SetBuffer(pSid);
}

CSid::CSid(const wchar_t* szSid) : m_pBuf(NULL)
{
	PSID pSidToFree = NULL;
	if (ConvertStringSidToSidW(szSid, &pSidToFree))
	{
		SetBuffer(pSidToFree);
		LocalFree(pSidToFree);
	}
}

CSid::~CSid()
{
	ClearBuffer();
}

CSid::CSid(const CSid& other) : m_pBuf(NULL)
{
	SetBuffer(other.psid());
}

CSid& CSid::operator=(const CSid& other)
{
	ClearBuffer();
	SetBuffer(other.psid());
	return *this;
}

bool CSid::operator==(PSID pSid) const
{
	if (NULL == pSid || NULL == this->psid())
		return false;
	return 0 != EqualSid(this->psid(), pSid);
}

bool CSid::operator==(const CSid& other) const
{
	if (NULL == other.psid() || NULL == this->psid())
		return false;
	return 0 != EqualSid(this->psid(), other.psid());
}

CSid::operator PSID() const
{
	return (PSID)m_pBuf;
}

PSID CSid::psid() const
{
	return (PSID)m_pBuf;
}

std::wstring CSid::toSidString() const
{
	std::wstring retval;
	if (m_pBuf)
	{
		wchar_t* szSid = NULL;
		if (ConvertSidToStringSidW(this->psid(), &szSid))
		{
			retval = szSid;
			LocalFree(szSid);
		}
	}
	return retval;
}

std::wstring CSid::toDomainAndUsername(bool bReturnSidOnFailure /*= false*/) const
{
	std::wstring sDomainName, sUserName;
	if (Lookup(sDomainName, sUserName))
	{
		if (sDomainName.empty())
			return sUserName;
		else
			return sDomainName + L"\\" + sUserName;
	}
	else
	{
		if (bReturnSidOnFailure)
			return toSidString();
		else
			return std::wstring();
	}
}

std::wstring CSid::toUsername() const
{
	std::wstring sDomainName, sUserName;
	if (Lookup(sDomainName, sUserName))
	{
		return sUserName;
	}
	else
	{
		return std::wstring();
	}
}

std::wstring CSid::toDomainAndUserNameIfNoNetworkNeeded() const
{
	// Considered reimplementing with LookupAccountSidLocalW - https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupaccountsidlocalw
	// which SOUNDED as though it will resolve a SID locally only, but it turns out that it WILL go off-box to resolve a SID the LSA doesn't have cached.

	std::wstring retval;
	// Don't look up S-1-5-21-* unless it's the local machine SID. Anything else is good, for the time being.
	// Note that this code will translate well-known SIDs to localized names on the machine where it executes.
	bool bDoLookup =
		IsMachineLocal() ||
		!TestNtAuthorityBaseRID(psid(), SECURITY_NT_NON_UNIQUE);
	if (bDoLookup)
		retval = toDomainAndUsername();
	if (0 == retval.length())
		retval = toSidString();
	return retval;
}

bool CSid::IsMachineLocal() const
{
	if (NULL == psid())
		return false;

	BOOL bEqual = FALSE;
	return (0 != EqualDomainSid(machineSid.Get(), psid(), &bEqual)) && bEqual;
}

//static
bool CSid::IsNtServiceSid(PSID pSid)
{
	// Check whether NT AUTHORITY (S-1-5-) with first subauth == NT SERVICE or RESTRICTED SERVICES
	return
		TestNtAuthorityBaseRID(pSid, SECURITY_SERVICE_ID_BASE_RID) ||
		TestNtAuthorityBaseRID(pSid, SECURITY_RESTRICTED_SERVICES_BASE_RID);
}

bool CSid::IsNtServiceSid() const
{
	return CSid::IsNtServiceSid(psid());
}

bool CSid::TestNtAuthorityBaseRID(PSID pSid, DWORD dwRid)
{
	if (NULL == pSid)
		return false;

	PSID_IDENTIFIER_AUTHORITY pAuth = GetSidIdentifierAuthority(pSid);
	_SID_IDENTIFIER_AUTHORITY secNtAuth = SECURITY_NT_AUTHORITY;
	if (0 != memcmp(pAuth, &secNtAuth, sizeof(SID_IDENTIFIER_AUTHORITY)))
	{
		return false;
	}
	// All SIDs must have at least one subauthority to be a valid SID
	// Check whether first subauth is dwRid
	return (dwRid == *GetSidSubAuthority(pSid, 0));
}

bool CSid::Lookup(std::wstring& sDomainName, std::wstring& sUserName) const
{
	sDomainName.clear();
	sUserName.clear();
	if (m_pBuf)
	{
		const DWORD cchMaxName = 256;
		WCHAR UserName[cchMaxName];
		WCHAR DomainName[cchMaxName];
		DWORD cchUserSize = cchMaxName;
		DWORD cchDomainSize = cchMaxName;
		SID_NAME_USE eNameUse;
		if (LookupAccountSidW(NULL, psid(), UserName, &cchUserSize, DomainName, &cchDomainSize, &eNameUse))
		{
			sDomainName = DomainName;
			sUserName = UserName;
			return true;
		}
	}
	return false;
}

void CSid::ClearBuffer()
{
	if (m_pBuf)
	{
		delete[] m_pBuf;
		m_pBuf = NULL;
	}
}

void CSid::SetBuffer(PSID pSid)
{
	if (IsValidSid(pSid))
	{
		DWORD dwLength = GetLengthSid(pSid);
		m_pBuf = new byte[dwLength];
		CopySid(dwLength, m_pBuf, pSid);
	}
}

