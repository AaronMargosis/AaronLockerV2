#include "pch.h"
//#include <sddl.h>
#include <LM.h>
#pragma comment(lib, "netapi32.lib")
#include "../AaronLocker_CommonUtils/SidStrings.h"
#include "../AaronLocker_CommonUtils/MachineSid.h"
#include "SidsToFilter.h"

// ------------------------------------------------------------------------------------------

SidsToFilter::SidsToFilter()
{
	// Add default set of SIDs to ignore in file system security descriptors
	AddSidToFilter(SidString::CreatorOwner);               // L"S-1-3-0");             // CREATOR OWNER
	AddSidToFilter(SidString::NtAuthBatch);                // L"S-1-5-3");             // NT AUTHORITY\BATCH
	AddSidToFilter(SidString::NtAuthService);              // L"S-1-5-6");             // NT AUTHORITY\SERVICE
	AddSidToFilter(SidString::NtAuthSystem);               // L"S-1-5-18");            // NT AUTHORITY\SYSTEM
	AddSidToFilter(SidString::NtAuthLocalService);         // L"S-1-5-19");            // NT AUTHORITY\LOCAL SERVICE
	AddSidToFilter(SidString::NtAuthNetworkService);       // L"S-1-5-20");            // NT AUTHORITY\NETWORK SERVICE
	AddSidToFilter(SidString::BuiltinAdministrators);      // L"S-1-5-32-544");        // BUILTIN\Administrators
	AddSidToFilter(SidString::BuiltinAccountOperators);    // L"S-1-5-32-548");        // BUILTIN\Account Operators
	AddSidToFilter(SidString::BuiltinServerOperators);     // L"S-1-5-32-549");        // BUILTIN\Server Operators
	AddSidToFilter(SidString::BuiltinPrintOperators);      // L"S-1-5-32-550");        // BUILTIN\Print Operators
	AddSidToFilter(SidString::BuiltinBackupOperators);     // L"S-1-5-32-551");        // BUILTIN\Backup Operators
	AddSidToFilter(SidString::BuiltinPerfLogUsers);        // L"S-1-5-32-559");        // BUILTIN\Performance Log Users
	AddSidToFilter(SidString::BuiltinIISIUsers);           // L"S-1-5-32-568");        // BUILTIN\IIS_IUSRS
	AddSidToFilter(SidString::BuiltinRdsMgtServers);       // L"S-1-5-32-577");        // BUILTIN\RDS Management Servers
	AddSidToFilter(SidString::NtSvcTrustedInstaller);      // L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");  // NT SERVICE\TrustedInstaller
	AddSidToFilter(SidString::NtVMVirtualMachines);        // L"S-1-5-83-0");          // NT VIRTUAL MACHINE\Virtual Machines
	AddSidToFilter(SidString::NtAuthUserModeDrivers);      // L"S-1-5-84-0-0-0-0-0");  // NT AUTHORITY\USER MODE DRIVERS
	AddSidToFilter(SidString::AppContainerSid_Unknown1);   // L"S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069167804-1277922394");               // App container SID for... (don't remember)
	AddSidToFilter(SidString::AppContainerSid_Unknown2);   // L"S-1-15-2-95739096-486727260-2033287795-3853587803-1685597119-444378811-2746676523");                 // App container SID for... (don't remember)
	AddSidToFilter(SidString::VmWorkerProcessCapability);  // L"S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704");// sidVmWorkerProcessCapability

	// Add members of local administrators group
	CSid BA(SidString::BuiltinAdministrators);
	LPBYTE buffer = NULL;
	DWORD entriesRead = 0, totalEntries = 0;
	DWORD_PTR resumeHandle = NULL;
	// Ignoring the remote possibility of needing multiple calls to retrieve all members.
	NET_API_STATUS status = NetLocalGroupGetMembers(NULL, BA.toUsername().c_str(), 0, &buffer, DWORD(-1), &entriesRead, &totalEntries, &resumeHandle);
	if (NERR_Success == status && entriesRead > 0)
	{
		LOCALGROUP_MEMBERS_INFO_0* pInfo = (LOCALGROUP_MEMBERS_INFO_0*)buffer;
		for (DWORD ixMember = 0; ixMember < entriesRead; ++ixMember)
		{
			AddSidToFilter(pInfo[ixMember].lgrmi0_sid);
		}
		NetApiBufferFree(buffer);
	}
}

SidsToFilter::~SidsToFilter()
{
}

void SidsToFilter::AddSidToFilter(PSID pSid)
{
	CSid sid(pSid);
	if (NULL != sid.psid() && !SidIsInSet(sid.psid()))
		m_SidSet.push_back(sid);
}

void SidsToFilter::AddSidToFilter(const wchar_t* szSid)
{
	CSid sid(szSid);

	if (NULL != sid.psid() && !SidIsInSet(sid.psid()))
		m_SidSet.push_back(sid);
}

// Determine whether the specified SID should be ignored in security descriptors.
// Returns true if the SID is in the list or is an NT SERVICE SID (S-1-5-80-*)
bool SidsToFilter::FilterThisSid(PSID pSid) const
{
	// See whether it's in the set
	if (SidIsInSet(pSid))
		return true;
	// Now look for NT SERVICE SIDs (S-1-5-80-*)
	if (CSid::IsNtServiceSid(pSid))
		return true;
	return false;
}

// Returns true if the SID is explicitly in the list.
// Implementation notes:
// It's a vector, so determining whether a SID is in the set requires iterating through the set
// each time and calling the EqualSid API on each until found or the end of the vector.
// I considered using std::unordered_set, but that would require writing a reliable hash function
// and verifying that it didn't turn out to be more expensive. To that end, I tested another 
// implementation using std::unordered_set<std::wstring> and using string representations of the
// SIDs, trading off the benefit of hash lookups for the cost of SID-to-string conversions.
// In a release build, that implementation was about 1000 times more expensive than iterating
// through the vector and calling EqualSid.
bool SidsToFilter::SidIsInSet(PSID pSid) const
{
	for (
		std::vector<CSid>::const_iterator iter = m_SidSet.begin();
		iter != m_SidSet.end();
		iter++)
	{
		// This is ultimately an EqualSid API call, not a test for pointer equality.
		if (*iter == pSid)
			return true;
	}
	return false;
}

// For diagnostic purposes: dump the list of SIDs, and names where possible
void SidsToFilter::DumpList(std::wostream& os) const
{
	for (
		std::vector<CSid>::const_iterator iter = m_SidSet.begin();
		iter != m_SidSet.end();
		iter++)
	{
		os << iter->toSidString() << L" " << iter->toDomainAndUsername() << std::endl;
	}
}

