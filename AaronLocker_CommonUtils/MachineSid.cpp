/// Class to retrieve the machine SID, representing the authority within which local 
/// users and groups are defined.
/// Takes care of its own memory management.

#include <Windows.h>
#include <NTSecAPI.h>
#include "MachineSid.h"

bool MachineSid::Init()
{
	// Uninit in case Init has been called before.
	Uninit();

	bool retval = false;
	LSA_OBJECT_ATTRIBUTES objectAttributes = { 0 };
	LSA_HANDLE hPolicy = NULL;
	NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
	if (0 == status) //if (STATUS_SUCCESS == status)
	{
		PVOID pData = NULL;
		status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, &pData);
		if (0 == status && NULL != pData) //if (STATUS_SUCCESS == status)
		{
			POLICY_ACCOUNT_DOMAIN_INFO* pInfo = (POLICY_ACCOUNT_DOMAIN_INFO*)pData;
			if (IsValidSid(pInfo->DomainSid))
			{
				DWORD dwSidLength = GetLengthSid(pInfo->DomainSid);
				pSidData = new byte[dwSidLength];
				if (CopySid(dwSidLength, (PSID)pSidData, pInfo->DomainSid))
				{
					retval = true;
				}
				else
				{
					Uninit();
				}
			}
			LsaFreeMemory(pData);
		}
		LsaClose(hPolicy);
	}
	return retval;
}
