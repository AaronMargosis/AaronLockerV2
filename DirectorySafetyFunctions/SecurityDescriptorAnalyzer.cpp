#include "pch.h"
#include "../AaronLocker_CommonUtils/SidStrings.h"
#include "../AaronLocker_CommonUtils/SysErrorMessage.h"
#include "SecurityDescriptorAnalyzer.h"

bool SecurityDescriptorAnalyzer::IsNonadminWritable(
	const wchar_t* szFileSystemPath, 
	const SidsToFilter& sidsToFilter, 
	bool& bIsNonadminWritable,
	bool& bNeedsAltDataStreamExclusion, 
	std::vector<CSid>& nonadminSids, 
	std::wstring& sErrorInfo)
{
	// Initialize return value and output parameters
	bool retval;
	bIsNonadminWritable = false;
	bNeedsAltDataStreamExclusion = false;
	nonadminSids.clear();
	sErrorInfo.clear();

	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwLengthNeeded = 0;
	BOOL ret = GetFileSecurityW(
		szFileSystemPath,
		OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
		NULL,
		0,
		&dwLengthNeeded);
	DWORD dwLastErr = GetLastError();
	if (ERROR_INSUFFICIENT_BUFFER == dwLastErr && dwLengthNeeded > 0)
	{
		pSD = (PSECURITY_DESCRIPTOR)(new byte[dwLengthNeeded]);
		ret = GetFileSecurityW(
			szFileSystemPath,
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
			pSD,
			dwLengthNeeded,
			&dwLengthNeeded);
		dwLastErr = GetLastError();
	}

	if (!ret || NULL == pSD)
	{
		retval = false;
		sErrorInfo = SysErrorMessage(dwLastErr);
	}
	else
	{
		retval = true;
		BOOL bOwnerDefaulted = FALSE;
		PSID pSid = NULL;
		if (GetSecurityDescriptorOwner(pSD, &pSid, &bOwnerDefaulted))
		{
			if (!sidsToFilter.FilterThisSid(pSid))
			{
				bIsNonadminWritable = true;
				nonadminSids.push_back(pSid);
			}
		}
		BOOL bDaclPresent = FALSE;
		PACL pDacl = NULL;
		BOOL bDaclDefaulted = FALSE;
		if (GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDacl, &bDaclDefaulted))
		{
			// NULL DACL is equivalent to Everyone/FullControl. 
			// Passing NULL as the first parameter to GetAclInformation results in an access violation,
			// so deal with it here
			if (NULL == pDacl)
			{
				bIsNonadminWritable = true;
				nonadminSids.push_back(SidString::Everyone);
				bNeedsAltDataStreamExclusion = true;
			}
			else
			{
				// Non-admin writable if any of the dirWritePerms are present for a non-admin
				// Non-admin can create and execute ADS on a directory if the directory
				// grants all of the ADSWriteExecPerms to nonadmin entities in aggregate.
				// Skip these:  FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD.
				// Skipping FILE_DELETE_CHILD because both Google Chrome and Microsoft Edge
				// grant it and no other write permissions to Authenticated Users on 
				// Program Files (x86)\[company]\[browser]\Application\SetupMetrics.
				// The granting of this permission is accidental and considered a very minor bug
				// at most by the Chromium project.
				// For the purposes of AaronLocker, these directories turning up as "user-writable" is
				// just noise - that permission by itself doesn't allow a non-admin to drop a file 
				// into the directory and execute it.
				const ACCESS_MASK dirWritePerms =
					FILE_ADD_FILE |
					FILE_ADD_SUBDIRECTORY |
					DELETE |
					WRITE_DAC |
					WRITE_OWNER |
					GENERIC_WRITE |
					GENERIC_ALL;
				const ACCESS_MASK ADSWriteExecPerms =
					FILE_ADD_FILE |
					FILE_ADD_SUBDIRECTORY |
					FILE_WRITE_EA |
					FILE_WRITE_ATTRIBUTES |
					FILE_READ_DATA |
					FILE_EXECUTE;

				ACCESS_MASK totalRights = 0;
				ACL_SIZE_INFORMATION aclSizeInfo = { 0 };
				if (GetAclInformation(pDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation))
				{
					for (DWORD ixAce = 0; ixAce < aclSizeInfo.AceCount; ++ixAce)
					{
						ACCESS_ALLOWED_ACE* pAce;
						if (GetAce(pDacl, ixAce, (LPVOID*)&pAce))
						{
							// Interested only in ACEs meeting all the following criteria:
							// * access-allowed ACE
							// * NOT inherit-only
							// * grant access to entities other than known admin/admin-equivalent
							// * grant write permissions or any of the ADSWriteExecPerms
							pSid = (PSID)(&pAce->SidStart);
							if (
								ACCESS_ALLOWED_ACE_TYPE == pAce->Header.AceType && // access-allowed
								0 == (INHERIT_ONLY_ACE & pAce->Header.AceFlags) && // not inherit-only
								!sidsToFilter.FilterThisSid(pSid)                  // grants access to entity we're not ignoring
								)
							{
								// contains at least one write perm
								if (0 != (dirWritePerms & pAce->Mask))
								{
									bIsNonadminWritable = true;
									nonadminSids.push_back(pSid);
								}
								// Aggregate any ADSWriteExecPerms in the access mask granted to this entity
								totalRights |= (ADSWriteExecPerms & pAce->Mask);
							}
						}
					}

					// Non-admin entities can create and execute alternate data streams on this object
					// (assuming it's a directory; not tested whether similar is possible on a file)
					bNeedsAltDataStreamExclusion = (ADSWriteExecPerms == totalRights);
				}
			}
		}
	}

	delete[] (byte*)pSD;

	return retval;
}
