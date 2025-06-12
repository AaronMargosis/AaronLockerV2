#pragma once
#include <Windows.h>

/// <summary>
/// Class to retrieve the machine SID, representing the authority within which local 
/// users and groups are defined.
/// Takes care of its own memory management.
/// </summary>
class MachineSid
{
public:
	// Constructor
	MachineSid() : pSidData(NULL) { Init(); }
	// Destructor
	~MachineSid() { Uninit(); }

	PSID Get() const { return (PSID)pSidData; }

private:
	// Call Init() once before any calls to the Get() function.
	bool Init();
	// Cleanup
	void Uninit()
	{
		if (NULL != pSidData)
			delete[] pSidData;
		pSidData = NULL;
	}
private:
	// Data
	byte* pSidData;
private:
	// Not implemented
	MachineSid(const MachineSid&) = delete;
	MachineSid& operator = (const MachineSid&) = delete;
};

