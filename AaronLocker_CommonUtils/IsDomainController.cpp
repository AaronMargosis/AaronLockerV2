#include <Windows.h>
#include "IsDomainController.h"

/// <summary>
/// Indicates whether the current computer is a domain controller.
/// Reports "false" if the machine has been booted into Directory Services Repair Mode (DSRM).
/// </summary>
/// <returns>true if the computer is a DC that is not in Directory Services Repair Mode; false otherwise.</returns>
bool IsDomainController()
{
	OSVERSIONINFOEXW osvi = { 0 };
	DWORDLONG dwlConditionMask = 0;
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	osvi.wProductType = VER_NT_DOMAIN_CONTROLLER;
	// Initialize the condition mask.
	VER_SET_CONDITION(dwlConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);
	// Perform the test.
	return (0 != VerifyVersionInfoW(&osvi, VER_PRODUCT_TYPE, dwlConditionMask));
}
