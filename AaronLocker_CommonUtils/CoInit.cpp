// Wrapper function for CoInitializeEx

#include "CoInit.h"

/// <summary>
/// Call CoInitializeEx for a caller that doesn't care whether COM is initialized for apartment-threaded or 
/// multithreaded.
/// If this function returns any successful HRESULT, CoInitializeEx was called successfully one time, and the
/// caller must eventually call CoUnitialize one time.
/// If this function returns any failed HRESULT, CoInitializeEx was not called successfully, and the caller
/// should not call CoUninitialize.
/// </summary>
/// <returns>A successful HRESULT if COM initialized; a failed HRESULT otherwise</returns>
HRESULT CoInitAnyThreaded()
{
	// We need to get CoInitializeEx to succeed once - doesn't matter whether apartment- or multi-threaded.
	// If CoInitializeEx returns S_OK, this call just initialized COM; if the API returns S_FALSE, COM was 
	// already initialized in the mode passed to the API.
	// If the API returns RPC_E_CHANGED_MODE, COM has already been initialized in another mode.
	// CoUnitialize must be called once for each successful CoInitialize[Ex] call, so make sure we succeed once.

	// Try apartment-threaded first.
	HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	// If it returns RPC_E_CHANGED_MODE, COM is initialized in a mode other than apartment-threaded.
	// Try multithreaded.
	if (RPC_E_CHANGED_MODE == hr)
		hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	return hr;
}