// Wrapper function for CoInitializeEx

#pragma once

#include <Windows.h>


/// <summary>
/// Call CoInitializeEx for a caller that doesn't care whether COM is initialized for apartment-threaded or 
/// multithreaded.
/// If this function returns any successful HRESULT, CoInitializeEx was called successfully one time, and the
/// caller must eventually call CoUnitialize one time.
/// If this function returns any failed HRESULT, CoInitializeEx was not called successfully, and the caller
/// should not call CoUninitialize.
/// </summary>
/// <returns>A successful HRESULT if COM initialized; a failed HRESULT otherwise</returns>
HRESULT CoInitAnyThreaded();