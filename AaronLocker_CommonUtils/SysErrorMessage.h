#pragma once

#include <Windows.h>
#include <string>

// ----------------------------------------------------------------------------------------------------

/// <summary>
/// Returns human-language error text from a Windows or NTSTATUS error code
/// </summary>
/// <param name="dwErrCode">Win32 or NTSTATUS error code</param>
/// <param name="bNtStatus">true for NTSTATUS code, false for Win32 code</param>
std::wstring SysErrorMessage(DWORD dwErrCode = GetLastError(), bool bNtStatus = false);

/// <summary>
/// Returns human-language error text (including the error code) from a Windows or NTSTATUS error code
/// </summary>
/// <param name="dwErrCode">Win32 or NTSTATUS error code</param>
/// <param name="bNtStatus">true for NTSTATUS code, false for Win32 code</param>
std::wstring SysErrorMessageWithCode(DWORD dwErrCode = GetLastError(), bool bNtStatus = false);

