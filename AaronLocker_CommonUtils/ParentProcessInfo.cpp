// Retrieve the PID and image path of the current process' parent process.
//

#include <Windows.h>
#include <winternl.h>
#include <iostream>

// NtQueryInformationProcess is defined in winternl.h but Visual Studio doesn't provide a corresponding import library.
// Its use requires dynamic linking (LoadLibrary/GetProcessAddress), so we need a typedef for its signature.
typedef
__kernel_entry NTSTATUS
(NTAPI*
	pfn_NtQueryInformationProcess_t)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
		);

// Pointer to the API's implementation:
static pfn_NtQueryInformationProcess_t pfn_NtQueryInformationProcess = NULL;

// Initialize the pointer to the API's implementation
static bool Init_NtQueryInformationProcess()
{
	HMODULE hMod = LoadLibraryW(L"ntdll.dll");
	if (NULL == hMod)
		return false;
	pfn_NtQueryInformationProcess = (pfn_NtQueryInformationProcess_t)GetProcAddress(hMod, "NtQueryInformationProcess");
	// It's safe to FreeLibrary ntdll.dll in this case because this call won't decrement its reference count to zero.
	FreeLibrary(hMod);
	return (NULL != pfn_NtQueryInformationProcess);
}


// The PROCESS_BASIC_INFORMATION definition in winternl.h is not useful for our purposes.
// This definition is from https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
// Both definitions are the same size, whether compiling for x86 or x64.
typedef struct _PROCESS_BASIC_INFORMATION_FROM_DOCS {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_FROM_DOCS;

/// <summary>
/// Retrieve the PID and image path of the current process' parent process 
/// </summary>
/// <param name="dwPPID">Output: on success, the parent process' Process ID (PID)</param>
/// <param name="sParentProcessExePath">Output: on success, the image path of the parent process' executable</param>
/// <returns>true on success, false otherwise</returns>
bool GetParentProcessInformation(DWORD& dwPPID, std::wstring& sParentProcessExePath)
{
	// Initialize output variables
	dwPPID = 0;
	sParentProcessExePath.clear();

	// Need to dynamically load the address of the NtQueryInformationProcess API.
	// Can't proceed if we can't do that.
	if (!Init_NtQueryInformationProcess())
		return false;

	// Retrieve "basic information" about the current process
	PROCESS_BASIC_INFORMATION_FROM_DOCS pbi = { 0 };
	ULONG ulRetLength = 0;
	NTSTATUS ntstat = pfn_NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &ulRetLength);
	if (0 != ntstat)
	{
		// std::wcout << L"NtQueryInformationProcess failed; status = " << ntstat << std::endl;
		return false;
	}

	// Parent process ID
	dwPPID = static_cast<DWORD>(pbi.InheritedFromUniqueProcessId);

	// Getting the executable image path of the parent process requires PROCESS_QUERY_LIMITED_INFORMATION or PROCESS_QUERY_INFORMATION
	HANDLE hPProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPPID);
	if (NULL != hPProc)
	{
		// MAX_PATH*2 should be plenty for all expected use cases.
		// Unfortunately, if QueryFullProcessImageNameW fails with ERROR_INSUFFICIENT_BUFFER, the fourth parameter does not return
		// the required buffer size, as most APIs like this do.
		wchar_t szParentExePath[MAX_PATH * 2] = { 0 };
		DWORD dwPathSize = sizeof(szParentExePath) / sizeof(szParentExePath[0]);
		BOOL ret = QueryFullProcessImageNameW(hPProc, 0, szParentExePath, &dwPathSize);
		CloseHandle(hPProc);
		if (ret)
		{
			sParentProcessExePath = szParentExePath;
			return true;
		}
	}

	return false;
}

