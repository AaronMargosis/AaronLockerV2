// String utility functions (Windows-specific).

#include <Windows.h>
#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")
#include <iostream>


std::wstring GuidToString(const GUID& guid)
{
	std::wstring retval;
	RPC_WSTR pWstr = NULL;
	if (RPC_S_OK == UuidToStringW(&guid, &pWstr))
	{
		retval = (const wchar_t*)pWstr;
		RpcStringFreeW(&pWstr);
	}
	return retval;
}

