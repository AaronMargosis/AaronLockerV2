#include "pch.h"

#include <sstream>
#include <random>
#include "../AaronLocker_CommonUtils/HEX.h"
#include "GuidGenerator.h"

// A GUID (globally-unique identifier, a.k.a., universally-unique identifier or UUID) is 16 bytes (128 bits) that is 
// generated in a way that is supposed to be guaranteed to be unique across both space and time. There is an RFC that
// defines how those bits are filled, (https://www.rfc-editor.org/rfc/rfc4122.txt) but TBH I don't know whether
// Microsoft still follows this method. IIRC there was a privacy issue regarding the use of MAC addresses in the
// algorithm, so the algorithm might be different now. Windows offers an API to create new GUIDs (UuidCreate).
// This implementation does not make the same claims to universal uniqueness; instead it generates 16 bytes of
// pseudo-random data using a robust random number generator, and renders it in the standard string format for GUIDs.

// This is Microsoft's definition of a GUID structure:
//
//		typedef struct _GUID {
//			unsigned long  Data1;
//			unsigned short Data2;
//			unsigned short Data3;
//			unsigned char  Data4[8];
//		} GUID;
//
//	 Here's an example of instantiation/initialization:
//
//		static const GUID g =
//		{ 0xf3604c0c, 0xf28b, 0x4ea7, { 0xbf, 0xf3, 0x4e, 0xf3, 0x12, 0x4b, 0x1b, 0x4c } };
//
//	This is how that same data is rendered as a string:
//
//		"{F3604C0C-F28B-4EA7-BFF3-4EF3124B1B4C}"
//
// This implementation defines the structure differently to simplify conversion to string.
// Note that the order of Data5a and Data5b is important to avoid padding and alignment issues, and ensuring that the 
// size of MyGuid_t is equal to that of GUID, and also equal to the size of the four unsigned long values in the 
// GuidThing_t union.
//
typedef struct
{
	unsigned long  Data1;
	unsigned short Data2;
	unsigned short Data3;
	unsigned short Data4;
	unsigned short Data5a;
	unsigned long  Data5b;
} MyGuid_t;

// Create a union so that we can generate 16 bytes of random data with four random unsigned longs,
// and then treat that data as a GUID.
typedef union {
	MyGuid_t guid;
	unsigned long numbers[4];
} GuidThing_t;

std::wstring GuidGenerator::CreateNewGuid()
{
	std::random_device randDev;   // non-deterministic generator
	std::mt19937 generator(randDev());  // to seed mersenne twister.

	// Set up memory
	GuidThing_t guidThing = { 0 };
	// Fill it with random data
	for (size_t ixNums = 0; ixNums < 4; ++ixNums)
	{
		guidThing.numbers[ixNums] = generator();
	}
	// Render that data in the standard GUID string format
	std::wstringstream sGuid;
	sGuid
		<< HEX(guidThing.guid.Data1, 8, true, false) << L"-"
		<< HEX(guidThing.guid.Data2, 4, true, false) << L"-"
		<< HEX(guidThing.guid.Data3, 4, true, false) << L"-"
		<< HEX(guidThing.guid.Data4, 4, true, false) << L"-"
		<< HEX(guidThing.guid.Data5a, 4, true, false) << HEX(guidThing.guid.Data5b, 8, true, false);
	return sGuid.str();
}

/*
* How to generate a new string GUID using Windows APIs:

#include <rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

std::wstring GuidGenerator::CreateNewGuid()
{
	std::wstring retval;
	GUID guid;
	RPC_WSTR pWstr = NULL;
	if (RPC_S_OK == UuidCreate(&guid) && RPC_S_OK == UuidToStringW(&guid, &pWstr))
	{
		retval = (const wchar_t*)pWstr;
		RpcStringFreeW(&pWstr);
	}
	return retval;
}
*/


