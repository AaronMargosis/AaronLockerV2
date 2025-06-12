// HEX.h: 
// Convert any numeric value into a zero-filled hex-formatted string.

#pragma once
#include <iostream>
#include <iomanip>
#include <sstream>

template <typename T>
inline uint64_t HEXHelperFn_ToU64ForHEX(T num)
{
	uint64_t u64 = static_cast<uint64_t>(num);
	switch (sizeof(T))
	{
	case 1:
		return u64 & 0xff;
	case 2:
		return u64 & 0xffff;
	case 4:
		return u64 & 0xffffffff;
	default:
		return u64;
	}
}

template <typename T>
std::wstring HEXW(T num, unsigned long fieldwidth = sizeof(T) * 2, bool bUpcase = false, bool b0xPrefix = false)
{
	std::wstringstream str;
	str.fill(L'0');
	str << (b0xPrefix ? L"0x" : L"") << std::hex << (bUpcase ? std::uppercase : std::nouppercase) << std::setw(fieldwidth);
	str << HEXHelperFn_ToU64ForHEX(num);
	return str.str();
}

template <typename T>
std::string HEXA(T num, unsigned long fieldwidth = sizeof(T) * 2, bool bUpcase = false, bool b0xPrefix = false)
{
	std::stringstream str;
	str.fill('0');
	str << (b0xPrefix ? "0x" : "") << std::hex << (bUpcase ? std::uppercase : std::nouppercase) << std::setw(fieldwidth);
	str << HEXHelperFn_ToU64ForHEX(num);
	return str.str();
}

#ifdef UNICODE
#define HEX HEXW
#else
#define HEX HEXA
#endif // UNICODE


