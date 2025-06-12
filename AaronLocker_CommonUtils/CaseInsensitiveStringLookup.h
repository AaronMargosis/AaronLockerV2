#pragma once

#include <unordered_set>
#include <string>
#include "../AaronLocker_CommonUtils/StringUtils.h"

/// <summary>
/// Fast case-insensitive hash-table lookup to determine whether a string is already in the set.
/// Add strings to the set one by one, from a NULL-terminated array, or a counted array.
/// Query the collection with "IsInSet".
/// </summary>
class CaseInsensitiveStringLookup : public std::unordered_set<std::wstring>
{
public:
	// Default implementation of constructor, destructor, copy constructor, and assignment operator
	CaseInsensitiveStringLookup() = default;
	~CaseInsensitiveStringLookup() = default;
	CaseInsensitiveStringLookup(const CaseInsensitiveStringLookup&) = default;
	CaseInsensitiveStringLookup& operator = (const CaseInsensitiveStringLookup&) = default;

	/// <summary>
	/// Initialize from an array of strings that ends with a NULL pointer
	/// </summary>
	/// <param name="ppszStrings"></param>
	void Add(const wchar_t** ppszStrings)
	{
		if (NULL == ppszStrings)
			return;
		for (; NULL != *ppszStrings; ++ppszStrings)
			Add(*ppszStrings);
	}

	/// <summary>
	/// Initialize from an array of strings of known size
	/// </summary>
	/// <param name="ppszStrings"></param>
	/// <param name="nCount"></param>
	void Add(const wchar_t** ppszStrings, size_t nCount)
	{
		if (NULL == ppszStrings)
			return;
		for (size_t ixString = 0; ixString < nCount; ++ixString)
			Add(ppszStrings[ixString]);
	}

	/// <summary>
	/// Add a string if it's not already in the collection
	/// </summary>
	/// <param name="szString"></param>
	/// <returns></returns>
	bool Add(const wchar_t* szString)
	{
		if (NULL == szString)
			return false;
		std::wstring sCandidate(szString);
		WString_To_Upper(sCandidate);
		if (0 == this->count(sCandidate))
		{
			this->insert(sCandidate);
			return true;
		}
		return false;
	}

	/// <summary>
	/// Add a string if it's not already in the collection
	/// </summary>
	/// <param name="szString"></param>
	/// <returns></returns>
	bool Add(const std::wstring& sCandidate)
	{
		return Add(sCandidate.c_str());
	}

	/// <summary>
	/// Returns true if the string is in the collection
	/// </summary>
	/// <param name="szString"></param>
	/// <returns></returns>
	bool IsInSet(const wchar_t* szString) const
	{
		if (NULL == szString)
			return false;
		std::wstring sCandidate(szString);
		WString_To_Upper(sCandidate);
		return (0 != this->count(sCandidate));
	}

	/// <summary>
	/// Returns true if the string is in the collection
	/// </summary>
	/// <param name="szString"></param>
	/// <returns></returns>
	bool IsInSet(const std::wstring& sString) const
	{
		return IsInSet(sString.c_str());
	}
};

