#pragma once

#include <iostream>
#include "EmbeddedFiles.h"
#include "..\AaronLocker_CommonUtils\WindowsDirectories.h"

class CIPolicyPaths
{
public:
	// For systems that support only a single WDAC policy, the policy file goes in SiPolicy.p7b
	// in the CodeIntegrity root directory.
	//
	// For systems that support multiple WDAC policies (Win10 v1903+), the policy file has a
	// GUID name and goes into the CiPolicies\Active subdirectory of the CodeIntegrity directory.
	// The GUID file name must match the policy GUID embedded in the policy file.

	/// <summary>
	/// Return the path to the CodeIntegrity root directory.
	/// Does not verify whether the path exists.
	/// </summary>
	static const std::wstring& CodeIntegrityRootDir()
	{
		// Build the value only on first use
		static std::wstring sStringValue;
		if (0 == sStringValue.length())
		{
			sStringValue = WindowsDirectories::System32Directory() + L"\\CodeIntegrity";
		}
		return sStringValue;
	}

	/// <summary>
	/// Return the path to the CodeIntegrity active CI policies directory (for systems with multiple WDAC policy support).
	/// Does not verify whether the path exists.
	/// </summary>
	static const std::wstring& ActiveCiPoliciesDir()
	{
		// Build the value only on first use
		static std::wstring sStringValue;
		if (0 == sStringValue.length())
		{
			sStringValue = CodeIntegrityRootDir() + L"\\CiPolicies\\Active";
		}
		return sStringValue;
	}

	static const std::wstring& SinglePolicyFilePath()
	{
		// Build the value only on first use
		static std::wstring sStringValue;
		if (0 == sStringValue.length())
		{
			const std::wstring& sFileName = EmbeddedFiles::SinglePolicyFileName();
			if (sFileName.length() > 0)
			{
				sStringValue = CodeIntegrityRootDir() + L"\\" + sFileName;
			}
		}
		return sStringValue;
	}

	static const std::wstring& MultiPolicyAuditFilePath()
	{
		// Build the value only on first use
		static std::wstring sStringValue;
		if (0 == sStringValue.length())
		{
			const std::wstring& sFileName = EmbeddedFiles::MultiPolicyAuditFileName();
			if (sFileName.length() > 0)
			{
				sStringValue = ActiveCiPoliciesDir() + L"\\" + sFileName;
			}
		}
		return sStringValue;
	}

	static const std::wstring& MultiPolicyBlockingFilePath()
	{
		// Build the value only on first use
		static std::wstring sStringValue;
		if (0 == sStringValue.length())
		{
			const std::wstring& sFileName = EmbeddedFiles::MultiPolicyBlockingFileName();
			if (sFileName.length() > 0)
			{
				sStringValue = ActiveCiPoliciesDir() + L"\\" + sFileName;
			}
		}
		return sStringValue;
	}

	static void ValidateConstructedPaths()
	{
		if (
			0 == CodeIntegrityRootDir().length() ||
			0 == ActiveCiPoliciesDir().length() ||
			0 == SinglePolicyFilePath().length() ||
			0 == MultiPolicyAuditFilePath().length() ||
			0 == MultiPolicyBlockingFilePath().length()
			)
		{
			std::wcerr << L"Fatal internal program error. One or more file path strings not constructed." << std::endl;
			exit(-2);
		}
	}
};

