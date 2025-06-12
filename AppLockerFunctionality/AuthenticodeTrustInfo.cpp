// Authenticode-signature verification, both for embedded signatures and catalog-signed files.
// 
// In addition to API documentation on docs.microsoft.com, these examples are helpful:
// https://github.com/microsoft/Windows-classic-samples/blob/master/Samples/Security/CodeSigning/cpp/codesigning.cpp
// https://github.com/microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/security/cryptoapi/VerifyNameTrust/VerifyNameTrust/VerifyNameTrust.cpp
//

#include "pch.h"
#include <WinTrust.h>
#include <SoftPub.h>
#include <mscat.h>
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#include <iostream>
#include <sstream>
#include <locale>
#include "../AaronLocker_CommonUtils/StringUtils-Windows.h"
#include "AuthenticodeTrustInfo.h"


/// <summary>
/// Helper function that converts the input FILETIME into a string unless it's "too new" (less than one second ago).
/// </summary>
/// <param name="ftTimestamp">Input: FILETIME representing a signing timestamp or the current time.</param>
/// <returns>String representing timestamp if more than one second in the past; empty string otherwise.</returns>
std::wstring TimestampToStringIfValid(const FILETIME& ftTimestamp)
{
	std::wstring retval;
	ULARGE_INTEGER liTimestamp;
	liTimestamp.HighPart = ftTimestamp.dwHighDateTime;
	liTimestamp.LowPart = ftTimestamp.dwLowDateTime;
	if (0 != liTimestamp.QuadPart)
	{
		FILETIME ftNow;
		ULARGE_INTEGER liNow;
		GetSystemTimeAsFileTime(&ftNow);
		liNow.HighPart = ftNow.dwHighDateTime;
		liNow.LowPart = ftNow.dwLowDateTime;
		// Unsigned comparison - don't do subtraction if it will result in "negative"
		if (liNow.QuadPart > liTimestamp.QuadPart)
		{
			// FILETIME's units are 100 nanoseconds; 10 * 1000 * 1000 = one second.
			if (liNow.QuadPart - liTimestamp.QuadPart > 10 * 1000 * 1000)
			{
				retval = FileTimeToWString(ftTimestamp);
			}
		}
	}
	return retval;
}

/// <summary>
/// If the specified file has an embedded signature, returns an AppLocker-compatible publisher name,
/// and an X.500-formatted signer name.
/// </summary>
/// <param name="szFilename">Input: file to verify</param>
/// <param name="sAppLockerPublisherName">Output: AppLocker-compatible publisher name</param>
/// <param name="sX500CertSignerName">Output: X.500-formatted certificate signer name</param>
/// <param name="sSigningTimestamp">Output: date/time that the file was signed, if signed and timestamped</param>
/// <returns>true if the file contains a trusted publisher signature, false otherwise</returns>
bool GetEmbeddedSignatureInfo(
	const wchar_t* szFilename, 
	std::wstring& sAppLockerPublisherName, 
	std::wstring& sX500CertSignerName,
	std::wstring& sSigningTimestamp)
{
	// Initialize return value and output parameters.
	bool retval = false;
	sAppLockerPublisherName.clear();
	sX500CertSignerName.clear();
	sSigningTimestamp.clear();

	// The file to inspect
	WINTRUST_FILE_INFO wtfi = { 0 };
	wtfi.cbStruct = sizeof(wtfi);
	wtfi.pcwszFilePath = szFilename;

	// Authenticode policy provider
	GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA wtd = { 0 };
	wtd.cbStruct = sizeof(wtd);
	wtd.dwUIChoice = WTD_UI_NONE;
	wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN; // WTD_REVOKE_NONE
	wtd.dwUnionChoice = WTD_CHOICE_FILE;
	wtd.pFile = &wtfi;
	wtd.dwStateAction = WTD_STATEACTION_VERIFY;

	// WinVerifyTrust reports only embedded signature information.
	if (0 == WinVerifyTrust(HWND(INVALID_HANDLE_VALUE), &guid, &wtd))
	{
		CRYPT_PROVIDER_DATA* pProvData = WTHelperProvDataFromStateData(wtd.hWVTStateData);
		if (NULL != pProvData)
		{
			CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(pProvData, 0, FALSE, 0);
			if (NULL != pProvSigner)
			{
				// If the signature is timestamped, sftVerifyAsOf contains the date/time of the timestamp as a FILETIME,
				// and we want to return that as a human-readable date/time string.
				// If the signature is not timestamped, sftVerifyAsOf is set to the current date/time, which we don't want.
				// So, assume that any date/time more than a second before now is a signing timestamp, and anything less
				// than a second old isn't.
				// There are more robust ways to get this information, but Microsoft's current documentation is obsolete.
				// What's documented here:
				// https://docs.microsoft.com/en-us/troubleshoot/windows/win32/get-information-authenticode-signed-executables
				// doesn't work with SHA-256 signatures. There are various examples online that are purported to work, but
				// it's not clear whether they are correct and reliable. This should work with very good reliability, and
				// it's certainly simple to code.
				sSigningTimestamp = TimestampToStringIfValid(pProvSigner->sftVerifyAsOf);

				/*
				* Extensively tested signatures with a variety of OID attributes present and absent, and verified the values returned by:
				*     $pubname = (Get-AppLockerFileInformation -Path $filename).Publisher.PublisherName
				* $pubname is always upper-cased, and prefers to be of this form and in this order:
				*     O=MY COMPANY, L=ARLINGTON, S=VIRGINIA, C=US
				* $pubname must always have O= and at least one of L=, S=, and C=. So these are possible valid results:
				*     O=MY COMPANY, L=ARLINGTON
				*     O=MY COMPANY, S=VIRGINIA, C=US
				* but these are not (unless these are also the exact X.500 names):
				*     O=MY COMPANY
				*     L=ARLINGTON, S=VIRGINIA, C=US
				* If the certificate cannot return values for O= and at least one of L=, S=, and C=, then the
				* Get-AppLockerFileInformation cmdlet uses the X.500 signer name (upper-cased) and in original order,
				* as retrieved by the below code.
				* 
				* Also tested with special characters in the subject DN, such as those described in the following link,
				* and confirmed that this code's result is identical with that of Get-AppLockerFileInformation:
				* https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certnametostrw
					Comma (,)
					Plus sign (+)
					Equal sign (=)
					Inch mark (")
					Backslash followed by the letter n (\n)
					Less than sign (<)
					Greater than sign (>)
					Number sign (#)
					Semicolon (;)
				*/
				// Get the publisher's certificate from the chain context
				PCCERT_CHAIN_CONTEXT pChainContext = pProvSigner->pChainContext;
				PCERT_SIMPLE_CHAIN pChain = pChainContext->rgpChain[0];
				PCCERT_CONTEXT pCertContext = pChain->rgpElement[0]->pCertContext;

				// The OIDs used in AppLocker publisher name specs
				static const LPCSTR PublisherAttributeObjId[] = {
					// 0 - O=
					szOID_ORGANIZATION_NAME,
					// 1 - L=
					szOID_LOCALITY_NAME,
					// 2 - S=
					szOID_STATE_OR_PROVINCE_NAME,
					// 3 - C=
					szOID_COUNTRY_NAME
				};
				// Labels used with the above names, and separating commas. "O=" will always be first in a constructed publisher name
				static const LPCWSTR PublisherLabel[] = {
					L"O=",
					L", L=",
					L", S=",
					L", C="
				};

				// Pre-allocate plenty of buffer rather than allocating/freeing each time
				const DWORD cchNameString = 1024;
				wchar_t namebuf[cchNameString] = { 0 };
				DWORD dwChars;
				// OID has to be in a non-const buffer. Allocate it once here, large enough for the longest OID.
				char oidbuf[20] = { 0 };
				// wstringstream for building the publisher name
				std::wstringstream str;
				// Create a locale for correct upper-casing of returned text.
				// AppLocker upper-cases names in publisher rules...
				std::locale loc("");
				// Get each of the specified attributes from the certificate, and build the
				// AppLocker-compatible publisher name.
				bool bHasOrg = false, bHasMore = false;
				for (size_t ixOid = 0; ixOid < sizeof(PublisherAttributeObjId) / sizeof(PublisherAttributeObjId[0]); ++ixOid)
				{
					// Copy the current OID into the non-const buffer.
					strcpy_s(oidbuf, PublisherAttributeObjId[ixOid]);
					dwChars = CertGetNameStringW(
						pCertContext,
						CERT_NAME_ATTR_TYPE,
						0,
						oidbuf,
						namebuf,
						cchNameString);
					// Documentation for CertGetNameStringW says it returns 1 or greater. Check anyway.
					if (dwChars > 1)
					{
						// Track whether we have O= plus one more
						if (0 == ixOid)
						{
							bHasOrg = true;
						}
						else
						{
							bHasMore = true;
						}
						// Convert this name to upper case. (Don't use the default "C" locale.)
						for (DWORD ixChar = 0; ixChar < dwChars - 1; ++ixChar)
							namebuf[ixChar] = std::toupper(namebuf[ixChar], loc);
						// Add the returned attribute name into the publisher name along with preceding label
						str << PublisherLabel[ixOid] << namebuf;
					}
				}

				// Get the X.500 certificate signer name.
				namebuf[0] = L'\0';
				dwChars = CertNameToStrW(
					pCertContext->dwCertEncodingType,
					&pCertContext->pCertInfo->Subject,
					CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
					namebuf,
					cchNameString);
				// Return this string exactly as retrieved, without upper-casing.
				sX500CertSignerName = namebuf;

				// Return result through the AppLocker Publisher output parameter.
				// If the certificate had an O= and at least one more of L=, S=, and C=, use the constructed value.
				// Otherwise, upper-case the X500 name and return that.
				if (bHasOrg && bHasMore)
				{
					sAppLockerPublisherName = str.str();
				}
				else
				{
					// Upper-case the X500 name that was just returned from CertNameToStrW.
					if (dwChars > 0)
					{
						for (DWORD ixChar = 0; ixChar < dwChars - 1; ++ixChar)
							namebuf[ixChar] = std::toupper(namebuf[ixChar], loc);
					}
					sAppLockerPublisherName = namebuf;
				}

				retval = true;
			}
		}
	}

	// Any hWVTStateData must be released by a call with close.
	wtd.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &guid, &wtd);

	return retval;
}

/// <summary>
/// If the hash of the input file is in a registered catalog file, return the path of that catalog file.
/// </summary>
/// <param name="szFilename">Input: file to inspect</param>
/// <param name="sCatalogFile">Output: path to registered catalog file with that hash</param>
/// <returns>true if the hash of the input file is in a registered catalog file; false otherwise</returns>
bool FindCatalogFile(const wchar_t* szFilename, std::wstring& sCatalogFile)
{
	// Initialize return value and output parameter
	bool retval = false;
	sCatalogFile.clear();

	// Get the file, with permission to read its data
	HANDLE hFile = CreateFileW(szFilename, FILE_READ_DATA, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE != hFile)
	{
		// Note that Microsoft samples show CryptCATAdminAcquireContext2 and CryptCATAdminCalcHashFromFileHandle2,
		// but these are not available on Windows 7. Debugger analysis of secpol.msc indicates that the AppLocker
		// interface doesn't use the newer APIs even on Windows 10.

		BOOL ret;
		HCATADMIN hCatAdmin = NULL;
		ret = CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0);
		if (ret)
		{
			// Allocate plenty of buffer to get the hash, rather than calling the API twice and allocating
			// the memory. 128 should be plenty; on Windows 10 I've observed the hash being 20 bytes.
			byte hash[128] = { 0 };
			DWORD cbHash = 128;
			ret = CryptCATAdminCalcHashFromFileHandle(hFile, &cbHash, hash, 0);
			if (ret)
			{
				// Just use the first catalog returned. Don't enumerate.
				HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, cbHash, 0, NULL);
				if (NULL != hCatInfo)
				{
					CATALOG_INFO catInfo = { 0 };
					catInfo.cbStruct = sizeof(catInfo);
					ret = CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0);
					if (ret)
					{
						// Get the catalog file name.
						sCatalogFile = catInfo.wszCatalogFile;
						retval = true;
					}
				}
				CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
			}
			CryptCATAdminReleaseContext(hCatAdmin, 0);
		}
		CloseHandle(hFile);
	}

	return retval;
}

/// <summary>
/// If the file is signed, returns the same publisher name that the
/// Get-AppLockerFileInformation PowerShell cmdlet does and that AppLocker publisher rules use.
/// Also returns the full X.500 signer name, in case it can be used for diagnostics.
/// Works both for embedded signatures and catalog-signed files.
/// </summary>
/// <param name="szFilename">Input: file to verify</param>
/// <param name="sAppLockerPublisherName">Output: AppLocker-compatible publisher name</param>
/// <param name="sX500CertSignerName">Output: X.500-formatted certificate signer name</param>
/// <param name="sSigningTimestamp">Output: date/time that the file was signed, if signed and timestamped</param>
/// <returns>true if the file is signed by a trusted publisher, false otherwise</returns>
bool GetSignerInfo(
	const wchar_t* szFilename, 
	std::wstring& sAppLockerPublisherName, 
	std::wstring& sX500CertSignerName,
	std::wstring& sSigningTimestamp)
{
	// If the file has an embedded signature, return the information from its signer.
	bool retval = GetEmbeddedSignatureInfo(szFilename, sAppLockerPublisherName, sX500CertSignerName, sSigningTimestamp);
	if (!retval)
	{
		// If the file does not have an embedded signature, see whether its hash is in a registered/signed catalog file.
		// If it is, return the embedded signature information from that catalog file.
		std::wstring sCatalogFile;
		if (FindCatalogFile(szFilename, sCatalogFile))
		{
			retval = GetEmbeddedSignatureInfo(sCatalogFile.c_str(), sAppLockerPublisherName, sX500CertSignerName, sSigningTimestamp);
		}
	}
	return retval;
}




