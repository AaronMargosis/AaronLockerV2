#include "pch.h"
#include <mssip.h>
#pragma comment(lib, "crypt32.lib")
#include <sstream>
#include "AuthenticodeTrustInfo.h"
#include "../AaronLocker_CommonUtils/AaronLocker_CommonUtils.h"
#include "AppLockerFileInformation.h"

// Constructor
AppLockerFileInformation::AppLockerFileInformation(const wchar_t* szFilePath)
	: m_file(szFilePath)
{
}

AppLockerFileInformation::~AppLockerFileInformation()
{
}

/// <summary>
/// Retrieve the Publisher information that Get-AppLockerFileInformation returns (and additional info)
/// </summary>
/// <param name="sPublisherName">Output: publisher name from signing certificate</param>
/// <param name="sProductName">Output: product name from version resource</param>
/// <param name="sBinaryName">Output: binary name (OriginalFilename version resource)</param>
/// <param name="wMajor">Output: binary file version, major number</param>
/// <param name="wMinor">Output: binary file version, minor number</param>
/// <param name="wBuild">Output: binary file version, build number</param>
/// <param name="wRevision">Output: binary file version, revision number</param>
/// <param name="sX500CertName">Output: certificate subject name, X.500 format</param>
/// <param name="sSigningTimestamp">Output: date/time that the file was signed, if signed and timestamped</param>
/// <param name="dwApiError">Output: error code from any API error that prevents the check from being performed</param>
/// <returns>true if file is signed; false otherwise</returns>
bool AppLockerFileInformation::GetPublisherInfo(
	std::wstring& sPublisherName, 
	std::wstring& sProductName, 
	std::wstring& sBinaryName, 
	WORD& wMajor, 
	WORD& wMinor, 
	WORD& wBuild, 
	WORD& wRevision,
	std::wstring& sX500CertName,
	std::wstring& sSigningTimestamp,
	DWORD& dwApiError) const
{
	// Initialize return value and output parameters
	bool retval = false;
	sPublisherName.clear();
	sProductName.clear();
	sBinaryName.clear();
	wMajor = wMinor = wBuild = wRevision = 0;
	sX500CertName.clear();
	sSigningTimestamp.clear();
	dwApiError = 0;

	//TODO: Set dwApiError on certain failures (but not normal errors such as "file not signed")

	// Disable WOW64 file system redirection for the duration of this function.
	// Automatically revert when this object goes out of scope.
	// Note: I tested whether this broad scope works or if disabling should be more tightly 
	// scoped around specific API calls. It appears to work fine this way.
	Wow64FsRedirection wow64FSRedir(true);

	if (m_file.FileExistsFullyPresent())
	{
		// Get signer information for the file.
		// The sPublisherName is what's used in publisher rules.
		// The X500 cert string is there in case we need/want it for diagnostics.
		retval = GetSignerInfo(m_file.FilePath().c_str(), sPublisherName, sX500CertName, sSigningTimestamp);
		if (retval)
		{
			// For signed files, get version information for product name, 
			// binary name (original file name), and binary file version.
			VersionInfo::GetVersionInfoForAppLocker(m_file.FilePath().c_str(), sProductName, sBinaryName, wMajor, wMinor, wBuild, wRevision);
		}
	}
	return retval;
}

/// <summary>
/// Retrieve the Publisher information that Get-AppLockerFileInformation returns (and additional info)
/// </summary>
/// <param name="sPublisherName">Output: publisher name from signing certificate</param>
/// <param name="sProductName">Output: product name from version resource</param>
/// <param name="sBinaryName">Output: binary name (OriginalFilename version resource)</param>
/// <param name="sBinaryVersion">Output: binary file version in string format a.b.c.d</param>
/// <param name="sX500CertName">Output: certificate subject name, X.500 format</param>
/// <param name="sSigningTimestamp">Output: date/time that the file was signed, if signed and timestamped</param>
/// <param name="dwApiError">Output: error code from any API error that prevents the check from being performed</param>
/// <returns>true if file is signed; false otherwise</returns>
bool AppLockerFileInformation::GetPublisherInfo(
	std::wstring& sPublisherName, 
	std::wstring& sProductName, 
	std::wstring& sBinaryName, 
	std::wstring& sBinaryVersion,
	std::wstring& sX500CertName,
	std::wstring& sSigningTimestamp,
	DWORD& dwApiError) const
{
	// Call the other implementation, then build the sBinaryVersion string from the returned WORD values
	WORD wMajor, wMinor, wBuild, wRevision;
	bool retval = GetPublisherInfo(sPublisherName, sProductName, sBinaryName, wMajor, wMinor, wBuild, wRevision, sX500CertName, sSigningTimestamp, dwApiError);
	if (retval)
	{
		wchar_t szVersionBuf[32] = { 0 };
		wsprintfW(szVersionBuf, L"%u.%u.%u.%u", wMajor, wMinor, wBuild, wRevision);
		sBinaryVersion = szVersionBuf;
	}
	else
	{
		sBinaryVersion.clear();
	}
	return retval;
}

/// <summary>
/// Retrieve the Publisher information that Get-AppLockerFileInformation returns for MSI files (with additional info)
/// </summary>
/// <param name="sPublisherName">Output: publisher name from signing certificate</param>
/// <param name="sX500CertName">Output: certificate subject name, X.500 format</param>
/// <param name="sSigningTimestamp">Output: date/time that the file was signed, if signed and timestamped</param>
/// <param name="msiFileInfo">Output: raw property values and corresponding AppLocker-formatted values. Don't use the AppLocker ones if the file isn't signed.</param>
/// <param name="dwApiError">Output: error code from any API error that prevents the check from being performed</param>
/// <returns>true if the file exists and is signed.</returns>
bool AppLockerFileInformation::GetPublisherInfo(std::wstring& sPublisherName, std::wstring& sX500CertName, std::wstring& sSigningTimestamp, MsiFileInfo_t& msiFileInfo, DWORD& dwApiError) const
{
	// Initialize return value and output parameters
	bool retval = false;
	sPublisherName.clear();
	msiFileInfo.clear();
	dwApiError = 0;

	//TODO: Set dwApiError on certain failures (but not normal errors such as "file not signed")

	// Disable WOW64 file system redirection for the duration of this function.
	// Automatically revert when this object goes out of scope.
	// Note: I tested whether this broad scope works or if disabling should be more tightly 
	// scoped around specific API calls. It appears to work fine this way.
	Wow64FsRedirection wow64FSRedir(true);

	// Don't inspect the file if it needs to be downloaded
	if (m_file.FileExistsFullyPresent())
	{
		// Get signer information for the file.
		// The sPublisherName is what's used in publisher rules.
		// The X500 cert string is there in case we need/want it for diagnostics.
		retval = GetSignerInfo(m_file.FilePath().c_str(), sPublisherName, sX500CertName, sSigningTimestamp);
		// Pull the MSI properties no matter what. The raw values can be used but the AppLocker-formatted ones shouldn't be.
		MsiFileInfo::Get(m_file.FilePath().c_str(), msiFileInfo);
	}
	return retval;
}

/// <summary>
/// Retrieve the Hash information that Get-AppLockerFileInformation returns
/// </summary>
/// <param name="hash">Output: Authenticode hash for Portable Executable files, SHA256 flat-file hash for non-PE files</param>
/// <param name="sFilename">Output: filename without directory, upper case</param>
/// <param name="filesize">Output: file size</param>
/// <param name="dwApiError">Output: error code from any API that fails</param>
/// <returns>true if successful; false otherwise</returns>
bool AppLockerFileInformation::GetHash256Info(
	Hash32_t& hash, 
	std::wstring& sFilename, 
	LARGE_INTEGER& filesize,
	DWORD& dwApiError) const
{
	bool retval = false;

	// Disable WOW64 file system redirection for the duration of this function.
	// Automatically revert when this object goes out of scope.
	// Note: I tested whether this broad scope works or if disabling should be more tightly 
	// scoped around specific API calls. It appears to work fine this way.
	Wow64FsRedirection wow64FSRedir(true);

	// Verify that file exists (and is a file) before proceeding
	if (!m_file.FileExistsFullyPresent())
		return false;
	// If can't get file size, don't proceed
	if (!m_file.FileSize(filesize))
		return false;
	// It's not possible to get the AppLocker hash of a 0-length file; don't proceed.
	if (0 == filesize.QuadPart)
		return false;
	// Get the filename information
	sFilename = m_file.GetFileNameFromFilePath();

	// Get the same hash that Get-AppLockerFileInformation returns and that
	// Sysinternals Sigcheck reports as "PE256".
	// Relevant information:
	// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#appendix-a-calculating-authenticode-pe-image-hash
	// https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx
	//

	// Get the GUID required for the call to CryptSIPCreateIndirectData.
	// I've seen two GUIDs come back from this call:
	// * c689aab8-8e78-11d0-8c47-00c04fc295ee for PE files
	// * de351a42-8e59-11d0-8c47-00c04fc295ee for non-PE files
	// This GUID *appears* to drive whether we get an Authenticode hash or a flat-file hash.
	GUID guidSubject = { 0 };
	//TODO: Although documentation fails to mention it, this API can fail with ERROR_SHARING_VIOLATION. If that happens it should be captured.
	BOOL ret = CryptSIPRetrieveSubjectGuidForCatalogFile(m_file.FilePath().c_str(), NULL, &guidSubject);
	if (!ret)
	{
		dwApiError = GetLastError();
		return false;
	}

	//TODO: Set dwApiError on other failures

	HCRYPTPROV hCryptProv = NULL;
	if (CryptAcquireContextW(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		SIP_SUBJECTINFO subjectInfo = { 0 };
		subjectInfo.cbSize = sizeof(subjectInfo);
		subjectInfo.pgSubjectType = &guidSubject;
		subjectInfo.pwsFileName = m_file.FilePath().c_str();
		//subjectInfo.pwsDisplayName = szFilename; // Display name not needed AFAICT
		subjectInfo.hProv = hCryptProv;
		// Specify SHA256.
		// The structure demands a non-const pointer to OID string, so create a writable buffer.
		char szObjId[] = szOID_NIST_sha256;
		subjectInfo.DigestAlgorithm.pszObjId = szObjId;
		subjectInfo.DigestAlgorithm.Parameters.cbData = 0;
		subjectInfo.DigestAlgorithm.Parameters.pbData = NULL;
		/*
		* With SPC_EXC_PE_PAGE_HASHES_FLAG seems to exclude from hashing the portions of the PE
		* file that Authenticode hashes exclude. From the documentation:
		* "Exclude page hashes when creating SIP indirect data for the PE file. [...]
		* If neither the SPC_EXC_PE_PAGE_HASHES_FLAG or the SPC_INC_PE_PAGE_HASHES_FLAG 
		* flag is specified, the value set with the WintrustSetDefaultIncludePEPageHashes 
		* function is used for this setting. The default for this setting is to exclude page 
		* hashes when creating SIP indirect data for PE files."
		*/
		subjectInfo.dwFlags = SPC_EXC_PE_PAGE_HASHES_FLAG;
		subjectInfo.dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
		subjectInfo.psFlat = NULL;
		subjectInfo.psCatMember = NULL;
		subjectInfo.psBlob = NULL;
		subjectInfo.pClientData = NULL;

		// First call, determine amount of memory required to receive data
		DWORD cbIndirectData = 0;
		ret = CryptSIPCreateIndirectData(&subjectInfo, &cbIndirectData, NULL);
		if (ret && cbIndirectData > 0)
		{
			// Allocate the memory to retrieve the data
			byte* pBuffer = new byte[cbIndirectData];
			SIP_INDIRECT_DATA* pData = (SIP_INDIRECT_DATA*)pBuffer;
			// Second call, get the hash
			ret = CryptSIPCreateIndirectData(&subjectInfo, &cbIndirectData, pData);
			if (ret)
			{
				// Make sure the size of the returned hash is the size we're expecting.
				if (sizeof(hash) == pData->Digest.cbData)
				{
					// Copy hash bytes into the output parameter.
					CopyMemory(hash, pData->Digest.pbData, sizeof(hash));
					// And indicate success
					retval = true;
				}
			}
			delete[] pBuffer;
		}

		CryptReleaseContext(hCryptProv, 0);
	}

	return retval;
}

/// <summary>
/// Retrieve the Hash information that Get-AppLockerFileInformation returns, in string form
/// </summary>
/// <param name="hash">Output: Authenticode hash for Portable Executable files, SHA256 flat-file hash for non-PE files</param>
/// <param name="sFilename">Output: filename without directory, upper case</param>
/// <param name="filesize">Output: file size</param>
/// <param name="dwApiError">Output: error code from any API that fails</param>
/// <returns>true if successful; false otherwise</returns>
bool AppLockerFileInformation::GetHash256Info(
	std::wstring& hash, 
	std::wstring& sFilename, 
	std::wstring& filesize,
	DWORD& dwApiError) const
{
	hash.clear();
	sFilename.clear();
	filesize.clear();
	dwApiError = 0;

	Hash32_t binaryHash;
	LARGE_INTEGER binaryFilesize;

	bool retval = GetHash256Info(binaryHash, sFilename, binaryFilesize, dwApiError);
	if (retval)
	{
		std::wstringstream strHash;
		strHash << L"0x";
		for (size_t ixHash = 0; ixHash < sizeof(AppLockerFileInformation::Hash32_t); ++ixHash)
			strHash << HEX(binaryHash[ixHash], 2, true);
		hash = strHash.str();
	}

	// Return file size even if 0.
	std::wstringstream strFilesize;
	strFilesize << binaryFilesize.QuadPart;
	filesize = strFilesize.str();

	return retval;
}

