#pragma once

#include <Windows.h>
#include <string>
#include "AppLockerFileDetails.h"
#include "MsiFileInfo.h"

/// <summary>
/// Class to replicate (and go beyond) the functionality of the Get-AppLockerFileInformation cmdlet with the -Path parameter.
/// </summary>
class AppLockerFileInformation
{
public:
	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="szFilePath">Path to file to inspect</param>
	AppLockerFileInformation(const wchar_t* szFilePath);
	~AppLockerFileInformation();

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
	bool GetPublisherInfo(
		std::wstring& sPublisherName,
		std::wstring& sProductName,
		std::wstring& sBinaryName,
		WORD& wMajor,
		WORD& wMinor,
		WORD& wBuild,
		WORD& wRevision,
		std::wstring& sX500CertName,
		std::wstring& sSigningTimestamp,
		DWORD& dwApiError
	) const;

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
	bool GetPublisherInfo(
		std::wstring& sPublisherName,
		std::wstring& sProductName,
		std::wstring& sBinaryName,
		std::wstring& sBinaryVersion,
		std::wstring& sX500CertName,
		std::wstring& sSigningTimestamp,
		DWORD& dwApiError
	) const;

	/// <summary>
	/// Retrieve the Publisher information that Get-AppLockerFileInformation returns for MSI files (with additional info)
	/// </summary>
	/// <param name="sPublisherName">Output: publisher name from signing certificate</param>
	/// <param name="sX500CertName">Output: certificate subject name, X.500 format</param>
	/// <param name="sSigningTimestamp">Output: date/time that the file was signed, if signed and timestamped</param>
	/// <param name="msiFileInfo">Output: raw property values and corresponding AppLocker-formatted values. Don't use the AppLocker ones if the file isn't signed.</param>
	/// <param name="dwApiError">Output: error code from any API error that prevents the check from being performed</param>
	/// <returns>true if the file exists and is signed.</returns>
	bool GetPublisherInfo(
		std::wstring& sPublisherName,
		std::wstring& sX500CertName,
		std::wstring& sSigningTimestamp,
		MsiFileInfo_t& msiFileInfo,
		DWORD& dwApiError
	) const;

	/// <summary>
	/// Retrieve the Hash information that Get-AppLockerFileInformation returns, in string form
	/// </summary>
	/// <param name="sAuthenticodeHash">Output: Authenticode hash for Portable Executable files, SHA256 flat-file hash for non-PE files</param>
	/// <param name="sFlatFileHash">Output: SHA256 flat-file hash</param>
	/// <param name="sFilename">Output: filename without directory, upper case</param>
	/// <param name="filesize">Output: file size</param>
	/// <param name="dwApiError">Output: error code from any API that fails</param>
	/// <returns>true if successful; false otherwise</returns>
	bool GetHash256Info(
		std::wstring& sAuthenticodeHash,
		std::wstring& sFlatFileHash,
		std::wstring& sFilename,
		std::wstring& filesize,
		DWORD& dwApiError) const;

	/// <summary>
	/// Access to additional information about the file, including type of rule collection it should be associated with.
	/// </summary>
	/// <returns>Reference to interface to query additional information about the file</returns>
	const AppLockerFileDetails& FileDetails() const { return m_file; }

private:
	/// <summary>
	/// typedef for byte array for SHA256/PESHA256 hash (32 bytes)
	/// </summary>
	typedef BYTE Hash32_t[32];
	
	/// <summary>
	/// Convert 32-byte hash to a string
	/// </summary>
	static std::wstring Hash32toString(Hash32_t& hash);

	/// <summary>
	/// Retrieve the Hash information that Get-AppLockerFileInformation returns
	/// </summary>
	/// <param name="authenticodeHash">Output: Authenticode hash for Portable Executable files, SHA256 flat-file hash for non-PE files</param>
	/// <param name="flatFileHash">Output: SHA256 flat-file hash</param>
	/// <param name="sFilename">Output: filename without directory, upper case</param>
	/// <param name="filesize">Output: file size</param>
	/// <param name="dwApiError">Output: error code from any API that fails</param>
	/// <returns>true if successful; false otherwise</returns>
	bool GetHash256Info(
		Hash32_t& authenticodeHash,
		Hash32_t& flatFileHash,
		std::wstring& sFilename,
		LARGE_INTEGER& filesize,
		DWORD& dwApiError) const;

	/// <summary>
	/// Retrieve a specific file hash type
	/// </summary>
	/// <param name="guidSubject">Input: identifies the subject type</param>
	/// <param name="hash">Output: hash of the file</param>
	/// <param name="dwApiError">Output: Win32 API error code in case of error</param>
	/// <returns>true if successful, false otherwise</returns>
	bool GetHash256InfoInternal(
		GUID& guidSubject,
		Hash32_t& hash,
		DWORD dwApiError) const;

private:
	AppLockerFileDetails m_file;

private:
	// Not implemented
	AppLockerFileInformation(const AppLockerFileInformation&) = delete;
	AppLockerFileInformation& operator = (const AppLockerFileInformation&) = delete;
};

