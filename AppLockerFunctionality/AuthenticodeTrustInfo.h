// Authenticode-signature verification, both for embedded signatures and catalog-signed files.

#pragma once

/// <summary>
/// If the file is signed, returns the same publisher name that the
/// Get-AppLockerFileInformation PowerShell cmdlet does and that AppLocker publisher rules use.
/// Also returns the full X.500 signer name, in case it can be used for diagnostics.
/// Works both for embedded signatures and catalog-signed files.
/// Disables WOW64 file system redirection for the duration of the function.
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
	std::wstring& sSigningTimestamp);
