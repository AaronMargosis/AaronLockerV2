#pragma once
#include <Windows.h>
#include <string>
#include "AppLockerFileDetails_ftype.h"
#include "PEFileInfo.h"

/// <summary>
/// Interface to additional AppLocker-relevant information, including apparent file type for rule collections.
/// Function methods disable WOW64 file system redirection where needed.
/// </summary>
class AppLockerFileDetails
{
public:
	/// <summary>
	/// Constructor
	/// </summary>
	/// <param name="szFilePath">Path to file to inspect</param>
	AppLockerFileDetails(const wchar_t* szFilePath);
	~AppLockerFileDetails();

	/// <summary>
	/// The file path
	/// </summary>
	const std::wstring& FilePath() const;

	/// <summary>
	/// Returns the file name by itself without the directory.
	/// </summary>
	std::wstring GetFileNameFromFilePath() const;

	/// <summary>
	/// Returns the file extension (if any) without the dot.
	/// </summary>
	std::wstring GetFileExtensionFromFilePath() const;

	/// <summary>
	/// Verifies that the instance's path has been set
	/// </summary>
	bool BasicValidation() const { return m_sFilePath.size() > 0; }

	/// <summary>
	/// Verify that the file path represents an existing file that is fully present in the target location.
	/// Where "fully present" means that it's not offline, doesn't need to be downloaded from OneDrive, etc.
	/// </summary>
	bool FileExistsFullyPresent() const;

	/// <summary>
	/// Returns the file's size
	/// </summary>
	/// <param name="filesize">Output: the file's size</param>
	/// <returns>true if the file's size can be retrieved; false otherwise</returns>
	bool FileSize(LARGE_INTEGER& filesize) const;

	/// <summary>
	/// Calls Windows API to determine whether the file is a valid MSI package, regardless of extension.
	/// </summary>
	/// <returns>true if the file is a valid MSI package; false otherwise.</returns>
	bool IsMSI() const;

	/// <summary>
	/// Indicates whether the file's extension is usually not relevant to AppLocker so that
	/// content inspection is not needed. E.g., don't want to open every .PDF to determine whether
	/// it's actually a PE file.
	/// </summary>
	/// <returns>true if the file extension is normally a non-code file.</returns>
	bool IsExtensionKnownNonCode() const;

	/// <summary>
	/// Returns the AppLocker-relevant file type based on file extension alone.
	/// </summary>
	/// <returns>Value in the AppLockerFileDetails_ftype_t enumeration</returns>
	AppLockerFileDetails_ftype_t GetFileTypeBasedOnExtension() const;

	/// <summary>
	/// Returns the AppLocker-relevant file type based on file extension or file content.
	/// If bFavorExtension is true (default), returns file type based on hardcoded set of
	/// known extensions; if extension is not known, inspects file content for EXE, DLL, or MSI
	/// content. If bFavorExtension is false, inspects file content first for EXE, DLL, or MSI 
	/// content, and if still unknown, then returns type based on file extension.
	/// If the file is a Portable Executable file, additional information can be returned through
	/// the peFileInfo parameter.
	/// </summary>
	/// <param name="peFileInfo">Output: If the file is a Portable Executable (PE) file, additional information can be returned through peFileInfo</param>
	/// <param name="bFavorExtension">Input: indicates whether to evaluate file extension first, or only after file content inspection doesn't return EXE, DLL, or MSI.</param>
	/// <param name="dwFileApiError">Output: error code from file API if opening the file fails.</param>
	/// <returns>Returns the AppLocker-relevant file type.</returns>
	AppLockerFileDetails_ftype_t GetFileType(PEFileInfo& peFileInfo, bool bFavorExtension, DWORD& dwFileApiError) const;

private:
	std::wstring m_sFilePath;
	// Extended-specifier file path, if needed. Can be modified by const member functions.
	mutable std::wstring m_sAltFilePath;

private:
	// Not implemented
	AppLockerFileDetails(const AppLockerFileDetails&) = delete;
	AppLockerFileDetails& operator = (const AppLockerFileDetails&) = delete;
};

