#pragma once

#include <Windows.h>
#include <string>

/// <summary>
/// Class to determine whether a file is a Portable Executable (PE) file, and if so,
/// retrieve information about the file.
/// </summary>
class PEFileInfo
{
public:
	/// <summary>
	/// Constructor, default dtor, cctor, assignment
	/// </summary>
	PEFileInfo();
	~PEFileInfo() = default;
	PEFileInfo(const PEFileInfo&) = default;
	PEFileInfo& operator = (const PEFileInfo&) = default;

	/// <summary>
	/// Initialize
	/// </summary>
	void Clear();

	/// <summary>
	/// Inspects file's content to determine whether it is a Portable Executable (PE) file,
	/// and if so, retrieves additional information about it, exposed through other member functions.
	/// </summary>
	/// <param name="szFilename">Input: The file to inspect</param>
	/// <param name="dwFileApiError">Output: error code from file API if opening the file fails.</param>
	/// <returns>true if the named file is a PE file; false otherwise.</returns>
	bool IsPEFile(const wchar_t* szFilename, DWORD& dwFileApiError);

	/// <summary>
	/// Returns true if the file is a Win32 user-mode executable.
	/// </summary>
	bool IsExe() const;
	/// <summary>
	/// Returns true if the file is a Win32 user-mode DLL.
	/// </summary>
	bool IsDll() const;
	/// <summary>
	/// Returns true if the file is a Win32 user-mode DLL with no code.
	/// </summary>
	bool IsResourceOnlyDll() const;
	/// <summary>
	/// Returns true if the file is native-mode code (e.g., a kernel-mode driver).
	/// </summary>
	bool IsKernelCode() const;
	/// <summary>
	/// If the file's internal linker timestamp is valid, converts it to a string and returns true.
	/// The linker timestamp is not valid if the PE file is a reproducible build.
	/// </summary>
	/// <param name="sLinkTimestamp">Output: the linker timestamp, if not a reproducible build.</param>
	/// <returns>true if the file's linker timestamp is a valid timestamp (file not a reproducible build).</returns>
	bool LinkTimestamp(std::wstring& sLinkTimestamp) const;
	/// <summary>
	/// Returns true if the file is an x86 binary.
	/// </summary>
	bool IsX86() const;
	/// <summary>
	/// Returns true if the file is an x64 (AMD64) binary.
	/// </summary>
	bool IsX64() const;

public:
	// Raw data from the PE file's headers
	
	/// <summary>
	/// true if the file is a PE file
	/// </summary>
	bool m_bIsPEFile;
	/// <summary>
	/// Value from the FileHeader.TimeDateStamp field.
	/// </summary>
	DWORD m_TimeDateStamp;
	/// <summary>
	/// True if the debug headers indicate reproducible build (and TimeDateStamp not an actual timestamp)
	/// </summary>
	bool m_bReproducibleBuild;
	/// <summary>
	/// True if the OptionalHeader.SizeOfCode field is 0.
	/// </summary>
	bool m_bZeroCodeSize;
	/// <summary>
	/// Value from the OptionalHeader.Subsystem field.
	/// </summary>
	WORD m_Subsystem;
	/// <summary>
	/// Value from the FileHeader.Machine field.
	/// </summary>
	WORD m_Machine;
	/// <summary>
	/// Value from the FileHeader.Characteristics field.
	/// </summary>
	WORD m_Characteristics;
};



