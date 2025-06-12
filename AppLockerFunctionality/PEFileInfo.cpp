#include "PEFileInfo.h"
#include "../AaronLocker_CommonUtils/StringUtils-Windows.h"
#include "../AaronLocker_CommonUtils/Wow64FsRedirection.h"
#include "../AaronLocker_CommonUtils/FileSystemUtils-Windows.h"

// ------------------------------------------------------------------------------------------


PEFileInfo::PEFileInfo()
{
	Clear();
}

void PEFileInfo::Clear()
{
	m_bIsPEFile = false;
	m_TimeDateStamp = 0;
	m_bReproducibleBuild = false;
	m_bZeroCodeSize = false;
	m_Subsystem = 0;
	m_Machine = 0;
	m_Characteristics = 0;
}


static const WORD ImageBits_Exe    = IMAGE_FILE_EXECUTABLE_IMAGE;
static const WORD ImageBits_ExeDll = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_DLL;

/// <summary>
/// Returns true if subsystem is a Win32 subsystem (console or GUI)
/// </summary>
static inline bool IsWin32Subsystem(WORD subsystem)
{
	return (subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI || subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
}

bool PEFileInfo::IsExe() const
{
	return
		m_bIsPEFile &&
		// Win32 subsystem
		IsWin32Subsystem(m_Subsystem) &&
		// Executable and not also DLL
		ImageBits_Exe == (ImageBits_ExeDll & m_Characteristics);
}

bool PEFileInfo::IsDll() const
{
	return
		m_bIsPEFile &&
		// Win32 subsystem
		IsWin32Subsystem(m_Subsystem) &&
		// Executable and also DLL
		ImageBits_ExeDll == (ImageBits_ExeDll & m_Characteristics);
}

bool PEFileInfo::IsResourceOnlyDll() const
{
	return IsDll() && m_bZeroCodeSize;
}

bool PEFileInfo::IsKernelCode() const
{
	return m_bIsPEFile && (IMAGE_SUBSYSTEM_NATIVE == m_Subsystem);
}

bool PEFileInfo::LinkTimestamp(std::wstring& sLinkTimestamp) const
{
	// If PE file and not a reproducible build, convert the TimeDateStamp value to a string
	if (m_bIsPEFile && !m_bReproducibleBuild)
	{
		// convert time_t to string
		sLinkTimestamp = TimeTToWString(m_TimeDateStamp);
		return true;
	}
	else
	{
		sLinkTimestamp.clear();
		return false;
	}
}

bool PEFileInfo::IsX86() const
{
	return m_bIsPEFile && (IMAGE_FILE_MACHINE_I386 == m_Machine);
}

bool PEFileInfo::IsX64() const
{
	return m_bIsPEFile && (IMAGE_FILE_MACHINE_AMD64 == m_Machine);
}

/*
References about reproducible builds and this technique for digging into the 
PE's debugger headers where the flag indicating reproducible build is:
https://devblogs.microsoft.com/oldnewthing/20180103-00/?p=97705
http://www.debuginfo.com/articles/debuginfomatch.html#debuginfoinpe
http://www.debuginfo.com/examples/src/DebugDir.cpp
*/
static bool GetFileOffsetFromRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Rva, DWORD& FileOffset);

bool PEFileInfo::IsPEFile(const wchar_t* szFilename, DWORD& dwFileApiError)
{
	Clear();
	dwFileApiError = 0;

	Wow64FsRedirection wow64FSRedir(true);
	std::wstring sAltName;
	HANDLE hFile = OpenExistingFile_ExtendedPath(szFilename, FILE_READ_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, dwFileApiError, sAltName);
	wow64FSRedir.Revert();
	if (INVALID_HANDLE_VALUE == hFile)
		return false;

	LARGE_INTEGER filesize = { 0 };
	if (GetFileSizeEx(hFile, &filesize))
	{
		// Make sure we can read all the bytes in a DOS header
		if (filesize.QuadPart > sizeof(IMAGE_DOS_HEADER))
		{
			// Create file mapping so it can be treated like memory. (Note that file content is mapped into RAM only if/when referenced.)
			HANDLE hFileMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, filesize.HighPart, filesize.LowPart, NULL);
			if (NULL != hFileMapping)
			{
				byte* pFilemap = (byte*)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
				if (NULL != pFilemap)
				{
					// Validate that contents match PE specification
					IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pFilemap;
					// The "MZ" header
					if (IMAGE_DOS_SIGNATURE == pDosHeader->e_magic)
					{
						// NOTE: Can be using IMAGE_NT_HEADERS32 here for 32 and 64 bit code when looking at members at the same offsets in both IMAGE_NT_HEADERS32 and IMAGE_NT_HEADERS64.
						// Also, casting values to a common type to avoid signed/unsigned-mismatch warnings, which are different on x64 and x86 builds.
						if ((unsigned long long)(filesize.QuadPart) > (unsigned long long)pDosHeader->e_lfanew + (unsigned long long)(sizeof(IMAGE_NT_HEADERS32)))
						{
							IMAGE_NT_HEADERS32* pNtHeader32 = (IMAGE_NT_HEADERS32*)(pFilemap + pDosHeader->e_lfanew);
							IMAGE_NT_HEADERS64* pNtHeader64 = (IMAGE_NT_HEADERS64*)(pFilemap + pDosHeader->e_lfanew);

							// Offset of Signature is the same in 32 and 64
							if (IMAGE_NT_SIGNATURE == pNtHeader32->Signature)
							{
								WORD optMagic = pNtHeader32->OptionalHeader.Magic;
								// Ignoring IMAGE_ROM_OPTIONAL_HDR_MAGIC. I don't know what it's ever been used for.
								m_bIsPEFile = (IMAGE_NT_OPTIONAL_HDR32_MAGIC == optMagic || IMAGE_NT_OPTIONAL_HDR64_MAGIC == optMagic);
								if (m_bIsPEFile)
								{
									bool bIs64bit = IMAGE_NT_OPTIONAL_HDR64_MAGIC == optMagic;

									// Retrieve the header values that will be used to answer all the questions.
									DWORD NumberOfRvaAndSizes;
									PIMAGE_DATA_DIRECTORY pDataDirectory;
									if (bIs64bit)
									{
										m_Machine = pNtHeader64->FileHeader.Machine;
										m_Subsystem = pNtHeader64->OptionalHeader.Subsystem;
										m_Characteristics = pNtHeader64->FileHeader.Characteristics;
										m_bZeroCodeSize = (0 == pNtHeader64->OptionalHeader.SizeOfCode);
										m_TimeDateStamp = pNtHeader64->FileHeader.TimeDateStamp;
										NumberOfRvaAndSizes = pNtHeader64->OptionalHeader.NumberOfRvaAndSizes;
										pDataDirectory = pNtHeader64->OptionalHeader.DataDirectory;
									}
									else
									{
										m_Machine = pNtHeader32->FileHeader.Machine;
										m_Subsystem = pNtHeader32->OptionalHeader.Subsystem;
										m_Characteristics = pNtHeader32->FileHeader.Characteristics;
										m_bZeroCodeSize = (0 == pNtHeader32->OptionalHeader.SizeOfCode);
										m_TimeDateStamp = pNtHeader32->FileHeader.TimeDateStamp;
										NumberOfRvaAndSizes = pNtHeader32->OptionalHeader.NumberOfRvaAndSizes;
										pDataDirectory = pNtHeader32->OptionalHeader.DataDirectory;
									}

									// Dig into debug headers (if any) to look for flag indicating reproducible build.
									// See references listed above for more information.
									if (IMAGE_DIRECTORY_ENTRY_DEBUG <= NumberOfRvaAndSizes)
									{
										PIMAGE_DATA_DIRECTORY pDataDirectoryDebug = pDataDirectory + IMAGE_DIRECTORY_ENTRY_DEBUG;
										if (0 != pDataDirectoryDebug->Size && NULL != pDataDirectoryDebug->VirtualAddress)
										{
											PIMAGE_DEBUG_DIRECTORY pDebugDirectory = NULL;
											DWORD FileOffset = 0;
											if (GetFileOffsetFromRVA((IMAGE_NT_HEADERS*)pNtHeader32, pDataDirectoryDebug->VirtualAddress, FileOffset))
											{
												pDebugDirectory = (PIMAGE_DEBUG_DIRECTORY)(pFilemap + FileOffset);

												if (((byte*)pDebugDirectory + pDataDirectoryDebug->Size) - pFilemap < filesize.QuadPart)
												{
													// Iterate through debug directories; stop if we find one for reproducible build
													for (PIMAGE_DEBUG_DIRECTORY pDD = pDebugDirectory;
														(byte*)pDD < ((byte*)pDebugDirectory + pDataDirectoryDebug->Size);
														++pDD
														)
													{
														if (IMAGE_DEBUG_TYPE_REPRO == pDD->Type)
														{
															m_bReproducibleBuild = true;
															break;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
					UnmapViewOfFile(pFilemap);
				}
				CloseHandle(hFileMapping);
			}
		}
	}

	CloseHandle(hFile);

	return m_bIsPEFile;
}

// 
// The function walks through the section headers, finds out the section 
// the given RVA belongs to, and uses the section header to determine 
// the file offset that corresponds to the given RVA 
// 
// Return value: "true" if succeeded, "false" if failed 
//
// See references listed above for more information.
//
bool GetFileOffsetFromRVA(PIMAGE_NT_HEADERS pNtHeaders, DWORD Rva, DWORD& FileOffset)
{
	// Check parameters 
	if (pNtHeaders == 0)
		return false;

	// Look up the section the RVA belongs to 
	bool bFound = false;
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		DWORD SectionSize = pSectionHeader->Misc.VirtualSize;

		if (SectionSize == 0) // compensate for Watcom linker strangeness, according to Matt Pietrek (ancient history!)
			pSectionHeader->SizeOfRawData;

		if ((Rva >= pSectionHeader->VirtualAddress) && (Rva < pSectionHeader->VirtualAddress + SectionSize))
		{
			// Yes, the RVA belongs to this section 
			bFound = true;
			break;
		}
	}

	if (!bFound)
	{
		// Section not found 
		return false;
	}

	// Look up the file offset using the section header 
	INT Diff = (INT)(pSectionHeader->VirtualAddress - pSectionHeader->PointerToRawData);
	FileOffset = Rva - Diff;

	return true;
}

