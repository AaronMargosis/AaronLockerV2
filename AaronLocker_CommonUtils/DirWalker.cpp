/// Class to process entire directory hierarchies without recursive calls that can lead to stack exhaustion.
/// Usage:
/// void SampleFn(const wchar_t* szRootDir)
/// {
/// 	DirWalker dirWalker;
/// 	std::wstringstream strErrorInfo;
/// 	if (dirWalker.Initialize(szRootDir, strErrorInfo))
/// 	{
/// 		std::wstring sCurrDir;
/// 		while (dirWalker.GetCurrent(sCurrDir))
/// 		{
/// 			// Do things in sCurrDir - inspect files, etc.
/// 			// ...
/// 
/// 			dirWalker.DoneWithCurrent();
/// 		}
/// 	}
/// }

#include "DirWalker.h"
#include "GetFilesAndSubdirectories.h"
#include "FileSystemUtils-Windows.h"
#include "SysErrorMessage.h"
#include "Wow64FsRedirection.h"

DirWalker::DirWalker()
{
}

DirWalker::~DirWalker()
{
}

bool DirWalker::Initialize(const wchar_t* szRootDir, std::wstringstream& strErrorInfo)
{
	// Clear the deque, in case this class instance has been used before
	m_dirsToProcess.clear();

	// Ignore completely invalid input
	if (NULL == szRootDir || 0 == szRootDir[0])
	{
		return false;
	}

	// Verify that the input szRootDir is a valid, non-reparse directory
	// Disable WOW64 file system redirection. Reverts to previous state when this variable goes out of scope (function exit).
	Wow64FsRedirection fsredir(true);
	DWORD dwFileAttributes, dwLastErr;
	std::wstring sAltName;
	dwFileAttributes = GetFileAttributes_ExtendedPath(szRootDir, dwLastErr, sAltName);
	if (INVALID_FILE_ATTRIBUTES == dwFileAttributes)
	{
		strErrorInfo << L"Invalid directory " << szRootDir << L": " << SysErrorMessageWithCode(dwLastErr) << std::endl;
		return false;
	}
	if (!IsNonReparseDirectory(dwFileAttributes))
	{
		strErrorInfo << L"Not a non-reparse directory: " << szRootDir << std::endl;
		return false;
	}

	// Add starting directory to the collection of directories to process.
	m_dirsToProcess.push_back(szRootDir);
	return true;
}

bool DirWalker::GetCurrent(std::wstring& sCurrDir) const
{
	// Fail the call if the collection is empty
	if (m_dirsToProcess.empty())
	{
		sCurrDir.clear();
		return false;
	}
	else
	{
		// Return the directory at the front of the queue
		sCurrDir = m_dirsToProcess.front();
		return true;
	}
}

void DirWalker::DoneWithCurrent(bool bGetSubdirectories /*= true*/)
{
	// Nothing to do if the queue is empty
	if (!m_dirsToProcess.empty())
	{
		// Adding the current directory's subdirectories is optional
		if (bGetSubdirectories)
		{
			// Add all of the current directory's subdirectories to the queue
			std::vector<std::wstring> vSubdirs;
			GetSubdirectories(m_dirsToProcess.front(), vSubdirs);
			m_dirsToProcess.insert(m_dirsToProcess.end(), vSubdirs.begin(), vSubdirs.end());
		}

		// Remove the item at the front of the queue.
		m_dirsToProcess.pop_front();
	}
}

bool DirWalker::Done() const
{
	// Returns true if the queue is empty.
	return m_dirsToProcess.empty();
}
