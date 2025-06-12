// Directory hierarchy walker

#pragma once

#include <deque>
#include <sstream>

/// <summary>
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
/// </summary>
class DirWalker
{
public:
	// Constructor
	DirWalker();
	// Destructor
	~DirWalker();

	/// <summary>
	/// Initialize directory walker instance.
	/// </summary>
	/// <param name="szRootDir">Input: root directory of hierarchy to scan</param>
	/// <param name="strErrorInfo">Output: error info (e.g., if invalid input directory</param>
	/// <returns>true if initialized successfully</returns>
	bool Initialize(const wchar_t* szRootDir, std::wstringstream& strErrorInfo);

	/// <summary>
	/// Returns the name of the current directory to process, unless no more to process
	/// </summary>
	/// <param name="sCurrDir">Output: name of the current directory to process</param>
	/// <returns>true if directory name returned, false if no more to process</returns>
	bool GetCurrent(std::wstring& sCurrDir) const;

	/// <summary>
	/// Call this method when done processing the current directory to remove the current
	/// directory from the collection of directories to process and (optionally) to add the current
	/// directory's subdirectories to the collection.
	/// </summary>
	/// <param name="bGetSubdirectories">Input: whether to add subdirectories of current directory to the collection to process</param>
	void DoneWithCurrent(bool bGetSubdirectories = true);

	/// <summary>
	/// Indicates whether all directories in the hierarchy have been processed.
	/// </summary>
	/// <returns></returns>
	bool Done() const;

private:
	// Collection of directories to process implemented as a queue in which items
	// are processed from the front of the queue and then removed, while new items
	// are added to the back of the queue.
	std::deque<std::wstring> m_dirsToProcess;

private:
	// Not implemented
	DirWalker(const DirWalker&) = delete;
	DirWalker& operator = (const DirWalker&) = delete;
};

