#pragma once

#include <string>

/// <summary>
/// Class to manage extractable files embedded as resources in this executable.
/// </summary>
class EmbeddedFiles
{
public:
	/// <summary>
	/// Identifiers for available embedded resources
	/// </summary>
	enum File_t {
		undefined,
		Single_Policy_Audit,
		Single_Policy_Block,
		Multi_Policy_Audit,
		Multi_Policy_Blocking
	};
	/// <summary>
	/// Map file ID to corresponding string form
	/// </summary>
	static const wchar_t* FileIdToName(File_t fileId);

	/// <summary>
	/// Name of the policy file for single-policy platforms.
	/// </summary>
	static const std::wstring& SinglePolicyFileName();
	/// <summary>
	/// Name of the audit policy file for multiple-policy platforms.
	/// </summary>
	static const std::wstring& MultiPolicyAuditFileName();
	/// <summary>
	/// Name of the blocking policy file for multiple-policy platforms.
	/// </summary>
	static const std::wstring& MultiPolicyBlockingFileName();

	/// <summary>
	/// Extract an embedded resource to a target file path.
	/// </summary>
	/// <param name="fileId">Input: ID for the embedded resource to extract</param>
	/// <param name="szTargetFile">Input: file path to which to extract the resource</param>
	/// <param name="sErrorInfo">Output: error information on failure</param>
	/// <returns>true if successful, false otherwise.</returns>
	static bool Extract(File_t fileId, const wchar_t* szTargetFile, std::wstring& sErrorInfo);
};

