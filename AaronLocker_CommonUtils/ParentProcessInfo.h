#pragma once


/// <summary>
/// Retrieve the PID and image path of the current process' parent process 
/// </summary>
/// <param name="dwPPID">Output: on success, the parent process' Process ID (PID)</param>
/// <param name="sParentProcessExePath">Output: on success, the image path of the parent process' executable</param>
/// <returns>true on success, false otherwise</returns>
bool GetParentProcessInformation(DWORD& dwPPID, std::wstring& sParentProcessExePath);
