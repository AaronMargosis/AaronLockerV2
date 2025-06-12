#pragma once

/// <summary>
/// Enumeration of file types for AppLocker rule collections.
/// </summary>
enum class AppLockerFileDetails_ftype_t {
	/// <summary>
	/// ft_Unknown: indeterminate file type, probably not relevant to AppLocker.
	/// Note that Portable Executable (PE) files that do not run in the Windows GUI or
	/// Console subsystems, such as kernel drivers, are reported as ft_Unknown.
	/// </summary>
	ft_Unknown,

	/// <summary>
	/// ft_KnownNonCodeExtension: a file extension that is (almost) always associated with
	/// files that never contain code (e.g., .pdf). Although an executable file can be
	/// hidden behind any file extension, for the purposes of AppLocker rules it's usually
	/// not worth the expense of inspecting every file for executable content.
	/// </summary>
	ft_KnownNonCodeExtension,

	/// <summary>
	/// ft_EXE: A Portable Executable (PE) file that runs in the Windows GUI or Console 
	/// subsystems and that is not a DLL. Rules in the EXE rule collection apply to these files.
	/// </summary>
	ft_EXE,

	/// <summary>
	/// ft_DLL: A Portable Executable (PE) file that runs in the Windows GUI or Console 
	/// subsystems and that is a DLL and contains executable code. Rules in the DLL rule 
	/// collection apply to these files.
	/// </summary>
	ft_DLL,

	/// <summary>
	/// ft_ResourceOnlyDLL: A Portable Executable (PE) file that runs in the Windows GUI or 
	/// Console subsystems and that is a DLL but contains no executable code. Whether to create 
	/// rules in the DLL rule collection depends on use and needs to be verified through testing. 
	/// If the process that loads the DLL explicitly loads it as a data file (e.g., see 
	/// LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE) then AppLocker doesn't 
	/// apply rules. However, if the developer who wrote the code doesn't explicitly do that,
	/// AppLocker will apply rules in the DLL rule collection to the file.
	/// The reason here for distinguishing resource-only DLLs is advisory. Where processes do
	/// the right thing, you can reduce the number of DLL rules that need to be implemented.
	/// </summary>
	ft_ResourceOnlyDLL,

	/// <summary>
	/// ft_MSI: A Windows Installer package (typically .msi but can also be .mst or .msp).
	/// Rules in the MSI rule collection apply to these files.
	/// Determination of ft_MSI is based on file extension by default, but can be verified
	/// through file content inspection.
	/// </summary>
	ft_MSI,

	/// <summary>
	/// ft_Script: A file that runs in an AppLocker-compatible scripting host process, which
	/// is responsible for enforcing rules in the Script rules collection. Determination of 
	/// ft_Script is based solely on file extension, as it's not feasible to determine whether 
	/// a given text file happens to be a batch file or a VBScript file based on content.
	/// </summary>
	ft_Script,

	/// <summary>
	/// ft_ScriptJS: A .js file. While .js can be executed in the AppLocker-compatible Windows 
	/// Script Host (e.g., by wscript.exe or cscript.exe), most .js files are processed by
	/// non-AppLocker-aware processes such as web browsers (which impose other restrictions).
	/// Scans of user profiles often turn up TONS of .js files; creating rules for all those
	/// files is unnecessary and costly. 
	/// If a .js file is executed by Windows Script Host, the Script rules collection comes 
	/// into play.
	/// </summary>
	ft_ScriptJS,

	/// <summary>
	/// ft_Appx: "Packaged" apps; a.k.a., "modern", Universal Windows Platform (UWP).
	/// Determination of ft_Appx is based only on file extension, and is not used by this product at this time.
	/// </summary>
	ft_Appx
};

