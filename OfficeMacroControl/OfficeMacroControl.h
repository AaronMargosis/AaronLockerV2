// OfficeMacroControl.h
// Interface to apply groups of related GPO settings as cohesive units to control execution of Microsoft Office macros.

#pragma once

#include "../AaronLocker_CommonUtils/LocalGPO.h"
#include <sstream>

/// <summary>
/// Interface to apply groups of related GPO settings as cohesive units to control execution of Microsoft Office macros. 
/// </summary>
class OfficeMacroControl
{
public:
	OfficeMacroControl(bool bLgpoReadOnly = false);
	~OfficeMacroControl();

	// --------------------------------------------------------------------------------------------------------------

	/// <summary>
	/// Commit all policy changes made through the Enforce_ methods.
	/// </summary>
	/// <returns>HRESULT from the save/commit operation.</returns>
	HRESULT CommitChanges();

	/// <summary>
	/// Aggregated error information beginning from instantiation.
	/// </summary>
	/// <returns>Aggregated error information</returns>
	std::wstring ErrorInfo();

	// --------------------------------------------------------------------------------------------------------------

	/// <summary>
	/// Attack Surface Reduction Rules configuration options. (eFalse and eOff are essentially equivalent.)
	/// </summary>
	enum class eASR_options_t { eNotConfigured, eAudit, eBlock, eWarn, eOff };
	/// <summary>
	/// Options for disabling unsigned macros
	/// </summary>
	enum class eUnsignedMacro_options_t { eNotConfigured, eBasic, eReqTrustedPublisher, eStrict };

	// --------------------------------------------------------------------------------------------------------------
	// Set or clear local GPO settings

	/// <summary>
	/// Enforce a group of Attack Surface Reduction rules related to Office macro execution.
	/// </summary>
	/// <param name="option">Set to Audit, Block, or Warn mode, or disable</param>
	/// <returns>true if successful</returns>
	bool Enforce_AttackSurfaceReduction(eASR_options_t option);
	/// <summary>
	/// Configures "Block macros from running in Office files from the internet" for all Office apps.
	/// </summary>
	/// <param name="bConfigure">true to enforce, false to set Not Configured</param>
	/// <returns>true if successful</returns>
	bool Enforce_BlockMacrosFromRunningInOfficeFilesFromTheInternet(bool bConfigure);
	/// <summary>
	/// Configures "Disable all except digitally signed macros" for all Office apps, with additional
	/// options available in Office versions newer than 2019.
	/// </summary>
	/// <param name="option">
	/// eFalse: set to Not Configured
	/// eBasic: configures only "Disable all except digitally signed macros;" checkboxes all unchecked.
	/// eReqTrustedPublisher: also checks "Require macros to be signed by a trusted publisher."
	/// eStrict: also checks "Block certificates from trusted publishers that are only installed in the current user certificate store" and "Require Extended Key Usage (EKU) for certificates from trusted publishers"
	/// </param>
	/// <returns>true if successful</returns>
	bool Enforce_DisableAllUnsignedMacros(eUnsignedMacro_options_t option);
	/// <summary>
	/// Configures "Require that application add-ins are signed by Trusted Publisher" for Excel and PowerPoint (the two Office apps that support VBA add-ins)
	/// </summary>
	/// <param name="bConfigure">true to enforce, false to set Not Configured</param>
	/// <returns>true if successful</returns>
	bool Enforce_DisableUnsignedVbaAddins(bool bConfigure);
	/// <summary>
	/// Disables all trusted locations for all Office apps.
	/// </summary>
	/// <param name="bConfigure">true to enforce, false to set Not Configured</param>
	/// <returns>true if successful</returns>
	bool Enforce_DisableAllTrustedLocations(bool bConfigure);
	/// <summary>
	/// Disable Visual Basic for Applications for all Office apps.
	/// </summary>
	/// <param name="bConfigure">true to enforce, false to set Not Configured</param>
	/// <returns>true if successful</returns>
	bool Enforce_DisableAllVBA(bool bConfigure);
	/// <summary>
	/// Blocks Office apps from opening documents saved in legacy and non-Office file formats.
	/// </summary>
	/// <param name="bConfigure">true to enforce, false to set Not Configured</param>
	/// <returns>true if successful</returns>
	bool Enforce_LegacyFileBlock(bool bConfigure);
	/// <summary>
	/// Require that encrypted macros must be scanned by an AV engine before execution.
	/// </summary>
	/// <param name="bConfigure">true to enforce, false to set Not Configured</param>
	/// <returns>true if successful</returns>
	bool Enforce_ScanEncryptedMacros(bool bConfigure);

	// --------------------------------------------------------------------------------------------------------------
	// Report the GP paths and registry keys/values associated with selected options.
	// (Neither reads nor writes any actual policy/registry values.)

	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="option">Audit, Block, or Warn mode, or disable</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_AttackSurfaceReduction(eASR_options_t option, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="bConfigure">true to configure, false to set Not Configured</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_BlockMacrosFromRunningInOfficeFilesFromTheInternet(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="option">Not Configured, Basic, Require Trusted Publisher, or Strict</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_DisableAllUnsignedMacros(eUnsignedMacro_options_t option, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="bConfigure">true to configure, false to set Not Configured</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_DisableUnsignedVbaAddins(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="bConfigure">true to configure, false to set Not Configured</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_DisableAllTrustedLocations(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="bConfigure">true to configure, false to set Not Configured</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_DisableAllVBA(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="bConfigure">true to configure, false to set Not Configured</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_LegacyFileBlock(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of changes that are made with the corresponding Enforce_ method,
	/// reported as GPO editor paths/names and as registry keys/values.
	/// </summary>
	/// <param name="bConfigure">true to configure, false to set Not Configured</param>
	/// <param name="strOutput">Stream to write results to</param>
	static void Report_ScanEncryptedMacros(bool bConfigure, std::wostream& strOutput);

	// --------------------------------------------------------------------------------------------------------------
	// Report the GP paths and registry keys/values associated with selected options, and
	// the value of the actual corresponding local GPO value on the local computer.

	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_AttackSurfaceReduction(eASR_options_t option, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_BlockMacrosFromRunningInOfficeFilesFromTheInternet(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_DisableAllUnsignedMacros(eUnsignedMacro_options_t option, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_DisableUnsignedVbaAddins(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_DisableAllTrustedLocations(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_DisableAllVBA(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_LegacyFileBlock(bool bConfigure, std::wostream& strOutput);
	/// <summary>
	/// Tab-delimited output of GP editor paths/names and registry keys/values associated with
	/// the corresponding Enforce_ method, and the actual value found in the current local GPO
	/// setting, or "[NOT SET]" if value isn't set.
	/// </summary>
	void Verify_ScanEncryptedMacros(bool bConfigure, std::wostream& strOutput);


private:
	// Object used to interface with local GPO.
	LocalGPO m_lgpo;
	// Object to aggregate error information
	std::wstringstream m_strErrorInfo;

private:
	// Not implemented
	OfficeMacroControl(const OfficeMacroControl&) = delete;
	OfficeMacroControl& operator = (const OfficeMacroControl&) = delete;
};