#pragma once

/// <summary>
/// Class to disable WOW64 file system redirection that automatically cleans up in the destructor;
/// i.e., when the class instance goes out of scope.
/// Operative only in a 32-bit process on 64-bit Windows. No-op anyplace else.
/// 
/// Class instances can be nested, but they must be reverted in the opposite order of their disabling.
/// Note that this implementation doesn't count the number of .Disable() calls on a single class instance, 
/// so if the caller invokes .Disable() five times on an object, the first call to .Revert() will revert 
/// to previous state.
/// </summary>
class Wow64FsRedirection
{
public:
	/// <summary>
	/// Class constructor; optionally disable WOW64 file system redirection during construction
	/// </summary>
	/// <param name="bDisableNow">if true, disables WOW64 redirection immediately</param>
	explicit Wow64FsRedirection(bool bDisableNow = false) : m_OldValue(NULL), m_bDisabled(false)
	{
		if (bDisableNow)
		{
			Disable();
		}
	}
	
	/// <summary>
	/// Class destructor; reverts WOW64 FS redirection if it was disabled.
	/// </summary>
	~Wow64FsRedirection() { Revert(); }

	/// <summary>
	/// Disables WOW64 file system redirection
	/// </summary>
	void Disable()
	{
		// Don't disable again if it's currently disabled.
		if (!m_bDisabled)
		{
			Wow64DisableWow64FsRedirection(&m_OldValue);
			m_bDisabled = true;
		}
	}
	/// <summary>
	/// Reverts WOW64 FS redirection if it was disabled.
	/// </summary>
	void Revert()
	{
		if (m_bDisabled)
		{
			Wow64RevertWow64FsRedirection(m_OldValue);
			m_bDisabled = false;
		}
		m_OldValue = NULL;
	}

private:
	PVOID m_OldValue;
	bool m_bDisabled;

private:
	// Not implemented
	Wow64FsRedirection(const Wow64FsRedirection&) = delete;
	Wow64FsRedirection& operator = (const Wow64FsRedirection&) = delete;
};

