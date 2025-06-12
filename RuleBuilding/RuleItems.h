// Class hierarchy to represent AppLocker Path, Publisher, and Hash rules.
//

#pragma once
//#include "../AaronLocker_EndpointScanLogic/AaronLocker_EndpointScanLogic.h"
#include "../AppLockerFunctionality/AppLockerFileDetails_ftype.h"
#include "../AaronLocker_EndpointScanLogic/EndpointScan_Structs.h"


// Single definitions of commonly-used strings, to minimize use of string literals throughout code.
// "*"
const std::wstring& sStar();
// "\*"
const std::wstring& sBackslashStar();
// "S-1-1-0"
const std::wstring& SidEveryone();
// "S-1-5-32-544" -- called "BUILTIN\Administrators" on US-English
const std::wstring& SidAdministrators();
// "S-1-3-0" -- called "CREATOR OWNER" on US-English
const std::wstring& SidCreatorOwner();

/// <summary>
/// The string that represents AppLocker's representation of the Microsoft publisher name
/// for EXE, DLL, MSI, and Script (everything but AppX):
/// "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
/// (AppLocker uses just portions of the cert subject name for non-AppX, but the full cert subject name for AppX.)
/// </summary>
const std::wstring& MicrosoftPublisher();

/// <summary>
/// The string that represents AppLocker's representation of the Microsoft publisher name
/// for AppX not part of Windows:
/// "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
/// (AppLocker uses just portions of the cert subject name for non-AppX, but the full cert subject name for AppX.)
/// </summary>
const std::wstring& MicrosoftAppxPublisher();

/// <summary>
/// The string that represents AppLocker's representation of the Microsoft Windows publisher
/// for AppX:
/// "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
/// (AppLocker uses just portions of the cert subject name for non-AppX, but the full cert subject name for AppX.)
/// </summary>
const std::wstring& MicrosoftWindowsAppxPublisher();


// ------------------------------------------------------------------------------------------

/// <summary>
/// Pure virtual base class for all rule items.
/// </summary>
class RuleItem
{
public:
	/// <summary>
	/// Rule collections
	/// </summary>
	enum class Collection_t {
		NotSet,
		Exe,
		Dll,
		Msi,
		Script,
		Appx,
		All
	};

	/// <summary>
	/// Properties common to all AppLocker rule items (public visibility)
	/// </summary>
	std::wstring m_sName, m_sDescription;
	std::wstring m_sUserOrGroupSid;
	bool m_bAllow; // true for Allow, false for Deny
	Collection_t m_collection;

private:
	/// <summary>
	/// GUID is created only on first need; if it's never needed it's not created.
	/// Anything accessing this property should go through the public Guid() method.
	/// Note that "mutable" means it can be modified in const functions.
	/// </summary>
	mutable std::wstring m_sGuid;

public:
	/// <summary>
	/// Returns unique ID for the rule item. Created on first access, not on object construction.
	/// <param name="bForceNew">If true, forces creation of a new GUID even if one already exists.</param>
	/// <returns>Reference to the GUID string</returns>
	const std::wstring& Guid(bool bForceNew = false) const;

public:
	/// <summary>
	/// Returns true if the rule covers the input file.
	/// (Applies only if the rule is defined for "Everyone".)
	/// Pure virtual - must be implemented by a derived class.
	/// </summary>
	virtual bool Match(const FileDetails_t&) const = 0;

	/// <summary>
	/// Performs basic validation of the rule item.
	/// Pure virtual - must be implemented by a derived class.
	/// </summary>
	virtual bool Valid() const = 0;

	/// <summary>
	/// Writes the XML representation of the rule item, including a new GUID ID, to the stream.
	/// Enforces length limits in AppLocker XSD: https://docs.microsoft.com/en-us/windows/client-management/mdm/applocker-xsd
	/// </summary>
	/// <param name="os">Output stream to write XML into</param>
	/// <param name="bForceNewGuid">If true, forces creation of a new GUID even if one already exists.</param>
	void ToXml(std::wostream& os, bool bForceNewGuid = false) const;

	/// <summary>
	/// Maps an AppLockerFileDetails_ftype_t value to the corresponding AppLocker rule collection.
	/// </summary>
	static Collection_t FromFType(AppLockerFileDetails_ftype_t ftype);

	/// <summary>
	/// Maps a rule collection type to its string form
	/// </summary>
	static const std::wstring& Collection2Str(Collection_t collection);

	/// <summary>
	/// Enum for evaluating rules against one another (used by derived classes)
	/// so that unnecessary rules can be removed.
	/// </summary>
	enum class Redundancy_t {
		NoRedundancy,
		ProposedIsRedundant,
		ProposedSupersedesExisting
	};

protected:
	// Not constructed directly, only through derived classes.
	// Defaults to Allow rule that applies to Everyone.
	RuleItem() :
		m_bAllow(true), 
		m_collection(Collection_t::NotSet), 
		m_sUserOrGroupSid(SidEveryone())
	{}
	// Default implementation of dtor, cctor, assignment
	virtual ~RuleItem() = default;
	RuleItem(const RuleItem&) = default;
	RuleItem& operator = (const RuleItem&) = default;

protected:
	/// <summary>
	/// Basic validation that the rule item's rule collection is set.
	/// </summary>
	bool ValidCollection() const { return Collection_t::NotSet != m_collection; }

	/// <summary>
	/// Common checks when determining whether the rule covers the input file.
	/// Used by derived classes' implementation of the pure virtual Match function.
	/// </summary>
	bool MatchBaseChecks(const FileDetails_t& fileDetails) const;

protected:
	// Functions to support "ToXml()":

	/// <summary>
	/// Returns the XML root element for the rule's XML representation.
	/// E.g., "FilePathRule".
	/// Pure virtual - must be implemented by a derived class.
	/// </summary>
	virtual const wchar_t* XmlRootElem() const = 0;

	/// <summary>
	/// Virtual function that can be implemented by a derived class to write its
	/// "<Exceptions>", if applicable. Default implemention is to do nothing.
	/// Note that if the derived class writes anything into the stream, it needs to
	/// include the <Exceptions> tags.
	/// </summary>
	/// <param name=""></param>
	virtual void ExceptionsAsXml(std::wostream&) const {};

public:
	/// <summary>
	/// Write the rule item-specific XML for its conditions into the stream.
	/// Derived classes' overrides should NOT include the "<Conditions>" elements, just
	/// what goes inside.
	/// (This is a public method because rule items of one type can have exceptions of a
	/// different type. E.g., path rules can have publisher exceptions.)
	/// Pure virtual - must be implemented by a derived class.
	/// </summary>
	virtual void ConditionAsXml(std::wostream&) const = 0;

};

// ------------------------------------------------------------------------------------------

/// <summary>
/// Representation of an AppLocker Path rule item (not including exceptions)
/// </summary>
class PathRuleItem : public RuleItem
{
public:
	/// <summary>
	/// Every path rule item specifies a path.
	/// </summary>
	std::wstring m_sPath;

public:
	// Default ctor, dtor, cctor, assignment
	PathRuleItem() = default;
	~PathRuleItem() = default;
	PathRuleItem(const PathRuleItem&) = default;
	PathRuleItem& operator = (const PathRuleItem&) = default;

	// Overrides of pure virtual Match and Valid functions.
	virtual bool Match(const FileDetails_t& fileDetails) const;
	virtual bool Valid() const;

	/// <summary>
	/// Reports whether 1) the proposed rule is redundant because of this item,
	/// 2) the proposed rule supersedes the the current item and makes it redundant,
	/// or 3) neither of those are true.
	/// </summary>
	Redundancy_t RedundancyCheck(const PathRuleItem& proposed) const;

protected:
	// Override of pure virtual
	virtual const wchar_t* XmlRootElem() const {
		return L"FilePathRule";
	}
public:
	// Override of pure virtual
	virtual void ConditionAsXml(std::wostream&) const;

};

// ------------------------------------------------------------------------------------------

/// <summary>
/// Representation of an AppLocker Publisher rule item (not including exceptions)
/// </summary>
class PublisherRuleItem : public RuleItem
{
public:
	/// <summary>
	/// Data for Publisher rules (public visibility).
	/// Default value is "*" for all of them except for Publisher.
	/// </summary>
	std::wstring
		m_sPublisher,
		m_sProduct,
		m_sBinaryName,
		m_sBinaryVersionLow,
		m_sBinaryVersionHigh;

public:
	// A variety of constructors
	PublisherRuleItem();
	PublisherRuleItem(
		const std::wstring& sLabel,
		const std::wstring& sPublisher,
		const std::wstring& sProduct,
		const std::wstring& sBinaryName,
		Collection_t collection
	);
	PublisherRuleItem(
		const std::wstring& sLabel,
		const std::wstring& sPublisher,
		const std::wstring& sProduct,
		const std::wstring& sBinaryName,
		const std::wstring& sDescription,
		Collection_t collection
	);
	PublisherRuleItem(
		const std::wstring& sLabel,
		const std::wstring& sPublisher,
		const std::wstring& sProduct,
		Collection_t collection
	);
	PublisherRuleItem(
		const std::wstring& sLabel,
		const std::wstring& sPublisher,
		const std::wstring& sProduct
	);
	PublisherRuleItem(
		const std::wstring& sLabel,
		const std::wstring& sPublisher,
		Collection_t collection
	);
	PublisherRuleItem(
		const std::wstring& sLabel,
		const std::wstring& sPublisher
	);

	// Default implementations for dtor, cctor, assignment.
	~PublisherRuleItem() = default;
	PublisherRuleItem(const PublisherRuleItem&) = default;
	PublisherRuleItem& operator = (const PublisherRuleItem&) = default;

	// Overrides of pure virtual Match and Valid functions.
	virtual bool Match(const FileDetails_t& fileDetails) const;
	virtual bool Valid() const;

	/// <summary>
	/// Reports whether 1) the proposed rule is redundant because of this item,
	/// 2) the proposed rule supersedes the the current item and makes it redundant,
	/// or 3) neither of those are true.
	/// </summary>
	Redundancy_t RedundancyCheck(const PublisherRuleItem& proposed) const;

protected:
	// Override of pure virtual
	virtual const wchar_t* XmlRootElem() const {
		return L"FilePublisherRule";
	}
public:
	// Override of pure virtual
	virtual void ConditionAsXml(std::wostream&) const;
};

// ------------------------------------------------------------------------------------------

/// <summary>
/// Representation of an AppLocker Hash rule item
/// </summary>
class HashRuleItem : public RuleItem
{
public:
	/// <summary>
	/// Data for hash rules: hash value in string form, file name, file length.
	/// Assuming hash is always "SHA256", meaning Authenticode hash for PE files
	/// (EXEs and DLLs) and flat-file hash for everything else. (That is what
	/// AppLocker natively uses across the board.)
	/// </summary>
	std::wstring m_sHashData, m_sFilename, m_sFileLength;

public:
	// Default ctor, dtor, cctor, assignment.
	HashRuleItem() = default;
	~HashRuleItem() = default;
	HashRuleItem(const HashRuleItem&) = default;
	HashRuleItem& operator = (const HashRuleItem&) = default;

	// Overrides of pure virtuals
	virtual bool Match(const FileDetails_t& fileDetails) const;
	virtual bool Valid() const;

	/// <summary>
	/// Reports whether 1) the proposed rule is redundant because of this item,
	/// 2) the proposed rule supersedes the the current item and makes it redundant,
	/// or 3) neither of those are true.
	/// </summary>
	Redundancy_t RedundancyCheck(const HashRuleItem& proposed) const;

protected:
	// Overrides of pure virtual
	virtual const wchar_t* XmlRootElem() const {
		return L"FileHashRule";
	}
public:
	// Overrides of pure virtual
	virtual void ConditionAsXml(std::wostream&) const;
};

// ------------------------------------------------------------------------------------------

/// <summary>
/// Custom implementation of a hash rule to embed a comment in a rule set.
/// The rule is inert and never comes into play, but can show information
/// about the rule set.
/// </summary>
class CommentRule : public HashRuleItem
{
public:
	CommentRule();
	// Default implementation of dtor, cctor, and assignment operator
	~CommentRule() = default;
	CommentRule(const CommentRule&) = default;
	CommentRule& operator = (const CommentRule&) = default;

	void SetComment(const std::wstring& sName, const std::wstring& sDescription);
};

/// <summary>
/// Custom implementation of a CommentRule to embed a timestamp in a rule set.
/// The rule is inert and never comes into play, but can show when the rule set
/// was created, which can serve as an ID.
/// </summary>
class TimestampRule : public CommentRule
{
public:
	// A TimestampRule's properties reflect the current date/time when it was instantiated.
	TimestampRule();
	// Default implementation of dtor, cctor, and assignment operator
	~TimestampRule() = default;
	TimestampRule(const TimestampRule&) = default;
	TimestampRule& operator = (const TimestampRule&) = default;

public:
	// Also generates a timestamp that can be used within a filename.
	// Not part of the rule item, per se.
	std::wstring m_sTimestampForFilename;
};


// ------------------------------------------------------------------------------------------
// Typedef collections of rules.

typedef std::vector<PathRuleItem>      PathRuleCollection_t;
typedef std::vector<PublisherRuleItem> PublisherRuleCollection_t;
typedef std::vector<HashRuleItem>      HashRuleCollection_t;
typedef std::vector<CommentRule>       CommentRuleCollection_t;

/// <summary>
/// RuleSet_t represents a collection of path, publisher, and hash rules.
/// </summary>
struct RuleSet_t
{
	PathRuleCollection_t      m_PathRules;
	PublisherRuleCollection_t m_PublisherRules;
	HashRuleCollection_t      m_HashRules;
};

// ------------------------------------------------------------------------------------------

/// <summary>
/// Representation of an AppLocker Path rule, including exceptions.
/// Most of this class' implementation is in the PathRuleItem class. This class
/// adds some data and a virtual function override.
/// AaronLocker needs this class for path rules for the Windows and ProgramFiles directories.
/// (Could also do this for Publisher rules, but AaronLocker doesn't need them at this time.)
/// </summary>
class PathRuleItemWithExceptions : public PathRuleItem
{
public:
	// Exceptions are specified with path, publisher, and/or hash conditions.
	// Note that most rule item member data is inert when it's in an exceptions collection.
	RuleSet_t m_exceptions;

public:
	// Default implementation of ctor, dtor, cctor, and assignment.
	PathRuleItemWithExceptions() = default;
	~PathRuleItemWithExceptions() = default;
	PathRuleItemWithExceptions(const PathRuleItemWithExceptions&) = default;
	PathRuleItemWithExceptions& operator = (const PathRuleItemWithExceptions&) = default;

	/// <summary>
	/// Helper function to reinitialize the contents of the m_exceptions member.
	/// </summary>
	void clearExceptions();

protected:
	// Override of the base class virtual function to represent exceptions to this path rule.
	virtual void ExceptionsAsXml(std::wostream&) const;
};

