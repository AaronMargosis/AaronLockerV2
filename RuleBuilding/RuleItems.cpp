// Class hierarchy to represent AppLocker Path, Publisher, and Hash rules.
//

#include "pch.h"
#include <ctime>
#include "RuleItems.h"
#include "GuidGenerator.h"

// ------------------------------------------------------------------------------------------
// Single definitions of commonly-used strings, to minimize use of string literals throughout code.

const std::wstring& sStar()
{
    static std::wstring retval = L"*";
    return retval;
}

const std::wstring& sBackslashStar()
{
    static std::wstring retval = L"\\*";
    return retval;
}

const std::wstring& SidEveryone()
{
    static std::wstring retval = SidString::Everyone;
    return retval;
}

const std::wstring& SidAdministrators()
{
    static std::wstring retval = SidString::BuiltinAdministrators;
    return retval;
}

const std::wstring& SidCreatorOwner()
{
    static std::wstring retval = SidString::CreatorOwner;
    return retval;
}

const std::wstring& MicrosoftPublisher()
{
    static std::wstring retval = L"O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";
    return retval;
}

const std::wstring& MicrosoftAppxPublisher()
{
    static std::wstring retval = L"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
    return retval;
}

const std::wstring& MicrosoftWindowsAppxPublisher()
{
    static std::wstring retval = L"CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US";
    return retval;
}


// ------------------------------------------------------------------------------------------
// RuleItem implementation

/// <summary>
/// Maps an AppLockerFileDetails_ftype_t value to the corresponding AppLocker rule collection.
/// </summary>
RuleItem::Collection_t RuleItem::FromFType(AppLockerFileDetails_ftype_t ftype)
{
    switch (ftype)
    {
    case AppLockerFileDetails_ftype_t::ft_EXE:
        return Collection_t::Exe;

    case AppLockerFileDetails_ftype_t::ft_DLL:
    case AppLockerFileDetails_ftype_t::ft_ResourceOnlyDLL:
        return Collection_t::Dll;

    case AppLockerFileDetails_ftype_t::ft_MSI:
        return Collection_t::Msi;

    case AppLockerFileDetails_ftype_t::ft_Script:
    case AppLockerFileDetails_ftype_t::ft_ScriptJS:
        return Collection_t::Script;

    case AppLockerFileDetails_ftype_t::ft_Appx:
        return Collection_t::Appx;

    default:
        return Collection_t::NotSet;
    }
}

/// <summary>
/// Maps a rule collection type to its string form
/// </summary>
const std::wstring& RuleItem::Collection2Str(Collection_t collection)
{
    static const std::wstring sExe = L"Exe";
    static const std::wstring sDll = L"Dll";
    static const std::wstring sMsi = L"Msi";
    static const std::wstring sScript = L"Script";
    static const std::wstring sAppx = L"Appx";
    static const std::wstring sEmpty;

    switch (collection)
    {
    case Collection_t::Exe:
        return sExe;
    case Collection_t::Dll:
        return sDll;
    case Collection_t::Msi:
        return sMsi;
    case Collection_t::Script:
        return sScript;
    case Collection_t::Appx:
        return sAppx;

    case Collection_t::NotSet:
    case Collection_t::All:
    default:
        return sEmpty;
    }
}

/// <summary>
/// Common checks when determining whether the rule covers the input file.
/// Used by derived classes' implementation of the pure virtual Match function.
/// </summary>
bool RuleItem::MatchBaseChecks(const FileDetails_t& fileDetails) const
{
    // Verification against group/user: match only against rules for Everyone;
    // if this rule item applies to anything else, it's not a match here.
    if (SidEveryone() != m_sUserOrGroupSid)
        return false;

    // Check whether this rule's collection matches the input file details.

    // If the rule applies to "All", it matches. 
    if (Collection_t::All == this->m_collection)
    {
        return true;
    }
    else
    {   // Otherwise, see what rule collection applies to this file, and determine
        // whether this rule applies to that collection.
        // If it doesn't map to a rule collection (returns NotSet), then it doesn't.
        Collection_t coll = FromFType(fileDetails.m_fileType);
        if (Collection_t::NotSet == coll)
            return false;
        else
            return this->m_collection == coll;
    }
}

// Returns GUID for this rule item, creating it on first access.

/// <summary>
/// Returns unique ID for the rule item. Created on first access, not on object construction.
/// <param name="bForceNew">If true, forces creation of a new GUID even if one already exists.</param>
/// <returns>Reference to the GUID string</returns>
const std::wstring& RuleItem::Guid(bool bForceNew /*= false*/) const
{
    if (bForceNew || 0 == m_sGuid.length())
    {
        m_sGuid = GuidGenerator::CreateNewGuid();
    }
    return m_sGuid;
}

/// <summary>
/// Writes the XML representation of the rule item, including a new GUID ID, to the stream.
/// Enforces length limits in AppLocker XSD: https://docs.microsoft.com/en-us/windows/client-management/mdm/applocker-xsd
/// </summary>
/// <param name="os">Output stream to write XML into</param>
/// <param name="bForceNewGuid">If true, forces creation of a new GUID even if one already exists.</param>
void RuleItem::ToXml(std::wostream& os, bool bForceNewGuid /*= false*/) const
{
    // "Name" and "Description" attributes cannot be greater than 1024 characters each. If either is,
    // limit it and end it with "[...]" to indicate that additional text was intended.
    std::wstring sName, sDescription;
    const wchar_t sExtra[] = L"[...]";
    const size_t cchMaxLen = 1024, cchExtra = 5;
    sName = (m_sName.length() <= cchMaxLen) ? m_sName : m_sName.substr(0, cchMaxLen - cchExtra) + sExtra;
    sDescription = (m_sDescription.length() <= cchMaxLen) ? m_sDescription : m_sDescription.substr(0, cchMaxLen - cchExtra) + sExtra;

    // Write the common parts out, getting the root element from the derived class and
    // generating a new GUID.
    os
        << L"<" << XmlRootElem() << L" "
        << L"Name=\"" << EncodeForXml(sName.c_str()) << L"\" "
        << L"Description=\"" << EncodeForXml(sDescription.c_str()) << L"\" "
        << L"Action=\"" << (m_bAllow ? L"Allow" : L"Deny") << L"\" "
        << L"UserOrGroupSid=\"" << m_sUserOrGroupSid << L"\" "
        << L"Id=\"" << Guid(bForceNewGuid) << L"\">"
        << L"<Conditions>"
        ;
    // Derived class supplies the content for the Conditions element
    ConditionAsXml(os);
    os
        << L"</Conditions>"
        ;
    // Derived class might supply content for exceptions.
    ExceptionsAsXml(os);
    os
        << L"</" << XmlRootElem() << L">"
        ;
}

// ------------------------------------------------------------------------------------------
// PathRuleItem implementation

bool PathRuleItem::Match(const FileDetails_t& fileDetails) const
{
    // Path rule applies to the input file if base checks pass and
    // the file's path begins with the rule's path.
    return
        MatchBaseChecks(fileDetails) &&
        PathStartsWithDirectory(fileDetails.m_sFilePath, this->m_sPath);
}

bool PathRuleItem::Valid() const
{
    // Basic validity check: is the collection set, and is the path's length non-zero
    return
        ValidCollection() &&
        m_sPath.length() > 0;
}

/// <summary>
/// Reports whether 1) the proposed rule is redundant because of this item,
/// 2) the proposed rule supersedes the the current item and makes it redundant,
/// or 3) neither of those are true.
/// </summary>
RuleItem::Redundancy_t PathRuleItem::RedundancyCheck(const PathRuleItem& proposed) const
{
    // For now, if the collections aren't the same, there's no overlap/redundancy.
    //TODO: RedundancyCheck needs to take collection "All" into account (see how PublisherRuleItem does it)
    if (this->m_collection != proposed.m_collection)
        return Redundancy_t::NoRedundancy;

    // If one is Allow and one is Deny, neither makes the other redundant
    if (this->m_bAllow != proposed.m_bAllow)
        return Redundancy_t::NoRedundancy;

    // If the paths are the same, the proposed is redundant
    if (EqualCaseInsensitive(this->m_sPath, proposed.m_sPath))
        return Redundancy_t::ProposedIsRedundant;

    // If the proposed is a subdirectory of this one, the proposed is redundant
    if (PathStartsWithDirectory(proposed.m_sPath, this->m_sPath))
        return Redundancy_t::ProposedIsRedundant;

    // If this item is a subdirectory of the proposed, the proposed supersedes this item.
    if (PathStartsWithDirectory(this->m_sPath, proposed.m_sPath))
        return Redundancy_t::ProposedSupersedesExisting;

    // Otherwise, no redundancy.
    return Redundancy_t::NoRedundancy;
}

// Override of pure virtual
void PathRuleItem::ConditionAsXml(std::wostream& os) const
{
    //TODO: Disallow any Path attribute from exceeding 32767 characters, as the AppLocker XSD schema demands. The entire policy XML will be considered invalid if any path exceeds that:
    // https://docs.microsoft.com/en-us/windows/client-management/mdm/applocker-xsd
    // The RuleItem class hierarchy needs a new validation pure virtual that returns bool indicating whether the rule can be built. That pure virtual must be called by the ToXml
    // method before writing anything to the wostream. If it fails, write a comment into the stream with the bad Path value. Should also return that info in another manner as well.
    os
        << L"<FilePathCondition Path=\"" << EncodeForXml(m_sPath.c_str()) << L"\"/>"
        ;
}

// ------------------------------------------------------------------------------------------
// PublisherRuleItem implementation

// Numerous constructors to simplify building arrays and other collections.
// Unless otherwise specified, all members of this class are initialized to "*" except for publisher.

PublisherRuleItem::PublisherRuleItem()
    :
    // m_sPublisher - default constructor, empty
    m_sProduct(sStar()), 
    m_sBinaryName(sStar()), 
    m_sBinaryVersionLow(sStar()), 
    m_sBinaryVersionHigh(sStar())
{
}

PublisherRuleItem::PublisherRuleItem(
    const std::wstring& sLabel, 
    const std::wstring& sPublisher, 
    const std::wstring& sProduct, 
    const std::wstring& sBinaryName, 
    Collection_t collection)
    :
    m_sPublisher(sPublisher),
    m_sProduct(sProduct),
    m_sBinaryName(sBinaryName),
    m_sBinaryVersionLow(sStar()),
    m_sBinaryVersionHigh(sStar())
{
    m_sName = sLabel;
    m_collection = collection;
}

PublisherRuleItem::PublisherRuleItem(
    const std::wstring& sLabel, 
    const std::wstring& sPublisher, 
    const std::wstring& sProduct, 
    const std::wstring& sBinaryName, 
    const std::wstring& sDescription, 
    Collection_t collection)
    :
    m_sPublisher(sPublisher),
    m_sProduct(sProduct),
    m_sBinaryName(sBinaryName),
    m_sBinaryVersionLow(sStar()),
    m_sBinaryVersionHigh(sStar())
{
    m_sName = sLabel;
    m_sDescription = sDescription;
    m_collection = collection;
}

PublisherRuleItem::PublisherRuleItem(
    const std::wstring& sLabel, 
    const std::wstring& sPublisher, 
    const std::wstring& sProduct, 
    Collection_t collection)
    :
    m_sPublisher(sPublisher),
    m_sProduct(sProduct),
    m_sBinaryName(sStar()),
    m_sBinaryVersionLow(sStar()),
    m_sBinaryVersionHigh(sStar())
{
    m_sName = sLabel;
    m_collection = collection;
}

PublisherRuleItem::PublisherRuleItem(
    const std::wstring& sLabel, 
    const std::wstring& sPublisher, 
    const std::wstring& sProduct)
    :
    m_sPublisher(sPublisher),
    m_sProduct(sProduct),
    m_sBinaryName(sStar()),
    m_sBinaryVersionLow(sStar()),
    m_sBinaryVersionHigh(sStar())
{
    m_sName = sLabel;
    m_collection = Collection_t::All;
}

PublisherRuleItem::PublisherRuleItem(
    const std::wstring& sLabel, 
    const std::wstring& sPublisher, 
    Collection_t collection)
    :
    m_sPublisher(sPublisher),
    m_sProduct(sStar()),
    m_sBinaryName(sStar()),
    m_sBinaryVersionLow(sStar()),
    m_sBinaryVersionHigh(sStar())
{
    m_sName = sLabel;
    m_collection = collection;
}

PublisherRuleItem::PublisherRuleItem(
    const std::wstring& sLabel, 
    const std::wstring& sPublisher)
    :
    m_sPublisher(sPublisher),
    m_sProduct(sStar()),
    m_sBinaryName(sStar()),
    m_sBinaryVersionLow(sStar()),
    m_sBinaryVersionHigh(sStar())
{
    m_sName = sLabel;
    m_collection = Collection_t::All;
}

// Reports whether this rule applies to the input file.
bool PublisherRuleItem::Match(const FileDetails_t& fileDetails) const
{
    // Basic validity check
    if (!Valid())
        return false;
    // Base class checks
    if (!MatchBaseChecks(fileDetails))
        return false;
    // If this rule doesn't have a publisher, it's not a match
    if (this->m_sPublisher.length() == 0)
        return false;
    // Assumes everything is upper case
    // Does the publisher match?
    // Note that this does not and will not support publisher = "*". Only place to use that is for Appx,
    // which this implementation doesn't really take into account.
    if (this->m_sPublisher != fileDetails.m_ALPublisherName)
        return false;
    // Does the product match, or does the rule say "any product?"
    if (this->m_sProduct != sStar() && this->m_sProduct != fileDetails.m_ALProductName)
        return false;
    // Does the binary name match, or does the rule say "any binary name?"
    if (this->m_sBinaryName != sStar() && this->m_sBinaryName != fileDetails.m_ALBinaryName)
        return false;
    // If this rule applies version criteria (i.e., applies to some versions but not all versions), it might not
    // apply to the current file. Performing that check correctly will take some doing. For now, assume that this
    // rule does not apply to the input file.
    // (One important use case: predefined Deny rule for older versions of BgInfo doesn't apply to all versions; need to make
    // it possible to create a publisher rule allowing newer versions.)
    if (this->m_sBinaryVersionHigh != sStar() || this->m_sBinaryVersionLow != sStar())
        return false;
    // Got through those checks, it's a match.
    return true;
}

bool PublisherRuleItem::Valid() const
{
    // Basic validity check - is the publisher set to something?
    return
        ValidCollection() &&
        // Invalid publisher rule if no publisher set
        (this->m_sPublisher.length() != 0);
}

// Local enum and function to support publisher-rule RedundancyCheck comparisons for product and binary names
enum class pubCmp_t
{
    equal,
    thisCoversMore,
    proposedCoversMore,
    noOverlap
};
inline static pubCmp_t PubCmp(const std::wstring& thisStr, const std::wstring& proposedStr)
{
    // Two string the same - equal
    if (thisStr == proposedStr)
        return pubCmp_t::equal;
    // Otherwise, if this is "*" and the proposed isn't, this covers more than the proposed
    if (thisStr == sStar())
        return pubCmp_t::thisCoversMore;
    // Otherwise, if the proposed is "*" and the other isn't, the proposed covers more.
    if (proposedStr == sStar())
        return pubCmp_t::proposedCoversMore;
    // Otherwise, they are different from one another and neither is "*", so no overlap.
    return pubCmp_t::noOverlap;
}

/// <summary>
/// Reports whether 1) the proposed rule is redundant because of this item,
/// 2) the proposed rule supersedes the the current item and makes it redundant,
/// or 3) neither of those are true.
/// </summary>
RuleItem::Redundancy_t PublisherRuleItem::RedundancyCheck(const PublisherRuleItem& proposed) const
{
    // Assumptions: (perhaps enforce these assumptions in the class validation)
    // + this and proposed rules are valid
    // + If publisher is "*", so is product, binary name, and version. (Expect only ever to see publisher=="*" for Store apps.)
    // + If product name is "*", so is the binary name and the binary version
    // + If binary name is "*", so are the binary version low and high

    // Note: If the current and proposed rules are identical, the proposed is redundant

    // If one is Allow and one is Deny, neither makes the other redundant
    if (this->m_bAllow != proposed.m_bAllow)
        return Redundancy_t::NoRedundancy;

    // If the current rule allows all publishers for the proposed's collection, the proposed is redundant
    // Assuming no proposed or existing collection allows all publishers for Collection_t::All.
    if (sStar() == this->m_sPublisher && this->m_collection == proposed.m_collection)
        return Redundancy_t::ProposedIsRedundant;

    // Otherwise, if the proposed rule allows all publishers for this collection, the current rule is redundant
    // Assuming no proposed or existing collection allows all publishers for Collection_t::All.
    if (sStar() == proposed.m_sPublisher && this->m_collection == proposed.m_collection)
        return Redundancy_t::ProposedSupersedesExisting;

    // Otherwise, if the publishers are different then there's definitely no overlap
    if (this->m_sPublisher != proposed.m_sPublisher)
        return Redundancy_t::NoRedundancy;

    // Look at current and proposed collections. If they are different and neither is "All", there's no overlap.
    // Otherwise, keep a note about whether one collection covers more than the other.
    //TODO: Refactor this and put logic into the base class so PathRuleItem can use it too.
    bool bThisCollectionCoversMore =
        (Collection_t::All == this->m_collection) &&
        (Collection_t::All != proposed.m_collection);
    bool bProposedCollectionCoversMore =
        (Collection_t::All != this->m_collection) &&
        (Collection_t::All == proposed.m_collection);
    bool bSameCollectionCoverage =
        (this->m_collection == proposed.m_collection);
    // If the collections are different from one another and neither is "All", no redundancy/overlap.
    if (!bThisCollectionCoversMore && !bProposedCollectionCoversMore && !bSameCollectionCoverage)
        return Redundancy_t::NoRedundancy;

    // Compare product names, taking "*" into account.
    pubCmp_t pubCmt = PubCmp(this->m_sProduct, proposed.m_sProduct);
    // If product names the same, compare binary names, taking "*" into account.
    if (pubCmp_t::equal == pubCmt) { pubCmt = PubCmp(this->m_sBinaryName, proposed.m_sBinaryName); }
    //TODO: If binary names the same in PublisherRuleItem::RedundancyCheck, compare binary version specs
    // if (pubCmp_t::equal == pubCmt) { ... still need to deal with version comparisons }
    switch (pubCmt)
    {
    case pubCmp_t::equal:
        // If the publisher content is equal, the proposed is redundant unless its collection covers more
        return bProposedCollectionCoversMore ? Redundancy_t::ProposedSupersedesExisting : Redundancy_t::ProposedIsRedundant;

    case pubCmp_t::thisCoversMore:
        // If the current rule's publisher content covers more, the proposed is redundant unless its collection covers more,
        // in which case neither makes the other redundant.
        return bProposedCollectionCoversMore ? Redundancy_t::NoRedundancy : Redundancy_t::ProposedIsRedundant;

    case pubCmp_t::proposedCoversMore:
        // If the proposed rule's publisher content covers more, the current item is superseded unless its collection covers
        // more, in which case neither makes the other redundant.
        return bThisCollectionCoversMore ? Redundancy_t::NoRedundancy : Redundancy_t::ProposedSupersedesExisting;

    case pubCmp_t::noOverlap:
    default:
        // Anything else, there's no redundancy/overlap.
        return Redundancy_t::NoRedundancy;
    }
}

// Override of pure virtual
void PublisherRuleItem::ConditionAsXml(std::wostream& os) const
{
    os
        << L"<FilePublisherCondition "
        << L"PublisherName=\"" << EncodeForXml(m_sPublisher.c_str()) << L"\" "
        << L"ProductName=\"" << EncodeForXml(m_sProduct.c_str()) << L"\" "
        << L"BinaryName=\"" << EncodeForXml(m_sBinaryName.c_str()) << L"\">"
        << L"<BinaryVersionRange LowSection=\"" << m_sBinaryVersionLow << L"\" HighSection=\"" << m_sBinaryVersionHigh << L"\"/>"
        << L"</FilePublisherCondition>"
        ;
}

// ------------------------------------------------------------------------------------------
// HashRuleItem implementation

bool HashRuleItem::Match(const FileDetails_t& fileDetails) const
{
    // Match is simple. Base checks and then verify that the hashes match.
    return
        MatchBaseChecks(fileDetails) &&
        EqualCaseInsensitive(this->m_sHashData, fileDetails.m_ALHash);
}

bool HashRuleItem::Valid() const
{
    return
        ValidCollection() &&
        // Minimal check - is the hash set to something?
        (this->m_sHashData.length() > 0);
}

RuleItem::Redundancy_t HashRuleItem::RedundancyCheck(const HashRuleItem& proposed) const
{
    // If the collections aren't the same, or one is allow and one is deny, or the hashes aren't the same,
    // neither makes the other redundant. If they're all the same, the proposed is redundant.
    // Ideally, collection comparison should take collection "All" into account, but we should never see
    // it show up in a hash rule.
    if (
        this->m_collection != proposed.m_collection ||
        this->m_bAllow != proposed.m_bAllow ||
        !EqualCaseInsensitive(this->m_sHashData, proposed.m_sHashData)
        )
        return Redundancy_t::NoRedundancy;
    else
        return Redundancy_t::ProposedIsRedundant;
}

// Override of pure virtual
void HashRuleItem::ConditionAsXml(std::wostream& os) const
{
    os
        << L"<FileHashCondition>"
        << L"<FileHash Type=\"SHA256\" Data=\"" << m_sHashData << L"\" "
        << L"SourceFileName=\"" << EncodeForXml(m_sFilename.c_str()) << L"\" "
        << L"SourceFileLength=\"" << m_sFileLength << L"\"/>"
        << L"</FileHashCondition>"
        ;
}

// ------------------------------------------------------------------------------------------
// CommentRule and TimestampRule implementations

CommentRule::CommentRule()
{
    this->m_collection = Collection_t::Exe;
    this->m_bAllow = false;
    this->m_sUserOrGroupSid = SidCreatorOwner();
    this->m_sFileLength = L"1";
    this->m_sFilename = L"Comment";
    this->m_sHashData = L"0x0000000000000000000000000000000000000000000000000000000000000000";
}

void CommentRule::SetComment(const std::wstring& sName, const std::wstring& sDescription)
{
    this->m_sName = sName;
    this->m_sDescription = sDescription;
}

TimestampRule::TimestampRule()
{
    // Get the current time (UTC) and embed it into the rule's properties.
    // Rule applies to "CREATOR OWNER" which is never in an access token and therefore will never turn up in an 
    // AppLocker rule evaluation.
    /* Windows API implementation: */
    SYSTEMTIME st;
    GetSystemTime(&st);
    wchar_t szRuleDocTimestamp[24], szTimestampHash[72], szTimestampForFilename[16];
    swprintf_s(szRuleDocTimestamp, L"%04u-%02u-%02u %02u:%02u UTC", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    swprintf_s(szTimestampHash, L"0x00000000000000000000000000000000000000000000000000" L"%04u%02u%02u%02u%02u%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    swprintf_s(szTimestampForFilename, L"%04u%02u%02u-%02u%02u", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

    this->m_sName = std::wstring(L"Rule set created ") + szRuleDocTimestamp;
    this->m_sDescription = std::wstring(L"Never-applicable rule to document that this AppLocker rule set was created via AaronLocker automation at ") + szRuleDocTimestamp;
    // The following properties set by the CommentRule base class.
    //this->m_collection = Collection_t::Exe;
    //this->m_bAllow = false;
    //this->m_sUserOrGroupSid = SidCreatorOwner();
    //this->m_sFileLength = L"1";
    this->m_sFilename = L"DateTimeInfo";
    this->m_sHashData = szTimestampHash;

    // Extra property that can be used in a filename
    m_sTimestampForFilename = szTimestampForFilename;
}

// ------------------------------------------------------------------------------------------
// PathRuleItemWithExceptions implementation

/// <summary>
/// Helper function to reinitialize the contents of the m_exceptions member.
/// </summary>
void PathRuleItemWithExceptions::clearExceptions()
{
    m_exceptions.m_PathRules.clear();
    m_exceptions.m_PublisherRules.clear();
    m_exceptions.m_HashRules.clear();
}

// Override of the base class virtual function to represent exceptions to this path rule.
void PathRuleItemWithExceptions::ExceptionsAsXml(std::wostream& os) const
{
    // Exceptions are specified with the rule items' condition XML tags.
    os << L"<Exceptions>";
    
    for (
        PathRuleCollection_t::const_iterator iter = m_exceptions.m_PathRules.begin();
        iter != m_exceptions.m_PathRules.end();
        ++iter
        )
    {
        iter->ConditionAsXml(os);
    }
    for (
        PublisherRuleCollection_t::const_iterator iter = m_exceptions.m_PublisherRules.begin();
        iter != m_exceptions.m_PublisherRules.end();
        ++iter
        )
    {
        iter->ConditionAsXml(os);
    }
    for (
        HashRuleCollection_t::const_iterator iter = m_exceptions.m_HashRules.begin();
        iter != m_exceptions.m_HashRules.end();
        ++iter
        )
    {
        iter->ConditionAsXml(os);
    }

    os << L"</Exceptions>";
}