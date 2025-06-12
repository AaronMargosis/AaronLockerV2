// Template functions to support the different RuleItem-based collections.

#pragma once

#include "../RuleBuilding/RuleItems.h"

// ------------------------------------------------------------------------------------------
// RuleCollection_t expected to be replaced with PathRuleCollection_t, PublisherRuleCollection_t, HashRuleCollection_t
// RuleCollection_const_iterator is expected to be replaced with one of the above classes + ::const_iterator.
// RuleCollection_iterator is expected to be replaced with one of the above classes + ::iterator.
// RuleItem_t is expected to be replaced with a RuleItem-derived class corresponding to the collection.
// ------------------------------------------------------------------------------------------

// Indicates whether one or more of the rules in the collection covers the file

/// <summary>
/// Template function to determine whether any of the rules in the collection applies to the input file.
/// </summary>
/// <returns>true if one of the rule matches the file, false otherwise</returns>
template<class RuleCollection_t, class RuleCollection_const_iterator>
inline bool Match(const RuleCollection_t& RuleCollection, const FileDetails_t& fileDetails)
{
    for (
        RuleCollection_const_iterator iterRules = RuleCollection.begin();
        iterRules != RuleCollection.end();
        ++iterRules
        )
    {
        if (iterRules->Match(fileDetails))
            return true;
    }

    return false;
}

/// <summary>
/// Template function that indicates any overlap between a proposed rule and any of the rules in the rule collection.
/// </summary>
/// <returns>A RuleItem::Redundancy_t value indicating whether any overlap and what kind.</returns>
template<class RuleCollection_t, class RuleCollection_const_iterator, class RuleItem_t>
inline RuleItem::Redundancy_t RedundancyCheck(const RuleCollection_t& RuleCollection, const RuleItem_t& proposed)
{
    for (
        RuleCollection_const_iterator iterRules = RuleCollection.begin();
        iterRules != RuleCollection.end();
        ++iterRules
        )
    {
        RuleItem::Redundancy_t redundancy = iterRules->RedundancyCheck(proposed);
        if (RuleItem::Redundancy_t::NoRedundancy != redundancy)
            return redundancy;
    }

    return RuleItem::Redundancy_t::NoRedundancy;
}

/// <summary>
/// Adds a rule to a rule collection if it's not redundant, and removes any superseded rules from the collection.
/// </summary>
/// <returns>true if the collection is modified at all; false otherwise</returns>
template<class RuleCollection_t, class RuleCollection_iterator, class RuleItem_t>
inline bool AddRuleToCollectionWithCleanup(RuleCollection_t& RuleCollection, const RuleItem_t& ruleToAdd)
{
    // Iterate through collection, erasing anything that's superseded, then add if not redundant.
	// Return value is false unless something is changed in the collection.
	bool retval = false;
	// Assume to start that we will be adding the rule.
	bool bAdd = true;
	// Iterate through the collection and compare each rule to the new rule
	// Don't increment the iterator in the loop after an item has been removed;
	// see https://en.cppreference.com/w/cpp/container/vector/erase
	for (
		RuleCollection_iterator iterRules = RuleCollection.begin();
		bAdd && iterRules != RuleCollection.end();
		// ++iterRules
		)
	{
		bool bIncrementIter = true;
		switch (iterRules->RedundancyCheck(ruleToAdd))
		{
		case RuleItem::Redundancy_t::NoRedundancy:
			// No redundancy for the current comparison.
			break;

		case RuleItem::Redundancy_t::ProposedIsRedundant:
			// The new rule is redundant. Quit iterating through the collection and exit.
			bAdd = false;
			break;

		case RuleItem::Redundancy_t::ProposedSupersedesExisting:
			// The new rule makes the current existing rule redundant; remove the redundant rule.
			iterRules = RuleCollection.erase(iterRules);
			bIncrementIter = false;
			// Collection modified
			retval = true;
			break;
		}

		if (bIncrementIter)
		{
			++iterRules;
		}
	}
	// If still adding the new rule, do so now.
	if (bAdd)
	{
		RuleCollection.push_back(ruleToAdd);
		// Collection modified
		retval = true;
	}
	return retval;
}

/// <summary>
/// Adds a new rule into the collection if it isn't redundant, but without removing any existing rules.
/// Reason for this is that we'll have some rules we always want in the set, even if something else supersedes it.
/// Keep the always-in rules there in case this superseding rule gets removed.
/// </summary>
template<class RuleCollection_t, class RuleCollection_const_iterator, class RuleItem_t>
inline void MergeToRuleCollection(RuleCollection_t& RuleCollection, const RuleItem_t& rule)
{
	// Invoke the RedundancyCheck template function above to see whether the proposed rule is redundant.
	// If it's not redundant, add it (even if it makes an existing rule redundant).
	RuleItem::Redundancy_t redundancy = RedundancyCheck<RuleCollection_t, RuleCollection_const_iterator, RuleItem_t>(RuleCollection, rule);
	if (RuleItem::Redundancy_t::ProposedIsRedundant != redundancy)
	{
		RuleCollection.push_back(rule);
	}
}

/// <summary>
/// Adds rules from "collectionToAdd" into the "RuleCollection" that aren't redundant, but without removing any existing rules.
/// Reason for this is that we'll have some rules we always want in the set, even if something else supersedes it.
/// Keep the always-in rules there in case this superseding rule gets removed.
/// </summary>
template<class RuleCollection_t, class RuleCollection_const_iterator, class RuleItem_t>
inline void MergeToRuleCollection(RuleCollection_t& RuleCollection, const RuleCollection_t& collectionToAdd)
{
	for (
		RuleCollection_const_iterator iterRulesToAdd = collectionToAdd.begin();
		iterRulesToAdd != collectionToAdd.end();
		++iterRulesToAdd
		)
	{
		MergeToRuleCollection<RuleCollection_t, RuleCollection_const_iterator, RuleItem_t>(RuleCollection, *iterRulesToAdd);
	}

	// How to do it without a redundancy check
	//RuleCollection.insert(RuleCollection.end(), collectionToAdd.begin(), collectionToAdd.end());
}


