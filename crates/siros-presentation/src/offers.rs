//! Offers (A3): the combinations of credentials the user chooses from, and the optional
//! additions to each.

mod choices;
mod entries;
mod joining;

use itertools::{Either, Itertools};
use serde_json::Value;
use siros_dcql::{CredentialSetQuery, Dropped, SetRequirement};

use crate::ids::{CandidateIndex, QueryIndex, SetIndex};
use crate::matching::Answered;
use choices::{product, sum, Capped, Choices, Examining, Space};
use joining::{Agreed, Joining, Proposal};

pub use entries::{EntryCarriers, EntryQueries};

/// The most offers of a request.
pub const MAX_OFFERS: usize = 32;

/// The most additions of an offer.
pub const MAX_ADDITIONS: usize = 32;

/// The most combinations and joins examined for the offers of a request, and the most
/// combinations examined for the additions of an offer.
pub const MAX_EXAMINED: usize = 1024;

/// What an offer presents for one Credential Query: one candidate, or every candidate of a
/// query that sets `multiple`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Member {
    query: QueryIndex,
    candidates: Vec<CandidateIndex>,
}

impl Member {
    /// The position of the Credential Query in the DCQL query.
    pub fn query(&self) -> QueryIndex {
        self.query
    }

    /// The candidates' positions among the query's candidates, at least one; every candidate
    /// of a `multiple` query, of which the selection chooses a subset.
    pub fn candidates(&self) -> &[CandidateIndex] {
        &self.candidates
    }

    /// The member of the candidates `keep` accepts, in the member's order.
    #[cfg(feature = "wallet")]
    pub(crate) fn keeping(&self, mut keep: impl FnMut(CandidateIndex) -> bool) -> Self {
        Self {
            query: self.query,
            candidates: self
                .candidates
                .iter()
                .copied()
                .filter(|&c| keep(c))
                .collect(),
        }
    }
}

/// A combination of credentials the user may present together.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    purposes: Vec<Value>,
    members: Vec<Member>,
    additions: Capped<Addition, MAX_ADDITIONS>,
    unexamined: Dropped,
}

/// An option of an optional credential set the user may add to an offer (OpenID4VP 1.0,
/// Section 6.4.2).
#[derive(Debug, Clone, PartialEq)]
pub struct Addition {
    set: SetIndex,
    purpose: Option<Value>,
    members: Vec<Member>,
}

/// The offers of a request.
#[derive(Debug, Clone, PartialEq)]
pub struct Offers {
    offers: Capped<Offer, MAX_OFFERS>,
    unexamined: Dropped,
}

/// Why a combination the enumeration examined is no offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal<E> {
    /// No join lets it carry every transaction entry (A3).
    Uncarried,
    /// The acceptance refused it.
    Refused(E),
}

impl Offer {
    /// The `purpose` of each credential set the offer satisfies, in set order (Section 6.2).
    pub fn purposes(&self) -> &[Value] {
        &self.purposes
    }

    /// The members, each Credential Query once.
    pub fn members(&self) -> &[Member] {
        &self.members
    }

    /// The additions, none of whose members answers a query of the offer.
    pub fn additions(&self) -> &[Addition] {
        &self.additions
    }

    /// How many combinations of the optional sets were not examined for additions.
    pub fn unexamined(&self) -> Dropped {
        self.unexamined
    }

    /// Whether the offer's members are `members`, in any order.
    fn has(&self, members: &[Member]) -> bool {
        self.members.len() == members.len() && members.iter().all(|m| self.members.contains(m))
    }
}

impl Addition {
    /// The credential set's position in `credential_sets`.
    pub fn set(&self) -> SetIndex {
        self.set
    }

    /// The set's `purpose`.
    pub fn purpose(&self) -> Option<&Value> {
        self.purpose.as_ref()
    }

    /// The members.
    pub fn members(&self) -> &[Member] {
        &self.members
    }
}

impl Offers {
    /// The offers of `answered` that `accept` accepts, and the first refusal. `entries` holds
    /// each `transaction_data` entry with the candidates that can carry it.
    ///
    /// - Without `credential_sets`, an offer answers every query (Section 6.4.2).
    /// - Each combination of an option of every required credential set is an offer.
    /// - When every set is optional, each option of each set is an offer.
    /// - When no member of an offer can carry an entry, each option of an optional set whose
    ///   credentials can carry it joins the offer as members, in an offer of its own (Section
    ///   8.4). Joining repeats until every entry is carried, at most one option per set. An offer
    ///   that cannot carry every entry is dropped.
    /// - An option holds a member per query: a candidate, or all candidates of a query that
    ///   sets `multiple`.
    /// - Two offers with the same members are one offer: the first.
    ///
    /// The options of the other optional sets are each offer's additions, except those that
    /// answer a query of the offer or a query an entry names. Combinations are examined in
    /// order, the last set varying fastest, each followed by its joins; up to [`MAX_EXAMINED`]
    /// combinations and joins are examined, and at most [`MAX_OFFERS`] offers and
    /// [`MAX_ADDITIONS`] additions per offer are kept.
    pub fn of<C, R, E>(
        answered: &Answered<'_, C, R>,
        entries: &[EntryCarriers],
        mut accept: impl FnMut(&[Member]) -> Result<(), E>,
    ) -> (Self, Option<Refusal<E>>) {
        let space = Space::of(answered);
        let (required, optional) = sets(&space, answered.credential_sets());
        let (bases, total): (Box<dyn Iterator<Item = Proposal<'_>> + '_>, _) =
            if required.is_empty() {
                let total = sum(optional.iter().map(|set| set.choices.count()));
                (Box::new(each_option(&optional)), total)
            } else {
                let total = product(required.iter().map(Choices::count));
                (Box::new(each_combination(&required, &optional)), total)
            };
        let mut proposals = Joining::new(bases, total, entries);
        let mut offers: Vec<Offer> = Vec::new();
        let mut refusal = None;
        while offers.len() < MAX_OFFERS {
            let proposal = proposals.next();
            if refusal.is_none() && proposals.dropped() {
                refusal = Some(Refusal::Uncarried);
            }
            let Some(proposal) = proposal else {
                break;
            };
            if offers.iter().any(|offer| offer.has(&proposal.members)) {
                continue;
            }
            match accept(&proposal.members) {
                Ok(()) => offers.push(offer(proposal, entries)),
                Err(error) => {
                    if refusal.is_none() {
                        refusal = Some(Refusal::Refused(error));
                    }
                }
            }
        }
        let offers = Self {
            offers: offers.into_iter().collect(),
            unexamined: proposals.unexamined(),
        };
        (offers, refusal)
    }

    /// The offers, in the order of the combinations.
    pub fn offers(&self) -> &[Offer] {
        &self.offers
    }

    /// How many combinations were not examined.
    pub fn unexamined(&self) -> Dropped {
        self.unexamined
    }
}

/// An optional credential set: its position in `credential_sets`, and its choices.
struct OptionalSet {
    index: SetIndex,
    choices: Choices,
}

/// The required and the optional credential sets of a request. Without `credential_sets`,
/// every query at once is the one required choice.
fn sets(
    space: &Space<'_>,
    credential_sets: Option<&[CredentialSetQuery]>,
) -> (Vec<Choices>, Vec<OptionalSet>) {
    let Some(credential_sets) = credential_sets else {
        return (vec![Choices::all(space)], Vec::new());
    };
    credential_sets
        .iter()
        .enumerate()
        .partition_map(|(index, set)| {
            let choices = Choices::of_set(space, set);
            if set.requirement() == SetRequirement::Required {
                Either::Left(choices)
            } else {
                let index = SetIndex::at(index);
                Either::Right(OptionalSet { index, choices })
            }
        })
}

/// The members of one choice of each set of a combination.
enum Combination {
    /// The choices answer each query once.
    Agreed(Vec<Member>),
    /// Two choices answer one query with different candidates.
    Conflict,
}

impl Combination {
    /// The members of `choices`, a query answered by identical choices once.
    fn of(choices: Vec<Vec<Member>>) -> Self {
        let agreed = choices.into_iter().flatten().try_fold(
            Vec::new(),
            |mut members: Vec<Member>, member| match members
                .iter()
                .find(|m| m.query == member.query)
            {
                Some(same) => (*same == member).then_some(members),
                None => {
                    members.push(member);
                    Some(members)
                }
            },
        );
        agreed.map_or(Self::Conflict, Self::Agreed)
    }

    fn agreed(self) -> Option<Vec<Member>> {
        match self {
            Self::Agreed(members) => Some(members),
            Self::Conflict => None,
        }
    }
}

/// The offer of `proposal`, with its additions from the optional sets it leaves: those that
/// answer no query of the offer and no query an entry names.
fn offer(proposal: Agreed<'_>, entries: &[EntryCarriers]) -> Offer {
    let Agreed {
        purposes,
        members,
        others,
    } = proposal;
    let named = |query: QueryIndex| entries.iter().any(|entry| entry.names(query));
    let candidates = others
        .iter()
        .flat_map(|&set| set.choices.iter().map(move |added| (set, added)));
    let mut examining = Examining::new(candidates);
    let additions = examining
        .by_ref()
        .filter(|(_, added)| {
            added
                .iter()
                .all(|m| !named(m.query) && members.iter().all(|o| o.query != m.query))
        })
        .map(|(set, added)| Addition {
            set: set.index,
            purpose: set.choices.purpose().cloned(),
            members: added,
        })
        .collect();
    let total = sum(others.iter().map(|set| set.choices.count()));
    Offer {
        purposes,
        members,
        additions,
        unexamined: examining.examined().unexamined(total),
    }
}

/// Each option of each optional set as a proposal, the other sets its additions: the request
/// whose every set is optional.
fn each_option(optional: &[OptionalSet]) -> impl Iterator<Item = Proposal<'_>> {
    optional.iter().flat_map(move |offered| {
        let others: Vec<&OptionalSet> = optional
            .iter()
            .filter(|set| set.index != offered.index)
            .collect();
        let purposes: Vec<Value> = offered.choices.purpose().cloned().into_iter().collect();
        offered.choices.iter().map(move |members| Proposal {
            purposes: purposes.clone(),
            members: Combination::Agreed(members),
            others: others.clone(),
        })
    })
}

/// Each combination of a choice of every required set as a proposal, the optional sets its
/// additions.
fn each_combination<'s>(
    required: &'s [Choices],
    optional: &'s [OptionalSet],
) -> impl Iterator<Item = Proposal<'s>> {
    let purposes: Vec<Value> = required
        .iter()
        .filter_map(|choices| choices.purpose().cloned())
        .collect();
    let others: Vec<&OptionalSet> = optional.iter().collect();
    required
        .iter()
        .map(Choices::iter)
        .multi_cartesian_product()
        .map(move |choices| Proposal {
            purposes: purposes.clone(),
            members: Combination::of(choices),
            others: others.clone(),
        })
}
