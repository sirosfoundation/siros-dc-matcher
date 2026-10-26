//! Offers (A3): the combinations of credentials the user chooses from, and the optional
//! additions to each.

use std::num::NonZeroUsize;

use serde_json::Value;
use siros_dcql::{CredentialSetQuery, Dropped};

use crate::matching::Answered;

/// The most offers of a request.
pub const MAX_OFFERS: usize = 32;

/// The most additions of an offer.
pub const MAX_ADDITIONS: usize = 32;

/// The most combinations examined for the offers of a request, and for the additions of an
/// offer.
pub const MAX_EXAMINED: usize = 1024;

/// What an offer presents for one Credential Query: one candidate, or every candidate of a
/// query that sets `multiple`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Member {
    query: usize,
    candidates: Vec<usize>,
}

impl Member {
    /// The index of the Credential Query in the DCQL query.
    pub fn query(&self) -> usize {
        self.query
    }

    /// The indexes of the candidates among the query's candidates, at least one; every
    /// candidate of a `multiple` query, of which the selection chooses a subset.
    pub fn candidates(&self) -> &[usize] {
        &self.candidates
    }

    /// The member of the candidates at `positions` among [`Member::candidates`], each once.
    /// `None` for an empty subset or a position out of range or repeated.
    pub(crate) fn subset(&self, positions: &[usize]) -> Option<Self> {
        let mut candidates = Vec::with_capacity(positions.len());
        for position in positions {
            let candidate = *self.candidates.get(*position)?;
            if candidates.contains(&candidate) {
                return None;
            }
            candidates.push(candidate);
        }
        (!candidates.is_empty()).then_some(Self {
            query: self.query,
            candidates,
        })
    }
}

/// A combination of credentials the user may present together.
#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    purposes: Vec<Value>,
    members: Vec<Member>,
    additions: Vec<Addition>,
    unexamined: Dropped,
}

/// An option of an optional credential set the user may add to an offer (OpenID4VP 1.0,
/// Section 6.4.2).
#[derive(Debug, Clone, PartialEq)]
pub struct Addition {
    set: usize,
    purpose: Option<Value>,
    members: Vec<Member>,
}

/// The offers of a request.
#[derive(Debug, Clone, PartialEq)]
pub struct Offers {
    offers: Vec<Offer>,
    unexamined: Dropped,
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
}

impl Addition {
    /// The index of the credential set in `credential_sets`.
    pub fn set(&self) -> usize {
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
    /// The offers of `answered` that `accept` accepts. `entries` holds, for each
    /// `transaction_data` entry, the indexes of the Credential Queries its `credential_ids`
    /// name.
    ///
    /// - Without `credential_sets`, an offer answers every query (Section 6.4.2).
    /// - Each combination of an option of every required credential set is an offer.
    /// - An optional set that alone names a query of an entry no required set names joins the
    ///   required sets, so its credentials carry the entry (Section 8.4).
    /// - When every set is optional, each option of each set is an offer.
    /// - An option holds a member per query: a candidate, or all candidates of a query that
    ///   sets `multiple`.
    ///
    /// The options of the other optional sets are each offer's additions, except those that
    /// answer a query of the offer or a query an entry names. Combinations are examined in
    /// order, up to [`MAX_EXAMINED`], and at most [`MAX_OFFERS`] offers and [`MAX_ADDITIONS`]
    /// additions per offer are kept.
    pub fn of<C>(
        answered: &Answered<'_, C>,
        mut accept: impl FnMut(&[Member]) -> bool,
        entries: &[Vec<usize>],
    ) -> Self {
        let space = Space::of(answered);
        let named = |query: usize| entries.iter().any(|named| named.contains(&query));
        let mut required = Vec::new();
        let mut optional = Vec::new();
        match answered.asked().query().credential_sets.as_deref() {
            None => required.push(Choices::all(&space)),
            Some(sets) => {
                let joined = joined(&space, sets, entries);
                for (index, set) in sets.iter().enumerate() {
                    let choices = Choices::of_set(&space, set);
                    if set.required || joined.contains(&index) {
                        required.push(choices);
                    } else {
                        optional.push(Optional {
                            set: index,
                            choices,
                        });
                    }
                }
            }
        }
        let mut found = Found::default();
        if required.is_empty() {
            found.offer_each_option(&optional, &mut accept, &named);
        } else {
            found.offer_each_combination(&required, &optional, &mut accept, &named);
        }
        Self {
            offers: found.offers,
            unexamined: found.unexamined,
        }
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

/// The optional sets that join the required ones: for each entry no required set can carry,
/// the one optional set whose options name a query of the entry, when it is alone.
fn joined(space: &Space, sets: &[CredentialSetQuery], entries: &[Vec<usize>]) -> Vec<usize> {
    let names = |set: &CredentialSetQuery, entry: &[usize]| {
        set.options
            .iter()
            .flatten()
            .filter_map(|id| space.index(id))
            .any(|query| entry.contains(&query))
    };
    entries
        .iter()
        .filter(|entry| !sets.iter().any(|set| set.required && names(set, entry)))
        .filter_map(|entry| {
            let mut carrying = sets
                .iter()
                .enumerate()
                .filter(|(_, set)| names(set, entry))
                .map(|(index, _)| index);
            match (carrying.next(), carrying.next()) {
                (Some(alone), None) => Some(alone),
                _ => None,
            }
        })
        .collect()
}

/// The offers found so far.
struct Found {
    offers: Vec<Offer>,
    examined: usize,
    unexamined: Dropped,
}

impl Default for Found {
    fn default() -> Self {
        Self {
            offers: Vec::new(),
            examined: 0,
            unexamined: Dropped::Exact(0),
        }
    }
}

impl Found {
    fn room(&self) -> bool {
        self.offers.len() < MAX_OFFERS && self.examined < MAX_EXAMINED
    }

    fn consider(
        &mut self,
        members: Vec<Member>,
        purposes: Vec<Value>,
        accept: &mut impl FnMut(&[Member]) -> bool,
        additions: impl FnOnce(&[Member]) -> (Vec<Addition>, Dropped),
    ) {
        self.examined += 1;
        if !accept(&members) {
            return;
        }
        let (additions, unexamined) = additions(&members);
        self.offers.push(Offer {
            purposes,
            members,
            additions,
            unexamined,
        });
    }

    /// Each option of each set of `optional` as an offer, the options of the other sets its
    /// additions: the request whose every set is optional.
    fn offer_each_option(
        &mut self,
        optional: &[Optional],
        accept: &mut impl FnMut(&[Member]) -> bool,
        named: &impl Fn(usize) -> bool,
    ) {
        for (at, offered) in optional.iter().enumerate() {
            let others: Vec<&Optional> = optional
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != at)
                .map(|(_, other)| other)
                .collect();
            let mut n = 0;
            while self.room() {
                let Some(members) = offered.choices.choice(n) else {
                    break;
                };
                n += 1;
                self.consider(members, offered.choices.purposes(), accept, |members| {
                    additions(&others, members, named)
                });
            }
        }
        let counts = optional.iter().map(|o| o.choices.count);
        self.unexamined = remaining(counts, self.examined);
    }

    /// Each combination of an option of every set of `required` as an offer, the options of
    /// `optional` its additions.
    fn offer_each_combination(
        &mut self,
        required: &[Choices],
        optional: &[Optional],
        accept: &mut impl FnMut(&[Member]) -> bool,
        named: &impl Fn(usize) -> bool,
    ) {
        let purposes: Vec<Value> = required.iter().flat_map(Choices::purposes).collect();
        let optional: Vec<&Optional> = optional.iter().collect();
        let mut n = 0;
        while self.room() {
            let Some(combination) = combine(required, n) else {
                break;
            };
            n += 1;
            match combination {
                Combination::Conflict => self.examined += 1,
                Combination::Members(members) => {
                    self.consider(members, purposes.clone(), accept, |members| {
                        additions(&optional, members, named)
                    });
                }
            }
        }
        let total = product(required.iter().map(|c| c.count));
        self.unexamined = remaining(std::iter::once(total), self.examined);
    }
}

/// The additions to the offer of `members` from the options of `optional`, none answering a
/// query `named` names.
fn additions(
    optional: &[&Optional],
    members: &[Member],
    named: &impl Fn(usize) -> bool,
) -> (Vec<Addition>, Dropped) {
    let mut found = Vec::new();
    let mut examined = 0;
    for optional in optional {
        let mut n = 0;
        while found.len() < MAX_ADDITIONS && examined < MAX_EXAMINED {
            let Some(added) = optional.choices.choice(n) else {
                break;
            };
            n += 1;
            examined += 1;
            if added
                .iter()
                .any(|m| named(m.query) || answers(members, m.query))
            {
                continue;
            }
            found.push(Addition {
                set: optional.set,
                purpose: optional.choices.purpose.clone(),
                members: added,
            });
        }
    }
    let counts = optional.iter().map(|o| o.choices.count);
    (found, remaining(counts, examined))
}

/// Whether `members` answer the query `query`.
fn answers(members: &[Member], query: usize) -> bool {
    members.iter().any(|m| m.query == query)
}

/// A combination of the required sets.
enum Combination {
    /// A query answered once.
    Members(Vec<Member>),
    /// Two choices answer one query with different candidates.
    Conflict,
}

/// Combination `n` of `dimensions`, a choice of each in mixed radix, the first dimension
/// least significant. `None` past the last combination.
fn combine(dimensions: &[Choices], mut n: usize) -> Option<Combination> {
    let mut members: Vec<Member> = Vec::new();
    let mut conflict = false;
    for choices in dimensions {
        let count = choices.count.unwrap_or(usize::MAX);
        let chosen = choices.choice(n.checked_rem(count)?)?;
        n = n.checked_div(count)?;
        for member in chosen {
            match members.iter().find(|m| m.query == member.query) {
                Some(same) => conflict |= *same != member,
                None => members.push(member),
            }
        }
    }
    if n > 0 {
        return None;
    }
    Some(if conflict {
        Combination::Conflict
    } else {
        Combination::Members(members)
    })
}

/// The candidate counts of each query.
struct Space {
    queries: Vec<QuerySpace>,
}

struct QuerySpace {
    id: String,
    multiple: bool,
    candidates: usize,
}

impl QuerySpace {
    /// The slot of the query at `query`; `None` without a candidate.
    fn slot(&self, query: usize) -> Option<Slot> {
        NonZeroUsize::new(self.candidates).map(|candidates| Slot {
            query,
            multiple: self.multiple,
            candidates,
        })
    }
}

impl Space {
    fn of<C>(answered: &Answered<'_, C>) -> Self {
        Self {
            queries: answered
                .queries()
                .iter()
                .map(|a| QuerySpace {
                    id: a.query().id.clone(),
                    multiple: a.query().multiple,
                    candidates: a.candidates().len(),
                })
                .collect(),
        }
    }

    fn index(&self, id: &str) -> Option<usize> {
        self.queries.iter().position(|q| q.id == id)
    }

    /// The slot of the query `id`; `None` when no query has the id or the query has no
    /// candidate.
    fn slot(&self, id: &str) -> Option<Slot> {
        let (query, found) = self.queries.iter().enumerate().find(|(_, q)| q.id == id)?;
        found.slot(query)
    }
}

/// A query of an option and its candidates.
#[derive(Clone, Copy)]
struct Slot {
    query: usize,
    multiple: bool,
    candidates: NonZeroUsize,
}

impl Slot {
    /// The ways to answer the query in one combination: one per candidate, or one for a
    /// `multiple` query, which takes them all.
    fn width(&self) -> usize {
        if self.multiple {
            1
        } else {
            self.candidates.get()
        }
    }

    /// The member of way `n`, and what remains of `n` for the next slots.
    fn member(&self, n: usize) -> (Member, usize) {
        if self.multiple {
            let candidates = (0..self.candidates.get()).collect();
            (self.of(candidates), n)
        } else {
            (self.of(vec![n % self.candidates]), n / self.candidates)
        }
    }

    fn of(&self, candidates: Vec<usize>) -> Member {
        Member {
            query: self.query,
            candidates,
        }
    }
}

/// The ways to satisfy a credential set, or the whole request: an option and a candidate per
/// query of the option.
struct Choices {
    purpose: Option<Value>,
    options: Vec<OptionChoices>,
    /// `None` when the count overflows.
    count: Option<usize>,
}

/// An optional credential set: its index in `credential_sets`, and its choices.
struct Optional {
    set: usize,
    choices: Choices,
}

/// An option whose every query has a candidate.
struct OptionChoices {
    slots: Vec<Slot>,
    /// `None` when the count overflows.
    count: Option<usize>,
}

impl Choices {
    /// Every query at once: the request without `credential_sets`.
    fn all(space: &Space) -> Self {
        let slots = space
            .queries
            .iter()
            .enumerate()
            .map(|(query, q)| q.slot(query))
            .collect();
        Self::of_options(None, [slots])
    }

    /// The options of `set` whose every query has a candidate.
    fn of_set(space: &Space, set: &CredentialSetQuery) -> Self {
        let options = set
            .options
            .iter()
            .map(|ids| ids.iter().map(|id| space.slot(id)).collect());
        Self::of_options(set.purpose.clone(), options)
    }

    /// The choices of the `options` that have a slot per query, `None` for the others.
    fn of_options(
        purpose: Option<Value>,
        options: impl IntoIterator<Item = Option<Vec<Slot>>>,
    ) -> Self {
        let options: Vec<OptionChoices> = options
            .into_iter()
            .flatten()
            .filter(|slots| !slots.is_empty())
            .map(|slots| OptionChoices {
                count: product(slots.iter().map(|slot| Some(slot.width()))),
                slots,
            })
            .collect();
        let count = options
            .iter()
            .try_fold(0usize, |sum, o| o.count.and_then(|c| sum.checked_add(c)));
        Self {
            purpose,
            options,
            count,
        }
    }

    fn purposes(&self) -> Vec<Value> {
        self.purpose.iter().cloned().collect()
    }

    /// The members of choice `n`: the option it falls in, then a mixed-radix reading of the
    /// rest across the option's slots. `None` past the last choice.
    fn choice(&self, mut n: usize) -> Option<Vec<Member>> {
        for option in &self.options {
            let count = option.count.unwrap_or(usize::MAX);
            if n < count {
                return Some(option.choice(n));
            }
            n -= count;
        }
        None
    }
}

impl OptionChoices {
    /// The members of choice `n` of the option, `n` below its count.
    fn choice(&self, mut n: usize) -> Vec<Member> {
        self.slots
            .iter()
            .map(|slot| {
                let (member, rest) = slot.member(n);
                n = rest;
                member
            })
            .collect()
    }
}

/// The product of `counts`: zero with a zero factor, else `None` on overflow or for an
/// overflowed factor.
fn product(counts: impl Iterator<Item = Option<usize>>) -> Option<usize> {
    let counts: Vec<Option<usize>> = counts.collect();
    if counts.contains(&Some(0)) {
        return Some(0);
    }
    counts
        .into_iter()
        .try_fold(1usize, |p, c| p.checked_mul(c?))
}

/// What remains of the sum of `counts` after `examined`.
fn remaining(mut counts: impl Iterator<Item = Option<usize>>, examined: usize) -> Dropped {
    let total = counts.try_fold(0usize, |sum, c| sum.checked_add(c?));
    match total {
        Some(total) => Dropped::Exact(total.saturating_sub(examined)),
        None => Dropped::AtLeast(usize::MAX.saturating_sub(examined)),
    }
}
