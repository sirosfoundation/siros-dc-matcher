//! Offers (A3): the combinations of credentials the user chooses from, and the optional
//! additions to each.

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

/// A credential an offer presents: a candidate of a Credential Query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Member {
    query: usize,
    candidate: usize,
}

impl Member {
    /// The index of the Credential Query in the DCQL query.
    pub fn query(&self) -> usize {
        self.query
    }

    /// The index of the candidate among the query's candidates.
    pub fn candidate(&self) -> usize {
        self.candidate
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
    /// The offers of `answered` that `accept` accepts.
    ///
    /// - Without `credential_sets`, an offer answers every query (Section 6.4.2).
    /// - Each combination of an option of every required credential set is an offer.
    /// - When every set is optional, each option of each set is an offer.
    /// - An option is a candidate for each of its queries; a query that sets `multiple`
    ///   takes all of its candidates.
    ///
    /// The options of the optional sets are each offer's additions, except the set the offer
    /// came from and the options that answer a query of the offer or a query `fixed` names.
    /// Combinations are examined in order, up to [`MAX_EXAMINED`], and at most [`MAX_OFFERS`]
    /// offers and [`MAX_ADDITIONS`] additions per offer are kept.
    pub fn of<C>(
        answered: &Answered<'_, C>,
        mut accept: impl FnMut(&[Member]) -> bool,
        fixed: impl Fn(usize) -> bool,
    ) -> Self {
        let space = Space::of(answered);
        let mut required = Vec::new();
        let mut optional = Vec::new();
        match answered.asked().query().credential_sets.as_deref() {
            None => required.push(Choices::all(&space)),
            Some(sets) => {
                for (index, set) in sets.iter().enumerate() {
                    let choices = Choices::of_set(&space, index, set);
                    if set.required {
                        required.push(choices);
                    } else {
                        optional.push(choices);
                    }
                }
            }
        }
        let mut found = Found::default();
        if required.is_empty() {
            // Every set is optional: each option is an offer.
            for (at, choices) in optional.iter().enumerate() {
                let others: Vec<&Choices> = optional
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != at)
                    .map(|(_, other)| other)
                    .collect();
                let mut n = 0;
                while found.room() && choices.count.is_none_or(|count| n < count) {
                    let members = choices.choice(&space, n);
                    n += 1;
                    found.consider(members, choices.purposes(), &mut accept, |members| {
                        additions(&space, &others, members, &fixed)
                    });
                }
            }
            found.unexamined = remaining(optional.iter().map(|c| c.count), found.examined);
        } else {
            let total = product(required.iter().map(|c| c.count));
            let purposes: Vec<Value> = required.iter().flat_map(Choices::purposes).collect();
            let optional: Vec<&Choices> = optional.iter().collect();
            let mut n = 0;
            while found.room() && total.is_none_or(|total| n < total) {
                let combined = combine(&space, &required, n);
                n += 1;
                let Some(members) = combined else {
                    found.examined += 1;
                    continue;
                };
                found.consider(members, purposes.clone(), &mut accept, |members| {
                    additions(&space, &optional, members, &fixed)
                });
            }
            found.unexamined = remaining(std::iter::once(total), found.examined);
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
}

/// The additions to the offer of `members` from the option choices of `optional`.
fn additions(
    space: &Space,
    optional: &[&Choices],
    members: &[Member],
    fixed: &impl Fn(usize) -> bool,
) -> (Vec<Addition>, Dropped) {
    let mut found = Vec::new();
    let mut examined = 0;
    for choices in optional {
        let Some(set) = choices.set else {
            continue;
        };
        let mut n = 0;
        while found.len() < MAX_ADDITIONS
            && examined < MAX_EXAMINED
            && choices.count.is_none_or(|count| n < count)
        {
            let added = choices.choice(space, n);
            n += 1;
            examined += 1;
            if added
                .iter()
                .any(|m| fixed(m.query) || answers(members, m.query))
            {
                continue;
            }
            found.push(Addition {
                set,
                purpose: choices.purpose.clone(),
                members: added,
            });
        }
    }
    let counts = optional.iter().map(|c| c.count);
    (found, remaining(counts, examined))
}

/// Whether `members` answer the query `query`.
fn answers(members: &[Member], query: usize) -> bool {
    members.iter().any(|m| m.query == query)
}

/// The members of combination `n` of `dimensions`: a choice of each, a query answered once.
/// `None` when two choices answer one query with different candidates.
fn combine(space: &Space, dimensions: &[Choices], mut n: usize) -> Option<Vec<Member>> {
    let mut members: Vec<Member> = Vec::new();
    for choices in dimensions {
        let count = choices.count.unwrap_or(usize::MAX);
        let chosen = choices.choice(space, n.checked_rem(count)?);
        n = n.checked_div(count)?;
        for member in chosen {
            if members.contains(&member) {
                continue;
            }
            let multiple = space.queries.get(member.query).is_some_and(|q| q.multiple);
            if !multiple && answers(&members, member.query) {
                return None;
            }
            members.push(member);
        }
    }
    Some(members)
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
    /// The ways to answer the query in one combination: one per candidate, or one for a
    /// `multiple` query with candidates, which takes them all.
    fn width(&self) -> usize {
        if self.multiple {
            usize::from(self.candidates > 0)
        } else {
            self.candidates
        }
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
}

/// The ways to satisfy a credential set, or the whole request: an option and a candidate per
/// query of the option.
struct Choices {
    set: Option<usize>,
    purpose: Option<Value>,
    options: Vec<OptionChoices>,
    /// `None` when the count overflows.
    count: Option<usize>,
}

struct OptionChoices {
    queries: Vec<usize>,
    count: Option<usize>,
}

impl Choices {
    /// Every query at once: the request without `credential_sets`.
    fn all(space: &Space) -> Self {
        Self::of_options(space, None, None, [(0..space.queries.len()).collect()])
    }

    /// The options of `set`, at `index` in `credential_sets`, whose every query has a candidate.
    fn of_set(space: &Space, index: usize, set: &CredentialSetQuery) -> Self {
        let options = set.options.iter().filter_map(|ids| {
            ids.iter()
                .map(|id| space.index(id))
                .collect::<Option<Vec<usize>>>()
        });
        Self::of_options(space, Some(index), set.purpose.clone(), options)
    }

    fn of_options(
        space: &Space,
        set: Option<usize>,
        purpose: Option<Value>,
        options: impl IntoIterator<Item = Vec<usize>>,
    ) -> Self {
        let options: Vec<OptionChoices> = options
            .into_iter()
            .map(|queries| OptionChoices {
                count: product(
                    queries
                        .iter()
                        .map(|&q| Some(space.queries.get(q).map_or(0, QuerySpace::width))),
                ),
                queries,
            })
            .filter(|o| o.count != Some(0) && !o.queries.is_empty())
            .collect();
        let count = options
            .iter()
            .try_fold(0usize, |sum, o| o.count.and_then(|c| sum.checked_add(c)));
        Self {
            set,
            purpose,
            options,
            count,
        }
    }

    fn purposes(&self) -> Vec<Value> {
        self.purpose.iter().cloned().collect()
    }

    /// The members of choice `n`: the option it falls in, then a mixed-radix reading of the
    /// rest across the option's queries.
    fn choice(&self, space: &Space, mut n: usize) -> Vec<Member> {
        for option in &self.options {
            let count = option.count.unwrap_or(usize::MAX);
            if n >= count {
                n -= count;
                continue;
            }
            let mut members = Vec::new();
            for &query in &option.queries {
                let Some(q) = space.queries.get(query) else {
                    continue;
                };
                if q.multiple {
                    members.extend((0..q.candidates).map(|candidate| Member { query, candidate }));
                } else if let (Some(candidate), Some(rest)) =
                    (n.checked_rem(q.candidates), n.checked_div(q.candidates))
                {
                    members.push(Member { query, candidate });
                    n = rest;
                }
            }
            return members;
        }
        Vec::new()
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
