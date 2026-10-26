//! The ways to satisfy a credential set or a request, enumerated lazily, and the limits of what
//! an enumeration examines.

use std::cmp::Ordering;
use std::num::NonZeroUsize;
use std::ops::Deref;

use itertools::Itertools;
use serde_json::Value;
use siros_dcql::{CredentialSetQuery, Dropped};

use super::{Member, MAX_EXAMINED};
use crate::ids::{CandidateIndex, QueryIndex};
use crate::matching::Answered;

/// How a query is answered in one combination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Multiplicity {
    /// By one of its candidates.
    One,
    /// By every candidate: the query sets `multiple`.
    Every,
}

/// A Credential Query of an option, and its candidates.
#[derive(Debug, Clone, Copy)]
struct Slot {
    query: QueryIndex,
    multiplicity: Multiplicity,
    candidates: NonZeroUsize,
}

impl Slot {
    /// The number of ways to answer the query in one combination.
    fn width(self) -> usize {
        match self.multiplicity {
            Multiplicity::One => self.candidates.get(),
            Multiplicity::Every => 1,
        }
    }

    /// The member of each way, in the order of the candidates.
    fn ways(self) -> impl Iterator<Item = Member> + Clone {
        (0..self.width()).map(move |way| self.member(way))
    }

    fn member(self, way: usize) -> Member {
        let candidates = match self.multiplicity {
            Multiplicity::One => vec![CandidateIndex::at(way)],
            Multiplicity::Every => (0..self.candidates.get()).map(CandidateIndex::at).collect(),
        };
        Member {
            query: self.query,
            candidates,
        }
    }
}

/// The Credential Queries of a request, each with its slot, or none without a candidate.
pub(super) struct Space<'a> {
    queries: Vec<(&'a str, Option<Slot>)>,
}

impl<'a> Space<'a> {
    pub(super) fn of<C, R>(answered: &'a Answered<'_, C, R>) -> Self {
        let queries = answered
            .indexed()
            .map(|(query, answers)| {
                let multiplicity = if answers.query().multiple {
                    Multiplicity::Every
                } else {
                    Multiplicity::One
                };
                let slot = NonZeroUsize::new(answers.candidates().len()).map(|candidates| Slot {
                    query,
                    multiplicity,
                    candidates,
                });
                (answers.id().as_str(), slot)
            })
            .collect();
        Self { queries }
    }

    /// The slot of the Credential Query `id`; `None` when no query has the id or the query has
    /// no candidate.
    fn slot(&self, id: &str) -> Option<Slot> {
        self.queries
            .iter()
            .find(|(query, _)| *query == id)
            .and_then(|(_, slot)| *slot)
    }
}

/// The ways to satisfy a credential set, or the whole request: an option, and a way to answer
/// each query of the option.
pub(super) struct Choices {
    purpose: Option<Value>,
    options: Vec<Vec<Slot>>,
    /// `None` when the count overflows.
    count: Option<usize>,
}

impl Choices {
    /// Every query at once: the request without `credential_sets`.
    pub(super) fn all(space: &Space<'_>) -> Self {
        let option = space.queries.iter().map(|(_, slot)| *slot).collect();
        Self::of_options(None, [option])
    }

    /// The options of `set` whose every query has a candidate. An option that names a query
    /// the request lacks is one no credential satisfies (Section 6.4).
    pub(super) fn of_set(space: &Space<'_>, set: &CredentialSetQuery) -> Self {
        let options = set
            .options
            .iter()
            .map(|ids| ids.iter().map(|id| space.slot(id)).collect());
        Self::of_options(set.purpose.clone(), options)
    }

    /// The choices of the `options` that have a slot for each query.
    fn of_options(
        purpose: Option<Value>,
        options: impl IntoIterator<Item = Option<Vec<Slot>>>,
    ) -> Self {
        let options: Vec<Vec<Slot>> = options
            .into_iter()
            .flatten()
            .filter(|slots| !slots.is_empty())
            .collect();
        let count = sum(options
            .iter()
            .map(|slots| product(slots.iter().map(|slot| Some(slot.width())))));
        Self {
            purpose,
            options,
            count,
        }
    }

    /// The set's `purpose`.
    pub(super) fn purpose(&self) -> Option<&Value> {
        self.purpose.as_ref()
    }

    /// The number of choices; `None` when it overflows.
    pub(super) fn count(&self) -> Option<usize> {
        self.count
    }

    /// Each choice: the options in order, and in each the ways of its queries, the last query
    /// varying fastest.
    pub(super) fn iter(&self) -> impl Iterator<Item = Vec<Member>> + Clone + '_ {
        self.options.iter().flat_map(|slots| {
            slots
                .iter()
                .map(|slot| slot.ways())
                .multi_cartesian_product()
        })
    }

    /// The choices with a member `carries` accepts, and their number; `None` when it
    /// overflows. Each option's choices come grouped by the first of its queries whose member
    /// `carries` accepts, the last query varying fastest. No other choice is formed.
    pub(super) fn carrying(&self, carries: impl Fn(&Member) -> bool) -> Carrying {
        let options: Vec<Vec<Vec<(Member, bool)>>> = self
            .options
            .iter()
            .map(|slots| {
                slots
                    .iter()
                    .map(|slot| {
                        slot.ways()
                            .map(|way| (way.clone(), carries(&way)))
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let count = sum(options.iter().map(|slots| {
            let all = product(slots.iter().map(|ways| Some(ways.len())));
            let missing = product(
                slots
                    .iter()
                    .map(|ways| Some(ways.iter().filter(|(_, hit)| !hit).count())),
            );
            all.zip(missing)
                .map(|(all, missing)| all.saturating_sub(missing))
        }));
        let choices = options.into_iter().flat_map(|slots| {
            (0..slots.len())
                .map(|first| {
                    slots
                        .iter()
                        .enumerate()
                        .map(|(at, ways)| {
                            ways.iter()
                                .filter(|&&(_, hit)| match at.cmp(&first) {
                                    Ordering::Less => !hit,
                                    Ordering::Equal => hit,
                                    Ordering::Greater => true,
                                })
                                .map(|(way, _)| way.clone())
                                .collect::<Vec<Member>>()
                        })
                        .multi_cartesian_product()
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flatten()
        });
        Carrying {
            count,
            choices: Box::new(choices),
        }
    }
}

/// The choices of a credential set that carry a transaction entry.
pub(super) struct Carrying {
    /// Their number; `None` when it overflows.
    pub(super) count: Option<usize>,
    /// The choices, formed as they are taken.
    pub(super) choices: Box<dyn Iterator<Item = Vec<Member>>>,
}

/// The product of `factors`: zero with a zero factor, else `None` on overflow or for an
/// overflowed factor.
pub(super) fn product(factors: impl Iterator<Item = Option<usize>>) -> Option<usize> {
    let factors: Vec<Option<usize>> = factors.collect();
    if factors.contains(&Some(0)) {
        return Some(0);
    }
    factors
        .into_iter()
        .try_fold(1usize, |product, factor| product.checked_mul(factor?))
}

/// The sum of `terms`; `None` on overflow or for an overflowed term.
pub(super) fn sum(mut terms: impl Iterator<Item = Option<usize>>) -> Option<usize> {
    terms.try_fold(0usize, |sum, term| sum.checked_add(term?))
}

/// An enumeration that gives at most [`MAX_EXAMINED`] items, and counts those it gave.
pub(super) struct Examining<I> {
    items: std::iter::Take<I>,
    examined: usize,
}

/// A number of combinations examined, at most [`MAX_EXAMINED`].
#[derive(Debug, Clone, Copy)]
pub(super) struct Examined(usize);

impl<I: Iterator> Examining<I> {
    pub(super) fn new(items: I) -> Self {
        Self {
            items: items.take(MAX_EXAMINED),
            examined: 0,
        }
    }

    /// How many items it gave so far.
    pub(super) fn examined(&self) -> Examined {
        Examined(self.examined)
    }
}

impl<I: Iterator> Iterator for Examining<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.items.next()?;
        self.examined += 1;
        Some(item)
    }
}

impl Examined {
    /// What remains of `total` combinations; at least what remains of `usize::MAX` when the
    /// total overflows.
    pub(super) fn unexamined(self, total: Option<usize>) -> Dropped {
        match total {
            Some(total) => Dropped::Exact(total.saturating_sub(self.0)),
            None => Dropped::AtLeast(usize::MAX.saturating_sub(self.0)),
        }
    }
}

/// At most `N` items: the first `N` of what it is collected from.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Capped<T, const N: usize>(Vec<T>);

impl<T, const N: usize> FromIterator<T> for Capped<T, N> {
    fn from_iter<I: IntoIterator<Item = T>>(items: I) -> Self {
        Self(items.into_iter().take(N).collect())
    }
}

impl<T, const N: usize> Deref for Capped<T, N> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.0
    }
}
