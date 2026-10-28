//! The combinations of one credential set option: one candidate per query,
//! or every candidate of a §6.1 `multiple` query.

use std::slice;

use super::{Candidate, Dropped, QueryMatch, QueryResult};

/// Up to `budget` ways to answer each query id in `option`, and how many
/// further ways existed.
///
/// One candidate per query, except where the query set §6.1 `multiple`, in
/// which case that query is answered by *all* of its candidates at once and so
/// contributes a single way rather than one per credential.
///
/// The count is a product of the per-query widths, so it is computed rather
/// than reached by building every combination and discarding most of them.
pub(super) fn candidate_products(
    result: &QueryResult,
    option: &[String],
    budget: usize,
) -> (Vec<Vec<(String, Candidate)>>, Dropped) {
    let mut dials = Vec::with_capacity(option.len());
    for id in option {
        // A dangling id or a query without candidates leaves the option
        // without a combination.
        let Some(dial) = result.query(id).and_then(|query| Dial::of(id, query)) else {
            return (Vec::new(), Dropped::Exact(0));
        };
        dials.push(dial);
    }

    let mut total: usize = 1;
    // Whether the product ran out of `usize` on the way. Tracked rather than
    // inferred from `total == usize::MAX`, which a genuine product could also
    // reach, and clamping is what makes the count a bound instead of a number.
    let mut overflowed = false;
    for dial in &dials {
        match total.checked_mul(dial.width()) {
            Some(product) => total = product,
            None => {
                overflowed = true;
                total = usize::MAX;
            }
        }
    }

    let take = total.min(budget);
    let members_per_combination: usize = dials.iter().map(Dial::members).sum();
    let mut products: Vec<Vec<(String, Candidate)>> = Vec::new();
    // The dials turn like an odometer, the first fastest, so the nth
    // combination is the mixed-radix reading of n across the widths, and only
    // the ones wanted are built.
    for _ in 0..take {
        let mut members = Vec::with_capacity(members_per_combination);
        for dial in &dials {
            dial.read(&mut members);
        }
        products.push(members);
        for dial in &mut dials {
            if !dial.turn() {
                break;
            }
        }
    }

    let remaining = total - take;
    let dropped = if overflowed {
        Dropped::AtLeast(remaining)
    } else {
        Dropped::Exact(remaining)
    };
    (products, dropped)
}

/// How one query answers each combination of an option.
enum Dial<'a> {
    /// A query that set §6.1 `multiple`: all of its candidates together, which
    /// is one way, not none.
    ///
    /// Answering a `multiple` query with everything that matches, rather than
    /// enumerating each credential as its own alternative, is the reading
    /// under which the flag does something: "multiple Credentials can be
    /// returned for this Credential Query" (§6.1). It also collapses the
    /// combination count where the permissive reading would multiply it, and
    /// the holder still consents to the combination as a whole.
    Every {
        id: &'a str,
        candidates: &'a [Candidate],
    },
    /// Any other query: one candidate per combination, in wallet order.
    One {
        id: &'a str,
        first: &'a Candidate,
        rest: &'a [Candidate],
        current: &'a Candidate,
        upcoming: slice::Iter<'a, Candidate>,
    },
}

impl<'a> Dial<'a> {
    /// The dial of `query`, or `None` for a query without candidates.
    fn of(id: &'a str, query: &'a QueryMatch) -> Option<Self> {
        let (first, rest) = query.candidates.split_first()?;
        Some(if query.multiple {
            Self::Every {
                id,
                candidates: &query.candidates,
            }
        } else {
            Self::One {
                id,
                first,
                rest,
                current: first,
                upcoming: rest.iter(),
            }
        })
    }

    /// How many distinct ways the query answers a combination.
    fn width(&self) -> usize {
        match self {
            Self::Every { .. } => 1,
            Self::One { rest, .. } => rest.len() + 1,
        }
    }

    /// How many members the query adds to each combination.
    fn members(&self) -> usize {
        match self {
            Self::Every { candidates, .. } => candidates.len(),
            Self::One { .. } => 1,
        }
    }

    /// Append the query's members of the current combination.
    fn read(&self, members: &mut Vec<(String, Candidate)>) {
        match self {
            Self::Every { id, candidates } => members.extend(
                candidates
                    .iter()
                    .map(|candidate| ((*id).to_owned(), candidate.clone())),
            ),
            Self::One { id, current, .. } => members.push(((*id).to_owned(), (*current).clone())),
        }
    }

    /// Move to the next candidate. Whether the dial went past its last one and
    /// back to its first, which carries the turn to the next dial.
    fn turn(&mut self) -> bool {
        match self {
            Self::Every { .. } => true,
            Self::One {
                first,
                rest,
                current,
                upcoming,
                ..
            } => match upcoming.next() {
                Some(next) => {
                    *current = next;
                    false
                }
                None => {
                    *current = *first;
                    *upcoming = (*rest).iter();
                    true
                }
            },
        }
    }
}
