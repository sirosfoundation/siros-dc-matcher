//! The combinations of candidates that satisfy a request (§6.4): what a picker offers, each as
//! one choice.

use serde_json::Value;

use crate::id::QueryId;
use crate::query::{Multiplicity, SetRequirement};
use crate::result::{Candidate, QueryMatch, QueryResult, Satisfaction};

/// One way to satisfy the whole request.
///
/// Every member is presented *together*: this is what the picker offers as a
/// single choice, and what the user consents to as a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combination {
    members: Vec<(QueryId, Candidate)>,
    purposes: Vec<Value>,
}

/// How many combinations were not built.
///
/// A count and a *lie* are not the same thing, hence an enum. The number of combinations is a
/// product of the per-query widths, and a wallet holding enough credentials overflows it — at
/// which point the difference between "we skipped 18446744073709551551" and "we skipped more
/// than we can count" is the difference between a number a caller can show a user and one that
/// will make them doubt everything else on the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    /// Exactly this many were not built.
    Exact(usize),
    /// At least this many were not built; the true product overflowed
    /// `usize`, so it is unknown and unrepresentable.
    AtLeast(usize),
}

/// The combinations that satisfy a request, and whether the list was cut short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combinations {
    combinations: Vec<Combination>,
    dropped: Dropped,
}

impl Combination {
    /// Which credential answers which query, with the claims to disclose.
    #[must_use]
    pub fn members(&self) -> &[(QueryId, Candidate)] {
        &self.members
    }

    /// Why the verifier asked for this, from the `purpose` of each credential set this
    /// combination satisfies (§6.2), in set order.
    ///
    /// Carried per combination because that is where it is needed: a request with several
    /// credential sets offers several combinations, and the reason shown beside one of them is
    /// the reason belonging to *its* set. Empty when the verifier gave no reason, which
    /// includes every request without `credential_sets`.
    #[must_use]
    pub fn purposes(&self) -> &[Value] {
        &self.purposes
    }
}

impl Dropped {
    /// The number, exact or not. Pair it with [`Self::is_exact`] before
    /// showing it to anyone.
    #[must_use]
    pub fn count(self) -> usize {
        match self {
            Self::Exact(n) | Self::AtLeast(n) => n,
        }
    }

    /// Whether [`Self::count`] is the true number rather than a lower bound.
    #[must_use]
    pub fn is_exact(self) -> bool {
        matches!(self, Self::Exact(_))
    }

    /// Whether anything was dropped at all.
    #[must_use]
    pub fn any(self) -> bool {
        self.count() > 0
    }

    /// Both counts together.
    ///
    /// Inexact if either side is — and also if the sum itself overflows, which two exact
    /// counts can do. Saturating and still calling that `Exact` would be the very lie this
    /// type exists to prevent, one layer up from the product that motivated it.
    fn add(self, other: Self) -> Self {
        match self.count().checked_add(other.count()) {
            Some(total) if self.is_exact() && other.is_exact() => Self::Exact(total),
            Some(total) => Self::AtLeast(total),
            None => Self::AtLeast(usize::MAX),
        }
    }
}

impl Combinations {
    /// Ways to satisfy the request, in wallet order.
    #[must_use]
    pub fn combinations(&self) -> &[Combination] {
        &self.combinations
    }

    /// How many were discarded to stay within the caller's limit.
    ///
    /// Named rather than left implicit: a picker that silently shows the first few of many is
    /// telling the user those are the only options they have.
    #[must_use]
    pub fn dropped(&self) -> Dropped {
        self.dropped
    }

    fn none() -> Self {
        Self {
            combinations: Vec::new(),
            dropped: Dropped::Exact(0),
        }
    }
}

/// A required group: the purpose of its set, and the options whose every query is satisfied.
type Group = (Option<Value>, Vec<Vec<QueryId>>);

impl QueryResult {
    /// Enumerate the ways this wallet can satisfy the request.
    ///
    /// A combination is a set of credentials presented *together*, which is
    /// what a picker offers as one selectable option. Alternatives are
    /// separate combinations.
    ///
    /// `limit` bounds the result, because the count is a product: three
    /// queries with four candidates each is sixty-four combinations, and a
    /// picker cannot use them all. Whatever is dropped is counted in
    /// [`Combinations::dropped`] — a list of options that quietly omits some is a list the user
    /// cannot reason about.
    ///
    /// Optional credential sets (§6.2 `required: false`) are not enumerated.
    /// The wallet MAY include them, so whether to offer one is a UI decision
    /// about what to ask the user for, and folding them in here would multiply the combination
    /// count for choices the verifier said it can do without.
    #[must_use]
    pub fn combinations(&self, limit: usize) -> Combinations {
        if self.satisfaction() == Satisfaction::Unsatisfiable {
            return Combinations::none();
        }
        let groups = self.required_groups();
        // Every set optional: nothing is required, so there is no combination to enumerate.
        // One empty combination here would hand the picker an option containing no
        // credentials at all. What to offer from the optional sets is the caller's decision.
        if groups.is_empty() {
            return Combinations::none();
        }

        // Choose one option per required group, then one candidate per query in the chosen
        // options.
        let mut out: Vec<Combination> = vec![Combination {
            members: Vec::new(),
            purposes: Vec::new(),
        }];
        let mut dropped = Dropped::Exact(0);

        for (purpose, options) in &groups {
            let mut next: Vec<Combination> = Vec::new();
            for partial in &out {
                for option in options {
                    // Generate only what still fits. The full product can be enormous — ten
                    // candidates across three queries is a thousand — and materialising it to
                    // then keep 32 defeats the point of a limit. What is skipped is counted
                    // from the arithmetic.
                    let budget = limit.saturating_sub(next.len());
                    let (products, skipped) = candidate_products(self, option, budget);
                    dropped = dropped.add(skipped);
                    for members in products {
                        let mut combined = partial.members.clone();
                        combined.extend(members);
                        let mut purposes = partial.purposes.clone();
                        purposes.extend(purpose.clone());
                        next.push(Combination {
                            members: combined,
                            purposes,
                        });
                    }
                }
            }
            out = next;
            if out.is_empty() {
                break;
            }
        }

        Combinations {
            combinations: out,
            dropped,
        }
    }

    /// Each required group: the query ids one combination must all answer. Without
    /// `credential_sets` that is every query (§6.4); with them it is one satisfiable option per
    /// required set.
    fn required_groups(&self) -> Vec<Group> {
        match self.credential_sets() {
            None => vec![(
                None,
                vec![self
                    .matches()
                    .iter()
                    .map(|m| m.query_id().clone())
                    .collect()],
            )],
            Some(sets) => sets
                .iter()
                .filter(|s| s.requirement() == SetRequirement::Required)
                .map(|set| {
                    let options = set
                        .options()
                        .iter()
                        .filter(|option| {
                            option
                                .iter()
                                .all(|id| self.query(id).is_some_and(QueryMatch::is_satisfied))
                        })
                        .cloned()
                        .collect();
                    (set.purpose().cloned(), options)
                })
                .collect(),
        }
    }
}

/// Up to `budget` ways to answer each query id in `option`, and how many
/// further ways existed.
///
/// One candidate per query, except where the query set §6.1 `multiple`, in
/// which case that query is answered by *all* of its candidates at once and so
/// contributes a single way rather than one per credential.
///
/// The count is a product of the per-query widths, so it is computed rather
/// than reached by building every combination and discarding most of them.
fn candidate_products(
    result: &QueryResult,
    option: &[QueryId],
    budget: usize,
) -> (Vec<Vec<(QueryId, Candidate)>>, Dropped) {
    let Some(matches) = option
        .iter()
        .map(|id| result.query(id))
        .collect::<Option<Vec<&QueryMatch>>>()
    else {
        return (Vec::new(), Dropped::Exact(0));
    };
    // Whether the product ran out of `usize` on the way. Tracked rather than inferred from
    // `total == usize::MAX`, which a genuine product could also reach, and clamping is what
    // makes the count a bound instead of a number.
    let mut overflowed = false;
    let total = matches.iter().fold(1_usize, |total, m| {
        total.checked_mul(query_width(m)).unwrap_or_else(|| {
            overflowed = true;
            usize::MAX
        })
    });
    if total == 0 {
        return (Vec::new(), Dropped::Exact(0));
    }

    let take = total.min(budget);
    // How many members each combination will hold: one per query, except a `multiple` query
    // which contributes all of its candidates. Constant across the products, so it is computed
    // once.
    let members_per_combination: usize = matches
        .iter()
        .map(|m| match m.multiplicity() {
            Multiplicity::Several => m.candidates().len(),
            Multiplicity::One => 1,
        })
        .sum();

    // Index arithmetic rather than a growing cartesian product: the nth combination is a
    // mixed-radix reading of n across the per-query candidate counts, so only the ones actually
    // wanted are built.
    let mut products = Vec::with_capacity(take);
    for n in 0..take {
        products.push(nth_product(&matches, n, members_per_combination));
    }

    let remaining = total - take;
    let dropped = if overflowed {
        Dropped::AtLeast(remaining)
    } else {
        Dropped::Exact(remaining)
    };
    (products, dropped)
}

/// The `n`th way to answer `matches`, every one of which has a candidate: the mixed-radix
/// reading of `n` across their widths.
fn nth_product(matches: &[&QueryMatch], n: usize, members: usize) -> Vec<(QueryId, Candidate)> {
    let mut remainder = n;
    let mut product = Vec::with_capacity(members);
    for m in matches {
        // A `multiple` query has width 1 and contributes every candidate, so it consumes none
        // of the mixed-radix index.
        if m.multiplicity() == Multiplicity::Several {
            product.extend(
                m.candidates()
                    .iter()
                    .map(|candidate| (m.query_id().clone(), candidate.clone())),
            );
            continue;
        }
        let width = m.candidates().len();
        if let Some(candidate) = remainder
            .checked_rem(width)
            .and_then(|way| m.candidates().get(way))
        {
            product.push((m.query_id().clone(), candidate.clone()));
        }
        remainder = remainder.checked_div(width).unwrap_or(0);
    }
    product
}

/// How many distinct ways one query can be answered within a combination.
///
/// One per candidate normally. A query that set §6.1 `multiple` is answered by
/// all of its candidates together, which is one way — so a query with no candidates at all
/// still has width zero and makes the whole product zero.
///
/// Answering a `multiple` query with everything that matches, rather than
/// enumerating each credential as its own alternative, is the reading under
/// which the flag does something: "multiple Credentials can be returned for
/// this Credential Query" (§6.1). It also collapses the combination count
/// where the permissive reading would multiply it, and the holder still
/// consents to the combination as a whole.
fn query_width(m: &QueryMatch) -> usize {
    match m.multiplicity() {
        Multiplicity::Several if !m.candidates().is_empty() => 1,
        _ => m.candidates().len(),
    }
}
