//! Selecting claims and credentials — OpenID4VP 1.0 §6.4.
//!
//! Two rules here are easy to miss and both change what a wallet offers:
//!
//! - "If the Wallet cannot deliver all claims requested by the Verifier
//!   according to these rules, it MUST NOT return the respective Credential"
//!   (§6.4.1). A credential that lacks a requested claim is not a weak match;
//!   it is not a match. Filtering on format and metadata alone offers
//!   credentials that cannot satisfy the request.
//! - "If `credential_sets` is not provided, the Verifier requests
//!   presentations for all Credentials in `credentials`" (§6.4). Absent means
//!   *every* query must be satisfied, not *no constraint*.

use serde_json::Value;

use crate::path::{PathComponent, PathError};
use crate::query::{ClaimsQuery, CredentialQuery, CredentialSetQuery, DcqlQuery};

/// A credential the wallet holds, as far as DCQL is concerned.
pub trait Credential {
    /// Stable identifier, echoed back in match results.
    fn id(&self) -> &str;
    /// Storage format, e.g. `mso_mdoc`.
    fn format(&self) -> &str;
    /// Resolve a claims path pointer (§7) against this credential.
    ///
    /// # Errors
    ///
    /// [`PathError`] as defined by the processing rules for this credential's
    /// format. [`PathError::Empty`] — the credential simply lacks the claim —
    /// is the ordinary case and not exceptional.
    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError>;
}

/// Format and metadata matching, which DCQL deliberately leaves
/// format-specific.
///
/// §6.1 defines `meta` as "an object defining additional properties ...
/// defined per Credential Format", so a generic engine cannot interpret it.
/// Anything a deployment layers on top — a format that is satisfied by a
/// different stored format, a capability the wallet must actually have —
/// belongs here too.
pub trait Policy<C: Credential + ?Sized> {
    /// Whether this credential can satisfy this query's format, metadata and
    /// any deployment-specific constraints. Claims are checked separately.
    fn matches(&self, query: &CredentialQuery, credential: &C) -> bool;
}

/// Format equality and nothing else.
///
/// Enough to use the crate standalone, and the right default for a caller
/// with no `meta` conventions of its own. Anything richer — `doctype_value`,
/// `vct_values`, a ZK format satisfied by ordinary mdoc storage — is a
/// deployment's own [`Policy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactFormat;

impl<C: Credential + ?Sized> Policy<C> for ExactFormat {
    fn matches(&self, query: &CredentialQuery, credential: &C) -> bool {
        query.format == credential.format()
    }
}

/// A claim the wallet would disclose for a match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedClaim {
    /// `id` of the claims query this satisfies, when it had one.
    pub claim_id: Option<String>,
    /// The path that selected it.
    pub path: Vec<PathComponent>,
}

/// One credential that satisfies one credential query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The credential's own identifier.
    pub credential_id: String,
    /// Claims to disclose — exactly these, and no others (§6.4).
    pub claims: Vec<SelectedClaim>,
}

/// The candidates for one credential query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMatch {
    /// The credential query's `id`.
    pub query_id: String,
    /// Credentials that satisfy it, in the order the wallet holds them.
    pub candidates: Vec<Candidate>,
}

impl QueryMatch {
    /// Whether any credential satisfies this query.
    pub fn is_satisfied(&self) -> bool {
        !self.candidates.is_empty()
    }
}

/// One way to satisfy the whole request.
///
/// Every member is presented *together*: this is what the picker offers as a
/// single choice, and what the user consents to as a unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combination {
    /// Which credential answers which query, with the claims to disclose.
    pub members: Vec<(String, Candidate)>,
}

/// The combinations that satisfy a request, and whether the list was cut short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combinations {
    /// Ways to satisfy the request, in wallet order.
    pub combinations: Vec<Combination>,
    /// How many were discarded to stay within the caller's limit.
    ///
    /// Named rather than left implicit: a picker that silently shows the first
    /// few of many is telling the user those are the only options they have.
    pub dropped: usize,
}

/// The outcome of evaluating a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryResult {
    /// Per-credential-query candidates, in query order.
    pub matches: Vec<QueryMatch>,
    /// Whether the wallet can satisfy the request at all.
    ///
    /// False means the wallet "MUST NOT return any Credential(s)" (§6.4) —
    /// so nothing should be offered, not even the part that did match.
    pub satisfiable: bool,
    /// The request's credential sets, kept so combinations can be enumerated
    /// without handing the query around alongside its own result.
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl QueryResult {
    /// The candidates for a given query id.
    pub fn query(&self, id: &str) -> Option<&QueryMatch> {
        self.matches.iter().find(|m| m.query_id == id)
    }
}

/// Evaluate a DCQL query against the credentials a wallet holds.
///
/// `policy` decides format and metadata matching; this function owns the
/// claim selection and set logic the spec defines generically.
pub fn execute<C: Credential>(
    query: &DcqlQuery,
    credentials: &[C],
    policy: &impl Policy<C>,
) -> QueryResult {
    let matches: Vec<QueryMatch> = query
        .credentials
        .iter()
        .map(|cq| QueryMatch {
            query_id: cq.id.clone(),
            candidates: credentials
                .iter()
                .filter(|c| policy.matches(cq, *c))
                .filter_map(|c| {
                    select_claims(cq, c).map(|claims| Candidate {
                        credential_id: c.id().to_string(),
                        claims,
                    })
                })
                .collect(),
        })
        .collect();

    // `credentials` is REQUIRED and non-empty (§6), but parsing does not
    // enforce it, and every check below is vacuously true over an empty set:
    // an empty query would be reported satisfiable and the picker would offer
    // an entry backed by nothing.
    if query.credentials.is_empty() {
        return QueryResult {
            matches,
            satisfiable: false,
            credential_sets: query.credential_sets.clone(),
        };
    }

    let required_sets_met = match &query.credential_sets {
        // "If `credential_sets` is not provided, the Verifier requests
        // presentations for all Credentials in `credentials`" (§6.4) — every
        // query must be satisfied, which is the opposite of unconstrained.
        None => matches.iter().all(QueryMatch::is_satisfied),
        // Otherwise every required set must have at least one satisfiable
        // option; optional sets impose nothing.
        Some(sets) => sets.iter().filter(|s| s.required).all(|set| {
            set.options.iter().any(|option| {
                option.iter().all(|id| {
                    matches
                        .iter()
                        .any(|m| m.query_id == *id && m.is_satisfied())
                })
            })
        }),
    };

    // A request whose sets are all optional passes the check above with
    // nothing matched, because "all required sets are satisfied" is vacuously
    // true. Conformant, and useless in a picker: the wallet would be offered
    // to the user with no credential behind it.
    let anything_to_offer = matches.iter().any(QueryMatch::is_satisfied);

    QueryResult {
        satisfiable: required_sets_met && anything_to_offer,
        matches,
        credential_sets: query.credential_sets.clone(),
    }
}

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
    /// [`Combinations::dropped`] rather than silently discarded — a list of
    /// options that quietly omits some is a list the user cannot reason about.
    ///
    /// Optional credential sets (§6.2 `required: false`) are not enumerated.
    /// The wallet MAY include them, so whether to offer one is a UI decision
    /// about what to ask the user for, not a matching decision, and folding
    /// them in here would multiply the combination count for choices the
    /// verifier said it can do without.
    pub fn combinations(&self, limit: usize) -> Combinations {
        if !self.satisfiable {
            return Combinations {
                combinations: Vec::new(),
                dropped: 0,
            };
        }

        // Each required group is a set of query ids that must all be answered
        // by one combination. Without `credential_sets` that is every query
        // (§6.4); with them it is one satisfiable option per required set.
        let groups: Vec<Vec<Vec<String>>> = match &self.credential_sets {
            None => vec![vec![self
                .matches
                .iter()
                .map(|m| m.query_id.clone())
                .collect()]],
            Some(sets) => sets
                .iter()
                .filter(|s| s.required)
                .map(|set| {
                    set.options
                        .iter()
                        .filter(|option| {
                            option
                                .iter()
                                .all(|id| self.query(id).is_some_and(QueryMatch::is_satisfied))
                        })
                        .cloned()
                        .collect()
                })
                .collect(),
        };

        // Every set optional: nothing is required, so there is no combination
        // to enumerate. Returning one empty combination here would hand the
        // picker an option containing no credentials at all. What to offer
        // from the optional sets is the caller's decision.
        if groups.is_empty() {
            return Combinations {
                combinations: Vec::new(),
                dropped: 0,
            };
        }

        // Choose one option per required group, then one candidate per query
        // in the chosen options.
        let mut out: Vec<Combination> = vec![Combination {
            members: Vec::new(),
        }];
        let mut dropped = 0usize;

        for options in &groups {
            let mut next: Vec<Combination> = Vec::new();
            for partial in &out {
                for option in options {
                    // Generate only what still fits. The full product can be
                    // enormous — ten candidates across three queries is a
                    // thousand — and materialising it to then keep 32 defeats
                    // the point of a limit. What is skipped is counted from
                    // the arithmetic rather than by building it.
                    let budget = limit.saturating_sub(next.len());
                    let (products, skipped) = candidate_products(self, option, budget);
                    dropped = dropped.saturating_add(skipped);
                    for members in products {
                        let mut combined = partial.members.clone();
                        combined.extend(members);
                        next.push(Combination { members: combined });
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
}

/// Up to `budget` ways to pick one candidate for each query id in `option`,
/// and how many further ways existed.
///
/// The count is a product of the per-query candidate counts, so it is computed
/// rather than reached by building every combination and discarding most of
/// them.
fn candidate_products(
    result: &QueryResult,
    option: &[String],
    budget: usize,
) -> (Vec<Vec<(String, Candidate)>>, usize) {
    let mut total: usize = 1;
    for id in option {
        let Some(query_match) = result.query(id) else {
            return (Vec::new(), 0);
        };
        total = total.saturating_mul(query_match.candidates.len());
    }
    if total == 0 {
        return (Vec::new(), 0);
    }

    let take = total.min(budget);
    let mut products: Vec<Vec<(String, Candidate)>> = Vec::with_capacity(take);

    // Index arithmetic rather than a growing cartesian product: the nth
    // combination is a mixed-radix reading of n across the per-query candidate
    // counts, so only the ones actually wanted are built.
    for n in 0..take {
        let mut remainder = n;
        let mut members = Vec::with_capacity(option.len());
        for id in option {
            let Some(query_match) = result.query(id) else {
                return (Vec::new(), 0);
            };
            let width = query_match.candidates.len();
            let Some(candidate) = query_match.candidates.get(remainder % width) else {
                return (Vec::new(), 0);
            };
            members.push((id.clone(), candidate.clone()));
            remainder /= width;
        }
        products.push(members);
    }

    (products, total - take)
}

/// Which claims to disclose for one credential, or `None` if this credential
/// cannot satisfy the query at all (§6.4.1).
///
/// The four cases are the spec's, in its order:
///
/// - `claims` absent: no selectively disclosable claims are requested.
/// - `claims` present, `claim_sets` absent: all of them are requested, and
///   every one must resolve.
/// - both present: the first option the credential can satisfy wins, because
///   "The order of the options ... expresses the Verifier's preference".
/// - `claim_sets` without `claims` is invalid, and matches nothing.
pub fn select_claims<C: Credential + ?Sized>(
    query: &CredentialQuery,
    credential: &C,
) -> Option<Vec<SelectedClaim>> {
    match (query.claims.is_empty(), query.claim_sets.as_ref()) {
        // "`claim_sets` MUST NOT be present if `claims` is absent" (§6.4.1).
        // Refusing rather than ignoring: the verifier asked for a combination
        // of claims it never listed, so what it wants cannot be determined.
        (true, Some(_)) => None,

        // No selectively disclosable claims requested; mandatory-to-present
        // claims are the format's business, not the query engine's.
        (true, None) => Some(Vec::new()),

        // All listed claims requested. Any one missing disqualifies the whole
        // credential — "MUST NOT return the respective Credential" (§6.4.1).
        (false, None) => query
            .claims
            .iter()
            .map(|c| resolve(c, credential))
            .collect::<Option<Vec<_>>>(),

        // One combination, first satisfiable wins.
        (false, Some(sets)) => sets.iter().find_map(|set| {
            set.iter()
                .map(|id| query.claim(id).and_then(|c| resolve(c, credential)))
                .collect::<Option<Vec<_>>>()
        }),
    }
}

/// Resolve one claims query against a credential, honouring `values`.
///
/// Returns `None` when the credential lacks the claim, or when a `values`
/// restriction excludes it — §6.4.1 says such a claim "should be treated the
/// same as if it did not exist in the Credential", which is exactly what
/// returning `None` here achieves.
fn resolve<C: Credential + ?Sized>(claim: &ClaimsQuery, credential: &C) -> Option<SelectedClaim> {
    let found = credential.claim(&claim.path).ok()?;
    if found.is_empty() {
        return None;
    }

    if let Some(expected) = &claim.values {
        // "the type and value of the claim both match exactly for at least
        // one of the elements" (§6.3). serde_json's PartialEq is exact on
        // both, so `true` does not match `"true"` and 1 does not match "1".
        if !found.iter().any(|v| expected.contains(v)) {
            return None;
        }
    }

    Some(SelectedClaim {
        claim_id: claim.id.clone(),
        path: claim.path.clone(),
    })
}
