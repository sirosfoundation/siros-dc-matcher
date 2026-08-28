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
use crate::query::{ClaimsQuery, CredentialQuery, DcqlQuery};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combination {
    /// Which credential answers which query, with the claims to disclose.
    pub members: Vec<(String, Candidate)>,
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

    let satisfiable = match &query.credential_sets {
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

    QueryResult {
        matches,
        satisfiable,
    }
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
