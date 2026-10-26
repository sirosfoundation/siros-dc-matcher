//! Selecting claims and credentials — OpenID4VP 1.0 §6.4.
//!
//! Two rules here are easy to miss and both change what a wallet offers:
//!
//! - "If the Wallet cannot deliver all claims requested by the Verifier
//!   according to these rules, it MUST NOT return the respective Credential"
//!   (§6.4.1). A credential that lacks a requested claim is not a match.
//!   Filtering on format and metadata alone offers credentials that cannot
//!   satisfy the request.
//! - "If `credential_sets` is not provided, the Verifier requests
//!   presentations for all Credentials in `credentials`" (§6.4). Absent means
//!   *every* query must be satisfied.

use serde_json::Value;

use crate::path::{PathComponent, PathError};
use crate::query::{ClaimsQuery, CredentialQuery, DcqlQuery, HolderBinding, SetRequirement};
use crate::result::{Candidate, QueryMatch, QueryResult, Satisfaction, SelectedClaim};

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
    /// is the ordinary case.
    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError>;

    /// Whether this credential is cryptographically bound to its holder.
    ///
    /// Answers §6.1's `require_cryptographic_holder_binding`, whose default is
    /// `true`: a verifier says nothing and still means "bound". A credential
    /// that answers [`CryptographicBinding::Unbound`] is not offered to such a query.
    ///
    /// Without a default implementation: a blanket answer would let an implementor who never
    /// considered the question assert a security property on their credentials' behalf, and
    /// the failure mode is a verifier being handed exactly what it said it would not accept.
    fn binding(&self) -> CryptographicBinding;
}

/// Whether a credential is cryptographically bound to its holder (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptographicBinding {
    /// A presentation can prove possession of the credential's key.
    Bound,
    /// The credential is bound to no key.
    Unbound,
}

/// Format and metadata matching, which DCQL leaves format-specific.
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
/// `vct_values` — is a deployment's own [`Policy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactFormat;

impl<C: Credential + ?Sized> Policy<C> for ExactFormat {
    fn matches(&self, query: &CredentialQuery, credential: &C) -> bool {
        *query.format() == *credential.format()
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
        .credentials()
        .iter()
        .map(|cq| {
            QueryMatch::new(
                cq.id().clone(),
                cq.multiplicity(),
                candidates(cq, credentials, policy),
            )
        })
        .collect();
    let satisfaction = Satisfaction::of(satisfiable(query, &matches));
    QueryResult::new(
        matches,
        satisfaction,
        query.credential_sets().map(<[_]>::to_vec),
    )
}

/// The credentials of `credentials` that answer `cq`, each with the claims it discloses.
fn candidates<C: Credential>(
    cq: &CredentialQuery,
    credentials: &[C],
    policy: &impl Policy<C>,
) -> Vec<Candidate> {
    credentials
        .iter()
        // §6.1 `require_cryptographic_holder_binding`, default true. Before the policy and the
        // claims: an unbound credential is disqualified for a query that requires binding,
        // however well it fits otherwise.
        .filter(|c| {
            cq.holder_binding() == HolderBinding::Optional
                || c.binding() == CryptographicBinding::Bound
        })
        .filter(|c| policy.matches(cq, *c))
        .filter_map(|c| {
            select_claims(cq, c).map(|claims| Candidate::new(c.id().to_owned(), claims))
        })
        .collect()
}

/// Whether the wallet can satisfy `query` with `matches`.
fn satisfiable(query: &DcqlQuery, matches: &[QueryMatch]) -> bool {
    // `credentials` is REQUIRED and non-empty (§6), but parsing does not enforce it, and every
    // check below is vacuously true over an empty set: an empty query would be reported
    // satisfiable and the picker would offer an entry backed by nothing.
    if query.credentials().is_empty() {
        return false;
    }
    let required_sets_met = match query.credential_sets() {
        // "If `credential_sets` is not provided, the Verifier requests presentations for all
        // Credentials in `credentials`" (§6.4): every query must be satisfied.
        None => matches.iter().all(QueryMatch::is_satisfied),
        // Otherwise every required set must have at least one satisfiable option; optional
        // sets impose nothing.
        Some(sets) => sets
            .iter()
            .filter(|s| s.requirement() == SetRequirement::Required)
            .all(|set| {
                set.options().iter().any(|option| {
                    option.iter().all(|id| {
                        matches
                            .iter()
                            .any(|m| m.query_id() == id && m.is_satisfied())
                    })
                })
            }),
    };
    // A request whose sets are all optional passes the check above with nothing matched,
    // because "all required sets are satisfied" is vacuously true. Conformant, and useless in a
    // picker: the wallet would be offered to the user with no credential behind it.
    let anything_to_offer = matches.iter().any(QueryMatch::is_satisfied);
    required_sets_met && anything_to_offer
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
    match (query.claims().is_empty(), query.claim_sets()) {
        // "`claim_sets` MUST NOT be present if `claims` is absent" (§6.4.1). The verifier asked
        // for a combination of claims it never listed, so what it wants cannot be determined.
        (true, Some(_)) => None,

        // No selectively disclosable claims requested; mandatory-to-present
        // claims are the format's business.
        (true, None) => Some(Vec::new()),

        // All listed claims requested. Any one missing disqualifies the whole
        // credential — "MUST NOT return the respective Credential" (§6.4.1).
        (false, None) => query
            .claims()
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
/// `None` when the credential lacks the claim, or when a `values` restriction excludes it —
/// §6.4.1 says such a claim "should be treated the same as if it did not exist in the
/// Credential".
fn resolve<C: Credential + ?Sized>(claim: &ClaimsQuery, credential: &C) -> Option<SelectedClaim> {
    let found = credential.claim(claim.path()).ok()?;
    if found.is_empty() {
        return None;
    }

    if let Some(expected) = claim.values() {
        // "the type and value of the claim both match exactly for at least one of the
        // elements" (§6.3). serde_json's PartialEq is exact on both, so `true` does not match
        // `"true"` and 1 does not match "1".
        if !found.iter().any(|v| expected.contains(v)) {
            return None;
        }
    }

    Some(SelectedClaim::new(
        claim.id().cloned(),
        claim.path().to_vec(),
    ))
}
