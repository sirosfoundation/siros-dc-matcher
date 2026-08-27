//! Digital Credentials Query Language (DCQL), as defined by
//! [OpenID for Verifiable Presentations 1.0][oid4vp] §6.
//!
//! A DCQL query is how a verifier states what it wants. It carries a list of
//! [`CredentialQuery`] entries — each constrained by format, type and claims —
//! and optionally a list of [`CredentialSetQuery`] entries expressing which
//! *combinations* of those would satisfy the request.
//!
//! This crate evaluates such a query against anything implementing
//! [`CredentialSource`]. It does no I/O and has no opinion about how
//! credentials are stored, which is what lets the same engine run inside a
//! WebAssembly sandbox, in a Kotlin wallet, and in a Swift one.
//!
//! # Status
//!
//! The type model below is complete enough to parse against; evaluation is not
//! yet implemented. See the repository's `docs/plan.md`.
//!
//! [oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use serde::{Deserialize, Serialize};

/// A complete DCQL query (OpenID4VP 1.0 §6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DcqlQuery {
    /// The credential queries, each identified by its own `id` (§6.1).
    pub credentials: Vec<CredentialQuery>,
    /// Which combinations of the above satisfy the request (§6.2).
    ///
    /// Absent means every credential query must be satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One requested credential (OpenID4VP 1.0 §6.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// Identifier for this query, referenced from [`CredentialSetQuery`].
    pub id: String,
    /// Requested credential format, e.g. `mso_mdoc` or `dc+sd-jwt`.
    pub format: String,
    /// Format-specific type constraints — `doctype_value`, `vct_values`, and
    /// any profile-specific keys a deployment adds.
    ///
    /// Deliberately untyped: the set of meaningful `meta` keys is open, and a
    /// matcher's configuration decides how to interpret them. Baking the known
    /// keys in here would put every new credential format behind a release of
    /// this crate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Map<String, serde_json::Value>>,
    /// Claims the verifier wants from this credential (§6.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimsQuery>,
    /// Alternative sets of claims, referenced by [`ClaimsQuery::id`] (§6.3.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

/// A single requested claim (OpenID4VP 1.0 §6.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// Identifier, required when the query uses `claim_sets`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Path to the claim within the credential.
    ///
    /// For ISO mdoc this is `[namespace, element_identifier]`; for JSON-based
    /// credentials it is a JSON path expressed as path components.
    pub path: Vec<serde_json::Value>,
    /// If present, the claim matches only when its value is one of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<serde_json::Value>>,
}

/// A grouping constraint over credential queries (OpenID4VP 1.0 §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// Each option is a list of [`CredentialQuery::id`] values that together
    /// satisfy this set. Satisfying any one option satisfies the set.
    pub options: Vec<Vec<String>>,
    /// Whether this set must be satisfied. Defaults to `true` per spec.
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

/// A credential this wallet holds, as far as DCQL evaluation is concerned.
///
/// Implemented by the caller so the engine stays free of any storage model.
pub trait Credential {
    /// Stable identifier, returned in match results.
    fn id(&self) -> &str;
    /// Storage format, e.g. `mso_mdoc`.
    fn format(&self) -> &str;
    /// Value of a claim at `path`, or `None` if this credential lacks it.
    fn claim(&self, path: &[serde_json::Value]) -> Option<&serde_json::Value>;
}

/// The set of credentials a query is evaluated against.
pub trait CredentialSource {
    /// The concrete credential type.
    type Credential: Credential;
    /// Every credential available for matching.
    fn credentials(&self) -> &[Self::Credential];
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// `required` defaults to true when the verifier omits it (§6.2).
    #[test]
    fn credential_set_required_defaults_to_true() {
        let set: CredentialSetQuery = serde_json::from_str(r#"{"options":[["pid"]]}"#).unwrap();
        assert!(set.required);
    }

    /// A minimal query round-trips without losing its optional fields.
    #[test]
    fn minimal_query_parses() {
        let q: DcqlQuery = serde_json::from_str(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc",
                 "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
                 "claims":[{"path":["org.iso.18013.5.1","family_name"]}]}]}"#,
        )
        .unwrap();
        assert_eq!(q.credentials.len(), 1);
        assert_eq!(q.credentials[0].format, "mso_mdoc");
        assert!(q.credential_sets.is_none());
    }
}
