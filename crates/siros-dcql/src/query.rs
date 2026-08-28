//! The DCQL query model — OpenID4VP 1.0 §6.
//!
//! A faithful transcription of the wire format, with one deliberate
//! relaxation noted on [`CredentialQuery::meta`]. The spec's own instruction
//! shapes the rest: "Implementations MUST ignore any unknown properties"
//! (§6), so nothing here rejects a query for carrying fields it does not
//! recognise — a wallet that refuses tomorrow's extension is worse than one
//! that ignores it.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::path::PathComponent;

/// A complete DCQL query (§6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DcqlQuery {
    /// The requested credentials (§6.1). REQUIRED and non-empty per spec.
    pub credentials: Vec<CredentialQuery>,
    /// Constraints on which combinations to return (§6.2).
    ///
    /// Absent means something specific, not "no constraint": "If
    /// `credential_sets` is not provided, the Verifier requests presentations
    /// for all Credentials in `credentials`" (§6.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One requested credential (§6.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    /// Identifies this query in the response and in `credential_sets`.
    pub id: String,
    /// The requested credential format.
    pub format: String,
    /// Whether more than one credential may be returned for this query.
    ///
    /// "If omitted, the default value is `false`" (§6.1).
    #[serde(default)]
    pub multiple: bool,
    /// Format-specific constraints on metadata and validity.
    ///
    /// The spec marks this REQUIRED, but "If empty, no specific constraints
    /// are placed" (§6.1) — so a missing `meta` and an empty one ask for the
    /// same thing. Defaulting rather than rejecting keeps a slightly
    /// non-conformant verifier working, at no cost to what we match.
    #[serde(default)]
    pub meta: Map<String, Value>,
    /// Authorities whose issuance the verifier will accept (§6.1.1).
    ///
    /// Parsed but not evaluated here: deciding whether an issuer chains to a
    /// trusted authority needs certificate validation and trust-list state
    /// that a query engine has no business holding. Callers that can answer it
    /// should do so in their [`crate::eval::Policy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_authorities: Option<Vec<Value>>,
    /// Whether cryptographic holder binding is required.
    ///
    /// "The default value is `true`" (§6.1).
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub require_cryptographic_holder_binding: bool,
    /// Claims requested from this credential (§6.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<ClaimsQuery>,
    /// Alternative combinations of [`Self::claims`], by their ids (§6.1).
    ///
    /// "`claim_sets` MUST NOT be present if `claims` is absent" (§6.4.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_sets: Option<Vec<Vec<String>>>,
}

/// One requested claim (§6.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// Identifies this claim. "REQUIRED if `claim_sets` is present in the
    /// Credential Query; OPTIONAL otherwise" (§6.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Claims path pointer to the claim (§7).
    pub path: Vec<PathComponent>,
    /// Expected values. "the Wallet SHOULD return the claim only if the type
    /// and value of the claim both match exactly for at least one of the
    /// elements in the array" (§6.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

/// A constraint on which combinations of credentials satisfy the request (§6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// Each option is a set of [`CredentialQuery::id`]s that together satisfy
    /// this use case. Satisfying any one option satisfies the set.
    pub options: Vec<Vec<String>>,
    /// Whether this set must be satisfied. "If omitted, the default value is
    /// `true`" (§6.2).
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if shape
fn is_true(b: &bool) -> bool {
    *b
}

impl DcqlQuery {
    /// Parse a DCQL query from JSON.
    ///
    /// # Errors
    ///
    /// Returns the underlying `serde_json` error when the document is not a
    /// well-formed DCQL query. Unknown properties are not an error (§6).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The credential query with the given id.
    pub fn credential(&self, id: &str) -> Option<&CredentialQuery> {
        self.credentials.iter().find(|c| c.id == id)
    }
}

impl CredentialQuery {
    /// The claims query with the given id.
    pub fn claim(&self, id: &str) -> Option<&ClaimsQuery> {
        self.claims.iter().find(|c| c.id.as_deref() == Some(id))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Defaults the spec states explicitly, all of which change behaviour if
    /// got wrong: a missing `required` would make a mandatory set optional,
    /// and a missing `require_cryptographic_holder_binding` would silently
    /// accept an unbound credential.
    #[test]
    fn omitted_fields_take_their_specified_defaults() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{}}],
                "credential_sets":[{"options":[["pid"]]}]}"#,
        )
        .unwrap();
        let c = &q.credentials[0];
        assert!(!c.multiple);
        assert!(c.require_cryptographic_holder_binding);
        assert!(q.credential_sets.unwrap()[0].required);
    }

    /// "Implementations MUST ignore any unknown properties" (§6). A wallet
    /// that rejects tomorrow's extension is worse than one that ignores it.
    #[test]
    fn unknown_properties_are_ignored() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","meta":{},
                 "some_future_field":{"a":1}}],
                "another_future_field":[1,2,3]}"#,
        )
        .unwrap();
        assert_eq!(q.credentials.len(), 1);
    }

    /// `meta` is REQUIRED by the letter of §6.1, but an empty one means "no
    /// constraints" — so a missing one asks for the same thing and is not
    /// worth failing a request over.
    #[test]
    fn missing_meta_is_treated_as_no_constraints() {
        let q =
            DcqlQuery::from_json(r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}]}"#).unwrap();
        assert!(q.credentials[0].meta.is_empty());
    }

    /// A full query round-trips, including mdoc paths and value filters.
    #[test]
    fn realistic_query_round_trips() {
        let json = r#"{"credentials":[{"id":"mdl","format":"mso_mdoc",
            "meta":{"doctype_value":"org.iso.18013.5.1.mDL"},
            "claims":[{"id":"a","path":["org.iso.18013.5.1","age_over_18"],"values":[true]}],
            "claim_sets":[["a"]]}]}"#;
        let q = DcqlQuery::from_json(json).unwrap();
        let c = &q.credentials[0];
        assert_eq!(c.claims[0].values.as_ref().unwrap()[0], Value::Bool(true));
        assert_eq!(c.claim_sets.as_ref().unwrap()[0], vec!["a"]);
        assert_eq!(c.claim("a").unwrap().path.len(), 2);

        let back: DcqlQuery = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        assert_eq!(back, q);
    }
}
