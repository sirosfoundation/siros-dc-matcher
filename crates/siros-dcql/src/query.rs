//! The DCQL query model — OpenID4VP 1.0 §6.
//!
//! A faithful transcription of the wire format, with one deliberate
//! relaxation noted on [`CredentialQuery::meta`]. The spec's own instruction
//! shapes the rest: "Implementations MUST ignore any unknown properties"
//! (§6), so nothing here rejects a query for carrying fields it does not
//! recognise — a wallet that refuses tomorrow's extension is worse than one
//! that ignores it.

use std::collections::HashSet;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    /// Each option is a set of [`CredentialQuery::id`]s that together satisfy
    /// this use case. Satisfying any one option satisfies the set.
    pub options: Vec<Vec<String>>,
    /// Whether this set must be satisfied. "If omitted, the default value is
    /// `true`" (§6.2).
    #[serde(default = "default_true")]
    pub required: bool,
    /// Why the verifier wants this combination, for showing to the user (§6.2).
    ///
    /// "OPTIONAL. A string, integer or object" — all three, so a `Value` and
    /// not a `String`. Nothing here interprets it: the whole purpose of the
    /// field is to be displayed, and a wallet that drops it asks the user to
    /// consent to a disclosure without telling them what it is for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Value>,
}

fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if shape
fn is_true(b: &bool) -> bool {
    *b
}

/// Why a document is not a usable DCQL query.
///
/// Deliberately short. §6 instructs implementations to "ignore any unknown
/// properties", and this crate goes further in the same spirit: a query is
/// rejected only when what the verifier wants cannot be determined, never for
/// a deviation that can be read past. So a duplicated `id` is fatal — it makes
/// a reference ambiguous — while a `credential_sets` option naming a query
/// that does not exist is not, because an option the wallet cannot satisfy is
/// simply an option it does not offer.
///
/// In particular the character restrictions §6.1 and §6.3 place on an `id` are
/// *not* enforced. They carry no meaning for matching, and rejecting a
/// verifier over a dot in an identifier would fail a request that is perfectly
/// well understood.
#[derive(Debug)]
pub enum QueryError {
    /// Not well-formed JSON, or not shaped like a DCQL query.
    Json(serde_json::Error),
    /// A credential query `id` is empty. "MUST be a non-empty string" (§6.1).
    ///
    /// Rejected rather than read past because an identifier that identifies
    /// nothing is not something this crate can interpret on the verifier's
    /// behalf — not because a reference to it would fail to resolve, since
    /// `""` is a perfectly good JSON string and `credential_sets` could name
    /// it.
    EmptyCredentialId,
    /// Two credential queries share this `id`. §6.1 requires it to "be unique
    /// across all Credential Query objects": a reference from
    /// `credential_sets` to a duplicated id names two different requests, and
    /// answering the first silently drops the second.
    DuplicateCredentialId(String),
    /// Two claims queries within one credential query share this `id`. §6.3
    /// requires uniqueness "within the particular claims array", for the same
    /// reason one level down: `claim_sets` refers to claims by id.
    DuplicateClaimId {
        /// The `id` of the credential query holding the duplicate.
        credential: String,
        /// The duplicated claims query `id`.
        claim: String,
    },
}

impl core::fmt::Display for QueryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "not a DCQL query: {e}"),
            Self::EmptyCredentialId => {
                write!(f, "a credential query has an empty id (§6.1)")
            }
            Self::DuplicateCredentialId(id) => {
                write!(f, "two credential queries share the id {id:?} (§6.1)")
            }
            Self::DuplicateClaimId { credential, claim } => write!(
                f,
                "credential query {credential:?} has two claims with the id {claim:?} (§6.3)"
            ),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for QueryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl DcqlQuery {
    /// Parse and validate a DCQL query from JSON.
    ///
    /// Validation is on this path rather than beside it, so that a caller
    /// cannot hold a `DcqlQuery` whose ids are ambiguous. See [`QueryError`]
    /// for what is checked, and for the larger set of things deliberately
    /// tolerated.
    ///
    /// # Errors
    ///
    /// [`QueryError`]: the document is not a well-formed DCQL query, or its
    /// identifiers are not usable. Unknown properties are not an error (§6).
    pub fn from_json(json: &str) -> Result<Self, QueryError> {
        let query: Self = serde_json::from_str(json)?;
        query.validate()?;
        Ok(query)
    }

    /// Check that this query's identifiers are usable.
    ///
    /// Called by [`Self::from_json`]. Public for callers that build a query in
    /// memory rather than parsing one, who need the same guarantee.
    ///
    /// # Errors
    ///
    /// [`QueryError`], excluding [`QueryError::Json`] which only parsing can
    /// produce.
    pub fn validate(&self) -> Result<(), QueryError> {
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.credentials.len());
        for credential in &self.credentials {
            if credential.id.is_empty() {
                return Err(QueryError::EmptyCredentialId);
            }
            if !seen.insert(&credential.id) {
                return Err(QueryError::DuplicateCredentialId(credential.id.clone()));
            }
            credential.validate_claim_ids()?;
        }
        Ok(())
    }

    /// The credential query with the given id.
    pub fn credential(&self, id: &str) -> Option<&CredentialQuery> {
        self.credentials.iter().find(|c| c.id == id)
    }
}

impl CredentialQuery {
    /// The claims query with the given id.
    ///
    /// Unambiguous because [`DcqlQuery::validate`] rejects duplicated claim
    /// ids; without that, this would resolve to whichever came first.
    pub fn claim(&self, id: &str) -> Option<&ClaimsQuery> {
        self.claims.iter().find(|c| c.id.as_deref() == Some(id))
    }

    /// §6.3 claim id uniqueness, within this credential query's `claims`.
    fn validate_claim_ids(&self) -> Result<(), QueryError> {
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.claims.len());
        for id in self.claims.iter().filter_map(|c| c.id.as_deref()) {
            if !seen.insert(id) {
                return Err(QueryError::DuplicateClaimId {
                    credential: self.id.clone(),
                    claim: id.to_string(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
// `expect` alongside `unwrap`: a test that states why it expects to succeed
// says what broke when it stops succeeding.
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    /// §6.1: an `id` "MUST be unique across all Credential Query objects".
    /// Without this check the duplicate is not merely tolerated — it changes
    /// what gets offered, because `credential_sets` resolves a reference to
    /// whichever entry came first and the second is answered by nobody.
    #[test]
    fn duplicate_credential_ids_are_rejected() {
        let err = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc"},
                               {"id":"pid","format":"dc+sd-jwt"}]}"#,
        )
        .expect_err("a duplicated credential id is not usable");
        assert!(
            matches!(&err, QueryError::DuplicateCredentialId(id) if id == "pid"),
            "got {err:?}"
        );
    }

    /// §6.3: a claims `id` must be "unique within the particular claims
    /// array". Same defect one level down — `claim_sets` refers to claims by
    /// id, so a duplicate makes an option ambiguous.
    #[test]
    fn duplicate_claim_ids_are_rejected() {
        let err = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","claims":[
                 {"id":"a","path":["ns","given_name"]},
                 {"id":"a","path":["ns","family_name"]}],
                 "claim_sets":[["a"]]}]}"#,
        )
        .expect_err("a duplicated claim id is not usable");
        assert!(
            matches!(
                &err,
                QueryError::DuplicateClaimId { credential, claim }
                    if credential == "pid" && claim == "a"
            ),
            "got {err:?}"
        );
    }

    /// Claims without ids are the ordinary case when there are no
    /// `claim_sets`, and any number of them is fine — the uniqueness rule is
    /// about ids, and `None` is not an id.
    #[test]
    fn claims_without_ids_do_not_collide() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc","claims":[
                 {"path":["ns","given_name"]},
                 {"path":["ns","family_name"]}]}]}"#,
        )
        .expect("unidentified claims are not duplicates");
        assert_eq!(q.credentials[0].claims.len(), 2);
    }

    /// "MUST be a non-empty string" (§6.1). An empty id cannot be referred to
    /// from `credential_sets`, so it is rejected rather than read past.
    #[test]
    fn an_empty_credential_id_is_rejected() {
        let err = DcqlQuery::from_json(r#"{"credentials":[{"id":"","format":"mso_mdoc"}]}"#)
            .expect_err("an empty id is not usable");
        assert!(matches!(err, QueryError::EmptyCredentialId), "got {err:?}");
    }

    /// The line this crate draws: reject what cannot be interpreted, tolerate
    /// what can. §6.1 also restricts an id's characters, and a dot in one
    /// changes nothing about what the verifier asked for — failing the request
    /// over it would be a worse outcome than answering it.
    #[test]
    fn ids_outside_the_specified_character_set_are_tolerated() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"eu.europa.ec.eudi.pid.1","format":"mso_mdoc"}]}"#,
        )
        .expect("a dotted id is unusual, not ambiguous");
        assert!(q.credential("eu.europa.ec.eudi.pid.1").is_some());
    }

    /// A `credential_sets` option naming a query that does not exist is not
    /// fatal either: an option the wallet cannot satisfy is one it does not
    /// offer, which §6.4 already handles.
    #[test]
    fn a_dangling_credential_set_reference_is_tolerated() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}],
                "credential_sets":[{"options":[["pid"],["nonexistent"]]}]}"#,
        )
        .expect("a dangling reference is an option, not a contradiction");
        assert_eq!(q.credential_sets.as_ref().map(Vec::len), Some(1));
    }

    /// `purpose` is why the verifier wants a combination, and the wallet's
    /// only chance to tell the user. §6.2 allows a string, an integer or an
    /// object, so all three have to survive parsing.
    #[test]
    fn purpose_is_kept_in_all_three_shapes() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}],
                "credential_sets":[
                  {"options":[["pid"]],"purpose":"Proving your age"},
                  {"options":[["pid"]],"purpose":1},
                  {"options":[["pid"]],"purpose":{"id":1,"name":"Age check"}}]}"#,
        )
        .expect("valid DCQL");
        let sets = q.credential_sets.expect("sets");
        assert_eq!(
            sets[0].purpose,
            Some(Value::String("Proving your age".into()))
        );
        assert_eq!(sets[1].purpose, Some(Value::from(1)));
        assert_eq!(
            sets[2].purpose.as_ref().and_then(|p| p.get("name")),
            Some(&Value::String("Age check".into()))
        );
        assert_eq!(
            serde_json::to_string(&sets[0]).expect("serialize"),
            r#"{"options":[["pid"]],"required":true,"purpose":"Proving your age"}"#,
            "purpose round-trips; a wallet passing the query on must not drop it"
        );
    }

    /// An absent `purpose` stays absent rather than serialising as null — a
    /// verifier reading a re-encoded query should not see a field it never
    /// sent.
    #[test]
    fn an_absent_purpose_is_not_serialised() {
        let q = DcqlQuery::from_json(
            r#"{"credentials":[{"id":"pid","format":"mso_mdoc"}],
                "credential_sets":[{"options":[["pid"]]}]}"#,
        )
        .expect("valid DCQL");
        let sets = q.credential_sets.expect("sets");
        assert!(sets[0].purpose.is_none());
        assert_eq!(
            serde_json::to_string(&sets[0]).expect("serialize"),
            r#"{"options":[["pid"]],"required":true}"#
        );
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
