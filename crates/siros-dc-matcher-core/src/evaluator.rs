//! Evaluating the match profile — the part DCQL leaves to the deployment.
//!
//! [`siros_dcql`] handles what the specification defines generically: claim
//! selection, `claim_sets`, `values`, `credential_sets`. It deliberately
//! stops at `format` and `meta`, because OpenID4VP 1.0 §6.1 defines `meta`
//! "per Credential Format" — a generic engine has nothing to evaluate it
//! against.
//!
//! This module supplies that half from the registered [`MatchProfile`], which
//! is why a new credential format costs a re-registration rather than a
//! release of the matcher binary.

use serde_json::Value;
use siros_dcql::{
    ClaimPath, Credential as _, CredentialFormat, CredentialQuery, CredentialRef,
    CryptographicBinding, PathComponent, PathError,
};

use crate::db::{Claim, Credential, CredentialDatabase};
use crate::profile::{MatchProfile, Op, UnknownFormat, ZKP_REQ_FORMAT};

mod zkp_req;

pub use zkp_req::ZkpReqSelection;

/// A credential from the registered blob, wrapped so DCQL can evaluate it.
///
/// It needs nothing but the credential: the blob stores each claim under a
/// concrete path, so resolution is a lookup within this credential rather than
/// a walk over a surrounding document.
pub struct BlobCredential<'a> {
    /// The credential itself.
    pub credential: &'a Credential,
}

impl siros_dcql::Credential for BlobCredential<'_> {
    fn id(&self) -> &CredentialRef {
        &self.credential.id
    }

    fn format(&self) -> &CredentialFormat {
        &self.credential.format
    }

    /// Always bound.
    ///
    /// Every credential a SIROS wallet registers into the blob is held against
    /// a key in the WSCD — a device keystore or a roaming authenticator — so
    /// there is no unbound credential for this to be false about, and the blob
    /// records no field for it.
    ///
    /// This is a claim about the *storage*, not a default. If a credential
    /// type without holder binding ever becomes registrable, the blob needs a
    /// field and this needs to read it; answering `true` on its behalf would
    /// hand a verifier exactly what it said it would not accept.
    fn binding(&self) -> CryptographicBinding {
        CryptographicBinding::Bound
    }

    /// Resolve a claims path pointer against the claims the wallet registered.
    ///
    /// The blob stores each claim it holds under a concrete path, so this is a
    /// lookup rather than a walk over a document.
    ///
    /// # Limitation
    ///
    /// Only pointers made entirely of string components resolve. A pointer
    /// containing `null` (all elements of an array) or an index cannot match,
    /// because the blob records paths as strings and has no array structure to
    /// walk. ISO mdoc is unaffected — §7.2.1 requires exactly two string
    /// components — and JSON credentials whose claims live in nested *objects*
    /// are fine too. Only arrays are out of reach, and no format SIROS
    /// currently issues puts a requestable claim inside one. Widening this
    /// means giving the blob real value structure, which is a wire-format
    /// change and deliberately not smuggled in here.
    fn claim(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        let wanted: Option<Vec<&str>> = path
            .components()
            .iter()
            .map(PathComponent::as_key)
            .collect();
        let Some(wanted) = wanted else {
            // A pointer this blob cannot express is not a malformed query —
            // the verifier may be asking something perfectly valid of a
            // credential we simply cannot describe. Reporting "not found"
            // drops this credential from the match, which is the honest
            // answer, rather than failing the whole request.
            return Err(PathError::Empty);
        };

        self.credential
            .claims
            .iter()
            .find(|c| c.path.iter().map(String::as_str).eq(wanted.iter().copied()))
            .map(|c| vec![claim_value(c)])
            .ok_or(PathError::Empty)
    }
}

/// A stored claim's value as JSON, for DCQL `values` comparison.
///
/// Values are stored as strings, but a verifier writes `"values": [true]` or
/// `[18]` and §6.3 requires the *type* to match too. Parsing the stored string
/// as JSON first recovers the type the issuer meant, so `age_over_18` stored
/// as `"true"` matches a query for `true`. Anything that is not valid JSON —
/// an ordinary name, say — stays a string, which is also correct.
fn claim_value(claim: &Claim) -> Value {
    serde_json::from_str(&claim.value).unwrap_or_else(|_| Value::String(claim.value.clone()))
}

/// Evaluates a [`MatchProfile`] as a DCQL [`siros_dcql::Policy`].
pub struct ProfilePolicy<'a> {
    profile: &'a MatchProfile,
    client_metadata: Option<&'a Value>,
}

impl<'a> ProfilePolicy<'a> {
    /// Evaluate against this profile.
    ///
    /// Without the verifier's `client_metadata` a `zkp_req` query matches nothing: `zkp_req`,
    /// Section 1.2 matches it against the lists there. See [`Self::with_client_metadata`].
    pub fn new(profile: &'a MatchProfile) -> Self {
        Self {
            profile,
            client_metadata: None,
        }
    }

    /// Evaluate with the request's `client_metadata`, when it has one.
    #[must_use]
    pub fn with_client_metadata(mut self, client_metadata: Option<&'a Value>) -> Self {
        self.client_metadata = client_metadata;
        self
    }
}

/// Doctype of the ISO/IEC 18013-5 nym_auth attestation.
pub const NYM_AUTH_DOCTYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
/// Schema identifier of the `bbs_cd` nym_auth attestation.
pub const NYM_AUTH_BBS_SCHEMA: &str = "eu.europa.ec.eudi.nym_auth.bbs.1";
/// Attributes of a nym_auth attestation that no presentation may disclose.
pub const NYM_AUTH_UNDISCLOSABLE: [&str; 4] = ["ssc", "psc", "secret_seed", "birth_date"];

fn is_nym_auth(credential: &crate::db::Credential) -> bool {
    [credential.doctype.as_deref(), credential.vct.as_deref()]
        .into_iter()
        .flatten()
        .any(|t| t == NYM_AUTH_DOCTYPE || t == NYM_AUTH_BBS_SCHEMA)
}

/// Whether a non-`zkp_req` query asks a nym_auth attestation to disclose
/// anything: a named undisclosable attribute, a wildcard path that includes
/// one, or no `claims` at all (which asks for the whole attestation).
fn discloses_nym_auth_secrets(query: &CredentialQuery) -> bool {
    use siros_dcql::PathComponent;
    query.claims().is_empty()
        || query.claims().iter().any(|claim| {
            claim
                .path()
                .components()
                .iter()
                .any(|component| match component {
                    PathComponent::Key(k) => NYM_AUTH_UNDISCLOSABLE.contains(&k.as_str()),
                    PathComponent::Null => true,
                    PathComponent::Index(_) => false,
                })
        })
}

impl siros_dcql::Policy<BlobCredential<'_>> for ProfilePolicy<'_> {
    fn matches(&self, query: &CredentialQuery, credential: &BlobCredential<'_>) -> bool {
        let stored = credential.format();

        match self.profile.format_rule(query.format().as_str()) {
            Some(rule) => {
                if !rule.stored_formats.iter().any(|f| *stored == f.as_str()) {
                    return false;
                }
            }
            // An undescribed format. Rejecting is the production setting;
            // the permissive one exists for interop debugging and will offer
            // credentials the wallet may not be able to present.
            None => match self.profile.unknown_format {
                UnknownFormat::Reject => return false,
                UnknownFormat::MatchAny => {}
            },
        }

        // `zkp_req` is answered from its plan, not from claims, and an
        // invalid or unservable request is no match rather than a fallback.
        if *query.format() == ZKP_REQ_FORMAT {
            match self.zkp_req_selection(query) {
                // The proof is made over the stored attestation itself.
                Some(selection) if selection.query.credential_type().source_format() == *stored => {
                }
                _ => return false,
            }
        } else if is_nym_auth(credential.credential) && discloses_nym_auth_secrets(query) {
            // Rulebook, "Non-disclosure of seed commitments": `ssc`, `psc`,
            // `secret_seed` and `birth_date` of a nym_auth attestation are
            // never disclosed. Only `zkp_req` may use them, inside `_req`.
            return false;
        }

        self.profile
            .meta_rules
            .iter()
            .all(|meta_rule| meta_matches(meta_rule, query, credential.credential))
    }
}

/// Whether one `meta` rule holds for this credential.
///
/// A key the verifier did not send is not a constraint.
fn meta_matches(
    rule: &crate::profile::MetaRule,
    query: &CredentialQuery,
    cred: &Credential,
) -> bool {
    if rule.op == Op::Ignore {
        return true;
    }
    let Some(requested) = query.meta().get(&rule.meta_key) else {
        return true;
    };
    let Some(field) = rule
        .field
        .as_deref()
        .and_then(|f| credential_field(cred, f))
    else {
        // The rule names a field this credential does not have. The verifier
        // constrained something we cannot answer, so we do not match — the
        // alternative is offering a credential on the strength of a missing
        // value.
        return false;
    };

    match rule.op {
        Op::Eq => requested.as_str() == Some(field),
        Op::In => requested
            .as_array()
            .is_some_and(|vs| vs.iter().any(|v| v.as_str() == Some(field))),
        Op::Prefix => requested.as_str().is_some_and(|p| field.starts_with(p)),
        Op::Exists => true,
        Op::Ignore => true,
    }
}

/// The named field of a credential, for [`crate::profile::MetaRule::field`].
fn credential_field<'a>(cred: &'a Credential, field: &str) -> Option<&'a str> {
    match field {
        "doctype" => cred.doctype.as_deref(),
        "vct" => cred.vct.as_deref(),
        "format" => Some(cred.format.as_str()),
        _ => None,
    }
}

/// Every credential in the database, wrapped for DCQL evaluation.
pub fn credentials(db: &CredentialDatabase) -> Vec<BlobCredential<'_>> {
    db.credentials
        .iter()
        .map(|credential| BlobCredential { credential })
        .collect()
}

/// What the FFI hands a wallet about one matched credential, beyond its identity.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved<'a> {
    /// Exactly the claims to disclose, as path components.
    pub claims: Vec<Vec<String>>,
    /// For a `zkp_req` query: the circuit chosen and the planned request.
    /// Such a match carries no claims.
    pub zkp_req: Option<ZkpReqSelection<'a>>,
}

/// Resolve the details of one match.
pub fn resolve<'a>(
    policy: &ProfilePolicy<'a>,
    query: &CredentialQuery,
    candidate: &siros_dcql::Candidate,
) -> Resolved<'a> {
    // A `zkp_req` match discloses nothing: whatever the typed query says
    // about claims, none are selected.
    let zkp_req = if *query.format() == ZKP_REQ_FORMAT {
        policy.zkp_req_selection(query)
    } else {
        None
    };

    let claims = if zkp_req.is_some() {
        &[][..]
    } else {
        candidate.claims()
    };

    Resolved {
        zkp_req,
        claims: claims
            .iter()
            .map(|claim| {
                claim
                    .path()
                    .components()
                    .iter()
                    .filter_map(PathComponent::as_key)
                    .map(str::to_owned)
                    .collect()
            })
            .collect(),
    }
}
