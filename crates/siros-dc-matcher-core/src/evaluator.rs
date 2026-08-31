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
//!
//! # The ZK path
//!
//! `mso_mdoc_zk` is the reason the indirection exists. A verifier asking for
//! it is asking for a proof *about* an ordinary `mso_mdoc` credential —
//! producing that proof is a presentation-time transform, not a storage
//! format, so there is no separate ZK credential on the device to find. The
//! profile maps the requested format onto the stored one and attaches a
//! capability requirement, so the entry is offered only when this wallet can
//! actually produce the proof the verifier named.

use std::collections::BTreeMap;

use serde_json::Value;
use siros_dcql::{Credential as _, CredentialQuery, PathComponent, PathError};

use crate::db::{Claim, Credential, CredentialDatabase};
use crate::profile::{Capability, MatchProfile, Op, UnknownFormat};

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
    fn id(&self) -> &str {
        &self.credential.id
    }

    fn format(&self) -> &str {
        &self.credential.format
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
    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError> {
        if path.is_empty() {
            return Err(PathError::Malformed);
        }
        let wanted: Option<Vec<&str>> = path.iter().map(PathComponent::as_key).collect();
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
}

impl<'a> ProfilePolicy<'a> {
    /// Evaluate against this profile.
    pub fn new(profile: &'a MatchProfile) -> Self {
        Self { profile }
    }

    /// Every capability requirement that applies to this query.
    ///
    /// Two sources, deliberately. A format rule can require one — `mso_mdoc_zk`
    /// naming no proof system has asked for a proof without saying which, and
    /// must not be answered with an ordinary presentation. And a
    /// [`crate::profile::MetaTrigger`] fires on the *presence* of a `meta`
    /// key whatever the format, because what actually signals a ZK
    /// presentation is `zk_system_type`; the `mso_mdoc_zk` format says the
    /// same thing and is expected to be retired.
    fn requirements(&self, query: &CredentialQuery) -> Vec<crate::profile::Requirement> {
        let mut out: Vec<crate::profile::Requirement> = self
            .profile
            .format_rule(&query.format)
            .map(|rule| rule.requires.clone())
            .unwrap_or_default();

        for trigger in &self.profile.meta_triggers {
            if !query.meta.contains_key(&trigger.when_meta_present) {
                continue;
            }
            let requirement = crate::profile::Requirement {
                capability: trigger.capability.clone(),
                from_meta: trigger.when_meta_present.clone(),
            };
            if !out.contains(&requirement) {
                out.push(requirement);
            }
        }
        out
    }

    /// Whether the wallet can satisfy the capabilities this query requires.
    ///
    /// Returns the capabilities that matched, so the caller can tell the wallet
    /// *which* system was chosen rather than making it work that out again
    /// after the user has selected the entry.
    pub fn capability_for(
        &self,
        query: &CredentialQuery,
        format_rule_requires: &[crate::profile::Requirement],
    ) -> Option<Vec<&'a Capability>> {
        let mut chosen = Vec::new();
        for requirement in format_rule_requires {
            let held = self.profile.capabilities.get(&requirement.capability)?;
            let requested = query.meta.get(&requirement.from_meta)?.as_array()?;

            // Verifier preference order: the first entry this wallet can
            // actually satisfy wins, mirroring how claim_sets is handled.
            let matched = requested
                .iter()
                .find_map(|entry| held.iter().find(|c| satisfies(c, entry)))?;
            chosen.push(matched);
        }
        Some(chosen)
    }
}

/// Whether a held capability satisfies one entry from the verifier's list.
///
/// The wire shape is `{"id": …, "system": …, …params}`: **every** other
/// top-level key is a parameter. There is no nested `params` object, and
/// assuming one parses without error while silently reading no parameters at
/// all — which then matches a circuit this wallet does not have, and fails
/// after the user has consented.
///
/// Parameters constrain a match only where both sides name them.
///
/// A parameter the verifier does not mention is not a constraint, and one the
/// *wallet* does not declare is not one either. That asymmetry is deliberate:
/// some proof systems declare a nominal capability — "this system, any
/// attribute count" — and verify fetchability lazily at proof time, so
/// requiring them to enumerate every circuit up front would reject requests
/// they can in fact satisfy.
///
/// Where the wallet does declare a parameter, it must match exactly. A ZK
/// circuit is built for a fixed attribute count, so a wallet that knows its
/// circuits and says `num_attributes: 4` cannot produce a ten-attribute proof,
/// and an entry offered on that basis fails after the user has consented.
fn satisfies(held: &Capability, requested: &Value) -> bool {
    let Some(entry) = requested.as_object() else {
        return false;
    };
    if entry.get("system").and_then(Value::as_str) != Some(held.system.as_str()) {
        return false;
    }
    entry
        .iter()
        .filter(|(k, _)| k.as_str() != "id" && k.as_str() != "system")
        .all(|(key, value)| match held.params.get(key) {
            Some(ours) => as_text(value).as_deref() == Some(ours.as_str()),
            // Undeclared on our side: not a constraint.
            None => true,
        })
}

/// A JSON scalar as the text the profile stores it as.
///
/// Verifiers write `num_attributes` as a number in some requests and a string
/// in others; both mean the same circuit, and refusing one of them would
/// reject a wallet that can genuinely satisfy the request.
fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

impl siros_dcql::Policy<BlobCredential<'_>> for ProfilePolicy<'_> {
    fn matches(&self, query: &CredentialQuery, credential: &BlobCredential<'_>) -> bool {
        let stored = credential.format();

        let rule = match self.profile.format_rule(&query.format) {
            Some(rule) => {
                if !rule.stored_formats.iter().any(|f| f == stored) {
                    return false;
                }
                Some(rule)
            }
            // An undescribed format. Rejecting is the production setting;
            // the permissive one exists for interop debugging and will offer
            // credentials the wallet may not be able to present.
            None => match self.profile.unknown_format {
                UnknownFormat::Reject => return false,
                UnknownFormat::MatchAny => None,
            },
        };

        let _ = rule;

        // Capability first: it is the cheapest check and the one whose failure
        // is least visible later. An entry offered without the capability
        // walks the user through consent and then cannot deliver.
        //
        // Both sources, via requirements(): the format rule's own, and any
        // MetaTrigger fired by a `meta` key being present. A ZK request is
        // signalled by `zk_system_type`, not by the format.
        let required = self.requirements(query);
        if !required.is_empty() && self.capability_for(query, &required).is_none() {
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
    let Some(requested) = query.meta.get(&rule.meta_key) else {
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
        "format" => Some(&cred.format),
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

/// What a caller needs about one matched credential, beyond its identity.
///
/// Shared because two consumers derive it: the matcher binary, which puts it in
/// picker metadata, and the FFI, which hands it to a wallet. Deriving it twice
/// is how the two would come to disagree about which ZK system satisfied a
/// query — the drift this crate exists to stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved<'a> {
    /// Exactly the claims to disclose, as path components.
    pub claims: Vec<Vec<String>>,
    /// The capability chosen to satisfy the query, if its format needed one.
    pub capabilities: Vec<&'a Capability>,
    /// `meta` scalars the wallet needs but which did not decide the match —
    /// `ppid_context` above all, which changes what is produced rather than
    /// which credential can produce it.
    pub meta: BTreeMap<String, String>,
}

/// Resolve the details of one match.
pub fn resolve<'a>(
    policy: &ProfilePolicy<'a>,
    query: &CredentialQuery,
    candidate: &siros_dcql::Candidate,
) -> Resolved<'a> {
    let required = policy.requirements(query);
    let capabilities = if required.is_empty() {
        Vec::new()
    } else {
        policy.capability_for(query, &required).unwrap_or_default()
    };

    Resolved {
        claims: candidate
            .claims
            .iter()
            .map(|claim| {
                claim
                    .path
                    .iter()
                    .filter_map(PathComponent::as_key)
                    .map(str::to_owned)
                    .collect()
            })
            .collect(),
        capabilities,
        meta: query
            .meta
            .iter()
            .filter_map(|(key, value)| {
                // Scalars only: a nested object has no single string form, and
                // inventing one would hand the caller a value it cannot use.
                let text = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => return None,
                };
                Some((key.clone(), text))
            })
            .collect(),
    }
}
