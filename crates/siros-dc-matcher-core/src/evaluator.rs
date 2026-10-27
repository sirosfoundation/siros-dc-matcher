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
use siros_dcql::{
    ClaimPath, Credential as _, CredentialFormat, CredentialQuery, CredentialRef,
    CryptographicBinding, PathComponent, PathError,
};

use crate::circuit_capabilities::{Capabilities, RequestedItem};
use crate::db::{Claim, Credential, CredentialDatabase};
use crate::profile::{
    Capability, MatchProfile, Op, UnknownFormat, CAPABILITIES_PARAM, CREDENTIAL_TYPE_PARAM,
    FUNCTIONS_PARAM, SYSTEM_ID_PARAM, ZKP_REQ_CAPABILITY, ZKP_REQ_FORMAT,
};
use siros_dcql::Vct;
use siros_oid4vp::UnverifiedQuery;
use siros_zkp_req::{
    usable_backend, CredentialType, ProofBackend, QueryOption, SystemId, W3cType, ZkpFormats,
    ZkpReqQuery,
};
use siros_zkp_req_nym_auth::catalogue::NymAuthQuery;

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

/// Whether a trigger's capability is required, or merely preferred.
///
/// Optional unless the request explicitly demands it: a verifier naming proof
/// systems and saying nothing more is listing what it accepts, not what it
/// insists on. Only an explicit `true` in the flag the profile names makes the
/// capability a condition of being offered at all.
fn trigger_is_required(trigger: &crate::profile::MetaTrigger, query: &CredentialQuery) -> bool {
    // No flag configured: the trigger's presence is the requirement, as it was
    // before there was a flag at all.
    let Some(flag) = trigger.required_flag.as_deref() else {
        return true;
    };
    // Absent or false means optional; only an explicit `true` demands the
    // capability. That is the opposite of the safer-looking default, and it is
    // deliberate: `zk_system_type` is replacing the `mso_mdoc_zk` format
    // suffix as the way to ask for a proof, so during that migration a
    // verifier sends the systems it accepts without yet sending a flag. Read
    // as "required", those requests would stop being offered to every wallet
    // that cannot prove — which is the population the migration exists to keep
    // serving. A verifier that means "mandatory" says so.
    //
    // Anything other than a JSON boolean is not a `false`, and not a claim
    // that a proof is optional either, so it reads as absent.
    query
        .meta()
        .get(flag)
        .and_then(Value::as_bool)
        .unwrap_or(false)
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
    context: Option<Context<'a>>,
}

/// What a `zkp_req` query is matched against besides the profile.
#[derive(Clone, Copy)]
struct Context<'a> {
    query: &'a UnverifiedQuery,
    client_metadata: Option<&'a Value>,
}

/// The circuit a `zkp_req` query will be answered with, and the option it answers
/// (`zkp_req`, Section 1.3).
#[derive(Debug, Clone, PartialEq)]
pub struct ZkpReqSelection<'a> {
    /// The wallet's circuit capability chosen for this request.
    pub capability: &'a Capability,
    /// The query, as the protocol crate read it.
    pub query: ZkpReqQuery,
    /// The answered option: the first the Verifier prefers that a circuit serves.
    pub option: QueryOption,
    /// The proof backend of the pair: the first the Verifier lists that the circuit runs on.
    pub proof_backend: ProofBackend,
}

impl ZkpReqSelection<'_> {
    /// `{"circuit": <capability>, "proof_backend": …, "req_set": …, "items": […]}`, the one JSON
    /// form both the picker metadata and the FFI carry. `req_set` is absent for a query without
    /// `_req_sets`. Everything comes from the unauthenticated request; the wallet checks it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let items: Vec<usize> = self.option.items().iter().map(|i| i.value()).collect();
        let mut out = serde_json::json!({
            "circuit": self.capability,
            "proof_backend": self.proof_backend.as_str(),
            "items": items,
        });
        if let Some(req_set) = self.option.req_set() {
            out["req_set"] = req_set.value().into();
        }
        out
    }
}

/// A registered circuit as `zkp_req`, Section 1.3 judges a system.
struct Circuit<'p, 'a> {
    policy: &'p ProfilePolicy<'a>,
    capability: &'a Capability,
    system_id: SystemId,
}

impl siros_zkp_req::System for Circuit<'_, '_> {
    fn id(&self) -> SystemId {
        self.system_id.clone()
    }

    fn runs_on(&self, backend: &ProofBackend) -> bool {
        self.capability.system == backend.as_str()
    }

    fn proves_over(&self, credential_type: &CredentialType) -> bool {
        self.policy
            .circuit_type_matches(self.capability, credential_type)
    }
}

impl<'a> ProfilePolicy<'a> {
    /// Evaluate against this profile.
    ///
    /// Without a request context a `zkp_req` query matches nothing: what it
    /// asks for is not in the typed DCQL query, so there is nothing to plan.
    /// See [`Self::with_context`].
    pub fn new(profile: &'a MatchProfile) -> Self {
        Self {
            profile,
            context: None,
        }
    }

    /// Evaluate with the request the query came from: its `dcql_query` and the
    /// verifier's `client_metadata`.
    ///
    /// `zkp_req` is matched against its planned request and the verifier's
    /// `client_metadata`, neither of which the typed query carries.
    #[must_use]
    pub fn with_context(
        mut self,
        query: &'a UnverifiedQuery,
        client_metadata: Option<&'a Value>,
    ) -> Self {
        self.context = Some(Context {
            query,
            client_metadata,
        });
        self
    }

    /// The circuit and option for a `zkp_req` query, or `None` if it cannot be answered.
    ///
    /// `None` covers a request that breaks a rule of `zkp_req` or of the nym_auth catalogue, a
    /// wallet with no circuit, and options no circuit serves. It never falls back to claim
    /// matching: an invalid `zkp_req` request asks for nothing the matcher understands, and
    /// answering it with what the claims would select discloses data nobody asked for.
    pub fn zkp_req_selection(&self, query: &CredentialQuery) -> Option<ZkpReqSelection<'a>> {
        let context = self.context?;
        let raw = context
            .query
            .raw()
            .get("credentials")?
            .as_array()?
            .iter()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(query.id().as_str()))?;
        let parsed = ZkpReqQuery::parse(raw).ok()?;
        // zkp_req, Section 1.2: the Verifier MUST send both lists.
        let formats = ZkpFormats::from_client_metadata(context.client_metadata?).ok()?;
        // The nym_auth catalogue's rules, for a query of its credential type.
        let parsed = NymAuthQuery::from_query(parsed).ok()?.into_query();
        let held = self.profile.capabilities.get(ZKP_REQ_CAPABILITY)?;
        // zkp_req, Section 2.1: the first option the wallet can answer.
        let (capability, option, proof_backend) = parsed.options().iter().find_map(|option| {
            held.iter().find_map(|capability| {
                let circuit = Circuit {
                    policy: self,
                    capability,
                    system_id: SystemId::new(capability.params.get(SYSTEM_ID_PARAM)?),
                };
                let backend = usable_backend(&formats, parsed.credential_type(), &circuit, |c| {
                    self.circuit_supports(c.capability, &parsed, option)
                })
                .ok()?;
                Some((capability, option.clone(), backend.clone()))
            })
        })?;
        Some(ZkpReqSelection {
            capability,
            query: parsed,
            option,
            proof_backend,
        })
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
            .format_rule(query.format().as_str())
            .map(|rule| rule.requires.clone())
            .unwrap_or_default();

        for trigger in &self.profile.meta_triggers {
            if !query.meta().contains_key(&trigger.when_meta_present) {
                continue;
            }
            // Named systems, but the verifier said a proof is not required.
            // The capability is then preferred rather than demanded: the
            // wallet is offered either way, and resolve() still reports the
            // system it chose, so a wallet that *can* prove still will.
            if !trigger_is_required(trigger, query) {
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

    /// Every capability requirement this query could involve, whether or not
    /// the verifier insists on it.
    ///
    /// [`Self::requirements`] answers "what must hold for this to match".
    /// This answers "what would apply if the wallet can manage it", which is
    /// what a caller needs in order to report the chosen system for a request
    /// that names proof systems without requiring one.
    fn applicable_capabilities(&self, query: &CredentialQuery) -> Vec<crate::profile::Requirement> {
        let mut out: Vec<crate::profile::Requirement> = self
            .profile
            .format_rule(query.format().as_str())
            .map(|rule| rule.requires.clone())
            .unwrap_or_default();

        for trigger in &self.profile.meta_triggers {
            if !query.meta().contains_key(&trigger.when_meta_present) {
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
            let requested = query.meta().get(&requirement.from_meta)?.as_array()?;

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

/// The credential types a `zkp_req` query can mean: its `doctype_value`, `vct_values` or
/// `schema_id_value`.
fn requested_types(credential_type: &CredentialType) -> Vec<&str> {
    match credential_type {
        CredentialType::MsoMdoc { doctype } => vec![doctype.as_str()],
        CredentialType::SdJwt { vct_values } => vct_values.iter().map(Vct::as_str).collect(),
        CredentialType::W3c { type_values, .. } => {
            type_values.iter().flatten().map(W3cType::as_str).collect()
        }
        CredentialType::Profiled { meta, .. } => meta
            .get("schema_id_value")
            .and_then(Value::as_str)
            .into_iter()
            .collect(),
    }
}

impl ProfilePolicy<'_> {
    /// Whether a circuit proves over the credential type a query asks for.
    ///
    /// With a `capabilities` param, the structured rule of [`crate::circuit_capabilities`]
    /// decides, and a value that does not parse rules the circuit out. Without one, a circuit
    /// with a `credential_type` serves only a query whose `meta` names that type, and a circuit
    /// without it is not filtered.
    fn circuit_type_matches(
        &self,
        capability: &Capability,
        credential_type: &CredentialType,
    ) -> bool {
        if let Some(text) = capability.params.get(CAPABILITIES_PARAM) {
            let Ok(capabilities) = Capabilities::parse(text) else {
                return false;
            };
            return self
                .zkp_req_formats(credential_type)
                .is_some_and(|formats| {
                    capabilities.proves_over(
                        ZKP_REQ_FORMAT,
                        &formats,
                        &requested_types(credential_type),
                    )
                });
        }
        capability
            .params
            .get(CREDENTIAL_TYPE_PARAM)
            .is_none_or(|ours| requested_types(credential_type).contains(&ours.as_str()))
    }

    /// Whether a circuit supports the functions and parameter values of an option. With a
    /// `capabilities` param, the structured rule decides; without one, a circuit that declares
    /// `functions` serves only options using those.
    fn circuit_supports(
        &self,
        capability: &Capability,
        query: &ZkpReqQuery,
        option: &QueryOption,
    ) -> Result<(), ()> {
        let items: Vec<RequestedItem<'_>> = option
            .items()
            .iter()
            .filter_map(|&i| query.item(i))
            .map(|item| RequestedItem {
                function_id: item.fn_id().as_str(),
                params: item.params(),
            })
            .collect();
        let served = match (
            capability.params.get(CAPABILITIES_PARAM),
            capability.params.get(FUNCTIONS_PARAM),
        ) {
            (Some(text), _) => Capabilities::parse(text).is_ok_and(|c| c.supports(&items)),
            (None, Some(declared)) => items
                .iter()
                .all(|i| declared.split(',').any(|d| d.trim() == i.function_id)),
            (None, None) => true,
        };
        if served {
            Ok(())
        } else {
            Err(())
        }
    }

    /// The stored formats a `zkp_req` proof can be made over: the profile's for `zkp_req`
    /// that are the query's `source_format`. `None` without a `zkp_req` format rule.
    fn zkp_req_formats(&self, credential_type: &CredentialType) -> Option<Vec<&str>> {
        let rule = self.profile.format_rule(ZKP_REQ_FORMAT)?;
        Some(
            rule.stored_formats
                .iter()
                .map(String::as_str)
                .filter(|f| *f == credential_type.source_format())
                .collect(),
        )
    }
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
                Some(selection) if *stored == selection.query.credential_type().source_format() => {
                }
                _ => return false,
            }
        } else if is_nym_auth(credential.credential) && discloses_nym_auth_secrets(query) {
            // Rulebook, "Non-disclosure of seed commitments": `ssc`, `psc`,
            // `secret_seed` and `birth_date` of a nym_auth attestation are
            // never disclosed. Only `zkp_req` may use them, inside `_req`.
            return false;
        }

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

/// What a caller needs about one matched credential, beyond its identity.
///
/// Shared because two consumers derive it: the matcher binary, which puts it in
/// picker metadata, and the FFI, which hands it to a wallet. Deriving it twice
/// is how the two would come to disagree about which ZK system satisfied a
/// query — the drift this crate exists to stop.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved<'a> {
    /// Exactly the claims to disclose, as path components.
    pub claims: Vec<Vec<String>>,
    /// The capability chosen to satisfy the query, if its format needed one.
    pub capabilities: Vec<&'a Capability>,
    /// `meta` scalars the wallet needs but which did not decide the match —
    /// `ppid_context` above all, which changes what is produced rather than
    /// which credential can produce it.
    pub meta: BTreeMap<String, String>,
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
    // Every capability that *could* apply, not only the required ones: a
    // verifier may name proof systems without insisting on one, and a wallet
    // able to satisfy such a request should still be told which system to use.
    let applicable = policy.applicable_capabilities(query);
    let capabilities = if applicable.is_empty() {
        Vec::new()
    } else {
        policy
            .capability_for(query, &applicable)
            .unwrap_or_default()
    };

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
        capabilities,
        meta: query
            .meta()
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
