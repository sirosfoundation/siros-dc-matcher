//! The `zkp_req` half of the profile: the circuit and the option a `zkp_req` query is answered
//! with (`zkp_req`, Sections 1.3 and 2.1).

use serde_json::{Map, Value};
use siros_dcql::{CredentialQuery, Vct};
use siros_zkp_req::{
    usable_backend, CredentialType, ProofBackend, QueryOption, SystemId, W3cType, ZkpFormats,
    ZkpReqQuery,
};
use siros_zkp_req_nym_auth::catalogue::NymAuthQuery;

use super::ProfilePolicy;
use crate::circuit_capabilities::{Capabilities, RequestedItem};
use crate::profile::{
    Capability, CAPABILITIES_PARAM, CREDENTIAL_TYPE_PARAM, FUNCTIONS_PARAM, SYSTEM_ID_PARAM,
    ZKP_REQ_CAPABILITY, ZKP_REQ_FORMAT,
};

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
        let items = self
            .option
            .items()
            .iter()
            .map(|i| Value::from(i.value()))
            .collect();
        let mut out = Map::new();
        drop(out.insert("circuit".to_owned(), circuit(self.capability)));
        drop(out.insert(
            "proof_backend".to_owned(),
            self.proof_backend.as_str().into(),
        ));
        drop(out.insert("items".to_owned(), Value::Array(items)));
        if let Some(req_set) = self.option.req_set() {
            drop(out.insert("req_set".to_owned(), req_set.value().into()));
        }
        Value::Object(out)
    }
}

/// `{"system": …, "params": {…}}`: `capability` as the registration serializes it.
fn circuit(capability: &Capability) -> Value {
    let params = capability
        .params
        .iter()
        .map(|(name, value)| (name.clone(), Value::from(value.as_str())))
        .collect();
    let mut out = Map::new();
    drop(out.insert("system".to_owned(), capability.system.as_str().into()));
    drop(out.insert("params".to_owned(), Value::Object(params)));
    Value::Object(out)
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
    /// The circuit and option for a `zkp_req` query, or `None` if it cannot be answered.
    ///
    /// `None` covers a request that breaks a rule of `zkp_req` or of the nym_auth catalogue, a
    /// wallet with no circuit, and options no circuit serves. It never falls back to claim
    /// matching: an invalid `zkp_req` request asks for nothing the matcher understands, and
    /// answering it with what the claims would select discloses data nobody asked for.
    pub fn zkp_req_selection(&self, query: &CredentialQuery) -> Option<ZkpReqSelection<'a>> {
        let parsed = ZkpReqQuery::parse(query).ok()?;
        // zkp_req, Section 1.2: the Verifier MUST send both lists.
        let formats = ZkpFormats::from_client_metadata(self.client_metadata?).ok()?;
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
        let source_format = credential_type.source_format();
        Some(
            rule.stored_formats
                .iter()
                .map(String::as_str)
                .filter(|f| source_format == *f)
                .collect(),
        )
    }
}
