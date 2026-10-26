//! G3: one fixture per refusal rule, each with the exact typed error it must give.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod support;

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_zkp_req::{
    EncodingError, Match, PairRefusal, ProofEnvelope, RequestRule, StructureRejection,
    ZkpPresentation,
};
use siros_zkp_req_nym_auth::catalogue::CatalogueRule;
use siros_zkp_req_nym_auth::outcome::{CredentialCode, InvalidRequest, ItemCode, ZkpError};
use siros_zkp_req_nym_auth::policy::{check_request, Channel, PolicyRule};
use siros_zkp_req_nym_auth::presenter::{
    match_query, present, MatchInput, NymAuthMatch, ProveError, ProveInput,
};
use siros_zkp_req_nym_auth::prover::{ProofFailure, ProverFailure};
use siros_zkp_req_nym_auth::system::{NymAuthSystem, Unsupported};
use siros_zkp_req_nym_auth::verifier_id::{VerifierId, VerifierIdRule};
use siros_zkp_req_nym_auth::verify::{
    verify, IssuerKeySetError, ProofTimeError, Rejection, Tolerance, VerifyInput,
};
use support::*;

/// What a fixture gives.
#[derive(Debug, PartialEq)]
enum Got {
    Invalid(InvalidRequest),
    Unsupported(PairRefusal<Unsupported>),
    Rejected(Vec<ZkpError>),
    Prove(ProveError),
    Verify(Rejection),
    Policy(PolicyRule),
    VerifierId(VerifierIdRule),
    Accepted,
}

fn protocol(rule: RequestRule) -> Got {
    Got::Invalid(InvalidRequest::Protocol(rule))
}

fn catalogue(rule: CatalogueRule) -> Got {
    Got::Invalid(InvalidRequest::Catalogue(rule))
}

fn ds() -> Issuer {
    Issuer::root(0x11, "Test Document Signer")
}

fn matched(
    query: &Value,
    metadata: &Value,
    data: String,
    anchors: Option<&[Vec<u8>]>,
) -> NymAuthMatch {
    match_query(&MatchInput {
        query,
        client_metadata: metadata,
        credentials: &[stored("c1", data)],
        anchors,
        systems: &[NymAuthSystem::LongfellowV1],
        now: NOW,
    })
    .unwrap()
}

fn got(m: NymAuthMatch) -> Got {
    match m {
        Match::Invalid(rule) => Got::Invalid(rule),
        Match::Unsupported(options) => Got::Unsupported(options[0].systems[0].1.clone()),
        Match::Rejected(judged) => Got::Rejected(judged[0].errors.clone()),
        Match::Candidates(_) => Got::Accepted,
    }
}

/// Matches `query` against the default credential.
fn match_query_edit(edit: impl FnOnce(&mut Value)) -> Got {
    let mut q = query(Some("18+"), false);
    edit(&mut q);
    got(matched(
        &q,
        &client_metadata(),
        issue(&ds(), &Spec::default()),
        None,
    ))
}

fn match_metadata_edit(edit: impl FnOnce(&mut Value)) -> Got {
    let mut metadata = client_metadata();
    edit(&mut metadata);
    got(matched(
        &query(None, false),
        &metadata,
        issue(&ds(), &Spec::default()),
        None,
    ))
}

fn match_credential(spec: Spec, range: Option<&str>) -> Got {
    got(matched(
        &query(range, false),
        &client_metadata(),
        issue(&ds(), &spec),
        None,
    ))
}

/// Proves the default credential with this seed, device key and prover.
fn prove(seed: [u8; 16], device: u8, fail: Option<ProverFailure>) -> Got {
    let q = query(None, false);
    let metadata = client_metadata();
    let credential = stored("c1", issue(&ds(), &Spec::default()));
    let Match::Candidates(candidates) = matched(&q, &metadata, credential.data.clone(), None)
    else {
        panic!("no candidate");
    };
    let session = session(&q, NONCE);
    let prover = TestProver { fail };
    let result = present(
        &ProveInput {
            candidate: &candidates[0],
            query: &q,
            client_metadata: &metadata,
            session: &session,
            credential: &credential,
            secret_seed: &seed,
            anchors: None,
            now: NOW,
        },
        &DeviceSigner(device),
        &prover,
    );
    match result {
        Ok(_) => Got::Accepted,
        Err(e) => Got::Prove(e),
    }
}

fn policy(edit: impl FnOnce(&mut Value), signed: bool, channel: Channel) -> Got {
    let mut request = request_object(&query(None, false), NONCE);
    edit(&mut request);
    match check_request(&request, signed, channel) {
        Ok(_) => Got::Accepted,
        Err(rule) => Got::Policy(rule),
    }
}

fn verifier_id(result: Result<VerifierId, VerifierIdRule>) -> Got {
    match result {
        Ok(_) => Got::Accepted,
        Err(rule) => Got::VerifierId(rule),
    }
}

/// An honest presentation for a query with two options, made with `system`.
fn honest(system: NymAuthSystem, query: &Value) -> Vec<u8> {
    let metadata = client_metadata();
    let credential = stored("c1", issue(&ds(), &Spec::default()));
    let m = match_query(&MatchInput {
        query,
        client_metadata: &metadata,
        credentials: std::slice::from_ref(&credential),
        anchors: None,
        systems: &[system],
        now: NOW,
    })
    .unwrap();
    let Match::Candidates(candidates) = m else {
        panic!("no candidate")
    };
    present(
        &ProveInput {
            candidate: &candidates[0],
            query,
            client_metadata: &metadata,
            session: &session(query, NONCE),
            credential: &credential,
            secret_seed: &SEED,
            anchors: None,
            now: NOW,
        },
        &DeviceSigner(Spec::default().device),
        &TestProver { fail: None },
    )
    .unwrap()
    .encode()
}

fn sets_query() -> Value {
    let mut q = query(Some("18+"), true);
    q["_req_sets"] = json!([[0, 1], [0]]);
    q
}

struct Verifying {
    query: Value,
    metadata: Value,
    anchors: Vec<Vec<u8>>,
    now: i64,
}

impl Default for Verifying {
    fn default() -> Self {
        Self {
            query: sets_query(),
            metadata: client_metadata(),
            anchors: vec![ds().der],
            now: NOW + 5,
        }
    }
}

fn verified(v: Verifying, bytes: &[u8]) -> Got {
    let result = verify(
        &VerifyInput {
            query: &v.query,
            client_metadata: &v.metadata,
            session: &session(&v.query, NONCE),
            presentation: bytes,
            now: v.now,
            tolerance: Tolerance {
                future: 60,
                past: 600,
            },
            trust_anchors: &v.anchors,
        },
        &TestVerifier,
    );
    match result {
        Ok(_) => Got::Accepted,
        Err(r) => Got::Verify(r),
    }
}

/// Verifies the honest Longfellow presentation after `edit`.
fn verify_edit(edit: impl FnOnce(&mut ZkpPresentation)) -> Got {
    verify_edit_as(NymAuthSystem::LongfellowV1, Verifying::default(), edit)
}

fn verify_edit_as(
    system: NymAuthSystem,
    v: Verifying,
    edit: impl FnOnce(&mut ZkpPresentation),
) -> Got {
    let mut p = ZkpPresentation::decode(&honest(system, &sets_query())).unwrap();
    edit(&mut p);
    verified(v, &p.encode())
}

fn edit_envelope(p: &mut ZkpPresentation, edit: impl FnOnce(&mut ProofEnvelope)) {
    let mut envelope = ProofEnvelope::decode(&p.proof).unwrap();
    edit(&mut envelope);
    p.proof = envelope.encode();
}

fn set_input(envelope: &mut ProofEnvelope, name: &str, value: Cbor) {
    for (k, v) in &mut envelope.inputs {
        if k == name {
            *v = value.clone();
        }
    }
}

fn set_result(p: &mut ZkpPresentation, handle: &str, value: Option<Cbor>) {
    p.results.retain(|(k, _)| k != handle);
    if let Some(value) = value {
        p.results.push((handle.to_owned(), value));
    }
}

fn credential_error(code: CredentialCode) -> Got {
    Got::Rejected(vec![ZkpError::Credential(code)])
}

#[test]
fn every_refusal_rule() {
    let item = |q: &mut Value, i: usize, k: &str, v: Value| q["_req"][i][k] = v;
    let param = |q: &mut Value, i: usize, k: &str, v: Value| q["_req"][i]["params"][k] = v;
    let other_root = Issuer::root(0x22, "Another Root");
    let cases: Vec<(&str, Got, Got)> = vec![
        // zkp_req, Sections 1.1, 1.2, 2 and 2.1: invalid_request.
        (
            "query_not_object",
            match_query_edit(|q| *q = json!([1])),
            protocol(RequestRule::QueryNotObject),
        ),
        (
            "query_id_invalid",
            match_query_edit(|q| q["id"] = json!("")),
            protocol(RequestRule::QueryIdInvalid),
        ),
        (
            "format_not_zkp_req",
            match_query_edit(|q| q["format"] = json!("mso_mdoc")),
            protocol(RequestRule::FormatNotZkpReq),
        ),
        (
            "claims_present",
            match_query_edit(|q| q["claims"] = json!([])),
            protocol(RequestRule::ClaimsPresent),
        ),
        (
            "claim_sets_present",
            match_query_edit(|q| q["claim_sets"] = json!([])),
            protocol(RequestRule::ClaimSetsPresent),
        ),
        (
            "meta_invalid",
            match_query_edit(|q| q["meta"] = json!("mso_mdoc")),
            protocol(RequestRule::MetaInvalid),
        ),
        (
            "source_format_invalid",
            match_query_edit(|q| q["meta"] = json!({"doctype_value": DOCTYPE})),
            protocol(RequestRule::SourceFormatInvalid),
        ),
        (
            "type_value_invalid",
            match_query_edit(|q| q["meta"] = json!({"source_format": "mso_mdoc"})),
            protocol(RequestRule::TypeValueInvalid),
        ),
        (
            "req_invalid",
            match_query_edit(|q| q["_req"] = json!([])),
            protocol(RequestRule::ReqInvalid),
        ),
        (
            "item_not_object",
            match_query_edit(|q| q["_req"][1] = json!(1)),
            protocol(RequestRule::ItemNotObject { item: 1 }),
        ),
        (
            "item_member_unknown",
            match_query_edit(|q| item(q, 0, "id", json!("x"))),
            protocol(RequestRule::ItemMemberUnknown { item: 0 }),
        ),
        (
            "fn_id_invalid",
            match_query_edit(|q| item(q, 1, "fn_id", json!(7))),
            protocol(RequestRule::FnIdInvalid { item: 1 }),
        ),
        (
            "params_not_object",
            match_query_edit(|q| item(q, 1, "params", json!([]))),
            protocol(RequestRule::ParamsNotObject { item: 1 }),
        ),
        (
            "return_invalid",
            match_query_edit(|q| item(q, 0, "return", json!("a b"))),
            protocol(RequestRule::ReturnInvalid { item: 0 }),
        ),
        (
            "return_repeated",
            match_query_edit(|q| item(q, 1, "return", json!("nym"))),
            protocol(RequestRule::ReturnRepeated { item: 1 }),
        ),
        (
            "req_sets_invalid",
            match_query_edit(|q| q["_req_sets"] = json!([])),
            protocol(RequestRule::ReqSetsInvalid),
        ),
        (
            "option_invalid",
            match_query_edit(|q| q["_req_sets"] = json!([[0], [0, 0]])),
            protocol(RequestRule::OptionInvalid { option: 1 }),
        ),
        (
            "trusted_authorities_invalid",
            match_query_edit(|q| q["trusted_authorities"] = json!([{"type": "aki"}])),
            protocol(RequestRule::TrustedAuthoritiesInvalid),
        ),
        (
            "holder_binding_invalid",
            match_query_edit(|q| q["require_cryptographic_holder_binding"] = json!("yes")),
            protocol(RequestRule::HolderBindingInvalid),
        ),
        (
            "formats_missing",
            match_metadata_edit(|m| m["vp_formats_supported"] = json!({})),
            protocol(RequestRule::FormatsMissing),
        ),
        (
            "proof_backend_values_invalid",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["proof_backend_values"] = json!([])
            }),
            protocol(RequestRule::ProofBackendValuesInvalid),
        ),
        (
            "system_id_values_invalid",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["system_id_values"] = json!(["a", 1])
            }),
            protocol(RequestRule::SystemIdValuesInvalid),
        ),
        // The nym_auth catalogue: invalid_request.
        (
            "schema_id_invalid",
            match_query_edit(|q| q["meta"] = json!({"source_format": "bbs_cd"})),
            catalogue(CatalogueRule::SchemaIdInvalid),
        ),
        (
            "holder_binding_waived",
            match_query_edit(|q| q["require_cryptographic_holder_binding"] = json!(false)),
            catalogue(CatalogueRule::HolderBindingWaived),
        ),
        (
            "function_unknown",
            match_query_edit(|q| item(q, 1, "fn_id", json!("valid_on"))),
            catalogue(CatalogueRule::FunctionUnknown { item: 1 }),
        ),
        (
            "param_unknown",
            match_query_edit(|q| param(q, 0, "verifier_id_type", json!("x509_san_dns"))),
            catalogue(CatalogueRule::ParamUnknown { item: 0 }),
        ),
        (
            "pseudonym_return_missing",
            match_query_edit(|q| {
                q["_req"][0].as_object_mut().unwrap().remove("return");
            }),
            catalogue(CatalogueRule::PseudonymReturnMissing { item: 0 }),
        ),
        (
            "config_invalid",
            match_query_edit(|q| param(q, 0, "config", json!("known-offender-matching"))),
            catalogue(CatalogueRule::ConfigInvalid { item: 0 }),
        ),
        (
            "ver_invalid",
            match_query_edit(|q| param(q, 0, "ver", json!(2))),
            catalogue(CatalogueRule::VerInvalid { item: 0 }),
        ),
        (
            "prf_invalid",
            match_query_edit(|q| param(q, 0, "prf", json!("hashdh-bls12381g1"))),
            catalogue(CatalogueRule::PrfInvalid { item: 0 }),
        ),
        (
            "verifier_context_invalid",
            match_query_edit(|q| param(q, 0, "verifier_context", json!("account 7"))),
            catalogue(CatalogueRule::VerifierContextInvalid { item: 0 }),
        ),
        (
            "range_syntax",
            match_query_edit(|q| param(q, 1, "range", json!("18"))),
            catalogue(CatalogueRule::RangeSyntax { item: 1 }),
        ),
        (
            "range_inverted",
            match_query_edit(|q| param(q, 1, "range", json!("17-13"))),
            catalogue(CatalogueRule::RangeInverted { item: 1 }),
        ),
        (
            "pseudonym_repeated",
            match_query_edit(|q| {
                let mut second = q["_req"][0].clone();
                second["return"] = json!("nym2");
                q["_req"][1] = second;
            }),
            catalogue(CatalogueRule::PseudonymRepeated { option: None }),
        ),
        (
            "age_check_repeated",
            match_query_edit(|q| {
                let second = q["_req"][1].clone();
                q["_req"].as_array_mut().unwrap().push(second);
            }),
            catalogue(CatalogueRule::AgeCheckRepeated { option: None }),
        ),
        // The catalogue's Binding and Response confidentiality: invalid_request.
        (
            "unsigned",
            policy(|_| {}, false, Channel::Redirect),
            Got::Policy(PolicyRule::Unsigned),
        ),
        (
            "request_object_not_object",
            policy(|r| *r = json!("jwt"), true, Channel::Redirect),
            Got::Policy(PolicyRule::NotObject),
        ),
        (
            "client_id_missing",
            policy(
                |r| {
                    r.as_object_mut().unwrap().remove("client_id");
                },
                true,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ClientIdMissing),
        ),
        (
            "nonce_missing",
            policy(|r| r["nonce"] = json!(""), true, Channel::Redirect),
            Got::Policy(PolicyRule::NonceMissing),
        ),
        (
            "response_mode",
            policy(
                |r| r["response_mode"] = json!("direct_post"),
                true,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ResponseMode),
        ),
        (
            "response_uri_missing",
            policy(
                |r| {
                    r.as_object_mut().unwrap().remove("response_uri");
                },
                true,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::ResponseUriMissing),
        ),
        (
            "origin_not_expected",
            policy(
                |r| {
                    r["response_mode"] = json!("dc_api.jwt");
                    r["expected_origins"] = json!(["https://rp.example"]);
                },
                true,
                Channel::DcApi {
                    origin: "https://evil.example".into(),
                },
            ),
            Got::Policy(PolicyRule::OriginNotExpected),
        ),
        (
            "encryption_key_missing",
            policy(
                |r| r["client_metadata"]["jwks"] = json!({"keys": []}),
                true,
                Channel::Redirect,
            ),
            Got::Policy(PolicyRule::EncryptionKeyMissing),
        ),
        // The catalogue's verifier identity: invalid_request.
        (
            "semantic_id_missing",
            verifier_id(VerifierId::semantic("")),
            Got::VerifierId(VerifierIdRule::SemanticIdMissing),
        ),
        (
            "client_id_prefix",
            verifier_id(VerifierId::x509_san_dns(
                "x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk",
                false,
            )),
            Got::VerifierId(VerifierIdRule::ClientIdPrefix),
        ),
        (
            "dns_name",
            verifier_id(VerifierId::x509_san_dns(
                "x509_san_dns:bücher.example",
                false,
            )),
            Got::VerifierId(VerifierIdRule::DnsName),
        ),
        (
            "intermediary",
            verifier_id(VerifierId::x509_san_dns(CLIENT_ID, true)),
            Got::VerifierId(VerifierIdRule::Intermediary),
        ),
        // zkp_req, Section 1.3, and the systems' Section 2: vp_formats_not_supported.
        (
            "system_not_listed",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["system_id_values"] =
                    json!(["urn:circuits:vega:nym_auth:v1"])
            }),
            Got::Unsupported(PairRefusal::SystemNotListed),
        ),
        (
            "no_listed_backend",
            match_metadata_edit(|m| {
                m["vp_formats_supported"]["zkp_req"]["proof_backend_values"] = json!(["vega-v1"])
            }),
            Got::Unsupported(PairRefusal::NoListedBackend),
        ),
        (
            "credential_type",
            match_query_edit(|q| {
                q["meta"] = json!({"source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1"});
                param(q, 0, "prf", json!("hashdh-bls12381g1"));
            }),
            Got::Unsupported(PairRefusal::CredentialType),
        ),
        (
            "unsupported: no pseudonym",
            match_query_edit(|q| {
                q["_req"].as_array_mut().unwrap().remove(0);
            }),
            Got::Unsupported(PairRefusal::Unsupported(Unsupported::NoPseudonym)),
        ),
        (
            "unsupported: config",
            match_query_edit(|q| param(q, 0, "config", json!("known-offender-matching-psc"))),
            Got::Unsupported(PairRefusal::Unsupported(Unsupported::Config)),
        ),
        (
            "unsupported: age bounds",
            match_query_edit(|q| param(q, 1, "range", json!("2027+"))),
            Got::Unsupported(PairRefusal::Unsupported(Unsupported::AgeBounds)),
        ),
        // The systems' Section 9, Wallet side: access_denied.
        (
            "age_out_of_range",
            match_credential(
                Spec {
                    birth_date: "2015-01-01",
                    ..Spec::default()
                },
                Some("18+"),
            ),
            Got::Rejected(vec![ZkpError::Item {
                option: None,
                item: 1,
                code: ItemCode::AgeOutOfRange,
            }]),
        ),
        (
            "seed_mismatch",
            prove([0x5a; 16], Spec::default().device, None),
            Got::Prove(ProveError::Rejected(vec![ZkpError::Item {
                option: None,
                item: 0,
                code: ItemCode::SeedMismatch,
            }])),
        ),
        (
            "validity",
            match_credential(
                Spec {
                    valid_until: "2026-06-01T00:00:00Z",
                    ..Spec::default()
                },
                None,
            ),
            credential_error(CredentialCode::Validity),
        ),
        (
            "issuer_signature",
            match_credential(
                Spec {
                    wrong_signature: true,
                    ..Spec::default()
                },
                None,
            ),
            credential_error(CredentialCode::IssuerSignature),
        ),
        (
            "issuer_signature: digest",
            match_credential(
                Spec {
                    wrong_ssc_digest: true,
                    ..Spec::default()
                },
                None,
            ),
            credential_error(CredentialCode::IssuerSignature),
        ),
        (
            "issuer_untrusted",
            {
                let mut q = query(None, false);
                q["trusted_authorities"] = json!([{"type": "aki", "values": ["AAAA"]}]);
                got(matched(
                    &q,
                    &client_metadata(),
                    issue(&ds(), &Spec::default()),
                    Some(std::slice::from_ref(&other_root.der)),
                ))
            },
            credential_error(CredentialCode::IssuerUntrusted),
        ),
        (
            "device_binding",
            prove(SEED, 0x44, None),
            Got::Prove(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::DeviceBinding,
            )])),
        ),
        (
            "credential_form: unreadable",
            got(matched(
                &query(None, false),
                &client_metadata(),
                "not base64url!".into(),
                None,
            )),
            credential_error(CredentialCode::CredentialForm),
        ),
        (
            "credential_form: prover",
            prove(
                SEED,
                Spec::default().device,
                Some(ProverFailure::CredentialForm),
            ),
            Got::Prove(ProveError::Rejected(vec![ZkpError::Credential(
                CredentialCode::CredentialForm,
            )])),
        ),
        // zkp_req, Section 4.1, steps 1 to 5.
        (
            "presentation",
            verified(Verifying::default(), &[0x01]),
            Got::Verify(Rejection::Presentation(EncodingError::NotMap)),
        ),
        (
            "system_not_listed",
            verified(
                Verifying {
                    metadata: {
                        let mut m = client_metadata();
                        m["vp_formats_supported"]["zkp_req"]["system_id_values"] =
                            json!(["urn:circuits:vega:nym_auth:v1"]);
                        m
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Structure(StructureRejection::SystemNotListed)),
        ),
        (
            "backend_not_listed",
            verified(
                Verifying {
                    metadata: {
                        let mut m = client_metadata();
                        m["vp_formats_supported"]["zkp_req"]["proof_backend_values"] =
                            json!(["vega-v1"]);
                        m
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Structure(StructureRejection::BackendNotListed)),
        ),
        (
            "system_not_on_backend",
            verify_edit(|p| p.proof_backend = "vega-v1".into()),
            Got::Verify(Rejection::Structure(StructureRejection::SystemNotOnBackend)),
        ),
        (
            "req_set_missing",
            verify_edit(|p| p.req_set = None),
            Got::Verify(Rejection::Structure(StructureRejection::ReqSetMissing)),
        ),
        (
            "req_set_extra",
            verified(
                Verifying {
                    query: query(Some("18+"), true),
                    ..Verifying::default()
                },
                &edited_no_sets(),
            ),
            Got::Verify(Rejection::Structure(StructureRejection::ReqSetExtra)),
        ),
        (
            "req_set_unknown",
            verify_edit(|p| p.req_set = Some(5)),
            Got::Verify(Rejection::Structure(StructureRejection::ReqSetUnknown)),
        ),
        (
            "result_keys",
            verify_edit(|p| set_result(p, "adult", None)),
            Got::Verify(Rejection::Structure(StructureRejection::ResultKeys)),
        ),
        (
            "result_not_true",
            verify_edit(|p| set_result(p, "adult", Some(Cbor::Bool(false)))),
            Got::Verify(Rejection::Structure(StructureRejection::ResultNotTrue {
                item: 1,
            })),
        ),
        // The systems' Section 9, Verifier side.
        (
            "request: invalid",
            verified(
                Verifying {
                    query: {
                        let mut q = sets_query();
                        q["_req"][0]["params"]["ver"] = json!(2);
                        q
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Request(Some(InvalidRequest::Catalogue(
                CatalogueRule::VerInvalid { item: 0 },
            )))),
        ),
        (
            "request: unsupported",
            verified(
                Verifying {
                    query: {
                        let mut q = sets_query();
                        q["_req"][0]["params"]["config"] = json!("known-offender-matching-psc");
                        q
                    },
                    ..Verifying::default()
                },
                &honest(NymAuthSystem::LongfellowV1, &sets_query()),
            ),
            Got::Verify(Rejection::Unsupported(Unsupported::Config)),
        ),
        (
            "proof_encoding: proof",
            verify_edit(|p| p.proof = vec![0xff]),
            Got::Verify(Rejection::ProofEncoding),
        ),
        (
            "proof_encoding: inputs",
            verify_edit(|p| edit_envelope(p, |e| e.inputs.push(("extra".into(), Cbor::Null)))),
            Got::Verify(Rejection::ProofEncoding),
        ),
        (
            "proof_encoding: tdate",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(e, "proof_time", Cbor::text("2026-10-09T12:00:00Z"))
                })
            }),
            Got::Verify(Rejection::ProofEncoding),
        ),
        (
            "proof_encoding: zk_proof length",
            verify_edit_as(NymAuthSystem::VegaV1, Verifying::default(), |p| {
                edit_envelope(p, |e| {
                    e.zk_proof.pop();
                })
            }),
            Got::Verify(Rejection::ProofEncoding),
        ),
        (
            "proof_encoding: verifier",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    e.zk_proof.pop();
                })
            }),
            Got::Verify(Rejection::Proof(ProofFailure::Encoding)),
        ),
        (
            "issuer_key_set: count",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(
                        e,
                        "issuer_key_set",
                        Cbor::Array(vec![Cbor::Bytes(ds().der), Cbor::Bytes(ds().der)]),
                    )
                })
            }),
            Got::Verify(Rejection::IssuerKeySet(IssuerKeySetError::Count)),
        ),
        (
            "issuer_key_set: certificate",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(
                        e,
                        "issuer_key_set",
                        Cbor::Array(vec![Cbor::Bytes(vec![0x30, 0x00])]),
                    )
                })
            }),
            Got::Verify(Rejection::IssuerKeySet(IssuerKeySetError::Certificate(
                siros_mdoc::CertificateError::Der,
            ))),
        ),
        (
            "issuer_key_set: untrusted",
            verify_edit_as(
                NymAuthSystem::LongfellowV1,
                Verifying {
                    anchors: vec![other_root.der.clone()],
                    ..Verifying::default()
                },
                |_| {},
            ),
            Got::Verify(Rejection::IssuerKeySet(IssuerKeySetError::Untrusted)),
        ),
        (
            "proof_time: malformed",
            verify_edit(|p| {
                edit_envelope(p, |e| {
                    set_input(
                        e,
                        "proof_time",
                        Cbor::Tag(0, Box::new(Cbor::text("2026-10-09T12:00:00.5Z"))),
                    )
                })
            }),
            Got::Verify(Rejection::ProofTime(ProofTimeError::Malformed)),
        ),
        (
            "proof_time: tolerance",
            verify_edit_as(
                NymAuthSystem::LongfellowV1,
                Verifying {
                    now: NOW + 601,
                    ..Verifying::default()
                },
                |_| {},
            ),
            Got::Verify(Rejection::ProofTime(ProofTimeError::Tolerance)),
        ),
        (
            "results",
            verify_edit(|p| set_result(p, "nym", Some(Cbor::Bytes(vec![0; 31])))),
            Got::Verify(Rejection::Results),
        ),
    ];
    // The honest inputs each fixture edits are accepted: each fixture breaks only its rule.
    assert_eq!(match_query_edit(|_| {}), Got::Accepted);
    assert_eq!(prove(SEED, Spec::default().device, None), Got::Accepted);
    assert_eq!(verify_edit(|_| {}), Got::Accepted);
    assert_eq!(policy(|_| {}, true, Channel::Redirect), Got::Accepted);
    let failures: Vec<String> = cases
        .into_iter()
        .filter(|(_, got, want)| got != want)
        .map(|(name, got, want)| format!("{name}: got {got:?}, want {want:?}"))
        .collect();
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The honest presentation of a query without `_req_sets`, with a `req_set` added.
fn edited_no_sets() -> Vec<u8> {
    let mut p = ZkpPresentation::decode(&honest(
        NymAuthSystem::LongfellowV1,
        &query(Some("18+"), true),
    ))
    .unwrap();
    p.req_set = Some(0);
    p.encode()
}
