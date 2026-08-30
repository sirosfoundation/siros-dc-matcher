//! The matching surface Kotlin and Swift will call.
//!
//! These pin the behaviour that differs from what the two SDKs do today, so a
//! regression in the shared engine shows up here rather than as a wallet that
//! silently stops being offered.

use std::collections::HashMap;

use serde_json::json;
use siros_dc_matcher_core::db::{Claim, Credential, CredentialDatabase};
use siros_dc_matcher_core::profile::{Capability, MatchProfile, ZK_CAPABILITY};
use siros_dc_matcher_ffi::matching::{match_dc_api_request, match_dcql, MatchError};

fn wallet(zk: Option<Capability>) -> Vec<u8> {
    let mut profile = MatchProfile::siros_default();
    if let Some(cap) = zk {
        profile
            .capabilities
            .insert(ZK_CAPABILITY.to_string(), vec![cap]);
    }
    let mut db = CredentialDatabase::new(profile);
    db.credentials.push(Credential {
        id: "mdl-1".into(),
        format: "mso_mdoc".into(),
        doctype: Some("org.iso.18013.5.1.mDL".into()),
        vct: None,
        title: "Driving Licence".into(),
        subtitle: "Transportstyrelsen".into(),
        icon: None,
        claims: vec![
            Claim {
                path: vec!["org.iso.18013.5.1".into(), "age_over_18".into()],
                value: "true".into(),
                display: "Over 18".into(),
                display_value: Some("Yes".into()),
            },
            Claim {
                path: vec!["org.iso.18013.5.1".into(), "family_name".into()],
                value: "Johansson".into(),
                display: "Family name".into(),
                display_value: None,
            },
        ],
    });
    db.to_cbor().expect("encoding")
}

fn dcql(format: &str, claims: serde_json::Value, meta: serde_json::Value) -> String {
    json!({"credentials": [{
        "id": "q1", "format": format, "meta": meta, "claims": claims
    }]})
    .to_string()
}

fn age_claim() -> serde_json::Value {
    json!([{"path": ["org.iso.18013.5.1", "age_over_18"]}])
}

/// The rule both SDKs miss today: a credential lacking a requested claim must
/// not be offered (§6.4.1). Filtering on format and doctype alone would offer
/// this one, and the presentation would then fail after the user consented.
#[test]
fn a_credential_missing_a_requested_claim_is_not_offered() {
    let blob = wallet(None);
    let query = dcql(
        "mso_mdoc",
        json!([{"path": ["org.iso.18013.5.1", "portrait"]}]),
        json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
    );

    let out = match_dcql(blob, query).expect("matched");
    assert!(!out.satisfiable);
    assert!(out.combinations.is_empty());
}

/// Only the claims the query asked for are returned — not everything the
/// credential holds. The caller discloses exactly this set.
#[test]
fn only_the_requested_claims_come_back() {
    let blob = wallet(None);
    let query = dcql(
        "mso_mdoc",
        age_claim(),
        json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
    );

    let out = match_dcql(blob, query).expect("matched");
    let member = &out.combinations[0].members[0];
    assert_eq!(member.credential_id, "mdl-1");
    assert_eq!(
        member.claims,
        vec![vec!["org.iso.18013.5.1", "age_over_18"]]
    );
}

/// The ZK path, across the boundary: a mso_mdoc_zk request reaches an ordinary
/// stored mdoc, and the chosen system comes back so the caller does not have
/// to work it out again.
#[test]
fn a_zk_request_returns_the_chosen_system() {
    let blob = wallet(Some(Capability {
        system: "longfellow-libzk-v1".into(),
        params: std::collections::BTreeMap::new(),
    }));
    let query = dcql(
        "mso_mdoc_zk",
        age_claim(),
        json!({
            "doctype_value": "org.iso.18013.5.1.mDL",
            "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1", "num_attributes": "2"}]
        }),
    );

    let out = match_dcql(blob, query).expect("matched");
    let member = &out.combinations[0].members[0];
    assert_eq!(member.credential_id, "mdl-1");
    assert_eq!(member.capabilities[0].system, "longfellow-libzk-v1");
}

/// A wallet that cannot prove is not offered for a ZK request.
#[test]
fn a_zk_request_without_a_capability_offers_nothing() {
    let blob = wallet(None);
    let query = dcql(
        "mso_mdoc_zk",
        age_claim(),
        json!({
            "doctype_value": "org.iso.18013.5.1.mDL",
            "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1"}]
        }),
    );
    assert!(!match_dcql(blob, query).expect("matched").satisfiable);
}

/// `ppid_context` is carried, not matched on — a pseudonym context changes
/// what is produced, not which credential can produce it. Both SDKs read it
/// today, so losing it here would be a functional regression.
#[test]
fn ppid_context_is_carried_through() {
    let blob = wallet(None);
    let query = dcql(
        "mso_mdoc",
        age_claim(),
        json!({
            "doctype_value": "org.iso.18013.5.1.mDL",
            "ppid_context": "https://rp.example/ctx"
        }),
    );

    let out = match_dcql(blob, query).expect("matched");
    let meta: &HashMap<String, String> = &out.combinations[0].members[0].meta;
    assert_eq!(
        meta.get("ppid_context").map(String::as_str),
        Some("https://rp.example/ctx")
    );
}

/// The DC API envelope picks the first protocol the profile answers.
#[test]
fn the_envelope_selects_a_supported_protocol() {
    let blob = wallet(None);
    let request = json!({"requests": [
        {"protocol": "some-future-thing", "data": {}},
        {"protocol": "openid4vp-v1-signed", "data": {"dcql_query":
            serde_json::from_str::<serde_json::Value>(
                &dcql("mso_mdoc", age_claim(), json!({"doctype_value": "org.iso.18013.5.1.mDL"}))
            ).expect("query")}}
    ]})
    .to_string();

    let out = match_dc_api_request(blob, request).expect("matched");
    assert!(out.satisfiable);
}

/// An envelope offering nothing the wallet speaks is distinct from an empty
/// match: the wallet may hold exactly what was asked for and still not speak
/// the protocol it was asked in.
#[test]
fn an_unspeakable_protocol_is_its_own_error() {
    let blob = wallet(None);
    let request = json!({"requests": [{"protocol": "some-future-thing", "data": {}}]}).to_string();

    match match_dc_api_request(blob, request) {
        // What was offered comes back: a variant with no fields loses its
        // message crossing the boundary, so the protocols the verifier named
        // are the only thing that makes this actionable in a host app's log.
        Err(MatchError::UnsupportedProtocol { offered }) => {
            assert_eq!(offered, vec!["some-future-thing".to_string()]);
        }
        other => panic!("expected UnsupportedProtocol, got {other:?}"),
    }
}

/// Malformed input is an error, never a panic — this runs behind an FFI
/// boundary, and a panic there would take the host application with it.
#[test]
fn malformed_input_is_an_error_not_a_panic() {
    let blob = wallet(None);

    assert!(matches!(
        match_dcql(vec![0xff, 0xff], "{}".into()),
        Err(MatchError::Blob { .. })
    ));
    assert!(matches!(
        match_dcql(blob.clone(), "not json".into()),
        Err(MatchError::Request { .. })
    ));
    assert!(matches!(
        match_dc_api_request(blob, "not json".into()),
        Err(MatchError::Request { .. })
    ));
}
