//! The matching surface Kotlin and Swift will call.
//!
//! These pin the behaviour that differs from what the two SDKs do today, so a
//! regression in the shared engine shows up here rather than as a wallet that
//! silently stops being offered.

use std::collections::HashMap;

use serde_json::json;
use siros_dc_matcher_core::fixtures;
use siros_dc_matcher_core::profile::Capability;
use siros_dc_matcher_ffi::matching::{match_dc_api_request, match_dcql, MatchError};

fn wallet(zk: Option<Capability>) -> Vec<u8> {
    fixtures::wallet(zk.into_iter().collect())
        .to_cbor()
        .expect("encoding")
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
    let blob = wallet(Some(fixtures::longfellow(None)));
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

/// Per-query candidates are complete even when the combination list is capped.
///
/// The combination count is a product, so it is bounded; a caller unioning the
/// combinations to learn "which credentials qualify" would miss some, and
/// filtering on that union silently drops credentials a user could present.
/// `matches` exists so no caller has to.
#[test]
fn per_query_candidates_are_complete_when_combinations_are_capped() {
    // Two queries, forty credentials each: sixteen hundred combinations
    // against a cap of thirty-two.
    let mut db = fixtures::wallet(Vec::new());
    let template = db.credentials[0].clone();
    for i in 2..=40 {
        let mut extra = template.clone();
        extra.id = format!("mdl-{i}");
        db.credentials.push(extra);
    }
    let blob = db.to_cbor().expect("encoding");

    let claims = json!([{"path": ["org.iso.18013.5.1", "age_over_18"]}]);
    let meta = json!({"doctype_value": "org.iso.18013.5.1.mDL"});
    let query = json!({"credentials": [
        {"id": "a", "format": "mso_mdoc", "meta": meta, "claims": claims},
        {"id": "b", "format": "mso_mdoc", "meta": meta, "claims": claims}
    ]})
    .to_string();

    let out = match_dcql(blob, query).expect("matched");
    assert!(out.dropped > 0, "this fixture is meant to exceed the cap");

    for query_id in ["a", "b"] {
        let m = out
            .matches
            .iter()
            .find(|m| m.query_id == query_id)
            .unwrap_or_else(|| panic!("no matches for {query_id}"));
        assert_eq!(m.credentials.len(), 40, "every candidate for {query_id}");
    }

    // The union of the capped combinations is genuinely short of that — which
    // is the whole reason `matches` exists.
    let from_combinations: std::collections::BTreeSet<_> = out
        .combinations
        .iter()
        .flat_map(|c| c.members.iter())
        .filter(|m| m.query_id == "a")
        .map(|m| m.credential_id.clone())
        .collect();
    assert!(
        from_combinations.len() < 40,
        "expected the capped union to be incomplete, got {}",
        from_combinations.len()
    );
}

/// The per-query view carries the same detail as a combination member.
#[test]
fn per_query_candidates_carry_claims_and_capabilities() {
    let blob = wallet(Some(fixtures::longfellow(None)));
    let query = dcql(
        "mso_mdoc_zk",
        age_claim(),
        json!({
            "doctype_value": "org.iso.18013.5.1.mDL",
            "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1"}]
        }),
    );

    let out = match_dcql(blob, query).expect("matched");
    let candidate = &out.matches[0].credentials[0];
    assert_eq!(candidate.credential_id, "mdl-1");
    assert_eq!(
        candidate.claims,
        vec![vec!["org.iso.18013.5.1", "age_over_18"]]
    );
    assert_eq!(candidate.capabilities[0].system, "longfellow-libzk-v1");
}
