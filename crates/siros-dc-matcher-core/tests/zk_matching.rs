//! The `mso_mdoc_zk` path — the reason this project exists.
//!
//! Google's matcher understands `mso_mdoc` and `dc+sd-jwt`, so a verifier
//! asking for `mso_mdoc_zk` gets no entry and the wallet is never offered.
//! These tests pin the behaviour that fixes it, and the behaviour that keeps
//! the fix honest: an entry is offered only when this wallet can actually
//! produce the proof that was asked for.

use std::collections::BTreeMap;

use serde_json::json;
use siros_dc_matcher_core::db::{Claim, Credential, CredentialDatabase};
use siros_dc_matcher_core::evaluator::{credentials, ProfilePolicy};
use siros_dc_matcher_core::fixtures;
use siros_dc_matcher_core::profile::Capability;
use siros_dcql::{execute, DcqlQuery};

/// A wallet holding one ordinary mdoc driving licence.
fn wallet(zk_systems: Vec<Capability>) -> CredentialDatabase {
    fixtures::wallet(zk_systems)
}

fn longfellow(num_attributes: &str) -> Capability {
    Capability {
        system: "longfellow-libzk-v1".into(),
        params: BTreeMap::from([
            ("num_attributes".to_string(), num_attributes.to_string()),
            ("version".to_string(), "3".to_string()),
        ]),
    }
}

/// A ZK request, as a verifier actually sends it. Note the shape of
/// `zk_system_type`: `id` and `system`, then parameters as sibling keys.
fn zk_query(zk_system_type: serde_json::Value) -> DcqlQuery {
    serde_json::from_value(json!({
        "credentials": [{
            "id": "zk",
            "format": "mso_mdoc_zk",
            "meta": {
                "doctype_value": "org.iso.18013.5.1.mDL",
                "zk_system_type": zk_system_type
            },
            "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
        }]
    }))
    .expect("valid DCQL")
}

fn matches(db: &CredentialDatabase, query: &DcqlQuery) -> Vec<String> {
    let creds = credentials(db);
    let policy = ProfilePolicy::new(&db.profile);
    execute(query, &creds, &policy)
        .query("zk")
        .map(|m| {
            m.candidates
                .iter()
                .map(|c| c.credential_id.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The headline: a ZK request matches an ordinary stored mdoc, which the
/// stock matcher will not do.
#[test]
fn zk_request_matches_a_plain_mdoc_when_the_wallet_can_prove_it() {
    let db = wallet(vec![longfellow("4")]);
    let q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4", "version": "3"
    }]));
    assert_eq!(matches(&db, &q), ["mdl-1"]);
}

/// Without a declared capability there is nothing to satisfy the requirement,
/// so nothing is offered. Correct for a wallet that cannot produce the proof.
#[test]
fn zk_request_matches_nothing_when_no_system_is_declared() {
    let db = wallet(vec![]);
    let q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"
    }]));
    assert!(matches(&db, &q).is_empty());
}

/// The bug this check exists to prevent.
///
/// A ZK circuit is built for a fixed attribute count, so the right system with
/// the wrong `num_attributes` is a proof this wallet cannot produce. Ignoring
/// the parameter offers an entry that walks the user through consent and then
/// fails during proof generation — which is exactly how this surfaced the
/// first time, as MDOC_VERIFIER_HASH_PARSING_FAILURE.
#[test]
fn a_circuit_we_do_not_have_is_not_offered() {
    let db = wallet(vec![longfellow("4")]);
    let q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "10", "version": "3"
    }]));
    assert!(
        matches(&db, &q).is_empty(),
        "num_attributes=10 against a 4-attribute circuit must not match"
    );
}

/// Parameters are sibling keys of `id`/`system`, not a nested `params` object.
///
/// The load-bearing half: a real request whose parameter contradicts what this
/// wallet declared must not match. A parser that looked for a nested `params`
/// object would read no parameters at all here — `id` and `system` still parse,
/// so it would fail silently — and then match a circuit the wallet lacks.
#[test]
fn a_sibling_parameter_is_read_and_a_nested_one_is_not() {
    let db = wallet(vec![longfellow("4")]);

    let real = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "99"
    }]));
    assert!(
        matches(&db, &real).is_empty(),
        "a sibling num_attributes must be read and must not match"
    );

    // Nested under `params`, which is not the wire format. `num_attributes` is
    // therefore not requested at all, and the wallet's declared value is not
    // contradicted — so this matches, on the system alone. That is the same
    // rule as any other undeclared parameter: constraints come from what both
    // sides actually name.
    let nested = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "params": {"num_attributes": "99"}
    }]));
    assert_eq!(
        matches(&db, &nested),
        ["mdl-1"],
        "a shape outside the wire format constrains nothing"
    );
}

/// A wallet that declares only the system — a *nominal* capability — is not
/// constrained by parameters it never claimed. Some proof systems work this
/// way: they support any attribute count for a system they implement and check
/// whether the specific circuit is fetchable only at proof time. Requiring them
/// to enumerate circuits up front would reject requests they can satisfy.
#[test]
fn a_nominal_capability_is_not_constrained_by_undeclared_parameters() {
    let db = wallet(vec![Capability {
        system: "longfellow-libzk-v1".into(),
        params: BTreeMap::new(),
    }]);

    for count in ["1", "4", "10", "99"] {
        let q = zk_query(json!([{
            "id": "1", "system": "longfellow-libzk-v1", "num_attributes": count
        }]));
        assert_eq!(
            matches(&db, &q),
            ["mdl-1"],
            "num_attributes={count} should match"
        );
    }

    // The system itself is still checked.
    let other = zk_query(json!([{"id": "1", "system": "some-other-system"}]));
    assert!(matches(&db, &other).is_empty());
}

/// Verifier preference order: the first entry the wallet can satisfy wins.
#[test]
fn the_first_satisfiable_system_is_chosen() {
    let db = wallet(vec![longfellow("4")]);
    let q = zk_query(json!([
        {"id": "1", "system": "some-future-zk-system", "num_attributes": "4"},
        {"id": "2", "system": "longfellow-libzk-v1", "num_attributes": "4", "version": "3"}
    ]));
    assert_eq!(matches(&db, &q), ["mdl-1"]);
}

/// A parameter the verifier does not mention is not a constraint.
#[test]
fn unmentioned_parameters_do_not_constrain() {
    let db = wallet(vec![longfellow("4")]);
    let q = zk_query(json!([{"id": "1", "system": "longfellow-libzk-v1"}]));
    assert_eq!(matches(&db, &q), ["mdl-1"]);
}

/// Verifiers write `num_attributes` as a number in some requests and a string
/// in others. Both name the same circuit, and rejecting one would turn a
/// wallet that can satisfy the request into one that appears not to.
#[test]
fn a_numeric_parameter_matches_its_string_form() {
    let db = wallet(vec![longfellow("4")]);
    let q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": 4
    }]));
    assert_eq!(matches(&db, &q), ["mdl-1"]);
}

/// The ZK rule maps onto mdoc storage only. It must not start matching
/// SD-JWTs because they happen to be present.
#[test]
fn the_zk_rule_does_not_reach_other_stored_formats() {
    let mut db = wallet(vec![longfellow("4")]);
    db.credentials.push(Credential {
        id: "pid-1".into(),
        format: "dc+sd-jwt".into(),
        doctype: None,
        vct: Some("urn:eudi:pid:1".into()),
        title: "PID".into(),
        subtitle: "issuer".into(),
        icon: None,
        claims: vec![Claim {
            path: vec!["org.iso.18013.5.1".into(), "age_over_18".into()],
            value: "true".into(),
            display: "Over 18".into(),
            display_value: None,
        }],
    });

    let q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"
    }]));
    assert_eq!(matches(&db, &q), ["mdl-1"], "only the mdoc may satisfy it");
}

/// `ppid_context` is carried to the wallet, not used for matching: a
/// pseudonym context changes what is produced, not which credential can
/// produce it.
#[test]
fn ppid_context_does_not_affect_matching() {
    let db = wallet(vec![longfellow("4")]);
    let mut q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"
    }]));
    q.credentials[0]
        .meta
        .insert("ppid_context".into(), json!("https://rp.example/ctx"));
    assert_eq!(matches(&db, &q), ["mdl-1"]);
}

/// An ordinary mdoc request still works — the ZK rule is an addition, not a
/// replacement.
#[test]
fn a_plain_mdoc_request_is_unaffected() {
    let db = wallet(vec![]);
    let q: DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "zk",
            "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{"path": ["org.iso.18013.5.1", "family_name"]}]
        }]
    }))
    .expect("valid DCQL");
    assert_eq!(matches(&db, &q), ["mdl-1"]);
}

/// A doctype the wallet does not hold must not match, ZK or otherwise.
#[test]
fn a_different_doctype_does_not_match() {
    let db = wallet(vec![longfellow("4")]);
    let mut q = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"
    }]));
    q.credentials[0]
        .meta
        .insert("doctype_value".into(), json!("org.iso.23220.photoid.1"));
    assert!(matches(&db, &q).is_empty());
}

// ---------------------------------------------------------------------------
// What actually signals a ZK presentation
// ---------------------------------------------------------------------------

/// `zk_system_type` on an ordinary `mso_mdoc` query is a ZK request.
///
/// The `mso_mdoc_zk` format says the same thing and is expected to be retired,
/// so a verifier may well ask this way. Keying the capability check on the
/// format would miss it: the wallet would be offered and would then produce a
/// plain presentation for a verifier expecting a proof.
#[test]
fn zk_system_type_on_a_plain_mdoc_query_is_a_zk_request() {
    let capable = wallet(vec![longfellow("4")]);
    let q = plain_mdoc_query_with(json!({
        "doctype_value": "org.iso.18013.5.1.mDL",
        "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"}]
    }));
    assert_eq!(matches(&capable, &q), ["mdl-1"]);
}

/// And the gate bites: a wallet that cannot produce the named proof is not
/// offered, even though the format alone would have matched.
#[test]
fn a_plain_mdoc_query_naming_a_system_we_lack_is_not_offered() {
    let incapable = wallet(vec![]);
    let q = plain_mdoc_query_with(json!({
        "doctype_value": "org.iso.18013.5.1.mDL",
        "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1"}]
    }));
    assert!(
        matches(&incapable, &q).is_empty(),
        "the verifier asked for a proof this wallet cannot produce"
    );

    // The same wallet still answers the same query without the ZK signal.
    let plain = plain_mdoc_query_with(json!({"doctype_value": "org.iso.18013.5.1.mDL"}));
    assert_eq!(matches(&incapable, &plain), ["mdl-1"]);
}

/// The retired-but-still-sent format keeps working, and keeps requiring a
/// system: naming `mso_mdoc_zk` with no `zk_system_type` asks for a proof
/// without saying which, and must not be answered with a plain presentation.
#[test]
fn the_zk_format_still_matches_and_still_needs_a_named_system() {
    let capable = wallet(vec![longfellow("4")]);

    let named = zk_query(json!([{
        "id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"
    }]));
    assert_eq!(matches(&capable, &named), ["mdl-1"]);

    let unnamed: DcqlQuery = serde_json::from_value(json!({
        "credentials": [{
            "id": "zk",
            "format": "mso_mdoc_zk",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"},
            "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
        }]
    }))
    .expect("valid DCQL");
    assert!(
        matches(&capable, &unnamed).is_empty(),
        "a ZK format with no named system must not fall back to a plain presentation"
    );
}

/// A query in the plain `mso_mdoc` format, carrying whatever `meta` a test
/// needs. Used both with and without the ZK signal, since the point is that
/// the format is the same either way and only `meta` differs.
fn plain_mdoc_query_with(meta: serde_json::Value) -> DcqlQuery {
    serde_json::from_value(json!({
        "credentials": [{
            "id": "zk",
            "format": "mso_mdoc",
            "meta": meta,
            "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
        }]
    }))
    .expect("valid DCQL")
}
