//! Runs the real `matcher.wasm` under the test host.
//!
//! This is the test that could not exist before: in production the only
//! implementation of this ABI is Play Services, so a matcher was only
//! observable by installing it on a phone. Here the shipping binary — the same
//! bytes a wallet registers — is exercised in ordinary `cargo test`, against
//! blobs built with the encoder a wallet actually uses.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use siros_dc_matcher_core::db::{Claim, Credential, CredentialDatabase};
use siros_dc_matcher_core::profile::{Capability, MatchProfile, ZK_CAPABILITY};
use siros_dc_matcher_testhost::{run, Captured, Invocation};

/// Build (if needed) and load the matcher binary under test.
///
/// Builds on demand rather than assuming a prior `cargo build`, so a bare
/// `cargo test` in a fresh checkout exercises the real artifact instead of
/// quietly skipping. Cached per test binary — every test needs the module, and
/// spawning Cargo once per test costs seconds even when the build is a no-op.
fn matcher_wasm() -> &'static [u8] {
    static WASM: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    WASM.get_or_init(build_matcher_wasm)
}

fn build_matcher_wasm() -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let wasm = root.join("target/wasm32-wasip1/release/matcher.wasm");

    let out = Command::new(env!("CARGO"))
        .current_dir(&root)
        .args([
            "build",
            "-p",
            "siros-dc-matcher-wasm",
            "--target",
            "wasm32-wasip1",
            "--release",
        ])
        .output()
        .expect("running cargo build for the wasm target");
    assert!(
        out.status.success(),
        "could not build matcher.wasm — is the wasm32-wasip1 target installed?\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::read(&wasm).unwrap_or_else(|e| panic!("reading {}: {e}", wasm.display()))
}

/// A wallet holding one mdoc driving licence, optionally able to prove in ZK.
fn wallet(zk: Option<Capability>) -> CredentialDatabase {
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
        claims: vec![Claim {
            path: vec!["org.iso.18013.5.1".into(), "age_over_18".into()],
            value: "true".into(),
            display: "Over 18".into(),
            display_value: Some("Yes".into()),
        }],
    });
    db
}

fn longfellow(num_attributes: &str) -> Capability {
    Capability {
        system: "longfellow-libzk-v1".into(),
        params: BTreeMap::from([("num_attributes".to_string(), num_attributes.to_string())]),
    }
}

fn request(format: &str, meta: Value) -> Vec<u8> {
    json!({"requests": [{
        "protocol": "openid4vp-v1-signed",
        "data": {"dcql_query": {"credentials": [{
            "id": "q1",
            "format": format,
            "meta": meta,
            "claims": [{"path": ["org.iso.18013.5.1", "age_over_18"]}]
        }]}}
    }]})
    .to_string()
    .into_bytes()
}

fn invoke(db: &CredentialDatabase, request: Vec<u8>) -> Captured {
    run(
        matcher_wasm(),
        Invocation {
            request,
            credentials: db.to_cbor().expect("encoding blob"),
            calling_package: "com.android.chrome".into(),
            origin: "https://verifier.example.org".into(),
            wasm_version: 2,
        },
    )
    .expect("matcher ran")
}

/// An ordinary mdoc request produces a real entry for the credential that
/// matched — not a placeholder.
#[test]
fn a_matching_credential_is_offered() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        request(
            "mso_mdoc",
            json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
        ),
    );

    let entry = captured.entry("siros", 0).expect("one entry");
    assert_eq!(entry.credential_id, "mdl-1");
    assert_eq!(entry.title, "Driving Licence");
    assert_eq!(entry.subtitle, "Transportstyrelsen");

    // Only the claim this match discloses, shown by its display name and
    // display value.
    assert_eq!(
        entry.fields,
        vec![("Over 18".to_string(), "Yes".to_string())]
    );
}

/// The whole point: through the real binary, a `mso_mdoc_zk` request reaches
/// an ordinary stored mdoc — which the stock matcher will not do.
#[test]
fn a_zk_request_reaches_a_plain_mdoc_end_to_end() {
    let db = wallet(Some(longfellow("4")));
    let captured = invoke(
        &db,
        request(
            "mso_mdoc_zk",
            json!({
                "doctype_value": "org.iso.18013.5.1.mDL",
                "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1", "num_attributes": "4"}]
            }),
        ),
    );

    let entry = captured
        .entry("siros", 0)
        .expect("the ZK request should match");
    assert_eq!(entry.credential_id, "mdl-1");
}

/// And the honesty check: a circuit this wallet does not have produces no
/// entry, rather than one that fails after the user consents.
#[test]
fn a_zk_request_for_a_circuit_we_lack_offers_nothing() {
    let db = wallet(Some(longfellow("4")));
    let captured = invoke(
        &db,
        request(
            "mso_mdoc_zk",
            json!({
                "doctype_value": "org.iso.18013.5.1.mDL",
                "zk_system_type": [{"id": "1", "system": "longfellow-libzk-v1", "num_attributes": "10"}]
            }),
        ),
    );
    assert!(captured.is_empty());
}

/// Metadata carries the decision forward, so the wallet does not re-derive it
/// from a request it would have to parse again.
#[test]
fn metadata_carries_the_matchers_decision() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        request(
            "mso_mdoc",
            json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
        ),
    );

    let entry = captured.entry("siros", 0).expect("one entry");
    let meta: Value = serde_json::from_str(&entry.metadata).expect("metadata is JSON");
    assert_eq!(meta["query_id"], "q1");
    assert_eq!(meta["credential_id"], "mdl-1");
    assert_eq!(meta["protocol"], "openid4vp-v1-signed");
    // The platform-attested caller, so the wallet can check it was shown the
    // same one the matcher was.
    assert_eq!(meta["verified_origin"], "https://verifier.example.org");
    assert_eq!(meta["claims"][0][0], "org.iso.18013.5.1");
    assert_eq!(meta["claims"][0][1], "age_over_18");
}

/// A credential lacking a requested claim must not be offered (§6.4.1).
#[test]
fn a_credential_missing_the_requested_claim_is_not_offered() {
    let mut db = wallet(None);
    db.credentials[0].claims.clear();
    let captured = invoke(
        &db,
        request(
            "mso_mdoc",
            json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
        ),
    );
    assert!(captured.is_empty());
}

/// An unrecognised protocol produces nothing, and must not trap.
#[test]
fn unknown_protocol_emits_nothing() {
    let db = wallet(None);
    let captured = invoke(
        &db,
        json!({"requests": [{"protocol": "some-future-thing", "data": {}}]})
            .to_string()
            .into_bytes(),
    );
    assert!(captured.is_empty());
}

/// Malformed input reaches the matcher in the field — a truncated blob, a
/// request shape nobody anticipated. None of it may trap, because a trap emits
/// no entries and is indistinguishable from having no matching credential.
#[test]
fn malformed_input_does_not_trap() {
    let db = wallet(None);
    let good_blob = db.to_cbor().expect("encoding");

    for request in [
        &b""[..],
        b"not json",
        br#"{"requests":[]}"#,
        br#"{"requests":"not an array"}"#,
        br#"{"unexpected":"shape"}"#,
        br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{}}]}"#,
        br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{"dcql_query":42}}]}"#,
    ] {
        let captured = run(
            matcher_wasm(),
            Invocation {
                request: request.to_vec(),
                credentials: good_blob.clone(),
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("matcher trapped on {request:?}: {e:#}"));
        assert!(captured.is_empty());
    }

    // And a blob that is not a blob.
    for blob in [&b""[..], b"\xff\xff\xff", &[0xA1; 64]] {
        run(
            matcher_wasm(),
            Invocation {
                request: request("mso_mdoc", json!({})),
                credentials: blob.to_vec(),
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("matcher trapped on blob {blob:?}: {e:#}"));
    }
}

/// An empty wallet is the ordinary state of a fresh install, not an error.
#[test]
fn an_empty_wallet_offers_nothing() {
    let db = CredentialDatabase::new(MatchProfile::siros_default());
    let captured = invoke(&db, request("mso_mdoc", json!({})));
    assert!(captured.is_empty());
}
