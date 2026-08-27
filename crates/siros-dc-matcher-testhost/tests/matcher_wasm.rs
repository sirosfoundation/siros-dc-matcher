//! Runs the real `matcher.wasm` under the test host.
//!
//! This is the test that could not exist before: in production the only
//! implementation of this ABI is Play Services, so a matcher was only
//! observable by installing it on a phone. Here the shipping binary — the same
//! bytes a wallet registers — is exercised in ordinary `cargo test`.

use siros_dc_matcher_testhost::{run, Invocation};
use std::path::PathBuf;
use std::process::Command;

/// Build (if needed) and load the matcher binary under test.
///
/// Builds on demand rather than assuming a prior `cargo build`, so that a bare
/// `cargo test` in a fresh checkout exercises the real artifact instead of
/// quietly skipping.
fn matcher_wasm() -> Vec<u8> {
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

fn openid4vp_request() -> Vec<u8> {
    br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{"dcql_query":{"credentials":[]}}}]}"#
        .to_vec()
}

/// The whole point of Phase 1: our own binary, loaded by a host that
/// implements the real ABI, puts an entry in front of the user.
#[test]
fn emits_an_entry_for_a_known_protocol() {
    let captured = run(
        &matcher_wasm(),
        Invocation {
            request: openid4vp_request(),
            credentials: vec![0xA1, 0x00, 0x01],
            calling_package: "com.android.chrome".into(),
            origin: "https://verifier.example.org".into(),
            wasm_version: 2,
        },
    )
    .expect("matcher ran");

    assert_eq!(captured.sets, vec![("siros-phase1".to_string(), 1)]);
    let entry = captured
        .entry("siros-phase1", 0)
        .expect("one entry emitted");
    assert_eq!(entry.credential_id, "siros-phase1-placeholder");
    assert_eq!(entry.title, "SIROS test credential");
}

/// Every input leg is reported back, so a hardware run says which part worked
/// rather than only that something did.
#[test]
fn reports_what_it_observed_through_the_abi() {
    let captured = run(
        &matcher_wasm(),
        Invocation {
            request: openid4vp_request(),
            credentials: vec![7; 42],
            calling_package: "com.android.chrome".into(),
            origin: "https://verifier.example.org".into(),
            wasm_version: 3,
        },
    )
    .expect("matcher ran");

    let entry = captured
        .entry("siros-phase1", 0)
        .expect("one entry emitted");
    let meta: serde_json::Value = serde_json::from_str(&entry.metadata).expect("metadata is JSON");

    assert_eq!(meta["protocol"], "openid4vp-v1-signed");
    assert_eq!(meta["host_abi"], 3);
    assert_eq!(meta["calling_package"], "com.android.chrome");
    assert_eq!(meta["verified_origin"], "https://verifier.example.org");
    // Proves the registered blob survived the round-trip into the sandbox.
    assert_eq!(meta["credentials_bytes"], 42);
    assert!(entry
        .fields
        .contains(&("Registered blob".into(), "42 bytes".into())));
}

/// An unrecognised protocol must produce nothing — and must not trap, which
/// would look identical to the user but hide a real fault.
#[test]
fn unknown_protocol_emits_nothing() {
    let captured = run(
        &matcher_wasm(),
        Invocation {
            request: br#"{"requests":[{"protocol":"some-future-thing","data":{}}]}"#.to_vec(),
            ..Default::default()
        },
    )
    .expect("matcher ran without trapping");

    assert!(captured.is_empty());
}

/// Malformed input reaches the matcher in the field — a truncated blob, a
/// request from a protocol version nobody anticipated. None of it may trap.
#[test]
fn malformed_input_does_not_trap() {
    for request in [
        &b""[..],
        b"not json",
        br#"{"requests":[]}"#,
        br#"{"requests":"not an array"}"#,
        br#"{"unexpected":"shape"}"#,
    ] {
        let captured = run(
            &matcher_wasm(),
            Invocation {
                request: request.to_vec(),
                credentials: vec![0xFF; 3],
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("matcher trapped on {request:?}: {e:#}"));
        assert!(captured.is_empty());
    }
}

/// An empty registered blob is the ordinary state of a freshly installed
/// wallet, not an error.
#[test]
fn empty_credential_blob_is_handled() {
    let captured = run(
        &matcher_wasm(),
        Invocation {
            request: openid4vp_request(),
            credentials: Vec::new(),
            ..Default::default()
        },
    )
    .expect("matcher ran");

    let entry = captured
        .entry("siros-phase1", 0)
        .expect("one entry emitted");
    let meta: serde_json::Value = serde_json::from_str(&entry.metadata).expect("metadata is JSON");
    assert_eq!(meta["credentials_bytes"], 0);
}
