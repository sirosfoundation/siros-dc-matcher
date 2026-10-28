//! Runs the real `matcher.wasm` under the test host.
//!
//! In production the only implementation of this ABI is Play Services, so a matcher was only
//! observable by installing it on a phone and driving a real verifier. Here the shipping binary —
//! the same bytes a wallet registers — runs in ordinary `cargo test`, over registrations the
//! wallet's own writer makes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;

use serde_json::json;
use siros_picker_testhost::{run, Invocation};

mod bytes_read;
mod corpus;
mod differential;
mod families;
mod key_free;
mod paso;
mod sides;

/// Build (if needed) and load the matcher binary under test: the artifact `make matcher`
/// writes, stripped and optimized as it ships.
///
/// Builds on demand rather than assuming a prior `make matcher`, so a bare
/// `cargo test` in a fresh checkout exercises the real artifact instead of
/// quietly skipping. Cached per test binary — every test needs the module, and
/// spawning the build once per test costs seconds even when it is a no-op.
pub fn matcher_wasm() -> &'static [u8] {
    static WASM: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    WASM.get_or_init(build_matcher_wasm)
}

fn build_matcher_wasm() -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let wasm = root.join("target/wasm32-wasip1/wasm-release/matcher.wasm");

    let out = Command::new("make")
        .current_dir(&root)
        // The parent's compiler flags must not reach this build. Under
        // `cargo llvm-cov` they carry `-C instrument-coverage`, which
        // wasm32-wasip1 has no profiler runtime for, so the nested build fails
        // and every test here reports the target as missing.
        //
        // Clearing them is also the more correct thing independently of
        // coverage: these tests exist to run the artifact that ships, and an
        // instrumented build is a different binary — different size, different
        // code paths around the profiling hooks.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTDOCFLAGS")
        .env_remove("CARGO_ENCODED_RUSTDOCFLAGS")
        .arg("matcher")
        .output()
        .expect("running make matcher");
    assert!(
        out.status.success(),
        "could not build matcher.wasm — are the wasm32-wasip1 target and `make wasm-opt` installed?\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    std::fs::read(&wasm).unwrap_or_else(|e| panic!("reading {}: {e}", wasm.display()))
}

/// Malformed input reaches the matcher in the field — a truncated registration, a request shape
/// nobody anticipated, a host level without sets. None of it may trap, because a trap emits no
/// entries and is indistinguishable from having no matching credential.
#[test]
fn malformed_input_does_not_trap() {
    let wallet = siros_presentation::testing::wallet::Wallet::new(Vec::new());
    let registration = sides::registration(&wallet, &[]);
    let request = json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {
        "dcql_query": {"credentials": [{"id": "q1", "format": "mso_mdoc",
            "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}]}}}]})
    .to_string()
    .into_bytes();
    let blobs: [&[u8]; 4] = [b"", b"\xff\xff\xff", &[0xA1; 64], &registration];
    for blob in blobs {
        for level in [0, 1, 2, 7] {
            let captured = run(
                matcher_wasm(),
                Invocation {
                    request: request.clone(),
                    credentials: blob.to_vec(),
                    wasm_version: level,
                    ..Default::default()
                },
            )
            .unwrap_or_else(|e| panic!("matcher trapped on blob {blob:?} at {level}: {e:#}"));
            assert!(captured.is_empty());
        }
    }
}

/// The host drops an entry without an image: an entry carries the icon the wallet registered
/// for its credential as raw bytes, NUL included, and the wallet's default icon without one.
#[test]
fn every_entry_carries_an_image() {
    use siros_presentation::testing::wallet::{mdoc, Held, Wallet, MDL, MDL_NS};
    use siros_registration::CredentialIcon;

    let item = [("age_over_18", siros_codec::cbor::Value::Bool(true))];
    let wallet = Wallet::new(vec![
        Held::new(1, "mso_mdoc", mdoc(MDL, MDL_NS, &item)),
        Held::new(2, "mso_mdoc", mdoc(MDL, MDL_NS, &item)),
    ]);
    let icons = [CredentialIcon {
        credential: siros_wallet_state::CredentialId::new(1),
        icon: sides::icon(120, 80),
    }];
    let request = json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {
        "response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1",
        "dcql_query": {"credentials": [{"id": "q1", "format": "mso_mdoc",
            "meta": {"doctype_value": MDL}, "claims": [{"path": [MDL_NS, "age_over_18"]}]}]}}}]})
    .to_string()
    .into_bytes();
    let captured = sides::picker_run(&request, sides::registration(&wallet, &icons), 7);
    let icon = |credential: &str| {
        let entry = captured
            .entries
            .iter()
            .find(|entry| entry.credential_id == credential)
            .unwrap();
        entry.icon.clone()
    };
    assert_eq!(icon("1"), sides::png(120, 80));
    assert_eq!(icon("2"), sides::png(64, 64), "the wallet's default icon");
}
