//! Runs the real `matcher.wasm` under the test host.
//!
//! This is the test that could not exist before: in production the only
//! implementation of this ABI is Play Services, so a matcher was only
//! observable by installing it on a phone. Here the shipping binary — the same
//! bytes a wallet registers — is exercised in ordinary `cargo test`, against
//! blobs built with the encoder a wallet actually uses.

use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};
use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::fixtures;
use siros_dc_matcher_core::profile::{Capability, MatchProfile};
use siros_dc_matcher_testhost::{run, Captured, CapturedEntry, Invocation};

/// The matcher's own JSON: `data` in the standard metadata object.
fn data(entry: &CapturedEntry) -> Value {
    let object: Value = serde_json::from_str(&entry.metadata).expect("metadata is JSON");
    object["data"].clone()
}

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
    let wasm = root.join("target/wasm32-wasip1/wasm-release/matcher.wasm");

    let out = Command::new(env!("CARGO"))
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
        .args([
            "build",
            "-p",
            "siros-dc-matcher-wasm",
            "--target",
            "wasm32-wasip1",
            "--profile",
            "wasm-release",
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
    fixtures::wallet(zk.into_iter().collect())
}

fn longfellow(num_attributes: &str) -> Capability {
    fixtures::longfellow(Some(num_attributes))
}

/// An unsigned request: the request object is `data` itself.
///
/// Labelled `-unsigned` because that is the shape it sends. It used to say
/// `-signed` while sending this, which was accepted only because the protocol
/// id selected a parser and nothing else — the thing the shape check now
/// prevents. The genuinely signed shapes are exercised further down.
fn request(format: &str, meta: Value) -> Vec<u8> {
    json!({"requests": [{
        "protocol": "openid4vp-v1-unsigned",
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

mod offers;
mod purpose;
mod signed_requests;
mod zkp_req;
