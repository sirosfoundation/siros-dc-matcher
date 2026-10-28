//! The registration through `ReadCredentialsBuffer`: in short reads, and from a host that breaks
//! the read contract.

use std::num::NonZeroUsize;

use serde_json::json;
use siros_picker_testhost::{run, CredentialReads, Invocation};
use siros_presentation::testing::wallet::{mdoc, Held, Wallet, MDL, MDL_NS};

use crate::{matcher_wasm, sides};

/// An mDL request at level 7, over the registration of a wallet that holds one mDL.
fn mdl_invocation() -> Invocation {
    let item = [("age_over_18", siros_codec::cbor::Value::Bool(true))];
    let wallet = Wallet::new(vec![Held::new(1, "mso_mdoc", mdoc(MDL, MDL_NS, &item))]);
    let request = json!({"requests": [{"protocol": "openid4vp-v1-unsigned", "data": {
        "response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1",
        "dcql_query": {"credentials": [{"id": "q1", "format": "mso_mdoc",
            "meta": {"doctype_value": MDL}, "claims": [{"path": [MDL_NS, "age_over_18"]}]}]}}}]})
    .to_string()
    .into_bytes();
    Invocation {
        request,
        credentials: sides::registration(&wallet, &[]),
        wasm_version: 7,
        ..Default::default()
    }
}

/// The matcher reads the registration until it is complete, so a host that copies one byte
/// per call yields the output of a host that copies it whole.
#[test]
fn a_registration_delivered_in_short_reads_gives_the_output_of_a_whole_one() {
    let whole = run(matcher_wasm(), mdl_invocation()).expect("matcher ran");
    let one_byte_per_read = run(
        matcher_wasm(),
        Invocation {
            credential_reads: CredentialReads::Chunks(NonZeroUsize::MIN),
            ..mdl_invocation()
        },
    )
    .expect("matcher ran");
    assert!(!whole.is_empty(), "the comparison needs an entry");
    assert_eq!(one_byte_per_read, whole);
}

/// A host that reports more bytes than it was asked for, or copies none before the end of the
/// registration, breaks `ReadCredentialsBuffer`'s contract: the matcher traps with the panic
/// `android-credman` documents.
#[test]
fn a_host_that_breaks_the_read_contract_traps() {
    let size = mdl_invocation().credentials.len();
    for (credential_reads, panic) in [
        (
            CredentialReads::OverReport,
            format!(
                "host reported {} credential bytes for a {size}-byte buffer",
                size + 1
            ),
        ),
        (
            CredentialReads::Stall,
            format!("host stopped at credential byte 0 of {size}"),
        ),
    ] {
        let error = run(
            matcher_wasm(),
            Invocation {
                credential_reads,
                ..mdl_invocation()
            },
        )
        .expect_err("the matcher traps");
        assert_eq!(
            error.downcast_ref::<wasmtime::Trap>(),
            Some(&wasmtime::Trap::UnreachableCodeReached),
            "{credential_reads:?}: {error:#}"
        );
        assert!(
            format!("{error:#}").contains(&panic),
            "{credential_reads:?}: {error:#}"
        );
    }
}
