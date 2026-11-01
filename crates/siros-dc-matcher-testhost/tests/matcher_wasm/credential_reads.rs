//! The blob through `ReadCredentialsBuffer`: in short reads, and from a host
//! that breaks the read contract.

use std::num::NonZeroUsize;

use super::*;

fn mdl_request() -> Vec<u8> {
    request(
        "mso_mdoc",
        json!({"doctype_value": "org.iso.18013.5.1.mDL"}),
    )
}

/// The matcher reads the blob until it is complete, so a host that copies
/// one byte per call yields the output of a host that copies it whole.
#[test]
fn a_blob_delivered_in_short_reads_gives_the_output_of_a_whole_one() {
    let db = wallet(None);
    let whole = invoke(&db, mdl_request());
    let one_byte_per_read = run(
        matcher_wasm(),
        Invocation {
            credential_reads: CredentialReads::Chunks(NonZeroUsize::MIN),
            ..invocation(&db, mdl_request())
        },
    )
    .expect("matcher ran");
    assert!(!whole.is_empty(), "the comparison needs an entry");
    assert_eq!(one_byte_per_read, whole);
}

/// A host that reports more bytes than it was asked for, or copies none
/// before the end of the blob, breaks `ReadCredentialsBuffer`'s contract:
/// the matcher traps with the panic `android-credman` documents.
#[test]
fn a_host_that_breaks_the_read_contract_traps() {
    let db = wallet(None);
    let size = db.to_cbor().expect("encoding blob").len();
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
                ..invocation(&db, mdl_request())
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
