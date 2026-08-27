//! The matcher binary.
//!
//! Runs inside the Android credential picker: no network, no filesystem, and a
//! hard time budget. It reads the verifier's request and the credential blob
//! this wallet registered, decides which credentials to offer, and emits picker
//! entries.
//!
//! # A trap is a silent failure
//!
//! If this binary panics, the picker shows no entries — which the user cannot
//! tell apart from "you have no matching credential". There is no error
//! surface at all. That is why `unwrap` and `expect` are denied below rather
//! than merely discouraged, and why the release profile aborts instead of
//! unwinding.
//!
//! # Status
//!
//! Phase 2: the swap is real end to end and the registered blob is decoded,
//! but the matching is not. This emits a single fixed entry for any request
//! whose protocol it recognises, reporting what it read. DCQL evaluation
//! arrives in Phase 3 and the profile evaluator in Phase 4 — see
//! `docs/plan.md`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]

mod abi;

use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::sink::Entry;

/// Protocols this matcher answers to.
///
/// Recognised here rather than in the profile because Phase 1 has no profile
/// yet; Phase 4 moves this list into the registered blob, where adding one
/// costs a re-registration instead of a release.
const PROTOCOLS: [&str; 4] = [
    "openid4vp-v1-unsigned",
    "openid4vp-v1-signed",
    "openid4vp-v1-multisigned",
    "org.iso.mdoc",
];

/// The set every Phase 1 entry belongs to. One set, one entry.
const SET_ID: &str = "siros-phase1";

fn main() {
    let request = abi::request_bytes();
    let Some(protocol) = first_known_protocol(&request) else {
        // Emitting nothing is correct: an unrecognised protocol means we have
        // nothing to offer, which is what "no entries" tells the picker.
        return;
    };

    // Phase 1 exists to prove the plumbing, so read every input the real
    // matcher will depend on and report what came back. On a device this turns
    // "an entry appeared" into evidence about each leg separately: whether the
    // registered blob survived the round-trip, and whether the platform's
    // verified caller reaches the sandbox.
    let (package, origin) = abi::calling_app_info();
    let blob = abi::credentials_bytes();
    let credentials_len = blob.len();

    // Decoding the registered blob is the first thing the real matcher does,
    // so it is worth exercising now rather than at the same time as DCQL. A
    // failure here is reported through the entry instead of being swallowed:
    // "the wallet registered a blob this matcher cannot read" and "the wallet
    // has no matching credential" look identical in the picker, and only one
    // of them is a bug.
    let (blob_status, credential_count) = match CredentialDatabase::from_cbor(&blob) {
        Ok(db) => ("ok".to_string(), Some(db.credentials.len())),
        Err(e) => (e.to_string(), None),
    };

    // Metadata survives the picker round-trip, so it is where the wallet reads
    // back what this matcher decided. Phase 5 fills it with the matched query
    // id and chosen capability.
    let metadata = serde_json::json!({
        "matcher": "siros-dc-matcher",
        "phase": 1,
        "protocol": protocol,
        "host_abi": abi::wasm_version(),
        "calling_package": package,
        // Empty for a native caller; a real origin only when a browser is
        // acting for a page. This is the platform's own attestation — the only
        // trustworthy statement of who is asking.
        "verified_origin": origin,
        "credentials_bytes": credentials_len,
        "blob_status": blob_status,
        "credential_count": credential_count,
    })
    .to_string();

    abi::emit::entry_set(SET_ID, 1);
    abi::emit::entry(
        SET_ID,
        0,
        &Entry {
            credential_id: "siros-phase1-placeholder",
            title: "SIROS test credential",
            subtitle: "Emitted by siros-dc-matcher",
            metadata: &metadata,
        },
    );
    abi::emit::field(SET_ID, 0, "Matcher", "siros-dc-matcher (phase 1)");
    // Surfaced in the picker itself, not just in metadata: on a device the
    // metadata is only readable once the entry has been selected, and a blob
    // that failed to register is exactly the case where nobody gets that far.
    abi::emit::field(
        SET_ID,
        0,
        "Registered blob",
        &match credential_count {
            Some(n) => format!("{credentials_len} bytes, {n} credentials"),
            None => format!("{credentials_len} bytes, unreadable"),
        },
    );
}

/// The first protocol in the request that this matcher recognises.
///
/// The request is shaped `{"requests":[{"protocol":…,"data":…}]}` — a list,
/// because one DC API call can offer the same request under several protocols
/// and let the wallet pick. Taking the first *recognised* one rather than the
/// first one is what makes that negotiation work.
fn first_known_protocol(request: &[u8]) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_slice(request).ok()?;
    parsed
        .get("requests")?
        .as_array()?
        .iter()
        .filter_map(|r| r.get("protocol")?.as_str())
        .find(|p| PROTOCOLS.contains(p))
        .map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::first_known_protocol;

    #[test]
    fn finds_a_known_protocol() {
        let r = br#"{"requests":[{"protocol":"openid4vp-v1-signed","data":{}}]}"#;
        assert_eq!(
            first_known_protocol(r).as_deref(),
            Some("openid4vp-v1-signed")
        );
    }

    /// An unknown protocol earlier in the list must not mask a known one after
    /// it — that is the whole point of the request being a list.
    #[test]
    fn skips_unknown_protocols_to_find_a_known_one() {
        let r = br#"{"requests":[{"protocol":"some-future-thing"},
                                 {"protocol":"org.iso.mdoc"}]}"#;
        assert_eq!(first_known_protocol(r).as_deref(), Some("org.iso.mdoc"));
    }

    #[test]
    fn returns_none_when_nothing_is_recognised() {
        let r = br#"{"requests":[{"protocol":"some-future-thing"}]}"#;
        assert_eq!(first_known_protocol(r), None);
    }

    /// Malformed input must return None, never trap. A trap emits no entries,
    /// which is indistinguishable from having no matching credential.
    #[test]
    fn malformed_input_does_not_trap() {
        assert_eq!(first_known_protocol(b"not json at all"), None);
        assert_eq!(first_known_protocol(b""), None);
        assert_eq!(
            first_known_protocol(br#"{"requests":"not an array"}"#),
            None
        );
        assert_eq!(
            first_known_protocol(br#"{"requests":[{"no":"protocol"}]}"#),
            None
        );
        assert_eq!(
            first_known_protocol(br#"{"requests":[{"protocol":42}]}"#),
            None
        );
    }
}
