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
//! # Two host behaviours every emitter must respect
//!
//! An entry with no icon is dropped, and declaring one set id twice discards
//! everything — both silently. See [`Diagnostics`] for the full account.
//!
//! # The host
//!
//! Every host call goes through `android-credman`; its contract is
//! `crates/android-credman-sys/ABI.md`. The binary calls nothing above host
//! level 2.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]
// Off the wasm target there is no host, so the decision path is reached from
// the unit tests alone. The wasm build, which CI lints, keeps dead code an
// error.
#![cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]

mod picker;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod simple_allocator;

// The host calls `_start`, which `wasm32-unknown-unknown` has no CRT to
// export. The shipped build is `wasm32-wasip1` (see the Makefile); this
// target is the WASI-free alternative and builds on the pinned toolchain:
//
//     cargo build -p siros-dc-matcher-wasm --target wasm32-unknown-unknown \
//         --profile wasm-release
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    main();
}

use android_credman::{CallingAppError, SetSink};
use picker::{emit_set, Member};
use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, resolve, ProfilePolicy};
use siros_dcql::{execute, Satisfaction};
use siros_oid4vp::{diagnose, UnverifiedRequest};

/// Prefix for the per-entry set ids.
///
/// A set is a group of entries the picker selects *together*, so candidates
/// for the same query — which are alternatives the user chooses between — must
/// not share one. Each entry gets its own single-member set.
///
/// Real multi-credential sets arrive with DCQL `credential_sets` combinations
/// in Phase 5, where a set genuinely means "these, together".
const SET_PREFIX: &str = "siros";

/// How many combinations to offer at most.
///
/// The count is a product — three queries with four candidates each is
/// sixty-four — and a picker cannot use them all. The number dropped travels
/// in entry metadata rather than vanishing, because a list of options that
/// quietly omits some is one the user cannot reason about.
const MAX_COMBINATIONS: usize = 32;

#[cfg(target_arch = "wasm32")]
fn main() {
    let host = android_credman::Host::connect();
    // Every entry this matcher offers is in a set. A host below level 2 has
    // no sets, so it gets nothing, and the inputs are not read.
    let Some(mut sets) = host.entry_sets() else {
        return;
    };
    // Without both inputs there is nothing to offer, and no debug flag to
    // report the failure with.
    let (Ok(request), Ok(blob)) = (host.request(), host.credentials()) else {
        return;
    };
    let caller = host.calling_app();
    let input = Input {
        request: &request,
        blob: &blob,
        origin: caller
            .as_ref()
            .map(|app| app.origin().map_or("", android_credman::C8Str::as_str))
            .map_err(|error| *error),
    };
    run(&input, &mut sets);
}

/// Off the wasm target there is no host. The binary still builds there so
/// that its decision path is unit tested through [`run`].
#[cfg(not(target_arch = "wasm32"))]
fn main() {}

/// What the host hands one invocation.
struct Input<'a> {
    /// The DC API request JSON.
    request: &'a [u8],
    /// The blob this wallet registered.
    blob: &'a [u8],
    /// The caller's origin as the platform verified it, empty for an app;
    /// the error when the host's report could not be read.
    origin: Result<&'a str, CallingAppError>,
}

/// One matcher invocation, from the host's inputs to emitted entries.
///
/// Separate from [`main`] so it can be driven on the build machine in
/// tests, against a real request and the committed golden blob, with a
/// stand-in [`SetSink`].
fn run(input: &Input<'_>, sets: &mut impl SetSink) {
    let request = input.request;
    let Ok(db) = CredentialDatabase::from_cbor(input.blob) else {
        // Nothing can be offered from a blob we cannot read, and nothing can
        // be said about it either: the debug flag lives inside the blob. This
        // is indistinguishable from "no matching credential" in the picker —
        // the wallet-side registration is where such a failure has to be
        // caught, which is what the golden-vector test in core is for.
        return;
    };
    let diag = Diagnostics {
        enabled: db.profile.debug,
    };
    // Every entry carries the verified origin for the wallet to check, so a
    // caller the host reported unreadably leaves nothing to offer.
    let origin = match input.origin {
        Ok(origin) => origin,
        Err(error) => {
            diag.emit(sets, "caller", || error.to_string());
            return;
        }
    };

    // The whole request, not only the query: a `zkp_req` request is matched
    // against the verifier's `client_metadata` and has no typed DCQL form when
    // it uses the rulebook example's `claims` object. Nothing in it is
    // authenticated; the wallet runs intake at selection.
    let registered = |label: &str| db.profile.parser_for(label).is_some();
    let Some(unverified) = UnverifiedRequest::first_registered(request, &registered) else {
        diag.emit(sets, "request", || diagnose(request, &registered));
        return;
    };
    let protocol = unverified.protocol().label();
    let query = unverified.query();

    let held = credentials(&db);
    let policy = ProfilePolicy::new(&db.profile).with_client_metadata(unverified.client_metadata());
    let result = execute(query, &held, &policy);

    // "If the Wallet cannot deliver all non-optional Credentials requested by
    // the Verifier according to these rules, it MUST NOT return any
    // Credential(s)" — OpenID4VP 1.0 §6.4. Offering the half that matched
    // would be worse than offering nothing: the user consents to a
    // presentation that cannot satisfy the verifier.
    if result.satisfaction() == Satisfaction::Unsatisfiable {
        diag.emit(sets, "unsatisfiable", || {
            format!(
                "{protocol}: parsed {} cred queries, not satisfiable",
                query.credentials().len()
            )
        });
        return;
    }

    // A combination is what the picker offers as one selectable option: every
    // member is presented together and consented to as a unit. Alternatives
    // are separate combinations, and therefore separate sets.
    let enumerated = result.combinations(MAX_COMBINATIONS);
    if enumerated.combinations().is_empty() {
        diag.emit(sets, "zero", || {
            format!(
                "{protocol}: satisfiable but zero combinations ({} held)",
                held.len()
            )
        });
        return;
    }

    'combinations: for (index, combination) in enumerated.combinations().iter().enumerate() {
        // Resolve every member before declaring the set. Skipping one after
        // the fact would leave the declared length disagreeing with the
        // entries actually added, and a gap in the positions — which the host
        // is right to treat as a matcher bug. A combination we cannot fully
        // emit is not offered at all.
        let resolved: Option<Vec<_>> = combination
            .members()
            .iter()
            .map(|(query_id, candidate)| {
                db.credentials
                    .iter()
                    .find(|c| c.id == *candidate.credential_id())
                    .map(|credential| (query_id, candidate, credential))
            })
            .collect();
        let Some(resolved) = resolved else {
            continue;
        };

        let set_id = format!("{SET_PREFIX}-{index}");

        // Why the verifier says it wants this combination (§6.2). Computed
        // once per combination and shown on each of its entries: the purposes
        // belong to the credential sets the combination satisfies, and the
        // combination is what the user is consenting to as a unit, so every
        // card in it is being offered for those reasons.
        let purpose = siros_display::purpose::line(combination.purposes());

        let mut members = Vec::with_capacity(resolved.len());
        for (query_id, candidate, credential) in &resolved {
            // Resolved by core, which the FFI also calls: the wallet needs to
            // know which proof to produce, and deriving that in two places is
            // how the two would come to disagree.
            let resolved = query
                .credential(query_id)
                .map(|cq| resolve(&policy, cq, candidate));
            let capabilities = resolved
                .as_ref()
                .map(|r| r.capabilities.clone())
                .unwrap_or_default();
            let zk = resolved.as_ref().and_then(|r| r.zkp_req.as_ref());

            let data = serde_json::json!({
                "matcher": "siros-dc-matcher",
                "protocol": protocol,
                "query_id": query_id,
                "credential_id": credential.id,
                "capabilities": capabilities,
                "claims": resolved.as_ref().map(|r| r.claims.clone()).unwrap_or_default(),
                // For `zkp_req`: the chosen circuit and the planned
                // request, the latter derived from an unverified request
                // object. Absent for every other format.
                "zkp_req": zk.map(|z| z.to_json()),
                // The platform's own attestation of who is asking — the only
                // trustworthy statement of that, since anything naming an
                // origin inside the request body is the request describing
                // itself. The wallet is told it separately, so carrying it
                // lets the wallet check the matcher was shown the same caller.
                "verified_origin": origin,
                // How many further options existed. A picker showing the first
                // few of many is telling the user those are all they have.
                //
                // Still a plain number, and still true — it is a lower bound
                // when the product overflowed `usize`, not a wrapped value —
                // but a wallet cannot tell a count from a bound by looking, so
                // the second field says which this is.
                "combinations_dropped": enumerated.dropped().count(),
                "combinations_dropped_is_exact": enumerated.dropped().is_exact(),
            })
            .to_string();

            // A `zkp_req` match discloses no claims, so its rows describe
            // the proof being asked for instead, from the plan.
            let fields = match zk {
                Some(zk) => match siros_display::proof::rows(&zk.query, &zk.option) {
                    Ok(rows) => rows,
                    // The option names an item its query lacks: the combination
                    // has no rows to show, and is not offered.
                    Err(_) => continue 'combinations,
                },
                None => disclosed_fields(credential, candidate),
            };
            members.push(Member {
                credential_id: credential.id.as_str(),
                title: &credential.title,
                subtitle: &credential.subtitle,
                data,
                // A null icon costs the whole entry: the host drops it and
                // logs `Null icon for icon` in its own process, so a
                // credential registered without image bytes would silently
                // not exist in the picker. #19 gave the
                // diagnostic entries this fallback; a real entry needs it at
                // least as much, because a user is looking for that
                // credential. The `filter` covers a zero-length `IconRef`,
                // which yields `Some(&[])` and reaches the host as no image.
                icon: db
                    .icon_bytes(credential)
                    .filter(|bytes| !bytes.is_empty())
                    .unwrap_or(FALLBACK_ICON_PNG),
                disclaimer: purpose.as_deref(),
                fields,
            });
        }
        emit_set(sets, &set_id, &members);
    }
}

/// The display fields for the claims a match discloses, as
/// `(display name, display value)`.
///
/// Only the claims this match actually discloses. Showing every claim the
/// credential holds would misrepresent the request the user is being asked
/// to consent to.
fn disclosed_fields(
    credential: &siros_dc_matcher_core::db::Credential,
    candidate: &siros_dcql::Candidate,
) -> Vec<(String, String)> {
    candidate
        .claims()
        .iter()
        .filter_map(|claim| {
            credential.claims.iter().find(|c| {
                c.path.iter().map(String::as_str).eq(claim
                    .path()
                    .components()
                    .iter()
                    .filter_map(siros_dcql::PathComponent::as_key))
            })
        })
        .map(|stored| {
            let value = stored.display_value.as_deref().unwrap_or(&stored.value);
            (stored.display.clone(), value.to_owned())
        })
        .collect()
}

// ============================================================================
// Diagnostics
// ============================================================================

/// Why a request produced no entry, surfaced where it can actually be seen.
///
/// This binary has no logging channel: its only imports are `credman` and
/// `credman_v2`, neither of which exposes anything like a log call, and it
/// runs inside a sandboxed host process that no logcat filter on the wallet
/// side can look into. The picker UI is the one surface it has, so when the
/// wallet registered with `profile.debug` set, a request that matches nothing
/// gets exactly one entry naming the reason instead of silence.
///
/// Off by default, and the wallet must never enable it in production: an
/// end user cannot act on "not satisfiable", and selecting the entry hands
/// the wallet a credential id that does not exist. The wallet-side gate is
/// the app's own debuggable flag.
///
/// Two host behaviours shape this, both learned the hard way and neither
/// documented anywhere:
///
/// * An entry with no icon is silently dropped. The host logs
///   `WasmRuntime: Null icon for icon` in its own process and shows nothing.
///   Every diagnostic therefore carries [`FALLBACK_ICON_PNG`], and at the
///   same 64x64 as real entries — a 4x4 one was dropped just the same.
/// * Declaring the same set id twice in one invocation makes the host
///   discard the *whole* output, silently. Every path that emits a
///   diagnostic returns immediately afterwards, and each uses its own set
///   id, so no invocation can ever declare one twice.
struct Diagnostics {
    enabled: bool,
}

impl Diagnostics {
    /// Emit one entry in its own set, `siros-debug-<kind>`, if enabled.
    ///
    /// The message is a closure rather than a string so that composing it —
    /// which for the no-request case means re-parsing the request JSON — costs
    /// nothing on the production path, where diagnostics are off.
    fn emit(&self, sets: &mut impl SetSink, kind: &str, message: impl FnOnce() -> String) {
        if !self.enabled {
            return;
        }
        let message = message();
        let set_id = format!("siros-debug-{kind}");
        let entry = Member {
            credential_id: "siros-debug-entry",
            title: "[SIROS DEBUG] no match",
            // Picker subtitles are typically single-line and short. The
            // message is written terse and passed whole, so nothing important
            // silently falls off the end.
            subtitle: &message,
            data: "{}".to_owned(),
            icon: FALLBACK_ICON_PNG,
            // A diagnostic entry has no verifier reason to show; the whole
            // message is already in the subtitle.
            disclaimer: None,
            fields: Vec::new(),
        };
        emit_set(sets, &set_id, &[entry]);
    }
}

/// A 64x64 solid-colour PNG for diagnostic entries — the same dimensions the
/// wallet ships for real ones. See [`Diagnostics`] for why it exists and why
/// it is this size.
#[rustfmt::skip]
const FALLBACK_ICON_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x08, 0x02, 0x00, 0x00, 0x00, 0x25, 0x0B, 0xE6,
    0x89, 0x00, 0x00, 0x00, 0x50, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0xED, 0xCF, 0x41, 0x09, 0x00,
    0x00, 0x08, 0x04, 0xB0, 0xCB, 0x61, 0x10, 0xDB, 0xD8, 0xBF, 0x86, 0x11, 0x7C, 0x0B, 0x83, 0x15,
    0x58, 0xAA, 0xE7, 0xB5, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x5C, 0x16, 0x49, 0xAB, 0xD0, 0x97, 0x3A, 0x79, 0x4A, 0x21, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// The committed golden blob - the same bytes `golden_blob.rs` in core
    /// guards - so this exercises the real decoder against the real encoder's
    /// output, not a hand-built stand-in.
    fn golden_blob() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../siros-dc-matcher-core/tests/golden/credential_database_v1.cbor"
        ))
        .expect("golden vector")
    }

    /// Stands in for the host and drops what it is given.
    struct Discard;

    impl SetSink for Discard {
        fn add_entry_set<K: android_credman::EntryKind>(
            &mut self,
            _set: &android_credman::EntrySet<'_, K>,
        ) {
        }
    }

    /// One invocation of the decision path, with emission dropped.
    fn invoke(request: &[u8], blob: &[u8], origin: Result<&str, CallingAppError>) {
        let input = Input {
            request,
            blob,
            origin,
        };
        run(&input, &mut Discard);
    }

    /// What `calling_app` returns for an origin field with no NUL.
    fn unreadable_caller() -> CallingAppError {
        CallingAppError::Origin(android_credman::C8Str::from_bytes_until_nul(b"x").unwrap_err())
    }

    fn mdl_request(claim: &str) -> String {
        format!(
            r#"{{"requests":[{{"protocol":"openid4vp-v1-unsigned","data":{{"dcql_query":{{"credentials":[{{"id":"mdl","format":"mso_mdoc","meta":{{"doctype_value":"org.iso.18013.5.1.mDL"}},"claims":[{{"path":["org.iso.18013.5.1","{claim}"]}}]}}]}}}}}}]}}"#
        )
    }

    /// The whole decision path, host-side. Emission is dropped here, so what
    /// this proves is that every branch runs to completion without
    /// trapping on real inputs - the property the denied `unwrap`/`panic`
    /// lints exist for. A trap in the sandbox is a silent "no match".
    #[test]
    fn run_completes_on_every_path() {
        let blob = golden_blob();
        // Satisfiable: the golden credential has family_name.
        invoke(
            mdl_request("family_name").as_bytes(),
            &blob,
            Ok("https://verifier.example"),
        );
        // Unsatisfiable: it has no age_over_21. §6.4 says offer nothing.
        invoke(mdl_request("age_over_21").as_bytes(), &blob, Ok(""));
        // No supported request at all.
        invoke(b"{\"requests\":[]}", &blob, Ok(""));
        // A blob the decoder rejects.
        invoke(
            mdl_request("family_name").as_bytes(),
            b"\x00\x01\x02",
            Ok(""),
        );
        invoke(b"", b"", Ok(""));
        // A caller the host reported unreadably.
        invoke(
            mdl_request("family_name").as_bytes(),
            &blob,
            Err(unreadable_caller()),
        );
    }

    /// With the debug flag in the profile, the same paths run through the
    /// diagnostic emitters too.
    #[test]
    fn run_completes_on_every_path_with_diagnostics_on() {
        let mut db = CredentialDatabase::from_cbor(&golden_blob()).unwrap();
        db.profile.debug = true;
        let blob = db.to_cbor().unwrap();
        invoke(mdl_request("age_over_21").as_bytes(), &blob, Ok(""));
        invoke(
            b"{\"requests\":[{\"protocol\":\"urn:example:x\",\"data\":{}}]}",
            &blob,
            Ok(""),
        );
        invoke(mdl_request("family_name").as_bytes(), &blob, Ok(""));
        invoke(
            mdl_request("family_name").as_bytes(),
            &blob,
            Err(unreadable_caller()),
        );
    }

    /// Off is the production state, and it must cost nothing: the message
    /// closure — which for the no-request case re-parses the request — is
    /// never run.
    #[test]
    fn disabled_diagnostics_never_compose_their_message() {
        let composed = Cell::new(false);
        Diagnostics { enabled: false }.emit(&mut Discard, "x", || {
            composed.set(true);
            String::new()
        });
        assert!(!composed.get());

        let composed = Cell::new(false);
        Diagnostics { enabled: true }.emit(&mut Discard, "x", || {
            composed.set(true);
            String::new()
        });
        assert!(composed.get());
    }

    fn nym_blob(debug: bool) -> Vec<u8> {
        let mut db = siros_dc_matcher_core::fixtures::nym_wallet(vec![
            siros_dc_matcher_core::fixtures::circuit("longfellow-libzk-v1", "urn:circuit:1", None),
        ]);
        db.profile.debug = debug;
        db.to_cbor().unwrap()
    }

    fn zkp_req_request(query: serde_json::Value) -> String {
        serde_json::json!({"requests": [{"protocol": "openid4vp-v1-unsigned",
            "data": {"dcql_query": {"credentials": [query]}}}]})
        .to_string()
    }

    /// The `zkp_req` branch, every way through: a match, no circuit,
    /// an invalid plan, object `claims`, and ordinary claims on the format,
    /// with diagnostics on and off.
    #[test]
    fn run_completes_on_every_zkp_req_path() {
        let nym = "eu.europa.ec.eudi.nym_auth.1";
        let queries = [
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": {"source_format": "mso_mdoc", "doctype_value": nym},
                "_req": [{"fn_id": "age_check", "return": "a", "params": {"range": "18+"}},
                        {"fn_id": "pseudonym", "return": "n", "params": {"config": "x".repeat(300)}},
                        {"fn_id": "future", "return": "f"}],
                "_req_sets": [[0, 1], [1]]}),
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": {"source_format": "mso_mdoc", "doctype_value": nym},
                "claims": {"_req": [{"fn_id": "age_check", "return": "a"}]}}),
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": {"source_format": "mso_mdoc", "doctype_value": nym},
                "_req": [], "claims": [{"path": ["a", "b"]}]}),
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": 7}),
        ];
        for debug in [false, true] {
            for blob in [nym_blob(debug), golden_blob()] {
                for query in &queries {
                    invoke(zkp_req_request(query.clone()).as_bytes(), &blob, Ok(""));
                }
            }
        }
    }
}
