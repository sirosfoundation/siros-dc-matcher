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
//! unwinding. The deliberate traps are a host that breaks its ABI, which
//! `android-credman` turns into panics, and inputs too large to allocate.
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
// A panicking std method that clippy.toml names takes an #[expect] with the
// reason it cannot recover, as each panic of the matcher does.
#![cfg_attr(not(test), deny(clippy::disallowed_methods))]
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

use android_credman::SetSink;
use picker::{emit_set, Member};
use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, resolve, ProfilePolicy};
use siros_dc_matcher_core::request::{diagnose, first_supported_context};
use siros_dc_matcher_core::zkp_req::{Params, Plan};
use siros_dcql::execute;

/// Prefix of the set ids: combination `n` is the set `siros-n`.
///
/// A set is a group of entries the picker selects *together*. Each set holds
/// the members of one combination, which the user presents as a unit; the
/// alternative combinations are separate sets.
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
    let request = host.request();
    let blob = host.credentials();
    let caller = host.calling_app();
    let input = Input {
        request: &request,
        blob: &blob,
        origin: caller.origin().map_or("", android_credman::C8Str::as_str),
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
    /// The caller's origin as the platform verified it, empty for an app.
    origin: &'a str,
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

    // The whole request context, not only the query: a `zkp_req` request is
    // matched against the verifier's `client_metadata` and has no typed DCQL
    // form when it uses the rulebook example's `claims` object. Nothing in the
    // context is authenticated; the wallet checks the request at selection.
    let Some((context, query)) = first_supported_context(request, &db.profile, None)
        .and_then(|context| Some((context.clone(), context.matching_query()?)))
    else {
        diag.emit(sets, "request", || diagnose(request, &db.profile));
        return;
    };
    let protocol = context.protocol.as_str();

    let held = credentials(&db);
    let policy = ProfilePolicy::new(&db.profile).with_context(&context);
    let result = execute(&query, &held, &policy);

    // "If the Wallet cannot deliver all non-optional Credentials requested by
    // the Verifier according to these rules, it MUST NOT return any
    // Credential(s)" — OpenID4VP 1.0 §6.4. Offering the half that matched
    // would be worse than offering nothing: the user consents to a
    // presentation that cannot satisfy the verifier.
    if !result.satisfiable {
        diag.emit(sets, "unsatisfiable", || {
            format!(
                "{protocol}: parsed {} cred queries, not satisfiable",
                query.credentials.len()
            )
        });
        return;
    }

    // A combination is what the picker offers as one selectable option: every
    // member is presented together and consented to as a unit. Alternatives
    // are separate combinations, and therefore separate sets.
    let enumerated = result.combinations(MAX_COMBINATIONS);
    if enumerated.combinations.is_empty() {
        diag.emit(sets, "zero", || {
            format!(
                "{protocol}: satisfiable but zero combinations ({} held)",
                held.len()
            )
        });
        return;
    }

    for (index, combination) in enumerated.combinations.iter().enumerate() {
        // Resolve every member before declaring the set. Skipping one after
        // the fact would leave the declared length disagreeing with the
        // entries actually added, and a gap in the positions — which the host
        // is right to treat as a matcher bug. A combination we cannot fully
        // emit is not offered at all.
        let resolved: Option<Vec<_>> = combination
            .members
            .iter()
            .map(|(query_id, candidate)| {
                db.credentials
                    .iter()
                    .find(|c| c.id == candidate.credential_id)
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
        let purpose = siros_dc_matcher_core::purpose::line(&combination.purposes);

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
                "verified_origin": input.origin,
                // How many further options existed. A picker showing the first
                // few of many is telling the user those are all they have.
                //
                // Still a plain number, and still true — it is a lower bound
                // when the product overflowed `usize`, not a wrapped value —
                // but a wallet cannot tell a count from a bound by looking, so
                // the second field says which this is.
                "combinations_dropped": enumerated.dropped.count(),
                "combinations_dropped_is_exact": enumerated.dropped.is_exact(),
            })
            .to_string();

            // A `zkp_req` match discloses no claims, so its rows describe
            // the proof being asked for instead, from the plan.
            let fields = match zk {
                Some(zk) => zkp_req_rows(&zk.plan),
                None => disclosed_fields(credential, candidate),
            };
            members.push(Member {
                credential_id: &credential.id,
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
        .claims
        .iter()
        .filter_map(|claim| {
            credential.claims.iter().find(|c| {
                c.path.iter().map(String::as_str).eq(claim
                    .path
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
// zkp_req rows
// ============================================================================

/// The longest row value emitted. The values are verifier-supplied strings, and
/// a picker row is not the place for a paragraph of them.
const ROW_MAX_CHARS: usize = 80;

/// Said on every row, because every row is the request describing itself: the
/// matcher has not checked the signature, so these are claims about what is
/// being asked, not facts.
const UNVERIFIED: &str = "(unverified request)";

/// Picker rows for a planned `zkp_req` request: one per requested
/// function, no claim fields.
///
/// Text comes from the unverified request, so each row says so. Opaque values
/// (`config`, dates, `verifier_context`) are shown as given and truncated, and
/// nothing is judged: whether the request is acceptable is the wallet's call.
fn zkp_req_rows(plan: &Plan) -> Vec<(String, String)> {
    plan.functions
        .iter()
        .map(|function| {
            let (label, detail) = match &function.params {
                Params::AgeCheck { ge, le, .. } => (
                    "Age check",
                    match (ge.as_deref(), le.as_deref()) {
                        (Some(ge), Some(le)) => format!("born {ge} to {le}"),
                        (Some(ge), None) => format!("born on or after {ge}"),
                        (None, Some(le)) => format!("born on or before {le}"),
                        (None, None) => String::new(),
                    },
                ),
                Params::Pseudonym { config, .. } => (
                    "Pseudonym",
                    config
                        .as_deref()
                        .map(|c| format!("config {c}"))
                        .unwrap_or_default(),
                ),
                Params::Unknown(_) => (function.function_id.as_str(), String::new()),
            };
            // Clip the detail, never the marker: the marker is the part that
            // must survive.
            let value = if detail.is_empty() {
                UNVERIFIED.to_string()
            } else {
                format!(
                    "{} {UNVERIFIED}",
                    clip(&detail, ROW_MAX_CHARS - UNVERIFIED.len() - 1)
                )
            };
            (clip(label, ROW_MAX_CHARS), value)
        })
        .collect()
}

/// At most `max` characters, ending in an ellipsis if it had to cut.
fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
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
    fn invoke(request: &[u8], blob: &[u8], origin: &str) {
        let input = Input {
            request,
            blob,
            origin,
        };
        run(&input, &mut Discard);
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
            "https://verifier.example",
        );
        // Unsatisfiable: it has no age_over_21. §6.4 says offer nothing.
        invoke(mdl_request("age_over_21").as_bytes(), &blob, "");
        // No supported request at all.
        invoke(b"{\"requests\":[]}", &blob, "");
        // A blob the decoder rejects.
        invoke(mdl_request("family_name").as_bytes(), b"\x00\x01\x02", "");
        invoke(b"", b"", "");
    }

    /// With the debug flag in the profile, the same paths run through the
    /// diagnostic emitters too.
    #[test]
    fn run_completes_on_every_path_with_diagnostics_on() {
        let mut db = CredentialDatabase::from_cbor(&golden_blob()).unwrap();
        db.profile.debug = true;
        let blob = db.to_cbor().unwrap();
        invoke(mdl_request("age_over_21").as_bytes(), &blob, "");
        invoke(
            b"{\"requests\":[{\"protocol\":\"urn:example:x\",\"data\":{}}]}",
            &blob,
            "",
        );
        invoke(mdl_request("family_name").as_bytes(), &blob, "");
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
                "_req": [{"fn_id": "age_check", "return": "a", "params": {"ge": "2008-10-10"}},
                        {"fn_id": "pseudonym", "return": "n", "params": {"config": "x".repeat(300)}},
                        {"fn_id": "future", "return": "f"}]}),
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": {"source_format": "mso_mdoc", "doctype_value": nym},
                "claims": {"_req": [{"fn_id": "age_check", "return": "a"}]}}),
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": {"source_format": "mso_mdoc", "doctype_value": nym},
                "_req": [], "claims": [{"path": ["a", "b"]}]}),
            serde_json::json!({"id": "q", "format": "zkp_req", "meta": 7}),
        ];
        for debug in [false, true] {
            for blob in [nym_blob(debug), golden_blob()] {
                for query in &queries {
                    invoke(zkp_req_request(query.clone()).as_bytes(), &blob, "");
                }
            }
        }
    }

    #[test]
    fn zkp_req_rows_say_they_are_unverified_and_are_bounded() {
        let plan = siros_dc_matcher_core::zkp_req::plan(
            &serde_json::json!({"id": "q", "format": "zkp_req", "meta": {"source_format": "mso_mdoc"},
                "_req": [
                    {"fn_id": "age_check", "return": "a", "params": {"ge": "2008-10-10", "le": "2013-10-09"}},
                    {"fn_id": "pseudonym", "return": "n", "params": {"config": "c".repeat(500)}},
                    {"fn_id": "mystery", "return": "m"},
                    {"fn_id": "age_check", "return": "b"}]})
            .to_string(),
            None,
        )
        .unwrap();
        let rows = zkp_req_rows(&plan);
        assert_eq!(rows.len(), 4, "one row per function");
        assert_eq!(rows[0].0, "Age check");
        assert!(rows[0].1.starts_with("born 2008-10-10 to 2013-10-09"));
        assert_eq!(rows[2], ("mystery".to_string(), UNVERIFIED.to_string()));
        for (name, value) in &rows {
            assert!(value.ends_with(UNVERIFIED), "{name}: {value}");
            assert!(value.chars().count() <= ROW_MAX_CHARS, "{name}: {value}");
        }
    }
}
