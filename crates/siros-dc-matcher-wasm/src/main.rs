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

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]

mod abi;
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
mod simple_allocator;

// Entry point for the `wasm32-unknown-unknown` target.
//
// The Credential Manager host calls `_start`. On `wasm32-wasip1` wasi-libc's
// CRT exports it; this target has no CRT, so nothing would. Same fix as
// `digitalcredentialsdev/CMWallet`'s own matcher-rs. That target also needs
// the allocator in `simple_allocator`, since there is no libc to supply one.
//
// The shipped build is `wasm32-wasip1` (see the Makefile). This target is
// kept buildable as the WASI-free alternative should the host's WASI subset
// ever turn out narrower than the two imports the shipped build still has:
//
//     cargo +nightly build -p siros-dc-matcher-wasm -Z build-std \
//         --target wasm32-unknown-unknown --profile wasm-release
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
#[unsafe(no_mangle)]
extern "C" fn _start() {
    main();
}

use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, resolve, ProfilePolicy};
use siros_dc_matcher_core::request::{diagnose, first_supported_context};
use siros_dc_matcher_core::sink::Entry;
use siros_dcql::execute;
use siros_zkp_req::ReqItem;

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

fn main() {
    let request = abi::request_bytes();
    let blob = abi::credentials_bytes();
    let (_package, origin) = abi::calling_app_info();
    run(&request, &blob, &origin);
}

/// One matcher invocation, from the host's three inputs to emitted entries.
///
/// Separate from [`main`] so it can be driven on the host in tests: off the
/// wasm target, `abi::emit` is a no-op and the three readers return nothing,
/// so this is the only way to exercise the decision path against a real
/// request and the committed golden blob.
fn run(request: &[u8], blob: &[u8], origin: &str) {
    let Ok(db) = CredentialDatabase::from_cbor(blob) else {
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
        diag.emit("request", || diagnose(request, &db.profile));
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
        diag.emit("unsatisfiable", || {
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
        diag.emit("zero", || {
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
        abi::emit::entry_set(&set_id, resolved.len());

        // Why the verifier says it wants this combination (§6.2). Computed
        // once per combination and shown on each of its entries: the purposes
        // belong to the credential sets the combination satisfies, and the
        // combination is what the user is consenting to as a unit, so every
        // card in it is being offered for those reasons.
        let purpose = siros_dc_matcher_core::purpose::line(&combination.purposes);

        for (position, (query_id, candidate, credential)) in resolved.iter().enumerate() {
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

            let metadata = serde_json::json!({
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
                "host_abi": abi::wasm_version(),
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

            abi::emit::entry(
                &set_id,
                position,
                &Entry {
                    credential_id: &credential.id,
                    title: &credential.title,
                    subtitle: &credential.subtitle,
                    metadata: &metadata,
                    // Never `None`. A null icon is not a missing picture:
                    // the host drops the whole entry and logs `Null icon for
                    // icon` in its own process, so a credential registered
                    // without image bytes would silently not exist in the
                    // picker. #19 gave the diagnostic entries this fallback;
                    // a real entry needs it at least as much, because a user
                    // is looking for that credential.
                    // `filter`, not just `unwrap_or`: a zero-length `IconRef`
                    // yields `Some(&[])`, and the emitter maps an empty slice
                    // to the same null pointer as `None` — so without this the
                    // fallback misses exactly the case it was added for.
                    icon: Some(
                        db.icon_bytes(credential)
                            .filter(|bytes| !bytes.is_empty())
                            .unwrap_or(FALLBACK_ICON_PNG),
                    ),
                    disclaimer: purpose.as_deref(),
                },
            );

            // A `zkp_req` match discloses no claims, so its rows describe
            // the proof being asked for instead, from the plan.
            if let Some(zk) = zk {
                for (name, value) in zkp_req_rows(zk.items()) {
                    abi::emit::field(&set_id, position, &credential.id, &name, &value);
                }
                continue;
            }

            // Only the claims this match actually discloses. Showing every
            // claim the credential holds would misrepresent the request the
            // user is being asked to consent to.
            for claim in &candidate.claims {
                if let Some(stored) = credential.claims.iter().find(|c| {
                    c.path.iter().map(String::as_str).eq(claim
                        .path
                        .iter()
                        .filter_map(siros_dcql::PathComponent::as_key))
                }) {
                    abi::emit::field(
                        &set_id,
                        position,
                        &credential.id,
                        &stored.display,
                        stored.display_value.as_deref().unwrap_or(&stored.value),
                    );
                }
            }
        }
    }
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

/// Picker rows for the answered option of a `zkp_req` request: one per item, no claim
/// fields.
///
/// Text comes from the unverified request, so each row says so. Opaque values (`config`,
/// `range`) are shown as given and truncated, and nothing is judged: whether the request is
/// acceptable is the wallet's call.
fn zkp_req_rows<'q>(items: impl Iterator<Item = &'q ReqItem>) -> Vec<(String, String)> {
    items
        .map(|item| {
            let param = |name: &str| item.params.get(name).and_then(serde_json::Value::as_str);
            let (label, detail) = match item.fn_id.as_str() {
                "age_check" => ("Age check", param("range").map(|r| format!("age {r}"))),
                "pseudonym" => ("Pseudonym", param("config").map(|c| format!("config {c}"))),
                other => (other, None),
            };
            // Clip the detail, never the marker: the marker is the part that
            // must survive.
            let value = match detail {
                None => UNVERIFIED.to_string(),
                Some(detail) => format!(
                    "{} {UNVERIFIED}",
                    clip(&detail, ROW_MAX_CHARS - UNVERIFIED.len() - 1)
                ),
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
    fn emit(&self, kind: &str, message: impl FnOnce() -> String) {
        if !self.enabled {
            return;
        }
        let message = message();
        let set_id = format!("siros-debug-{kind}");
        abi::emit::entry_set(&set_id, 1);
        abi::emit::entry(
            &set_id,
            0,
            &Entry {
                credential_id: "siros-debug-entry",
                title: "[SIROS DEBUG] no match",
                // Picker subtitles are typically single-line and short; keep
                // the message itself terse rather than truncating here, so
                // nothing important silently falls off the end.
                subtitle: &message,
                metadata: "{}",
                icon: Some(FALLBACK_ICON_PNG),
                // A diagnostic entry has no verifier reason to show; the
                // whole message is already in the subtitle.
                disclaimer: None,
            },
        );
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

    fn mdl_request(claim: &str) -> String {
        format!(
            r#"{{"requests":[{{"protocol":"openid4vp-v1-unsigned","data":{{"dcql_query":{{"credentials":[{{"id":"mdl","format":"mso_mdoc","meta":{{"doctype_value":"org.iso.18013.5.1.mDL"}},"claims":[{{"path":["org.iso.18013.5.1","{claim}"]}}]}}]}}}}}}]}}"#
        )
    }

    /// The whole decision path, host-side. `abi::emit` is a no-op here, so
    /// what this proves is that every branch runs to completion without
    /// trapping on real inputs - the property the denied `unwrap`/`panic`
    /// lints exist for. A trap in the sandbox is a silent "no match".
    #[test]
    fn run_completes_on_every_path() {
        let blob = golden_blob();
        // Satisfiable: the golden credential has family_name.
        run(
            mdl_request("family_name").as_bytes(),
            &blob,
            "https://verifier.example",
        );
        // Unsatisfiable: it has no age_over_21. §6.4 says offer nothing.
        run(mdl_request("age_over_21").as_bytes(), &blob, "");
        // No supported request at all.
        run(b"{\"requests\":[]}", &blob, "");
        // A blob the decoder rejects.
        run(mdl_request("family_name").as_bytes(), b"\x00\x01\x02", "");
        run(b"", b"", "");
    }

    /// With the debug flag in the profile, the same paths run through the
    /// diagnostic emitters too.
    #[test]
    fn run_completes_on_every_path_with_diagnostics_on() {
        let mut db = CredentialDatabase::from_cbor(&golden_blob()).unwrap();
        db.profile.debug = true;
        let blob = db.to_cbor().unwrap();
        run(mdl_request("age_over_21").as_bytes(), &blob, "");
        run(
            b"{\"requests\":[{\"protocol\":\"urn:example:x\",\"data\":{}}]}",
            &blob,
            "",
        );
        run(mdl_request("family_name").as_bytes(), &blob, "");
    }

    /// Off is the production state, and it must cost nothing: the message
    /// closure — which for the no-request case re-parses the request — is
    /// never run.
    #[test]
    fn disabled_diagnostics_never_compose_their_message() {
        let composed = Cell::new(false);
        Diagnostics { enabled: false }.emit("x", || {
            composed.set(true);
            String::new()
        });
        assert!(!composed.get());

        let composed = Cell::new(false);
        Diagnostics { enabled: true }.emit("x", || {
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
                    run(zkp_req_request(query.clone()).as_bytes(), &blob, "");
                }
            }
        }
    }

    #[test]
    fn zkp_req_rows_say_they_are_unverified_and_are_bounded() {
        let query = siros_zkp_req::ZkpReqQuery::parse(&serde_json::json!({"id": "q",
            "format": "zkp_req", "meta": {"source_format": "mso_mdoc", "doctype_value": "d"},
            "_req": [
                {"fn_id": "age_check", "params": {"range": "13-17"}},
                {"fn_id": "pseudonym", "return": "n", "params": {"config": "c".repeat(500)}},
                {"fn_id": "mystery", "return": "m"},
                {"fn_id": "age_check", "return": "b"}]}))
        .unwrap();
        let rows = zkp_req_rows(query.items.iter());
        assert_eq!(rows.len(), 4, "one row per item");
        assert_eq!(rows[0].0, "Age check");
        assert!(rows[0].1.starts_with("age 13-17"));
        assert_eq!(rows[2], ("mystery".to_string(), UNVERIFIED.to_string()));
        for (name, value) in &rows {
            assert!(value.ends_with(UNVERIFIED), "{name}: {value}");
            assert!(value.chars().count() <= ROW_MAX_CHARS, "{name}: {value}");
        }
    }
}
