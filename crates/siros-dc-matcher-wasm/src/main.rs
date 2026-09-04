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
use siros_dc_matcher_core::profile::Parser;
use siros_dc_matcher_core::sink::Entry;
use siros_dcql::{execute, DcqlQuery};

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

    let Ok(db) = CredentialDatabase::from_cbor(&blob) else {
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

    let Some((protocol, query)) = first_supported_request(&request, &db) else {
        diag.emit("request", &diagnose_no_request(&request, &db));
        return;
    };

    let held = credentials(&db);
    let policy = ProfilePolicy::new(&db.profile);
    let result = execute(&query, &held, &policy);

    // "If the Wallet cannot deliver all non-optional Credentials requested by
    // the Verifier according to these rules, it MUST NOT return any
    // Credential(s)" — OpenID4VP 1.0 §6.4. Offering the half that matched
    // would be worse than offering nothing: the user consents to a
    // presentation that cannot satisfy the verifier.
    if !result.satisfiable {
        diag.emit(
            "unsatisfiable",
            &format!(
                "{protocol}: parsed {} cred queries, not satisfiable",
                query.credentials.len()
            ),
        );
        return;
    }

    // A combination is what the picker offers as one selectable option: every
    // member is presented together and consented to as a unit. Alternatives
    // are separate combinations, and therefore separate sets.
    let enumerated = result.combinations(MAX_COMBINATIONS);
    if enumerated.combinations.is_empty() {
        diag.emit(
            "zero",
            &format!(
                "{protocol}: satisfiable but zero combinations ({} held)",
                held.len()
            ),
        );
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

            let metadata = serde_json::json!({
                "matcher": "siros-dc-matcher",
                "protocol": protocol,
                "query_id": query_id,
                "credential_id": credential.id,
                "capabilities": capabilities,
                "claims": resolved.as_ref().map(|r| r.claims.clone()).unwrap_or_default(),
                // The platform's own attestation of who is asking — the only
                // trustworthy statement of that, since anything naming an
                // origin inside the request body is the request describing
                // itself. The wallet is told it separately, so carrying it
                // lets the wallet check the matcher was shown the same caller.
                "verified_origin": origin,
                "host_abi": abi::wasm_version(),
                // How many further options existed. A picker showing the first
                // few of many is telling the user those are all they have.
                "combinations_dropped": enumerated.dropped,
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
                    icon: db.icon_bytes(credential),
                },
            );

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

/// The first request this wallet's profile says it can answer, with its DCQL
/// query.
///
/// The request is a list because one DC API call can offer the same request
/// under several protocols and let the wallet pick. Taking the first
/// *supported* one rather than the first one is what makes that negotiation
/// work — and which protocols are supported comes from the registered profile,
/// so adding one costs a re-registration rather than a new binary.
fn first_supported_request(request: &[u8], db: &CredentialDatabase) -> Option<(String, DcqlQuery)> {
    let parsed: serde_json::Value = serde_json::from_slice(request).ok()?;
    parsed
        .get("requests")?
        .as_array()?
        .iter()
        .find_map(|entry| {
            let protocol = entry.get("protocol")?.as_str()?;
            let parser = db.profile.parser_for(protocol)?;
            let query = extract_query(parser, entry.get("data")?)?;
            Some((protocol.to_string(), query))
        })
}

/// The DCQL query carried by one protocol's request data.
fn extract_query(parser: Parser, data: &serde_json::Value) -> Option<DcqlQuery> {
    match parser {
        Parser::Openid4vpV1 => serde_json::from_value(data.get("dcql_query")?.clone()).ok(),
        // ISO 18013-7 carries a CBOR DeviceRequest rather than DCQL, so it
        // needs its own reader rather than a different JSON pointer. Returning
        // None declines the protocol, which lets the caller fall through to
        // another one the verifier offered instead of failing the request.
        Parser::IsoMdocApi => None,
    }
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
    fn emit(&self, kind: &str, message: &str) {
        if !self.enabled {
            return;
        }
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
                subtitle: message,
                metadata: "{}",
                icon: Some(FALLBACK_ICON_PNG),
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

/// Why [`first_supported_request`] found nothing to answer, in as much detail
/// as can be gotten without threading a proper error type through it. Only
/// ever shown when [`Diagnostics`] is enabled.
fn diagnose_no_request(request: &[u8], db: &CredentialDatabase) -> String {
    let parsed: Result<serde_json::Value, _> = serde_json::from_slice(request);
    let parsed = match parsed {
        Ok(v) => v,
        Err(e) => return format!("request ({} bytes) is not valid JSON: {e}", request.len()),
    };
    let Some(requests) = parsed.get("requests").and_then(|r| r.as_array()) else {
        return "request JSON has no `requests` array".to_string();
    };
    if requests.is_empty() {
        return "`requests` array is empty".to_string();
    }
    let mut parts = Vec::new();
    for entry in requests {
        let protocol = entry
            .get("protocol")
            .and_then(|p| p.as_str())
            .unwrap_or("<missing protocol>");
        let Some(parser) = db.profile.parser_for(protocol) else {
            parts.push(format!("{protocol}: not in registered profile"));
            continue;
        };
        let Some(data) = entry.get("data") else {
            parts.push(format!("{protocol}: request entry has no `data`"));
            continue;
        };
        match parser {
            Parser::Openid4vpV1 => match data.get("dcql_query") {
                None => parts.push(format!("{protocol}: data has no `dcql_query`")),
                Some(dcql) => match serde_json::from_value::<DcqlQuery>(dcql.clone()) {
                    Ok(q) => parts.push(format!(
                        "{protocol}: dcql_query parsed ({} credential queries) - should not have reached here",
                        q.credentials.len()
                    )),
                    Err(e) => parts.push(format!("{protocol}: dcql_query failed to parse: {e}")),
                },
            },
            Parser::IsoMdocApi => parts.push(format!("{protocol}: ISO mdoc API has no parser yet")),
        }
    }
    parts.join(" | ")
}
