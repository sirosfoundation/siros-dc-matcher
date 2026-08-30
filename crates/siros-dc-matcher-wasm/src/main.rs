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
//! Phase 4: real matching. Entry display and icons are Phase 5 — see
//! `docs/plan.md`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]

mod abi;

use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, ProfilePolicy};
use siros_dc_matcher_core::profile::Parser;
use siros_dc_matcher_core::sink::Entry;
use siros_dcql::{execute, DcqlQuery};

/// The set every entry belongs to.
///
/// One set for now: DCQL `credential_sets` can require a *combination* of
/// credentials selected together, and expressing that properly is Phase 5.
const SET_ID: &str = "siros";

fn main() {
    let request = abi::request_bytes();
    let blob = abi::credentials_bytes();

    // The platform's own attestation of who is asking — the only trustworthy
    // statement of that, since anything naming an origin inside the request
    // body is the request describing itself. The wallet learns the origin from
    // the platform too, so carrying it here lets the wallet check that the
    // matcher was shown the same caller it was.
    let (_package, origin) = abi::calling_app_info();

    let Ok(db) = CredentialDatabase::from_cbor(&blob) else {
        // Nothing can be offered from a blob we cannot read. It is worth
        // saying plainly that this is indistinguishable from "no matching
        // credential" in the picker — the wallet-side registration is where
        // such a failure has to be caught.
        return;
    };

    let Some((protocol, query)) = first_supported_request(&request, &db) else {
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
        return;
    }

    let mut entries = Vec::new();
    for query_match in &result.matches {
        for candidate in &query_match.candidates {
            if let Some(credential) = db
                .credentials
                .iter()
                .find(|c| c.id == candidate.credential_id)
            {
                entries.push((query_match.query_id.as_str(), candidate, credential));
            }
        }
    }
    if entries.is_empty() {
        return;
    }

    abi::emit::entry_set(SET_ID, entries.len());
    for (index, (query_id, candidate, credential)) in entries.iter().enumerate() {
        // Metadata survives the picker round-trip, so it carries the decision
        // this matcher already made. Without it the wallet would re-derive
        // which query matched and which capability was chosen, from a request
        // it has to parse again — and could reach a different answer.
        let metadata = serde_json::json!({
            "matcher": "siros-dc-matcher",
            "protocol": protocol,
            "query_id": query_id,
            "credential_id": credential.id,
            "verified_origin": origin,
            "host_abi": abi::wasm_version(),
            "claims": candidate
                .claims
                .iter()
                .map(|c| c.path.clone())
                .collect::<Vec<_>>(),
        })
        .to_string();

        abi::emit::entry(
            SET_ID,
            index,
            &Entry {
                credential_id: &credential.id,
                title: &credential.title,
                subtitle: &credential.subtitle,
                metadata: &metadata,
            },
        );

        // Only the claims this match actually discloses. Showing every claim
        // the credential holds would misrepresent the request the user is
        // being asked to consent to.
        for claim in &candidate.claims {
            if let Some(stored) = credential.claims.iter().find(|c| {
                c.path.iter().map(String::as_str).eq(claim
                    .path
                    .iter()
                    .filter_map(siros_dcql::PathComponent::as_key))
            }) {
                abi::emit::field(
                    SET_ID,
                    index,
                    &credential.id,
                    &stored.display,
                    stored.display_value.as_deref().unwrap_or(&stored.value),
                );
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
