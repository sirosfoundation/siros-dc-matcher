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

    // A combination is what the picker offers as one selectable option: every
    // member is presented together and consented to as a unit. Alternatives
    // are separate combinations, and therefore separate sets.
    let enumerated = result.combinations(MAX_COMBINATIONS);
    if enumerated.combinations.is_empty() {
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
