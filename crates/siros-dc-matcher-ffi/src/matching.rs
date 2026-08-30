//! Matching, across the FFI boundary.
//!
//! Kotlin and Swift each carry their own DCQL implementation. Both filter on
//! format and type metadata alone: neither checks that a credential actually
//! *has* the requested claims, which OpenID4VP 1.0 §6.4.1 requires, and
//! neither implements `claim_sets` or `values`. They have drifted from the
//! specification and from each other, in a component whose failures are
//! invisible — a wallet that is not offered looks exactly like a wallet with
//! nothing to offer.
//!
//! This exposes the engine those implementations should be calling instead.
//!
//! # What the engine is given
//!
//! The registered blob, and the request. Not a callback into the caller's own
//! credential store: that would be faithful to whatever shape a credential
//! really has, at the cost of re-entrancy across two language boundaries and a
//! bridge crossing per claim. The blob already carries the claims and the
//! profile, and both SDKs already build it.
//!
//! The trade to be aware of is that this makes the blob's fidelity
//! **load-bearing for correctness**, where before it only affected display. A
//! claim the wallet does not register is a claim no verifier can match, and
//! the symptom is the usual one for this component: nothing appears, and
//! nothing says why.

use std::collections::HashMap;

use siros_dc_matcher_core::db::CredentialDatabase;
use siros_dc_matcher_core::evaluator::{credentials, ProfilePolicy};
use siros_dc_matcher_core::profile::Parser;
use siros_dcql::{execute, DcqlQuery, PathComponent};

use crate::FfiCapability;

/// How many combinations to return at most.
///
/// The count is a product of the per-query candidate counts, so it is bounded
/// rather than enumerated. What is dropped is reported, never silently cut:
/// a list of options that quietly omits some is one the caller cannot reason
/// about.
const MAX_COMBINATIONS: usize = 32;

/// Why a request could not be matched.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MatchError {
    /// The registered blob could not be decoded.
    #[error("the credential blob could not be read: {reason}")]
    Blob {
        /// What went wrong.
        reason: String,
    },
    /// The request was not valid JSON, or not shaped like a request.
    #[error("the request could not be read: {reason}")]
    Request {
        /// What went wrong.
        reason: String,
    },
    /// No protocol in the request is one this wallet's profile answers.
    ///
    /// Distinct from "nothing matched": the wallet may hold exactly what was
    /// asked for and still be unable to speak the protocol it was asked in.
    #[error("no supported protocol in the request")]
    UnsupportedProtocol,
}

/// One credential answering one credential query.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMatchedCredential {
    /// The DCQL credential query this answers.
    pub query_id: String,
    /// The wallet-side credential identifier.
    pub credential_id: String,
    /// Exactly the claims to disclose — and no others (§6.4).
    ///
    /// Each is a path: for ISO mdoc, `[namespace, element_identifier]`.
    pub claims: Vec<Vec<String>>,
    /// The capability chosen to satisfy this query, if its format needed one.
    ///
    /// Returned rather than left to the caller because the engine has already
    /// decided. Working it out again means parsing the request a second time,
    /// in a second implementation, and possibly reaching a different answer.
    pub capabilities: Vec<FfiCapability>,
    /// `meta` entries the wallet needs at presentation time but which do not
    /// affect matching — `ppid_context` above all, which both SDKs read today.
    ///
    /// A pseudonym context changes what is produced, not which credential can
    /// produce it, so it is carried rather than matched on.
    pub meta: HashMap<String, String>,
}

/// One way to satisfy the request: every member presented together.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiCombination {
    /// The credentials making up this option.
    pub members: Vec<FfiMatchedCredential>,
}

/// The outcome of matching.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMatchOutcome {
    /// Whether the wallet can satisfy the request at all.
    ///
    /// False means §6.4's "MUST NOT return any Credential(s)" — nothing should
    /// be offered, not even the part that matched.
    pub satisfiable: bool,
    /// Ways to satisfy it. Alternatives are separate entries.
    pub combinations: Vec<FfiCombination>,
    /// How many further combinations existed beyond the returned ones.
    pub dropped: u32,
}

/// Match a full Digital Credentials API request.
///
/// The request is the `{"requests":[{"protocol":…,"data":…}]}` envelope, which
/// is a list because one call can offer the same request under several
/// protocols. The first protocol the wallet's registered profile answers wins.
///
/// # Errors
///
/// See [`MatchError`].
#[uniffi::export]
pub fn match_dc_api_request(
    blob: Vec<u8>,
    request_json: String,
) -> Result<FfiMatchOutcome, MatchError> {
    let db = decode(&blob)?;
    let parsed: serde_json::Value = serde_json::from_str(&request_json).map_err(request_err)?;

    let query = parsed
        .get("requests")
        .and_then(serde_json::Value::as_array)
        .ok_or(MatchError::UnsupportedProtocol)?
        .iter()
        .find_map(|entry| {
            let protocol = entry.get("protocol")?.as_str()?;
            match db.profile.parser_for(protocol)? {
                Parser::Openid4vpV1 => {
                    serde_json::from_value(entry.get("data")?.get("dcql_query")?.clone()).ok()
                }
                // ISO 18013-7 carries a CBOR DeviceRequest rather than DCQL,
                // so it needs its own reader. Declining lets the caller fall
                // through to another protocol the verifier offered.
                Parser::IsoMdocApi => None,
            }
        })
        .ok_or(MatchError::UnsupportedProtocol)?;

    Ok(evaluate(&db, &query))
}

/// Match a bare DCQL query.
///
/// The wallet's own presentation flow receives a DCQL query directly rather
/// than a DC API envelope, so it has no protocol to select and none to fail
/// on.
///
/// # Errors
///
/// See [`MatchError`].
#[uniffi::export]
pub fn match_dcql(blob: Vec<u8>, dcql_json: String) -> Result<FfiMatchOutcome, MatchError> {
    let db = decode(&blob)?;
    let query = DcqlQuery::from_json(&dcql_json).map_err(request_err)?;
    Ok(evaluate(&db, &query))
}

fn decode(blob: &[u8]) -> Result<CredentialDatabase, MatchError> {
    CredentialDatabase::from_cbor(blob).map_err(|e| MatchError::Blob {
        reason: e.to_string(),
    })
}

fn request_err(e: serde_json::Error) -> MatchError {
    MatchError::Request {
        reason: e.to_string(),
    }
}

fn evaluate(db: &CredentialDatabase, query: &DcqlQuery) -> FfiMatchOutcome {
    let held = credentials(db);
    let policy = ProfilePolicy::new(&db.profile);
    let result = execute(query, &held, &policy);
    let enumerated = result.combinations(MAX_COMBINATIONS);

    let combinations = enumerated
        .combinations
        .iter()
        .map(|combination| FfiCombination {
            members: combination
                .members
                .iter()
                .map(|(query_id, candidate)| {
                    let credential_query = query.credential(query_id);
                    FfiMatchedCredential {
                        query_id: query_id.clone(),
                        credential_id: candidate.credential_id.clone(),
                        claims: candidate
                            .claims
                            .iter()
                            .map(|claim| {
                                claim
                                    .path
                                    .iter()
                                    .filter_map(PathComponent::as_key)
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .collect(),
                        capabilities: credential_query
                            .and_then(|cq| {
                                let rule = db.profile.format_rule(&cq.format)?;
                                if rule.requires.is_empty() {
                                    return None;
                                }
                                policy.capability_for(cq, &rule.requires)
                            })
                            .unwrap_or_default()
                            .into_iter()
                            .map(|c| FfiCapability {
                                system: c.system.clone(),
                                params: c
                                    .params
                                    .iter()
                                    .map(|(k, v)| (k.clone(), v.clone()))
                                    .collect(),
                            })
                            .collect(),
                        meta: carried_meta(credential_query),
                    }
                })
                .collect(),
        })
        .collect();

    FfiMatchOutcome {
        satisfiable: result.satisfiable,
        combinations,
        dropped: u32::try_from(enumerated.dropped).unwrap_or(u32::MAX),
    }
}

/// `meta` entries the wallet needs but that do not decide a match.
///
/// Only scalars: a nested object has no single string form, and inventing one
/// would hand the caller a value it cannot use. Anything structural belongs in
/// a typed field rather than smuggled through here.
fn carried_meta(query: Option<&siros_dcql::CredentialQuery>) -> HashMap<String, String> {
    let Some(query) = query else {
        return HashMap::new();
    };
    query
        .meta
        .iter()
        .filter_map(|(key, value)| {
            let text = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => return None,
            };
            Some((key.clone(), text))
        })
        .collect()
}
