//! Response validator for `circuit_zk` presentations.
//!
//! [`validate_response`] checks the *shape* of a `circuit_zk` entry in a
//! `vp_token` against the [`Plan`] of the request it answers. The normative
//! description is `docs/circuit_zk_response.md`; the shared conformance
//! vectors are `tests/vectors/circuit_zk_response/`.
//!
//! It judges structure and the request/response binding only. It does **not**
//! verify the proof, and it does not decode it: a `proof` is checked to be
//! non-empty unpadded base64url and nothing more. Proof verification belongs to
//! the proof system's verifier.
//!
//! Nothing here is wired into matching, the FFI or the WASM picker.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(missing_docs)]

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::base64url;
use crate::circuit_zk::{Params, Plan};

/// Length in bytes of a decoded `pseudonym-v1-sha256` result.
pub const PSEUDONYM_LEN: usize = 32;

/// Why a `circuit_zk` response was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidResponse {
    /// The `vp_token` is not a JSON object.
    ResponseNotParseable,
    /// A JSON object has the same member name twice, outside `results`.
    DuplicateMember {
        /// The repeated member name.
        member: String,
    },
    /// The `vp_token` has no entry for the request's credential query id.
    QueryIdMissing,
    /// The entry is not an array.
    PresentationsNotArray,
    /// The entry is an empty array.
    PresentationsEmpty,
    /// More than one presentation, but the query does not set `multiple: true`.
    PresentationsMultipleNotAllowed,
    /// An array element is not an object.
    PresentationNotObject {
        /// Position in the array.
        index: usize,
    },
    /// The presentation carries an in-band `error` or `error_description`.
    /// Errors travel as an OpenID4VP decline, not in a presentation.
    PresentationErrorMember {
        /// Position in the array.
        index: usize,
    },
    /// The presentation has a member outside the defined four.
    PresentationUnknownMember {
        /// Position in the array.
        index: usize,
        /// The member name.
        member: String,
    },
    /// One of `circuit_id`, `proof_system`, `proof`, `results` is absent.
    PresentationMemberMissing {
        /// Position in the array.
        index: usize,
        /// The member name.
        member: &'static str,
    },
    /// A member has the wrong JSON type.
    PresentationMemberWrongType {
        /// Position in the array.
        index: usize,
        /// The member name.
        member: &'static str,
    },
    /// `circuit_id` is not one the request offered.
    CircuitIdNotOffered {
        /// Position in the array.
        index: usize,
    },
    /// `proof_system` is not one the request offered.
    ProofSystemNotOffered {
        /// Position in the array.
        index: usize,
    },
    /// `proof` is empty.
    ProofEmpty {
        /// Position in the array.
        index: usize,
    },
    /// `proof` is not unpadded base64url.
    ProofNotBase64url {
        /// Position in the array.
        index: usize,
    },
    /// `results` repeats a handle.
    DuplicateHandle {
        /// The repeated handle.
        handle: String,
    },
    /// The request returns a handle that `results` does not have.
    ResultHandleMissing {
        /// The handle.
        handle: String,
    },
    /// `results` has a handle the request did not return.
    ResultHandleUnexpected {
        /// The handle.
        handle: String,
    },
    /// A result value is not a JSON object.
    ResultNotObject {
        /// The handle.
        handle: String,
    },
    /// The request asked for a function this validator has no result shape for.
    ResultFunctionUnknown {
        /// The handle.
        handle: String,
    },
    /// A result object has a member its function does not define.
    ResultUnknownMember {
        /// The handle.
        handle: String,
        /// The member name.
        member: String,
    },
    /// A result object lacks its function's member.
    ResultMemberMissing {
        /// The handle.
        handle: String,
    },
    /// A result member has the wrong JSON type.
    ResultMemberWrongType {
        /// The handle.
        handle: String,
    },
    /// `age_check` returned `satisfied: false`.
    ResultNotSatisfied {
        /// The handle.
        handle: String,
    },
    /// A pseudonym is not unpadded base64url.
    PseudonymNotBase64url {
        /// The handle.
        handle: String,
    },
    /// A pseudonym does not decode to exactly [`PSEUDONYM_LEN`] bytes.
    PseudonymWrongLength {
        /// The handle.
        handle: String,
    },
}

impl InvalidResponse {
    /// A stable identifier for the refusal, shared with the conformance
    /// vectors. Unlike the `Display` text, it does not change wording.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::ResponseNotParseable => "response_not_parseable",
            Self::DuplicateMember { .. } => "duplicate_member",
            Self::QueryIdMissing => "query_id_missing",
            Self::PresentationsNotArray => "presentations_not_array",
            Self::PresentationsEmpty => "presentations_empty",
            Self::PresentationsMultipleNotAllowed => "presentations_multiple_not_allowed",
            Self::PresentationNotObject { .. } => "presentation_not_object",
            Self::PresentationErrorMember { .. } => "presentation_error_member",
            Self::PresentationUnknownMember { .. } => "presentation_unknown_member",
            Self::PresentationMemberMissing { .. } => "presentation_member_missing",
            Self::PresentationMemberWrongType { .. } => "presentation_member_wrong_type",
            Self::CircuitIdNotOffered { .. } => "circuit_id_not_offered",
            Self::ProofSystemNotOffered { .. } => "proof_system_not_offered",
            Self::ProofEmpty { .. } => "proof_empty",
            Self::ProofNotBase64url { .. } => "proof_not_base64url",
            Self::DuplicateHandle { .. } => "duplicate_handle",
            Self::ResultHandleMissing { .. } => "result_handle_missing",
            Self::ResultHandleUnexpected { .. } => "result_handle_unexpected",
            Self::ResultNotObject { .. } => "result_not_object",
            Self::ResultFunctionUnknown { .. } => "result_function_unknown",
            Self::ResultUnknownMember { .. } => "result_unknown_member",
            Self::ResultMemberMissing { .. } => "result_member_missing",
            Self::ResultMemberWrongType { .. } => "result_member_wrong_type",
            Self::ResultNotSatisfied { .. } => "result_not_satisfied",
            Self::PseudonymNotBase64url { .. } => "pseudonym_not_base64url",
            Self::PseudonymWrongLength { .. } => "pseudonym_wrong_length",
        }
    }
}

impl fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "circuit_zk response refused: {}", self.code())?;
        match self {
            Self::DuplicateMember { member: h }
            | Self::DuplicateHandle { handle: h }
            | Self::ResultHandleMissing { handle: h }
            | Self::ResultHandleUnexpected { handle: h }
            | Self::ResultNotObject { handle: h }
            | Self::ResultFunctionUnknown { handle: h }
            | Self::ResultUnknownMember { handle: h, .. }
            | Self::ResultMemberMissing { handle: h }
            | Self::ResultMemberWrongType { handle: h }
            | Self::ResultNotSatisfied { handle: h }
            | Self::PseudonymNotBase64url { handle: h }
            | Self::PseudonymWrongLength { handle: h } => write!(f, " (`{h}`)"),
            Self::PresentationNotObject { index }
            | Self::PresentationErrorMember { index }
            | Self::PresentationUnknownMember { index, .. }
            | Self::PresentationMemberMissing { index, .. }
            | Self::PresentationMemberWrongType { index, .. }
            | Self::CircuitIdNotOffered { index }
            | Self::ProofSystemNotOffered { index }
            | Self::ProofEmpty { index }
            | Self::ProofNotBase64url { index } => write!(f, " (presentation {index})"),
            _ => Ok(()),
        }
    }
}

impl std::error::Error for InvalidResponse {}

/// JSON that keeps duplicate object members instead of silently dropping all
/// but one, which `serde_json::Value` does.
enum Json {
    Object(Vec<(String, Json)>),
    Array(Vec<Json>),
    Scalar(Value),
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Json;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Json, E> {
                Ok(Json::Scalar(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Json, E> {
                Ok(Json::Scalar(Value::from(v)))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Json, E> {
                Ok(Json::Scalar(Value::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Json, E> {
                Ok(Json::Scalar(Value::from(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Json, E> {
                Ok(Json::Scalar(Value::String(v.to_owned())))
            }
            fn visit_unit<E>(self) -> Result<Json, E> {
                Ok(Json::Scalar(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
                let mut out = Vec::new();
                while let Some(item) = seq.next_element()? {
                    out.push(item);
                }
                Ok(Json::Array(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
                let mut out = Vec::new();
                while let Some(entry) = map.next_entry::<String, Json>()? {
                    out.push(entry);
                }
                Ok(Json::Object(out))
            }
        }
        d.deserialize_any(V).map_err(de::Error::custom)
    }
}

impl Json {
    fn as_str(&self) -> Option<&str> {
        match self {
            Self::Scalar(Value::String(s)) => Some(s),
            _ => None,
        }
    }
}

/// The members of an object, refusing a repeated name.
fn unique_members(members: &[(String, Json)]) -> Result<Vec<(&str, &Json)>, InvalidResponse> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(members.len());
    for (k, v) in members {
        if !seen.insert(k.as_str()) {
            return Err(InvalidResponse::DuplicateMember { member: k.clone() });
        }
        out.push((k.as_str(), v));
    }
    Ok(out)
}

fn find<'a>(members: &[(&str, &'a Json)], name: &str) -> Option<&'a Json> {
    members.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
}

/// Validate the `circuit_zk` entry of a `vp_token` against its request.
///
/// `vp_token_json` is the whole `vp_token` object. The entry checked is the one
/// keyed by the credential query's `id` (`plan.raw["id"]`); other keys belong
/// to other credential queries and are ignored. Every presentation in the entry
/// is checked against the same request.
///
/// See the module docs and `docs/circuit_zk_response.md` for the rules.
///
/// # Errors
///
/// [`InvalidResponse`] naming the first rule broken.
pub fn validate_response(plan: &Plan, vp_token_json: &str) -> Result<(), InvalidResponse> {
    let token: Json =
        serde_json::from_str(vp_token_json).map_err(|_| InvalidResponse::ResponseNotParseable)?;
    let Json::Object(token) = token else {
        return Err(InvalidResponse::ResponseNotParseable);
    };
    let token = unique_members(&token)?;
    let query_id = plan
        .raw
        .get("id")
        .and_then(Value::as_str)
        .ok_or(InvalidResponse::QueryIdMissing)?;
    let entry = find(&token, query_id).ok_or(InvalidResponse::QueryIdMissing)?;
    let Json::Array(presentations) = entry else {
        return Err(InvalidResponse::PresentationsNotArray);
    };
    if presentations.is_empty() {
        return Err(InvalidResponse::PresentationsEmpty);
    }
    // DCQL: `multiple` omitted means false, i.e. at most one presentation.
    if presentations.len() > 1 && plan.raw.get("multiple") != Some(&Value::Bool(true)) {
        return Err(InvalidResponse::PresentationsMultipleNotAllowed);
    }
    for (index, presentation) in presentations.iter().enumerate() {
        check_presentation(plan, index, presentation)?;
    }
    Ok(())
}

const MEMBERS: [&str; 4] = ["circuit_id", "proof_system", "proof", "results"];

fn check_presentation(plan: &Plan, index: usize, p: &Json) -> Result<(), InvalidResponse> {
    let Json::Object(members) = p else {
        return Err(InvalidResponse::PresentationNotObject { index });
    };
    let members = unique_members(members)?;
    if members
        .iter()
        .any(|(k, _)| *k == "error" || *k == "error_description")
    {
        return Err(InvalidResponse::PresentationErrorMember { index });
    }
    if let Some((k, _)) = members.iter().find(|(k, _)| !MEMBERS.contains(k)) {
        return Err(InvalidResponse::PresentationUnknownMember {
            index,
            member: (*k).to_owned(),
        });
    }
    let get = |member: &'static str| {
        find(&members, member).ok_or(InvalidResponse::PresentationMemberMissing { index, member })
    };
    let string = |member: &'static str| {
        get(member)?
            .as_str()
            .ok_or(InvalidResponse::PresentationMemberWrongType { index, member })
    };

    // Presence of every member first, then types, then the offer and the proof.
    for member in MEMBERS {
        get(member)?;
    }
    let circuit_id = string("circuit_id")?;
    let proof_system = string("proof_system")?;
    let proof = string("proof")?;
    let results = get("results")?;
    if !matches!(results, Json::Object(_)) {
        return Err(InvalidResponse::PresentationMemberWrongType {
            index,
            member: "results",
        });
    }

    // Fail closed: a request that stated no list offered nothing to match.
    let offered = |list: &Option<Vec<String>>, v: &str| {
        list.as_ref().is_some_and(|l| l.iter().any(|o| o == v))
    };
    if !offered(&plan.circuit_filter.circuit_ids, circuit_id) {
        return Err(InvalidResponse::CircuitIdNotOffered { index });
    }
    if !offered(&plan.circuit_filter.proof_systems, proof_system) {
        return Err(InvalidResponse::ProofSystemNotOffered { index });
    }
    if proof.is_empty() {
        return Err(InvalidResponse::ProofEmpty { index });
    }
    if !is_unpadded_base64url(proof) {
        return Err(InvalidResponse::ProofNotBase64url { index });
    }
    check_results(plan, index, results)
}

/// Strict unpadded base64url, without decoding. (`base64url::decode` caps its
/// input at 256 KiB, which a real proof can exceed.)
fn is_unpadded_base64url(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() % 4 == 1
        || !b
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
    {
        return false;
    }
    // Trailing bits of the last character must be zero (canonical encoding).
    let Some(&last) = b.last() else { return true };
    let v = match last {
        b'A'..=b'Z' => last - b'A',
        b'a'..=b'z' => last - b'a' + 26,
        b'0'..=b'9' => last - b'0' + 52,
        b'-' => 62,
        _ => 63,
    };
    match b.len() % 4 {
        2 => v & 0x0F == 0,
        3 => v & 0x03 == 0,
        _ => true,
    }
}

fn check_results(plan: &Plan, index: usize, results: &Json) -> Result<(), InvalidResponse> {
    let Json::Object(entries) = results else {
        // Reported against the member, not a handle.
        return Err(InvalidResponse::PresentationMemberWrongType {
            index,
            member: "results",
        });
    };
    let mut seen = HashSet::new();
    for (handle, _) in entries {
        if !seen.insert(handle.as_str()) {
            return Err(InvalidResponse::DuplicateHandle {
                handle: handle.clone(),
            });
        }
    }
    let wanted: HashSet<&str> = plan.functions.iter().map(|f| f.handle.as_str()).collect();
    if let Some((handle, _)) = entries.iter().find(|(h, _)| !wanted.contains(h.as_str())) {
        return Err(InvalidResponse::ResultHandleUnexpected {
            handle: handle.clone(),
        });
    }
    // Every handle is present before any value is judged (rule 6 before 7).
    for function in &plan.functions {
        if !entries.iter().any(|(h, _)| *h == function.handle) {
            return Err(InvalidResponse::ResultHandleMissing {
                handle: function.handle.clone(),
            });
        }
    }
    for function in &plan.functions {
        let handle = function.handle.clone();
        let Some((_, value)) = entries.iter().find(|(h, _)| *h == function.handle) else {
            return Err(InvalidResponse::ResultHandleMissing { handle });
        };
        let Json::Object(members) = value else {
            return Err(InvalidResponse::ResultNotObject { handle });
        };
        let members = unique_members(members)?;
        match &function.params {
            Params::Pseudonym { .. } => check_pseudonym(handle, &members)?,
            Params::AgeCheck { .. } => check_age(handle, &members)?,
            Params::Unknown(_) => return Err(InvalidResponse::ResultFunctionUnknown { handle }),
        }
    }
    Ok(())
}

/// The one member a result object may have, or the reason it cannot.
fn sole_member<'a>(
    handle: &str,
    members: &[(&str, &'a Json)],
    name: &str,
) -> Result<&'a Json, InvalidResponse> {
    if let Some((k, _)) = members.iter().find(|(k, _)| *k != name) {
        return Err(InvalidResponse::ResultUnknownMember {
            handle: handle.to_owned(),
            member: (*k).to_owned(),
        });
    }
    find(members, name).ok_or_else(|| InvalidResponse::ResultMemberMissing {
        handle: handle.to_owned(),
    })
}

fn check_pseudonym(handle: String, members: &[(&str, &Json)]) -> Result<(), InvalidResponse> {
    let value = sole_member(&handle, members, "pseudonym")?;
    let Some(text) = value.as_str() else {
        return Err(InvalidResponse::ResultMemberWrongType { handle });
    };
    match base64url::decode(text) {
        None => Err(InvalidResponse::PseudonymNotBase64url { handle }),
        Some(bytes) if bytes.len() != PSEUDONYM_LEN => {
            Err(InvalidResponse::PseudonymWrongLength { handle })
        }
        Some(_) => Ok(()),
    }
}

fn check_age(handle: String, members: &[(&str, &Json)]) -> Result<(), InvalidResponse> {
    match sole_member(&handle, members, "satisfied")? {
        Json::Scalar(Value::Bool(true)) => Ok(()),
        Json::Scalar(Value::Bool(false)) => Err(InvalidResponse::ResultNotSatisfied { handle }),
        _ => Err(InvalidResponse::ResultMemberWrongType { handle }),
    }
}
