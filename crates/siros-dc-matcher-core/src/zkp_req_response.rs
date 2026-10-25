//! Response validator for `zkp_req` presentations (rulebook v0.4).
//!
//! [`validate_response`] checks the *shape* of a `zkp_req` entry in a
//! `vp_token` against the [`Plan`] of the request it answers. Each element of
//! the entry's array is the base64url (unpadded) CBOR encoding of a
//! `ZkpPresentation`:
//!
//! ```cddl
//! ZkpPresentation = {
//!   "system_id"      => tstr,
//!   "proof"          => bstr,
//!   "issuer_key_set" => [+ bstr],
//!   ? "proof_time"   => tdate,      ; tag 0
//!   "results"        => { + tstr => bstr / true }
//! }
//! ```
//!
//! The normative description is `docs/zkp_req_response.md`; the shared
//! conformance vectors are `tests/vectors/zkp_req_response/`.
//!
//! It judges structure and the request/response binding only. It does **not**
//! verify the proof or any certificate, and it does not look inside `proof`.
//! The `proof_time` tolerance check is the verifier's and lives in
//! [`crate::proof_time`].
//!
//! The CBOR reader is strict and local to this module: definite lengths only,
//! no duplicate map keys, no trailing bytes, and a nesting limit.
//!
//! Nothing here is wired into matching, the FFI or the WASM picker.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(missing_docs)]

use rustc_hash::FxHashSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::base64url;
use crate::proof_time;
use crate::zkp_req::{Params, Plan, SOURCE_MSO_MDOC};

/// Length in bytes of a `pseudonym` result with `prf` `sha-256`.
pub const PSEUDONYM_LEN_SHA256: usize = 32;
/// Length in bytes of a `pseudonym` result with `prf` `hashdh-bls12381g1`
/// (a compressed G1 point).
pub const PSEUDONYM_LEN_HASHDH: usize = 48;
/// Most certificates an `issuer_key_set` may carry.
pub const ISSUER_KEY_SET_MAX: usize = 8;
/// Largest element of an `issuer_key_set`, in bytes.
pub const ISSUER_KEY_MAX_BYTES: usize = 4096;
/// Deepest CBOR nesting the reader accepts.
pub const CBOR_MAX_DEPTH: usize = 16;

/// Why a `zkp_req` response was refused.
///
/// `index` is the position of the presentation in the entry's array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidResponse {
    /// The `vp_token` is not a JSON object.
    ResponseNotParseable,
    /// The `vp_token` object has the same member name twice.
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
    /// An array element is not a JSON string.
    PresentationNotString {
        /// Position in the array.
        index: usize,
    },
    /// An array element is not unpadded base64url with a canonical end.
    PresentationNotBase64url {
        /// Position in the array.
        index: usize,
    },
    /// The CBOR is truncated, uses a reserved encoding, invalid UTF-8, or
    /// nests too deeply.
    CborMalformed {
        /// Position in the array.
        index: usize,
    },
    /// The CBOR uses an indefinite-length string, array or map.
    CborIndefiniteLength {
        /// Position in the array.
        index: usize,
    },
    /// Bytes follow the single CBOR item.
    CborTrailingBytes {
        /// Position in the array.
        index: usize,
    },
    /// A CBOR map repeats a key (at any level).
    CborDuplicateKey {
        /// Position in the array.
        index: usize,
    },
    /// The presentation is not a CBOR map.
    PresentationNotMap {
        /// Position in the array.
        index: usize,
    },
    /// A presentation key is not a text string.
    PresentationKeyNotText {
        /// Position in the array.
        index: usize,
    },
    /// The presentation has a member outside the defined five.
    PresentationUnknownMember {
        /// Position in the array.
        index: usize,
        /// The member name.
        member: String,
    },
    /// A required member is absent.
    PresentationMemberMissing {
        /// Position in the array.
        index: usize,
        /// The member name.
        member: &'static str,
    },
    /// A member has the wrong CBOR type.
    PresentationMemberWrongType {
        /// Position in the array.
        index: usize,
        /// The member name.
        member: &'static str,
    },
    /// `system_id` is not one the request offered (or it offered none).
    SystemIdNotOffered {
        /// Position in the array.
        index: usize,
    },
    /// `proof` is empty.
    ProofEmpty {
        /// Position in the array.
        index: usize,
    },
    /// `issuer_key_set` is an empty array.
    IssuerKeySetEmpty {
        /// Position in the array.
        index: usize,
    },
    /// `issuer_key_set` has more than [`ISSUER_KEY_SET_MAX`] elements.
    IssuerKeySetTooMany {
        /// Position in the array.
        index: usize,
    },
    /// An `issuer_key_set` element is not a byte string.
    IssuerKeyNotBytes {
        /// Position in the array.
        index: usize,
    },
    /// An `issuer_key_set` element is empty.
    IssuerKeyEmpty {
        /// Position in the array.
        index: usize,
    },
    /// An `issuer_key_set` element is longer than [`ISSUER_KEY_MAX_BYTES`].
    IssuerKeyTooLarge {
        /// Position in the array.
        index: usize,
    },
    /// `proof_time` is absent, and the source format's systems check validity.
    ProofTimeMissing {
        /// Position in the array.
        index: usize,
    },
    /// `proof_time` is not a tag-0 text string.
    ProofTimeNotTdate {
        /// Position in the array.
        index: usize,
    },
    /// `proof_time` is a tdate, but not the exact 20-byte form.
    ProofTimeForm {
        /// Position in the array.
        index: usize,
    },
    /// `results` has a key that is not a text string.
    ResultKeyNotText {
        /// Position in the array.
        index: usize,
    },
    /// `results` has a handle the request did not return.
    ResultHandleUnexpected {
        /// The handle.
        handle: String,
    },
    /// The request returns a handle that `results` does not have.
    ResultHandleMissing {
        /// The handle.
        handle: String,
    },
    /// The request asked for a function this validator has no result shape
    /// for.
    ResultFunctionUnknown {
        /// The handle.
        handle: String,
    },
    /// A result value has the wrong CBOR type (a pseudonym must be a byte
    /// string, a predicate must be a boolean).
    ResultWrongType {
        /// The handle.
        handle: String,
    },
    /// A predicate result is `false`.
    ResultNotSatisfied {
        /// The handle.
        handle: String,
    },
    /// The pseudonym's `prf` is missing or unknown, so its length is unknown.
    PseudonymPrfUnknown {
        /// The handle.
        handle: String,
    },
    /// A pseudonym is not the length its `prf` sets.
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
            Self::PresentationNotString { .. } => "presentation_not_string",
            Self::PresentationNotBase64url { .. } => "presentation_not_base64url",
            Self::CborMalformed { .. } => "cbor_malformed",
            Self::CborIndefiniteLength { .. } => "cbor_indefinite_length",
            Self::CborTrailingBytes { .. } => "cbor_trailing_bytes",
            Self::CborDuplicateKey { .. } => "cbor_duplicate_key",
            Self::PresentationNotMap { .. } => "presentation_not_map",
            Self::PresentationKeyNotText { .. } => "presentation_key_not_text",
            Self::PresentationUnknownMember { .. } => "presentation_unknown_member",
            Self::PresentationMemberMissing { .. } => "presentation_member_missing",
            Self::PresentationMemberWrongType { .. } => "presentation_member_wrong_type",
            Self::SystemIdNotOffered { .. } => "system_id_not_offered",
            Self::ProofEmpty { .. } => "proof_empty",
            Self::IssuerKeySetEmpty { .. } => "issuer_key_set_empty",
            Self::IssuerKeySetTooMany { .. } => "issuer_key_set_too_many",
            Self::IssuerKeyNotBytes { .. } => "issuer_key_not_bytes",
            Self::IssuerKeyEmpty { .. } => "issuer_key_empty",
            Self::IssuerKeyTooLarge { .. } => "issuer_key_too_large",
            Self::ProofTimeMissing { .. } => "proof_time_missing",
            Self::ProofTimeNotTdate { .. } => "proof_time_not_tdate",
            Self::ProofTimeForm { .. } => "proof_time_form",
            Self::ResultKeyNotText { .. } => "result_key_not_text",
            Self::ResultHandleUnexpected { .. } => "result_handle_unexpected",
            Self::ResultHandleMissing { .. } => "result_handle_missing",
            Self::ResultFunctionUnknown { .. } => "result_function_unknown",
            Self::ResultWrongType { .. } => "result_wrong_type",
            Self::ResultNotSatisfied { .. } => "result_not_satisfied",
            Self::PseudonymPrfUnknown { .. } => "pseudonym_prf_unknown",
            Self::PseudonymWrongLength { .. } => "pseudonym_wrong_length",
        }
    }
}

impl fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zkp_req response refused: {}", self.code())
    }
}

impl std::error::Error for InvalidResponse {}

// ---------------------------------------------------------------------------
// The vp_token: JSON that keeps duplicate members.

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

// ---------------------------------------------------------------------------
// A strict CBOR reader (RFC 8949), only as far as this shape needs.

#[derive(Debug, Clone, PartialEq)]
enum Cbor {
    Uint(u64),
    Nint,
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    /// null, undefined, floats and other simple values, as their raw bytes.
    Other(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CborError {
    Malformed,
    Indefinite,
    Trailing,
    DuplicateKey,
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CborError> {
        if n > self.rest.len() {
            return Err(CborError::Malformed);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn argument(&mut self, info: u8) -> Result<u64, CborError> {
        let width = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(CborError::Malformed),
        };
        Ok(self
            .take(width)?
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
    }

    fn item(&mut self, depth: usize) -> Result<Cbor, CborError> {
        if depth > CBOR_MAX_DEPTH {
            return Err(CborError::Malformed);
        }
        let initial = *self.take(1)?.first().ok_or(CborError::Malformed)?;
        let (major, info) = (initial >> 5, initial & 0x1f);
        if major == 7 {
            return match info {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                28..=31 => Err(CborError::Malformed),
                _ => {
                    let width = match info {
                        24 => 1,
                        25 => 2,
                        26 => 4,
                        27 => 8,
                        _ => 0,
                    };
                    let mut raw = vec![initial];
                    raw.extend_from_slice(self.take(width)?);
                    Ok(Cbor::Other(raw))
                }
            };
        }
        if info == 31 {
            return Err(if (2..=5).contains(&major) {
                CborError::Indefinite
            } else {
                CborError::Malformed
            });
        }
        let arg = self.argument(info)?;
        match major {
            0 => Ok(Cbor::Uint(arg)),
            1 => Ok(Cbor::Nint),
            2 | 3 => {
                let len = usize::try_from(arg).map_err(|_| CborError::Malformed)?;
                let bytes = self.take(len)?;
                if major == 2 {
                    Ok(Cbor::Bytes(bytes.to_vec()))
                } else {
                    String::from_utf8(bytes.to_vec())
                        .map(Cbor::Text)
                        .map_err(|_| CborError::Malformed)
                }
            }
            4 => {
                let len = usize::try_from(arg).map_err(|_| CborError::Malformed)?;
                // Every element takes at least a byte: refuse impossible
                // lengths before allocating for them.
                if len > self.rest.len() {
                    return Err(CborError::Malformed);
                }
                let mut out = Vec::with_capacity(len);
                for _ in 0..len {
                    out.push(self.item(depth + 1)?);
                }
                Ok(Cbor::Array(out))
            }
            5 => {
                let len = usize::try_from(arg).map_err(|_| CborError::Malformed)?;
                if len > self.rest.len() {
                    return Err(CborError::Malformed);
                }
                let mut out: Vec<(Cbor, Cbor)> = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    if out.iter().any(|(k, _)| *k == key) {
                        return Err(CborError::DuplicateKey);
                    }
                    out.push((key, value));
                }
                Ok(Cbor::Map(out))
            }
            _ => Ok(Cbor::Tag(arg, Box::new(self.item(depth + 1)?))),
        }
    }
}

fn decode_cbor(bytes: &[u8]) -> Result<Cbor, CborError> {
    let mut reader = Reader { rest: bytes };
    let item = reader.item(0)?;
    if reader.rest.is_empty() {
        Ok(item)
    } else {
        Err(CborError::Trailing)
    }
}

// ---------------------------------------------------------------------------
// The presentation.

/// A presentation that passed [`validate_response`]'s shape checks, for the
/// verifier to take its statement from (`issuer_key_set`, `proof_time` and
/// `results` only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presentation {
    /// The approved system the prover says it used.
    pub system_id: String,
    /// The proof, opaque here.
    pub proof: Vec<u8>,
    /// Issuer keys (DER Document Signer certificates for `mso_mdoc`).
    pub issuer_key_set: Vec<Vec<u8>>,
    /// `proof_time`, when present: the exact 20-byte form.
    pub proof_time: Option<String>,
    /// Results by handle, in the order the request returns them.
    pub results: Vec<(String, ResultValue)>,
}

/// A validated result value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultValue {
    /// A `pseudonym` result.
    Pseudonym(Vec<u8>),
    /// An `age_check` result (always `true`).
    Predicate,
}

/// Validate the `zkp_req` entry of a `vp_token` against its request.
///
/// `vp_token_json` is the whole `vp_token` object. The entry checked is the
/// one keyed by the credential query's `id` (`plan.raw["id"]`); other keys
/// belong to other credential queries and are ignored. Every presentation in
/// the entry is checked against the same request.
///
/// See the module docs and `docs/zkp_req_response.md` for the rules.
///
/// # Errors
///
/// [`InvalidResponse`] naming the first rule broken.
pub fn validate_response(plan: &Plan, vp_token_json: &str) -> Result<(), InvalidResponse> {
    parse_response(plan, vp_token_json).map(|_| ())
}

/// [`validate_response`], returning the decoded presentations.
///
/// # Errors
///
/// As [`validate_response`].
pub fn parse_response(
    plan: &Plan,
    vp_token_json: &str,
) -> Result<Vec<Presentation>, InvalidResponse> {
    let token: Json =
        serde_json::from_str(vp_token_json).map_err(|_| InvalidResponse::ResponseNotParseable)?;
    let Json::Object(token) = token else {
        return Err(InvalidResponse::ResponseNotParseable);
    };
    let mut seen = FxHashSet::default();
    for (k, _) in &token {
        if !seen.insert(k.as_str()) {
            return Err(InvalidResponse::DuplicateMember { member: k.clone() });
        }
    }
    let query_id = plan
        .raw
        .get("id")
        .and_then(Value::as_str)
        .ok_or(InvalidResponse::QueryIdMissing)?;
    let entry = token
        .iter()
        .find(|(k, _)| k == query_id)
        .map(|(_, v)| v)
        .ok_or(InvalidResponse::QueryIdMissing)?;
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
    presentations
        .iter()
        .enumerate()
        .map(|(index, p)| check_presentation(plan, index, p))
        .collect()
}

const MEMBERS: [&str; 5] = [
    "system_id",
    "proof",
    "issuer_key_set",
    "proof_time",
    "results",
];
const REQUIRED: [&str; 4] = ["system_id", "proof", "issuer_key_set", "results"];

fn check_presentation(
    plan: &Plan,
    index: usize,
    element: &Json,
) -> Result<Presentation, InvalidResponse> {
    let Json::Scalar(Value::String(text)) = element else {
        return Err(InvalidResponse::PresentationNotString { index });
    };
    let bytes =
        base64url::decode(text).ok_or(InvalidResponse::PresentationNotBase64url { index })?;
    let item = decode_cbor(&bytes).map_err(|e| match e {
        CborError::Malformed => InvalidResponse::CborMalformed { index },
        CborError::Indefinite => InvalidResponse::CborIndefiniteLength { index },
        CborError::Trailing => InvalidResponse::CborTrailingBytes { index },
        CborError::DuplicateKey => InvalidResponse::CborDuplicateKey { index },
    })?;
    let Cbor::Map(entries) = item else {
        return Err(InvalidResponse::PresentationNotMap { index });
    };

    let mut members: Vec<(&str, &Cbor)> = Vec::with_capacity(entries.len());
    for (k, v) in &entries {
        let Cbor::Text(name) = k else {
            return Err(InvalidResponse::PresentationKeyNotText { index });
        };
        members.push((name.as_str(), v));
    }
    if let Some((name, _)) = members.iter().find(|(k, _)| !MEMBERS.contains(k)) {
        return Err(InvalidResponse::PresentationUnknownMember {
            index,
            member: (*name).to_owned(),
        });
    }
    let find = |name: &str| members.iter().find(|(k, _)| *k == name).map(|(_, v)| *v);
    for member in REQUIRED {
        if find(member).is_none() {
            return Err(InvalidResponse::PresentationMemberMissing { index, member });
        }
    }
    let wrong =
        |member: &'static str| InvalidResponse::PresentationMemberWrongType { index, member };
    let Some(Cbor::Text(system_id)) = find("system_id") else {
        return Err(wrong("system_id"));
    };
    let Some(Cbor::Bytes(proof)) = find("proof") else {
        return Err(wrong("proof"));
    };
    let Some(Cbor::Array(keys)) = find("issuer_key_set") else {
        return Err(wrong("issuer_key_set"));
    };
    let Some(Cbor::Map(results)) = find("results") else {
        return Err(wrong("results"));
    };
    let proof_time_item = find("proof_time");

    // Binding to the offer. Fail closed: a request that stated no list offered
    // nothing to match. The presentation carries no proof system, so only
    // `system_id_values` can be checked here; the verifier's registry maps the
    // system id to its proof system.
    let offered = plan
        .system_filter
        .system_ids
        .as_ref()
        .is_some_and(|l| l.iter().any(|o| o == system_id));
    if !offered {
        return Err(InvalidResponse::SystemIdNotOffered { index });
    }
    if proof.is_empty() {
        return Err(InvalidResponse::ProofEmpty { index });
    }
    let issuer_key_set = check_issuer_key_set(index, keys)?;
    let proof_time = check_proof_time(plan, index, proof_time_item)?;
    let results = check_results(plan, index, results)?;

    Ok(Presentation {
        system_id: system_id.clone(),
        proof: proof.clone(),
        issuer_key_set,
        proof_time,
        results,
    })
}

/// Encoding and limits only. The certificates are not parsed.
fn check_issuer_key_set(index: usize, keys: &[Cbor]) -> Result<Vec<Vec<u8>>, InvalidResponse> {
    if keys.is_empty() {
        return Err(InvalidResponse::IssuerKeySetEmpty { index });
    }
    if keys.len() > ISSUER_KEY_SET_MAX {
        return Err(InvalidResponse::IssuerKeySetTooMany { index });
    }
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        let Cbor::Bytes(bytes) = key else {
            return Err(InvalidResponse::IssuerKeyNotBytes { index });
        };
        if bytes.is_empty() {
            return Err(InvalidResponse::IssuerKeyEmpty { index });
        }
        if bytes.len() > ISSUER_KEY_MAX_BYTES {
            return Err(InvalidResponse::IssuerKeyTooLarge { index });
        }
        out.push(bytes.clone());
    }
    Ok(out)
}

/// `proof_time`: required for `mso_mdoc` (every approved circuit checks the
/// MSO validity period), optional otherwise. When present it is a tag-0 text
/// string in the exact 20-byte form, the circuit's public input.
fn check_proof_time(
    plan: &Plan,
    index: usize,
    item: Option<&Cbor>,
) -> Result<Option<String>, InvalidResponse> {
    let Some(item) = item else {
        return if plan.source_format == SOURCE_MSO_MDOC {
            Err(InvalidResponse::ProofTimeMissing { index })
        } else {
            Ok(None)
        };
    };
    let Cbor::Tag(0, inner) = item else {
        return Err(InvalidResponse::ProofTimeNotTdate { index });
    };
    let Cbor::Text(text) = inner.as_ref() else {
        return Err(InvalidResponse::ProofTimeNotTdate { index });
    };
    if proof_time::parse(text).is_err() {
        return Err(InvalidResponse::ProofTimeForm { index });
    }
    Ok(Some(text.clone()))
}

/// Handles first (unexpected, then missing, all before any value), then the
/// values in request order.
fn check_results(
    plan: &Plan,
    index: usize,
    results: &[(Cbor, Cbor)],
) -> Result<Vec<(String, ResultValue)>, InvalidResponse> {
    let mut named: Vec<(&str, &Cbor)> = Vec::with_capacity(results.len());
    for (k, v) in results {
        let Cbor::Text(handle) = k else {
            return Err(InvalidResponse::ResultKeyNotText { index });
        };
        named.push((handle.as_str(), v));
    }
    let wanted: FxHashSet<&str> = plan.functions.iter().map(|f| f.handle.as_str()).collect();
    if let Some((handle, _)) = named.iter().find(|(h, _)| !wanted.contains(h)) {
        return Err(InvalidResponse::ResultHandleUnexpected {
            handle: (*handle).to_owned(),
        });
    }
    for function in &plan.functions {
        if !named.iter().any(|(h, _)| *h == function.handle) {
            return Err(InvalidResponse::ResultHandleMissing {
                handle: function.handle.clone(),
            });
        }
    }

    let mut out = Vec::with_capacity(plan.functions.len());
    for function in &plan.functions {
        let handle = function.handle.clone();
        let Some((_, value)) = named.iter().find(|(h, _)| *h == function.handle) else {
            return Err(InvalidResponse::ResultHandleMissing { handle });
        };
        let checked = match &function.params {
            Params::Pseudonym { prf, .. } => {
                let want = match prf.as_deref() {
                    Some("sha-256") => PSEUDONYM_LEN_SHA256,
                    Some("hashdh-bls12381g1") => PSEUDONYM_LEN_HASHDH,
                    _ => return Err(InvalidResponse::PseudonymPrfUnknown { handle }),
                };
                let Cbor::Bytes(bytes) = value else {
                    return Err(InvalidResponse::ResultWrongType { handle });
                };
                if bytes.len() != want {
                    return Err(InvalidResponse::PseudonymWrongLength { handle });
                }
                ResultValue::Pseudonym(bytes.clone())
            }
            Params::AgeCheck { .. } => match value {
                Cbor::Bool(true) => ResultValue::Predicate,
                // An unsatisfiable predicate is a decline, not a result.
                Cbor::Bool(false) => return Err(InvalidResponse::ResultNotSatisfied { handle }),
                _ => return Err(InvalidResponse::ResultWrongType { handle }),
            },
            Params::Unknown(_) => return Err(InvalidResponse::ResultFunctionUnknown { handle }),
        };
        out.push((handle, checked));
    }
    Ok(out)
}
