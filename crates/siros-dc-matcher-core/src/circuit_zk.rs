//! Planner for `circuit_zk` credential queries.
//!
//! [`plan`] parses a `circuit_zk` credential query (and, optionally, the
//! request's `client_metadata`) into a normalised [`Plan`], or rejects it with
//! [`InvalidRequest`] when it is structurally broken.
//!
//! # Why a separate layer
//!
//! The nym_auth rulebook has two inconsistent shapes in circulation, and both
//! are still moving:
//!
//! - the normative text puts the function calls in `req`, a sibling of `meta`:
//!   `req: [{id, return, params}]`, with `id` the function and `return` the
//!   output handle;
//! - the work-in-progress example nests them under `claims`:
//!   `claims: {_req: [{fn_id, id, params}]}`, with `fn_id` the function and `id`
//!   the handle, and wraps `vp_formats_supported.circuit_zk` in an envelope
//!   `{fn_id, input: base64(json)}`.
//!
//! All of that shape knowledge lives here — the function table, the
//! normaliser and the test vectors — and nowhere else in the matcher.
//!
//! # What the planner does not do
//!
//! It judges **structure**, never **satisfiability**. Whether a request can be
//! served (date spans and ordering, how many items of one function, which
//! `config` values exist, `verifier_context` length,
//! reserved `vct_values`, holder binding, a predicate against the holder's
//! `birth_date`) is decided by wallets, against the [`Plan`]. `config` and
//! `verifier_context` are therefore opaque strings here, and a function this
//! table does not know passes through as [`Params::Unknown`].
//!
//! `verifier_id_type` is no longer part of the `nym_auth` rulebook request: how
//! a verifier is identified is agreed between wallets and verifiers in the
//! shared trust framework. The planner still accepts it and passes it through
//! as an opaque optional string, so legacy and negative-test requests plan; no
//! function requires it and nothing here interprets it.
//!
//! Nothing here is wired into matching, the FFI or the WASM picker.
//!
//! The module runs inside the WASM matcher, where a trap is indistinguishable
//! from "no matching credential", so it must not panic on any input.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(missing_docs)]

use std::collections::HashSet;
use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::base64url;

/// What a planned function call's parameters look like, by type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// Any JSON string.
    String,
    /// A JSON string holding an RFC 3339 `full-date` (`YYYY-MM-DD`).
    FullDate,
}

/// One declared parameter of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamSpec {
    /// The parameter's name in `params`.
    pub name: &'static str,
    /// The type its value must have.
    pub ty: ParamType,
}

/// Which normaliser arm builds a function's [`Params`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FnKind {
    /// `pseudonym-v1-sha256`.
    Pseudonym,
    /// `age_check`.
    AgeCheck,
}

/// A function this planner knows the parameter types of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FnSpec {
    /// The function identifier as it appears in the request.
    pub function_id: &'static str,
    /// The normaliser arm for it.
    pub kind: FnKind,
    /// Its declared parameters. Every one is optional here: presence rules are
    /// satisfiability, which belongs to wallets.
    pub params: &'static [ParamSpec],
}

/// The function table. This is where a new rulebook function is added.
pub const FUNCTIONS: &[FnSpec] = &[
    FnSpec {
        function_id: "pseudonym-v1-sha256",
        kind: FnKind::Pseudonym,
        params: &[
            ParamSpec {
                name: "config",
                ty: ParamType::String,
            },
            ParamSpec {
                name: "verifier_context",
                ty: ParamType::String,
            },
            // Legacy: not in the current rulebook request; opaque pass-through.
            ParamSpec {
                name: "verifier_id_type",
                ty: ParamType::String,
            },
        ],
    },
    FnSpec {
        function_id: "age_check",
        kind: FnKind::AgeCheck,
        params: &[
            ParamSpec {
                name: "ge",
                ty: ParamType::FullDate,
            },
            ParamSpec {
                name: "le",
                ty: ParamType::FullDate,
            },
        ],
    },
];

/// The normalised parameters of one function call.
///
/// Serializes flat — a JSON object of the known parameters that were present,
/// followed by `extra` — so the shared conformance vectors can state it
/// without naming the Rust arm.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Params {
    /// `pseudonym-v1-sha256`. All values are opaque strings to the planner.
    Pseudonym {
        /// `config`.
        #[serde(skip_serializing_if = "Option::is_none")]
        config: Option<String>,
        /// `verifier_context`.
        #[serde(skip_serializing_if = "Option::is_none")]
        verifier_context: Option<String>,
        /// `verifier_id_type`: not carried by the current rulebook request;
        /// accepted and passed through opaquely for legacy requests.
        #[serde(skip_serializing_if = "Option::is_none")]
        verifier_id_type: Option<String>,
        /// Parameters the table does not declare, such as the example shape's
        /// `source`.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// `age_check`. Dates are validated RFC 3339 `full-date` strings; they are
    /// not ordered or compared.
    AgeCheck {
        /// `ge`.
        #[serde(skip_serializing_if = "Option::is_none")]
        ge: Option<String>,
        /// `le`.
        #[serde(skip_serializing_if = "Option::is_none")]
        le: Option<String>,
        /// Parameters the table does not declare.
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// A function the table does not know. Its parameters are untouched.
    Unknown(Map<String, Value>),
}

/// One function call from `req`, normalised.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlannedFunction {
    /// The function identifier (`id` in `req`, `fn_id` in `_req`).
    pub function_id: String,
    /// The output handle (`return` in `req`, `id` in `_req`).
    pub handle: String,
    /// The normalised parameters.
    pub params: Params,
}

/// What the verifier said it accepts, from
/// `client_metadata.vp_formats_supported.circuit_zk`.
///
/// Values are passed through as given. An empty list is not rejected here: it
/// means nothing can match, which is for wallets to conclude.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CircuitFilter {
    /// `circuit_proof_system_values`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_systems: Option<Vec<String>>,
    /// `circuit_id_values`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_ids: Option<Vec<String>>,
}

/// A normalised `circuit_zk` credential query.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    /// The requested function calls, in request order.
    pub functions: Vec<PlannedFunction>,
    /// The verifier's circuit constraints from `client_metadata`.
    pub circuit_filter: CircuitFilter,
    /// `meta.doctype_value`, when present.
    pub meta_doctype: Option<String>,
    /// The credential query exactly as parsed, so that unknown members at any
    /// level survive for wallets that understand them.
    pub raw: Value,
}

/// A structurally invalid `circuit_zk` request.
///
/// Every variant is a defect in the request's shape. None of them says a
/// well-formed request cannot be satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidRequest {
    /// The credential query is not JSON, or not a JSON object.
    QueryNotParseable,
    /// `req` (or `claims._req`) is missing, not an array, or empty.
    ReqMissingOrEmpty,
    /// Both `req` and `claims._req` are present, so the request names its
    /// function calls twice.
    ReqAmbiguous,
    /// A `req` item has no function identifier.
    ItemMissingFunctionId {
        /// Position of the item in the array.
        index: usize,
    },
    /// A `req` item has no output handle.
    ItemMissingHandle {
        /// Position of the item in the array.
        index: usize,
    },
    /// A parameter, or `params` itself, has the wrong JSON type.
    ParamWrongType {
        /// The handle of the item.
        handle: String,
        /// The parameter name, or `params` for the object itself.
        param: String,
    },
    /// A date parameter is not a valid RFC 3339 `full-date`.
    ParamInvalidFullDate {
        /// The handle of the item.
        handle: String,
        /// The parameter name.
        param: String,
    },
    /// Two items share an output handle.
    DuplicateHandle {
        /// The repeated handle.
        handle: String,
    },
    /// `claims` is present and is not the example shape's object holding
    /// `_req` (for instance an ordinary DCQL claims array).
    ClaimsPresent,
    /// `claim_sets` is present.
    ClaimSetsPresent,
    /// `req_sets` is present.
    ReqSetsPresent,
    /// `meta` is missing, not an object, or has a member of the wrong type.
    InvalidMeta,
    /// `client_metadata` is not parseable, or its `circuit_zk` object (or the
    /// envelope around it) has the wrong shape.
    InvalidClientMetadata,
}

impl InvalidRequest {
    /// A stable identifier for the defect, shared with the conformance
    /// vectors. Unlike the `Display` text, it does not change wording.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::QueryNotParseable => "query_not_parseable",
            Self::ReqMissingOrEmpty => "req_missing_or_empty",
            Self::ReqAmbiguous => "req_ambiguous",
            Self::ItemMissingFunctionId { .. } => "item_missing_function_id",
            Self::ItemMissingHandle { .. } => "item_missing_handle",
            Self::ParamWrongType { .. } => "param_wrong_type",
            Self::ParamInvalidFullDate { .. } => "param_invalid_full_date",
            Self::DuplicateHandle { .. } => "duplicate_handle",
            Self::ClaimsPresent => "claims_present",
            Self::ClaimSetsPresent => "claim_sets_present",
            Self::ReqSetsPresent => "req_sets_present",
            Self::InvalidMeta => "invalid_meta",
            Self::InvalidClientMetadata => "invalid_client_metadata",
        }
    }
}

impl fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryNotParseable => f.write_str("credential query is not a JSON object"),
            Self::ReqMissingOrEmpty => f.write_str("`req` is missing or empty"),
            Self::ReqAmbiguous => f.write_str("both `req` and `claims._req` are present"),
            Self::ItemMissingFunctionId { index } => {
                write!(f, "req item {index} has no function id")
            }
            Self::ItemMissingHandle { index } => write!(f, "req item {index} has no handle"),
            Self::ParamWrongType { handle, param } => {
                write!(f, "`{param}` of `{handle}` has the wrong type")
            }
            Self::ParamInvalidFullDate { handle, param } => {
                write!(f, "`{param}` of `{handle}` is not an RFC 3339 full-date")
            }
            Self::DuplicateHandle { handle } => write!(f, "handle `{handle}` is used twice"),
            Self::ClaimsPresent => f.write_str("`claims` is not used by circuit_zk"),
            Self::ClaimSetsPresent => f.write_str("`claim_sets` is not used by circuit_zk"),
            Self::ReqSetsPresent => f.write_str("`req_sets` is not defined"),
            Self::InvalidMeta => f.write_str("`meta` has the wrong shape"),
            Self::InvalidClientMetadata => f.write_str("`client_metadata` has the wrong shape"),
        }
    }
}

impl std::error::Error for InvalidRequest {}

/// Parse and normalise a `circuit_zk` credential query.
///
/// `credential_query_json` is one Credential Query object (an element of
/// `dcql_query.credentials`), not the whole `dcql_query`.
/// `client_metadata_json` is the request's `client_metadata`, if it has one.
///
/// Accepts the normative `req` shape and the example's `claims._req` shape, and
/// both forms of `vp_formats_supported.circuit_zk`. See the module docs for
/// what is and is not rejected.
///
/// # Errors
///
/// [`InvalidRequest`] for the structural defects listed on its variants.
pub fn plan(
    credential_query_json: &str,
    client_metadata_json: Option<&str>,
) -> Result<Plan, InvalidRequest> {
    let raw: Value = serde_json::from_str(credential_query_json)
        .map_err(|_| InvalidRequest::QueryNotParseable)?;
    let query = raw.as_object().ok_or(InvalidRequest::QueryNotParseable)?;

    // DCQL's own claim machinery has no meaning for this format. `claims` is
    // allowed only as the example shape's container for `_req`; an array there
    // is an ordinary DCQL claims list, and is never handed to the DCQL parser.
    if query.contains_key("claim_sets") {
        return Err(InvalidRequest::ClaimSetsPresent);
    }
    if query.contains_key("req_sets") {
        return Err(InvalidRequest::ReqSetsPresent);
    }
    let nested = match query.get("claims") {
        None => None,
        Some(Value::Object(claims)) => Some(claims),
        Some(_) => return Err(InvalidRequest::ClaimsPresent),
    };

    let meta_doctype = read_meta(query.get("meta"))?;

    let items = match (query.get("req"), nested.and_then(|c| c.get("_req"))) {
        (Some(_), Some(_)) => return Err(InvalidRequest::ReqAmbiguous),
        (Some(req), None) => (req, ItemKeys::Normative),
        (None, Some(req)) => (req, ItemKeys::Example),
        (None, None) => return Err(InvalidRequest::ReqMissingOrEmpty),
    };
    let functions = read_items(items.0, items.1)?;

    let circuit_filter = match client_metadata_json {
        None => CircuitFilter::default(),
        Some(text) => read_circuit_filter(text)?,
    };

    Ok(Plan {
        functions,
        circuit_filter,
        meta_doctype,
        raw,
    })
}

/// Which member names carry the function id and the handle.
#[derive(Clone, Copy)]
enum ItemKeys {
    /// `req` items: `id` is the function, `return` the handle.
    Normative,
    /// `claims._req` items: `fn_id` is the function, `id` the handle.
    Example,
}

impl ItemKeys {
    fn function(self) -> &'static str {
        match self {
            Self::Normative => "id",
            Self::Example => "fn_id",
        }
    }

    fn handle(self) -> &'static str {
        match self {
            Self::Normative => "return",
            Self::Example => "id",
        }
    }
}

/// `meta` must be an object. Its `doctype_value` is returned; whether `meta`
/// names the right credential, or exactly one of the two selectors, is not the
/// planner's to say.
fn read_meta(meta: Option<&Value>) -> Result<Option<String>, InvalidRequest> {
    let meta = meta
        .and_then(Value::as_object)
        .ok_or(InvalidRequest::InvalidMeta)?;
    let doctype = match meta.get("doctype_value") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(InvalidRequest::InvalidMeta),
    };
    if let Some(vct) = meta.get("vct_values") {
        let ok = vct
            .as_array()
            .is_some_and(|a| a.iter().all(Value::is_string));
        if !ok {
            return Err(InvalidRequest::InvalidMeta);
        }
    }
    Ok(doctype)
}

fn read_items(req: &Value, keys: ItemKeys) -> Result<Vec<PlannedFunction>, InvalidRequest> {
    let items = match req.as_array() {
        Some(items) if !items.is_empty() => items,
        _ => return Err(InvalidRequest::ReqMissingOrEmpty),
    };

    let mut seen: HashSet<&str> = HashSet::new();
    let mut functions = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let function_id = item
            .get(keys.function())
            .and_then(Value::as_str)
            .ok_or(InvalidRequest::ItemMissingFunctionId { index })?;
        let handle = item
            .get(keys.handle())
            .and_then(Value::as_str)
            .ok_or(InvalidRequest::ItemMissingHandle { index })?;
        if !seen.insert(handle) {
            return Err(InvalidRequest::DuplicateHandle {
                handle: handle.to_owned(),
            });
        }
        let params = read_params(function_id, handle, item.get("params"))?;
        functions.push(PlannedFunction {
            function_id: function_id.to_owned(),
            handle: handle.to_owned(),
            params,
        });
    }
    Ok(functions)
}

fn read_params(
    function_id: &str,
    handle: &str,
    params: Option<&Value>,
) -> Result<Params, InvalidRequest> {
    let mut map = match params {
        None => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => {
            return Err(InvalidRequest::ParamWrongType {
                handle: handle.to_owned(),
                param: "params".to_owned(),
            })
        }
    };

    let Some(spec) = FUNCTIONS.iter().find(|s| s.function_id == function_id) else {
        return Ok(Params::Unknown(map));
    };

    for param in spec.params {
        let Some(value) = map.get(param.name) else {
            continue;
        };
        let Some(text) = value.as_str() else {
            return Err(InvalidRequest::ParamWrongType {
                handle: handle.to_owned(),
                param: param.name.to_owned(),
            });
        };
        if param.ty == ParamType::FullDate && !is_full_date(text) {
            return Err(InvalidRequest::ParamInvalidFullDate {
                handle: handle.to_owned(),
                param: param.name.to_owned(),
            });
        }
    }

    // Validated above, so each known parameter is a string or absent.
    let mut take = |name: &str| match map.remove(name) {
        Some(Value::String(s)) => Some(s),
        _ => None,
    };
    Ok(match spec.kind {
        FnKind::Pseudonym => {
            let config = take("config");
            let verifier_context = take("verifier_context");
            let verifier_id_type = take("verifier_id_type");
            Params::Pseudonym {
                config,
                verifier_context,
                verifier_id_type,
                extra: map,
            }
        }
        FnKind::AgeCheck => {
            let ge = take("ge");
            let le = take("le");
            Params::AgeCheck { ge, le, extra: map }
        }
    })
}

/// RFC 3339 §5.6 `full-date`: `YYYY-MM-DD` with a real calendar day.
///
/// Syntax and calendar validity only. There is no ordering, span or "today"
/// here; those are satisfiability.
pub(crate) fn is_full_date(s: &str) -> bool {
    let mut parts = s.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let digits = |p: &str, len: usize| p.len() == len && p.bytes().all(|b| b.is_ascii_digit());
    if !(digits(y, 4) && digits(m, 2) && digits(d, 2)) {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (y.parse::<u32>(), m.parse::<u32>(), d.parse::<u32>())
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// Read `vp_formats_supported.circuit_zk` out of `client_metadata`.
///
/// The object is either the plain form, holding the value arrays directly, or
/// the envelope `{fn_id, input}` whose `input` is base64 of that same object as
/// JSON. A request with no `circuit_zk` entry has no filter.
fn read_circuit_filter(client_metadata_json: &str) -> Result<CircuitFilter, InvalidRequest> {
    let bad = || InvalidRequest::InvalidClientMetadata;
    let metadata: Value = serde_json::from_str(client_metadata_json).map_err(|_| bad())?;
    let metadata = metadata.as_object().ok_or_else(bad)?;

    let formats = match metadata.get("vp_formats_supported") {
        None => return Ok(CircuitFilter::default()),
        Some(v) => v.as_object().ok_or_else(bad)?,
    };
    let entry = match formats.get("circuit_zk") {
        None => return Ok(CircuitFilter::default()),
        Some(v) => v.as_object().ok_or_else(bad)?,
    };

    let decoded;
    let entry = match entry.get("input") {
        None => entry,
        Some(input) => {
            let bytes = decode_base64(input.as_str().ok_or_else(bad)?).ok_or_else(bad)?;
            decoded = serde_json::from_slice::<Value>(&bytes).map_err(|_| bad())?;
            decoded.as_object().ok_or_else(bad)?
        }
    };

    Ok(CircuitFilter {
        proof_systems: string_list(entry.get("circuit_proof_system_values"))?,
        circuit_ids: string_list(entry.get("circuit_id_values"))?,
    })
}

fn string_list(value: Option<&Value>) -> Result<Option<Vec<String>>, InvalidRequest> {
    let Some(value) = value else {
        return Ok(None);
    };
    let list = value
        .as_array()
        .ok_or(InvalidRequest::InvalidClientMetadata)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or(InvalidRequest::InvalidClientMetadata)?;
    Ok(Some(list))
}

/// Base64 of either alphabet, padded or not. The rulebook example says only
/// "base64", so a verifier may send any of them; the strict decoder in
/// [`base64url`] does the actual work once the spelling is normalised.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let normalised: String = input
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            other => other,
        })
        .collect();
    base64url::decode(&normalised)
}
