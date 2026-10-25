//! Planner for `zkp_req` credential queries.
//!
//! [`plan`] parses a `zkp_req` credential query (and, optionally, the
//! request's `client_metadata`) into a normalised [`Plan`], or rejects it with
//! [`InvalidRequest`] when it is structurally broken. The normative shape is
//! the `nym_auth` rulebook v0.4 ("DCQL profile and presentation syntax"):
//!
//! ```json
//! { "id": "...", "format": "zkp_req",
//!   "meta": { "source_format": "mso_mdoc", "doctype_value": "..." },
//!   "_req": [ { "fn_id": "pseudonym", "return": "nym", "params": { } } ] }
//! ```
//!
//! # Structure here, satisfiability separately
//!
//! [`plan`] judges **structure**: JSON types, presence of `_req` and `meta`,
//! duplicate handles. It never judges whether a request can be served. The
//! rulebook's "unsatisfiable" rules that need no knowledge of the holder's
//! attestation (REQUIRED `ver` and `prf`, `ver` equal to 1, a `prf` defined
//! for the `source_format`, one `pseudonym` and one `age_check` at most, the
//! `age_check` bounds, `verifier_context`, holder binding) live in
//! [`unsatisfiable`], which the evaluator applies and wallets may too. Which
//! `config` values a *circuit* supports is not decided here at all: it is what
//! the registry entry (the circuit's capabilities) says, and a configuration
//! the entry does not list is not served.
//!
//! A function this table does not know passes through as [`Params::Unknown`].
//! `verifier_id_type` is no longer part of the request; if sent it is an
//! undeclared parameter and survives in `extra` like any other.
//!
//! `bbs_cd` (held, not implemented in any wallet yet) plans like `mso_mdoc`:
//! `source_format` and `schema_id_value` are read, and a wallet whose stored
//! formats lack `bbs_cd` is simply not offered the request.
//!
//! The module runs inside the WASM matcher, where a trap is indistinguishable
//! from "no matching credential", so it must not panic on any input.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(missing_docs)]

use rustc_hash::FxHashSet;
use std::fmt;

use serde::Serialize;
use serde_json::{Map, Number, Value};

/// `source_format` of an ISO/IEC 18013-5 attestation proved with circuits.
pub const SOURCE_MSO_MDOC: &str = "mso_mdoc";
/// `source_format` of a BBS committed-disclosure attestation (held).
pub const SOURCE_BBS_CD: &str = "bbs_cd";
/// The only pseudonym function version this build knows.
pub const PSEUDONYM_VER: u64 = 1;
/// Minimum span of an `age_check` range, in days (inclusive count).
pub const MIN_AGE_SPAN_DAYS: i64 = 365;

/// What a planned function call's parameters look like, by type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamType {
    /// Any JSON string.
    String,
    /// A JSON string holding an RFC 3339 `full-date` (`YYYY-MM-DD`).
    FullDate,
    /// A JSON number with no fraction or exponent.
    Integer,
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
    /// `pseudonym`.
    Pseudonym,
    /// `age_check`.
    AgeCheck,
}

/// A function this planner knows the parameter types of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FnSpec {
    /// The function identifier as it appears in the request (`fn_id`).
    pub function_id: &'static str,
    /// The normaliser arm for it.
    pub kind: FnKind,
    /// Its declared parameters. Every one is optional here: presence rules are
    /// in [`unsatisfiable`].
    pub params: &'static [ParamSpec],
}

/// The function table. This is where a new rulebook function is added.
pub const FUNCTIONS: &[FnSpec] = &[
    FnSpec {
        function_id: "pseudonym",
        kind: FnKind::Pseudonym,
        params: &[
            ParamSpec {
                name: "config",
                ty: ParamType::String,
            },
            ParamSpec {
                name: "ver",
                ty: ParamType::Integer,
            },
            ParamSpec {
                name: "prf",
                ty: ParamType::String,
            },
            ParamSpec {
                name: "verifier_context",
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
    /// `pseudonym`.
    Pseudonym {
        /// `config`.
        #[serde(skip_serializing_if = "Option::is_none")]
        config: Option<String>,
        /// `ver`: a JSON integer, not judged here.
        #[serde(skip_serializing_if = "Option::is_none")]
        ver: Option<Number>,
        /// `prf`.
        #[serde(skip_serializing_if = "Option::is_none")]
        prf: Option<String>,
        /// `verifier_context`.
        #[serde(skip_serializing_if = "Option::is_none")]
        verifier_context: Option<String>,
        /// Parameters the table does not declare (for instance a legacy
        /// `verifier_id_type`).
        #[serde(flatten)]
        extra: Map<String, Value>,
    },
    /// `age_check`. Dates are validated RFC 3339 `full-date` strings; they are
    /// not ordered or compared here.
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

/// One function call from `_req`, normalised.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlannedFunction {
    /// The function identifier (`fn_id`).
    pub function_id: String,
    /// The output handle (`return`).
    pub handle: String,
    /// The normalised parameters.
    pub params: Params,
}

/// What the verifier said it accepts, from
/// `client_metadata.vp_formats_supported.zkp_req`.
///
/// Values are passed through as given. An empty list is not rejected here: it
/// means nothing can match, which is for wallets to conclude.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SystemFilter {
    /// `proof_system_values`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_systems: Option<Vec<String>>,
    /// `system_id_values`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_ids: Option<Vec<String>>,
}

/// A normalised `zkp_req` credential query.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    /// The requested function calls, in request order.
    pub functions: Vec<PlannedFunction>,
    /// The verifier's system constraints from `client_metadata`.
    pub system_filter: SystemFilter,
    /// `meta.source_format`: the format of the attestation the proof is made
    /// over (`mso_mdoc`, `bbs_cd`, ...). Not judged by [`plan`].
    pub source_format: String,
    /// `meta.doctype_value`, when present.
    pub meta_doctype: Option<String>,
    /// `meta.schema_id_value`, when present.
    pub meta_schema_id: Option<String>,
    /// The credential query exactly as parsed, so that unknown members at any
    /// level survive for wallets that understand them.
    pub raw: Value,
}

/// A structurally invalid `zkp_req` request.
///
/// Every variant is a defect in the request's shape. None of them says a
/// well-formed request cannot be satisfied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidRequest {
    /// The credential query is not JSON, or not a JSON object.
    QueryNotParseable,
    /// `_req` is missing, not an array, or empty.
    ReqMissingOrEmpty,
    /// A `_req` item has no function identifier (`fn_id`).
    ItemMissingFunctionId {
        /// Position of the item in the array.
        index: usize,
    },
    /// A `_req` item has no output handle (`return`).
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
    /// `claims` is present: `zkp_req` does not use it.
    ClaimsPresent,
    /// `claim_sets` is present.
    ClaimSetsPresent,
    /// `_req_sets` is present; this version does not define it.
    ReqSetsPresent,
    /// `meta` is missing, not an object, has no string `source_format`, or has
    /// a type value of the wrong type.
    InvalidMeta,
    /// `client_metadata` is not parseable, or its `zkp_req` object has the
    /// wrong shape.
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
            Self::ReqMissingOrEmpty => f.write_str("`_req` is missing or empty"),
            Self::ItemMissingFunctionId { index } => {
                write!(f, "_req item {index} has no `fn_id`")
            }
            Self::ItemMissingHandle { index } => write!(f, "_req item {index} has no `return`"),
            Self::ParamWrongType { handle, param } => {
                write!(f, "`{param}` of `{handle}` has the wrong type")
            }
            Self::ParamInvalidFullDate { handle, param } => {
                write!(f, "`{param}` of `{handle}` is not an RFC 3339 full-date")
            }
            Self::DuplicateHandle { handle } => write!(f, "handle `{handle}` is used twice"),
            Self::ClaimsPresent => f.write_str("`claims` is not used by zkp_req"),
            Self::ClaimSetsPresent => f.write_str("`claim_sets` is not used by zkp_req"),
            Self::ReqSetsPresent => f.write_str("`_req_sets` is not defined"),
            Self::InvalidMeta => f.write_str("`meta` has the wrong shape"),
            Self::InvalidClientMetadata => f.write_str("`client_metadata` has the wrong shape"),
        }
    }
}

impl std::error::Error for InvalidRequest {}

/// Parse and normalise a `zkp_req` credential query.
///
/// `credential_query_json` is one Credential Query object (an element of
/// `dcql_query.credentials`), not the whole `dcql_query`.
/// `client_metadata_json` is the request's `client_metadata`, if it has one.
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

    // DCQL's own claim machinery has no meaning for this format, and a
    // `claims` member is never handed to the DCQL parser.
    if query.contains_key("claims") {
        return Err(InvalidRequest::ClaimsPresent);
    }
    if query.contains_key("claim_sets") {
        return Err(InvalidRequest::ClaimSetsPresent);
    }
    if query.contains_key("_req_sets") {
        return Err(InvalidRequest::ReqSetsPresent);
    }

    let meta = read_meta(query.get("meta"))?;
    let functions = read_items(query.get("_req").ok_or(InvalidRequest::ReqMissingOrEmpty)?)?;

    let system_filter = match client_metadata_json {
        None => SystemFilter::default(),
        Some(text) => read_system_filter(text)?,
    };

    Ok(Plan {
        functions,
        system_filter,
        source_format: meta.source_format,
        meta_doctype: meta.doctype,
        meta_schema_id: meta.schema_id,
        raw,
    })
}

struct Meta {
    source_format: String,
    doctype: Option<String>,
    schema_id: Option<String>,
}

/// `meta` must be an object with a string `source_format`. Its type values are
/// read; whether exactly the right one is present for the source format is
/// [`unsatisfiable`]'s to say.
fn read_meta(meta: Option<&Value>) -> Result<Meta, InvalidRequest> {
    let meta = meta
        .and_then(Value::as_object)
        .ok_or(InvalidRequest::InvalidMeta)?;
    let source_format = match meta.get("source_format") {
        Some(Value::String(s)) => s.clone(),
        _ => return Err(InvalidRequest::InvalidMeta),
    };
    let text = |key: &str| match meta.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(InvalidRequest::InvalidMeta),
    };
    let doctype = text("doctype_value")?;
    let schema_id = text("schema_id_value")?;
    if let Some(vct) = meta.get("vct_values") {
        let ok = vct
            .as_array()
            .is_some_and(|a| a.iter().all(Value::is_string));
        if !ok {
            return Err(InvalidRequest::InvalidMeta);
        }
    }
    Ok(Meta {
        source_format,
        doctype,
        schema_id,
    })
}

fn read_items(req: &Value) -> Result<Vec<PlannedFunction>, InvalidRequest> {
    let items = match req.as_array() {
        Some(items) if !items.is_empty() => items,
        _ => return Err(InvalidRequest::ReqMissingOrEmpty),
    };

    let mut seen: FxHashSet<&str> = FxHashSet::default();
    let mut functions = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let function_id = item
            .get("fn_id")
            .and_then(Value::as_str)
            .ok_or(InvalidRequest::ItemMissingFunctionId { index })?;
        let handle = item
            .get("return")
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

fn is_integer(value: &Value) -> bool {
    matches!(value, Value::Number(n) if n.is_i64() || n.is_u64())
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
        let wrong = || InvalidRequest::ParamWrongType {
            handle: handle.to_owned(),
            param: param.name.to_owned(),
        };
        match param.ty {
            ParamType::Integer => {
                if !is_integer(value) {
                    return Err(wrong());
                }
            }
            ParamType::String | ParamType::FullDate => {
                let text = value.as_str().ok_or_else(wrong)?;
                if param.ty == ParamType::FullDate && !is_full_date(text) {
                    return Err(InvalidRequest::ParamInvalidFullDate {
                        handle: handle.to_owned(),
                        param: param.name.to_owned(),
                    });
                }
            }
        }
    }

    // Validated above, so each known parameter has its type or is absent.
    let take_text = |map: &mut Map<String, Value>, name: &str| match map.remove(name) {
        Some(Value::String(s)) => Some(s),
        _ => None,
    };
    Ok(match spec.kind {
        FnKind::Pseudonym => {
            let config = take_text(&mut map, "config");
            let prf = take_text(&mut map, "prf");
            let verifier_context = take_text(&mut map, "verifier_context");
            let ver = match map.remove("ver") {
                Some(Value::Number(n)) => Some(n),
                _ => None,
            };
            Params::Pseudonym {
                config,
                ver,
                prf,
                verifier_context,
                extra: map,
            }
        }
        FnKind::AgeCheck => {
            let ge = take_text(&mut map, "ge");
            let le = take_text(&mut map, "le");
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

/// Read `vp_formats_supported.zkp_req` out of `client_metadata`. A request
/// with no `zkp_req` entry has no filter.
fn read_system_filter(client_metadata_json: &str) -> Result<SystemFilter, InvalidRequest> {
    let bad = || InvalidRequest::InvalidClientMetadata;
    let metadata: Value = serde_json::from_str(client_metadata_json).map_err(|_| bad())?;
    let metadata = metadata.as_object().ok_or_else(bad)?;

    let formats = match metadata.get("vp_formats_supported") {
        None => return Ok(SystemFilter::default()),
        Some(v) => v.as_object().ok_or_else(bad)?,
    };
    let entry = match formats.get("zkp_req") {
        None => return Ok(SystemFilter::default()),
        Some(v) => v.as_object().ok_or_else(bad)?,
    };

    Ok(SystemFilter {
        proof_systems: string_list(entry.get("proof_system_values"))?,
        system_ids: string_list(entry.get("system_id_values"))?,
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

/// Why a well-formed request is unsatisfiable by the rulebook's own rules.
///
/// Only rules decidable from the request alone are here. Whether a
/// particular system supports a configuration, or the holder's attestation
/// satisfies a predicate, is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsatisfiable {
    /// `source_format` is not one this version defines (`mso_mdoc`, `bbs_cd`).
    SourceFormatUnsupported,
    /// `meta` does not carry exactly the type value of its `source_format`.
    MetaTypeValueInvalid,
    /// `require_cryptographic_holder_binding` is `false`.
    HolderBindingWaived,
    /// A function the rulebook does not define.
    FunctionUnknown,
    /// More than one `pseudonym` item.
    PseudonymRepeated,
    /// More than one `age_check` item.
    AgeCheckRepeated,
    /// `pseudonym` without `config`.
    PseudonymConfigMissing,
    /// `pseudonym` with a `config` this version does not define.
    PseudonymConfigUnknown,
    /// `pseudonym` without `ver`.
    PseudonymVerMissing,
    /// `ver` is not 1.
    PseudonymVerUnsupported,
    /// `pseudonym` without `prf`.
    PseudonymPrfMissing,
    /// `prf` is not defined for the source format and configuration.
    PseudonymPrfUnsupported,
    /// `verifier_context` absent where required, present where not allowed,
    /// or not 1 to 64 bytes.
    VerifierContextInvalid,
    /// `age_check` with neither `ge` nor `le`.
    AgeCheckNoBound,
    /// `age_check` with `le` before `ge`.
    AgeCheckInverted,
    /// `age_check` range shorter than [`MIN_AGE_SPAN_DAYS`].
    AgeCheckSpanTooShort,
}

impl Unsatisfiable {
    /// A stable identifier shared with the conformance vectors.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SourceFormatUnsupported => "source_format_unsupported",
            Self::MetaTypeValueInvalid => "meta_type_value_invalid",
            Self::HolderBindingWaived => "holder_binding_waived",
            Self::FunctionUnknown => "function_unknown",
            Self::PseudonymRepeated => "pseudonym_repeated",
            Self::AgeCheckRepeated => "age_check_repeated",
            Self::PseudonymConfigMissing => "pseudonym_config_missing",
            Self::PseudonymConfigUnknown => "pseudonym_config_unknown",
            Self::PseudonymVerMissing => "pseudonym_ver_missing",
            Self::PseudonymVerUnsupported => "pseudonym_ver_unsupported",
            Self::PseudonymPrfMissing => "pseudonym_prf_missing",
            Self::PseudonymPrfUnsupported => "pseudonym_prf_unsupported",
            Self::VerifierContextInvalid => "verifier_context_invalid",
            Self::AgeCheckNoBound => "age_check_no_bound",
            Self::AgeCheckInverted => "age_check_inverted",
            Self::AgeCheckSpanTooShort => "age_check_span_too_short",
        }
    }
}

impl fmt::Display for Unsatisfiable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsatisfiable request ({})", self.code())
    }
}

impl std::error::Error for Unsatisfiable {}

/// Pseudonym configurations the rulebook defines, with whether `bbs_cd`
/// defines them.
const CONFIGS: &[(&str, bool)] = &[
    ("known-offender-matching-ssc", true),
    ("known-offender-matching-psc", false),
    ("account-recovery-ssc", false),
    ("user-managed-pseudonym-xsite-ssc", false),
];

/// The rulebook's unsatisfiable-request rules that need only the request.
///
/// The first rule broken is returned. A request that passes is not thereby
/// served: the selected system's registry entry still decides which
/// configurations and parameters it supports.
///
/// # Errors
///
/// [`Unsatisfiable`].
pub fn unsatisfiable(plan: &Plan) -> Result<(), Unsatisfiable> {
    let bbs = match plan.source_format.as_str() {
        SOURCE_MSO_MDOC => false,
        SOURCE_BBS_CD => true,
        _ => return Err(Unsatisfiable::SourceFormatUnsupported),
    };
    let type_ok = if bbs {
        plan.meta_schema_id.is_some() && plan.meta_doctype.is_none()
    } else {
        plan.meta_doctype.is_some() && plan.meta_schema_id.is_none()
    };
    let has_vct = plan
        .raw
        .get("meta")
        .and_then(|m| m.get("vct_values"))
        .is_some();
    if !type_ok || has_vct {
        return Err(Unsatisfiable::MetaTypeValueInvalid);
    }
    if plan.raw.get("require_cryptographic_holder_binding") == Some(&Value::Bool(false)) {
        return Err(Unsatisfiable::HolderBindingWaived);
    }

    let (mut pseudonyms, mut ages) = (0, 0);
    for function in &plan.functions {
        match &function.params {
            Params::Unknown(_) => return Err(Unsatisfiable::FunctionUnknown),
            Params::Pseudonym {
                config,
                ver,
                prf,
                verifier_context,
                ..
            } => {
                pseudonyms += 1;
                if pseudonyms > 1 {
                    return Err(Unsatisfiable::PseudonymRepeated);
                }
                let config = config
                    .as_deref()
                    .ok_or(Unsatisfiable::PseudonymConfigMissing)?;
                let (_, bbs_ok) = CONFIGS
                    .iter()
                    .find(|(name, _)| *name == config)
                    .ok_or(Unsatisfiable::PseudonymConfigUnknown)?;
                let ver = ver.as_ref().ok_or(Unsatisfiable::PseudonymVerMissing)?;
                if ver.as_u64() != Some(PSEUDONYM_VER) {
                    return Err(Unsatisfiable::PseudonymVerUnsupported);
                }
                let prf = prf.as_deref().ok_or(Unsatisfiable::PseudonymPrfMissing)?;
                let prf_ok = if bbs {
                    prf == "hashdh-bls12381g1" && *bbs_ok
                } else {
                    prf == "sha-256"
                };
                if !prf_ok {
                    return Err(Unsatisfiable::PseudonymPrfUnsupported);
                }
                let wants_context = config == "account-recovery-ssc";
                let context_ok = match verifier_context {
                    Some(c) => wants_context && (1..=64).contains(&c.len()),
                    None => !wants_context,
                };
                if !context_ok {
                    return Err(Unsatisfiable::VerifierContextInvalid);
                }
            }
            Params::AgeCheck { ge, le, .. } => {
                ages += 1;
                if ages > 1 {
                    return Err(Unsatisfiable::AgeCheckRepeated);
                }
                match (ge, le) {
                    (None, None) => return Err(Unsatisfiable::AgeCheckNoBound),
                    (Some(ge), Some(le)) => {
                        let (Some(ge), Some(le)) = (day_number(ge), day_number(le)) else {
                            return Err(Unsatisfiable::AgeCheckNoBound);
                        };
                        if le < ge {
                            return Err(Unsatisfiable::AgeCheckInverted);
                        }
                        if le - ge + 1 < MIN_AGE_SPAN_DAYS {
                            return Err(Unsatisfiable::AgeCheckSpanTooShort);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Days since 1970-01-01 of a validated `full-date`.
fn day_number(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

/// Proleptic Gregorian (year, month, day) to days since 1970-01-01.
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}
