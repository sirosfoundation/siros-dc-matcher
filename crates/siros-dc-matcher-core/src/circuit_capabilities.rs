//! Structured circuit capabilities, and the rule that matches a request to them.
//!
//! A wallet registers a `circuit_zk` circuit with an optional `capabilities`
//! param: the `capabilities` object of the circuit catalog as a JSON string.
//! [`Capabilities::parse`] reads it and [`Capabilities::serves`] applies the
//! capability rule to a planned request (the catalog only stores the metadata;
//! filtering by proof system, circuit id and status is the wallet's, before it
//! registers circuits):
//!
//! 1. the circuit's presentation and credential (format and type) equal the
//!    request's;
//! 2. every requested function item names a function the circuit declares,
//!    every param the item carries is listed for that function with a value
//!    its constraint accepts, and the number of items naming a function is
//!    within its `max`;
//! 3. every function declared `always` appears among the items.
//!
//! The proof-system, circuit-id and status filters are not here. The
//! verifier's lists are matched by the evaluator, and a revoked or unwanted
//! circuit is simply not registered by the wallet.
//!
//! Function ids, param names and values are opaque strings. Nothing in this
//! module knows any function family: a new family adds catalog entries, not
//! code.
//!
//! # Malformed input fails closed
//!
//! [`Capabilities::parse`] is strict, like the catalog's own validator: an
//! unknown key at any level (so a constraint kind this build does not know), a
//! `schema` other than 1, a missing required field, an empty id or enum, a
//! duplicate function id, a `max` below 1, or a constraint that is not exactly
//! one of `enum` / `type` is an error. The evaluator treats an error as "this
//! circuit is not offered", never as "no constraint": a description we cannot
//! read must not widen what a circuit is shown for.
//!
//! The module runs inside the WASM matcher, where a trap is indistinguishable
//! from "no matching credential", so it must not panic on any input.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
#![deny(missing_docs)]

use std::fmt;

use serde_json::{Map, Value};

/// The only capabilities schema version this build reads.
pub const SCHEMA: u64 = 1;

/// A capabilities object that could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesError {
    /// What is wrong with it.
    pub reason: String,
}

impl fmt::Display for CapabilitiesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid circuit capabilities: {}", self.reason)
    }
}

impl std::error::Error for CapabilitiesError {}

fn invalid(reason: impl Into<String>) -> CapabilitiesError {
    CapabilitiesError {
        reason: reason.into(),
    }
}

/// What a circuit declares it can prove.
///
/// Read by hand from a [`Value`] rather than with serde's derive: this runs in
/// the WASM matcher, whose size budget the derive's generated code would
/// spend a tenth of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    presentation: String,
    credential_format: String,
    credential_type: String,
    functions: Vec<FunctionCap>,
}

/// One function a circuit supports.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionCap {
    id: String,
    max: Option<u64>,
    always: bool,
    params: Vec<(String, Constraint)>,
}

/// The type names a `{"type": ...}` constraint can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamKind {
    FullDate,
    String,
    Integer,
}

/// What a param's value must satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Constraint {
    Enum(Vec<String>),
    Type(ParamKind),
}

/// The members of `value` as an object whose keys are all in `allowed`.
fn object<'v>(
    value: &'v Value,
    what: &str,
    allowed: &[&str],
) -> Result<&'v Map<String, Value>, CapabilitiesError> {
    let map = value
        .as_object()
        .ok_or_else(|| invalid(format!("{what} is not an object")))?;
    match map.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(unknown) => Err(invalid(format!("{what} has unknown member {unknown:?}"))),
        None => Ok(map),
    }
}

fn required_text(
    map: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<String, CapabilitiesError> {
    match map.get(key).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(invalid(format!("{what}{key} is required"))),
    }
}

impl Constraint {
    fn read(value: &Value) -> Result<Self, CapabilitiesError> {
        let map = object(value, "a constraint", &["enum", "type"])?;
        match (map.get("enum"), map.get("type")) {
            (Some(Value::Null) | None, Some(Value::Null) | None) => Err(invalid(
                "constraint must have exactly one of enum or type, got neither",
            )),
            (Some(Value::Null) | None, Some(ty)) => match ty.as_str() {
                Some("full-date") => Ok(Self::Type(ParamKind::FullDate)),
                Some("string") => Ok(Self::Type(ParamKind::String)),
                Some("integer") => Ok(Self::Type(ParamKind::Integer)),
                _ => Err(invalid(format!("unknown type {ty}"))),
            },
            (Some(values), Some(Value::Null) | None) => {
                let mut list: Vec<String> = Vec::new();
                for v in values
                    .as_array()
                    .ok_or_else(|| invalid("enum is not an array"))?
                {
                    let v = v
                        .as_str()
                        .filter(|v| !v.is_empty())
                        .ok_or_else(|| invalid("enum values must be non-empty strings"))?;
                    if list.iter().any(|seen| seen == v) {
                        return Err(invalid(format!("enum value {v:?} is listed twice")));
                    }
                    list.push(v.to_owned());
                }
                if list.is_empty() {
                    return Err(invalid("enum must list at least one value"));
                }
                Ok(Self::Enum(list))
            }
            (Some(_), Some(_)) => Err(invalid(
                "constraint must have exactly one of enum or type, got both",
            )),
        }
    }

    fn accepts(&self, value: &Value) -> bool {
        match self {
            Self::Enum(values) => value
                .as_str()
                .is_some_and(|s| values.iter().any(|v| v == s)),
            Self::Type(ParamKind::String) => value.is_string(),
            Self::Type(ParamKind::FullDate) => {
                value.as_str().is_some_and(crate::circuit_zk::is_full_date)
            }
            // A JSON number with no fractional part. 2^53 is where f64 stops
            // being exact; the catalog's reference implementation draws the
            // same line.
            Self::Type(ParamKind::Integer) => value
                .as_f64()
                .is_some_and(|f| f == f.trunc() && f.abs() <= 9_007_199_254_740_992.0),
        }
    }
}

impl FunctionCap {
    fn read(value: &Value) -> Result<Self, CapabilitiesError> {
        let map = object(value, "a function", &["id", "max", "always", "params"])?;
        let id = required_text(map, "id", "function ")?;
        let max = match map.get("max") {
            None | Some(Value::Null) => None,
            Some(v) => match v.as_u64() {
                Some(n) if n >= 1 => Some(n),
                _ => return Err(invalid(format!("function {id:?}: max must be at least 1"))),
            },
        };
        let always = match map.get("always") {
            None | Some(Value::Null) => false,
            Some(v) => v
                .as_bool()
                .ok_or_else(|| invalid(format!("function {id:?}: always is not a boolean")))?,
        };
        let mut params = Vec::new();
        match map.get("params") {
            None | Some(Value::Null) => {}
            Some(v) => {
                let declared = v
                    .as_object()
                    .ok_or_else(|| invalid(format!("function {id:?}: params is not an object")))?;
                for (name, constraint) in declared {
                    if name.is_empty() {
                        return Err(invalid(format!(
                            "function {id:?}: param name must not be empty"
                        )));
                    }
                    let constraint = Constraint::read(constraint).map_err(|e| {
                        invalid(format!("function {id:?} param {name:?}: {}", e.reason))
                    })?;
                    params.push((name.clone(), constraint));
                }
            }
        }
        Ok(Self {
            id,
            max,
            always,
            params,
        })
    }
}

/// One requested function instance, as the planner normalised it.
#[derive(Debug, Clone, Copy)]
pub struct RequestedItem<'a> {
    /// The function id.
    pub function_id: &'a str,
    /// The params the item carries; may be empty.
    pub params: &'a Map<String, Value>,
}

impl Capabilities {
    /// Read and validate a capabilities object given as JSON text.
    ///
    /// # Errors
    ///
    /// [`CapabilitiesError`] for anything the catalog's validator would reject.
    /// See the module docs.
    pub fn parse(text: &str) -> Result<Self, CapabilitiesError> {
        let value: Value = serde_json::from_str(text).map_err(|e| invalid(e.to_string()))?;
        let map = object(
            &value,
            "capabilities",
            &["schema", "presentation", "credential", "functions"],
        )?;
        match map.get("schema").and_then(Value::as_u64) {
            Some(SCHEMA) => {}
            _ => {
                return Err(invalid(format!(
                    "schema must be {SCHEMA}, the only one this build understands"
                )))
            }
        }
        let presentation = required_text(map, "presentation", "")?;
        let credential = map
            .get("credential")
            .ok_or_else(|| invalid("credential is required"))?;
        let credential = object(credential, "credential", &["format", "type", "profile"])?;
        // `profile` only ranks circuits, which is the wallet's job. It is
        // accepted and ignored.
        if credential
            .get("profile")
            .is_some_and(|p| !p.is_string() && !p.is_null())
        {
            return Err(invalid("credential.profile is not a string"));
        }
        let credential_format = required_text(credential, "format", "credential.")?;
        let credential_type = required_text(credential, "type", "credential.")?;

        let mut functions: Vec<FunctionCap> = Vec::new();
        let listed = map
            .get("functions")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("functions must be an array"))?;
        for entry in listed {
            let function = FunctionCap::read(entry)?;
            if functions.iter().any(|f| f.id == function.id) {
                return Err(invalid(format!("duplicate function id {:?}", function.id)));
            }
            functions.push(function);
        }
        if functions.is_empty() {
            return Err(invalid("functions must list at least one function"));
        }
        Ok(Self {
            presentation,
            credential_format,
            credential_type,
            functions,
        })
    }

    /// Whether the circuit satisfies a request, by the three checks above.
    ///
    /// `credential_formats` and `credential_types` are what the request can
    /// mean by its credential: the circuit's format and type must each be one
    /// of them. A request that names no type has an empty `credential_types`
    /// and is served by nothing, as the catalog's rule treats a request with no
    /// type as malformed.
    #[must_use]
    pub fn serves(
        &self,
        presentation: &str,
        credential_formats: &[&str],
        credential_types: &[&str],
        items: &[RequestedItem<'_>],
    ) -> bool {
        // 3. presentation and credential.
        if self.presentation != presentation
            || !credential_formats.contains(&self.credential_format.as_str())
            || !credential_types.contains(&self.credential_type.as_str())
        {
            return false;
        }

        // 4. every item is supported: its function is declared, each param it
        // carries is listed there and accepted.
        for item in items {
            let Some(function) = self.functions.iter().find(|f| f.id == item.function_id) else {
                return false;
            };
            for (name, value) in item.params {
                let accepted = function
                    .params
                    .iter()
                    .find(|(declared, _)| declared == name)
                    .is_some_and(|(_, constraint)| constraint.accepts(value));
                if !accepted {
                    return false;
                }
            }
        }
        // ... and no function is asked for more often than its `max`, and
        // 5. every function the circuit always includes was asked for.
        self.functions.iter().all(|f| {
            let n = items.iter().filter(|i| i.function_id == f.id).count();
            let within_max = f
                .max
                .is_none_or(|max| u64::try_from(n).is_ok_and(|n| n <= max));
            within_max && (n > 0 || !f.always)
        })
    }
}
