//! JSON text as transaction data reads it: one value, no object repeating a member name, at most
//! [`MAX_DEPTH`] levels of objects and arrays, and every number with the text its writer chose.

use std::fmt;

use rustc_hash::FxHashSet;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;

use crate::error::{MemberPath, TransactionDataError};

/// The deepest nesting of objects and arrays a document may have.
pub const MAX_DEPTH: usize = 64;

/// Why a text is no JSON document this crate reads.
pub(crate) enum JsonError {
    /// The text is not one JSON value (RFC 8259), or a number exceeds binary64.
    Malformed,
    /// An object repeats a member name.
    DuplicateKey,
    /// Objects and arrays nest deeper than [`MAX_DEPTH`].
    TooDeep,
}

/// A JSON value.
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Json>),
    Object(Object),
}

/// A JSON object: its members in their order, each name once.
pub(crate) struct Object(Vec<(String, Json)>);

/// A JSON number: the text its writer chose, which denotes a finite binary64 value.
pub(crate) struct Number {
    text: String,
    value: f64,
}

impl Json {
    /// The value of the JSON text `text`.
    pub(crate) fn parse(text: &str) -> Result<Self, JsonError> {
        let raw: &RawValue = serde_json::from_str(text).map_err(|_| JsonError::Malformed)?;
        value(raw, 0)
    }
}

impl Object {
    /// The members, in their order.
    pub(crate) fn members(&self) -> &[(String, Json)] {
        &self.0
    }

    /// The members, to take one by one.
    pub(crate) fn into_fields(self) -> Fields {
        Fields(self.0)
    }
}

/// The members of an object not taken yet, in their order.
pub(crate) struct Fields(Vec<(String, Json)>);

impl Fields {
    /// Takes member `name`.
    pub(crate) fn take(&mut self, name: &str) -> Option<Json> {
        let at = self.0.iter().position(|(n, _)| n == name)?;
        Some(self.0.remove(at).1)
    }

    /// Takes member `name`, which must be present.
    pub(crate) fn require(
        &mut self,
        name: &str,
        path: MemberPath,
    ) -> Result<Json, TransactionDataError> {
        self.take(name)
            .ok_or(TransactionDataError::MissingMember(path))
    }

    /// The members not taken: those the schema of the object leaves open.
    pub(crate) fn rest(self) -> Vec<(String, Json)> {
        self.0
    }

    /// Refuses a member not taken (Section 8.5, unknown fields).
    pub(crate) fn finish(self) -> Result<(), TransactionDataError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(TransactionDataError::UnknownMember)
        }
    }
}

impl Number {
    /// The text the writer chose.
    pub(crate) fn text(&self) -> &str {
        &self.text
    }

    /// Whether the value has no fractional part: a JSON Schema `integer`.
    pub(crate) fn is_integer(&self) -> bool {
        self.value.fract() == 0.0
    }
}

/// The value `raw` holds, `depth` levels below the document.
fn value(raw: &RawValue, depth: usize) -> Result<Json, JsonError> {
    let text = raw.get();
    match text.as_bytes().first() {
        Some(b'{') => {
            let depth = nested(depth)?;
            let Members(members) = serde_json::from_str(text).map_err(|_| JsonError::Malformed)?;
            let mut names = FxHashSet::default();
            if !members.iter().all(|(name, _)| names.insert(name.as_str())) {
                return Err(JsonError::DuplicateKey);
            }
            let members = members
                .into_iter()
                .map(|(name, raw)| Ok((name, value(raw, depth)?)))
                .collect::<Result<_, JsonError>>()?;
            Ok(Json::Object(Object(members)))
        }
        Some(b'[') => {
            let depth = nested(depth)?;
            let items: Vec<&RawValue> =
                serde_json::from_str(text).map_err(|_| JsonError::Malformed)?;
            let items = items
                .into_iter()
                .map(|raw| value(raw, depth))
                .collect::<Result<_, JsonError>>()?;
            Ok(Json::Array(items))
        }
        Some(b'"') => Ok(Json::String(
            serde_json::from_str(text).map_err(|_| JsonError::Malformed)?,
        )),
        Some(b't') => Ok(Json::Bool(true)),
        Some(b'f') => Ok(Json::Bool(false)),
        Some(b'n') => Ok(Json::Null),
        // serde_json read the text as a number of RFC 8259, Section 6.
        _ => match text.parse::<f64>() {
            Ok(value) if value.is_finite() => Ok(Json::Number(Number {
                text: text.to_owned(),
                value,
            })),
            _ => Err(JsonError::Malformed),
        },
    }
}

/// The depth of a value inside an object or array at `depth`.
fn nested(depth: usize) -> Result<usize, JsonError> {
    if depth < MAX_DEPTH {
        Ok(depth + 1)
    } else {
        Err(JsonError::TooDeep)
    }
}

/// The members of an object, each value as its text.
struct Members<'a>(Vec<(String, &'a RawValue)>);

impl<'de> Deserialize<'de> for Members<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(MembersVisitor)
    }
}

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        std::iter::from_fn(|| map.next_entry::<String, &'de RawValue>().transpose())
            .collect::<Result<_, _>>()
            .map(Members)
    }
}

/// `value` as a string.
pub(crate) fn text(value: Json, path: MemberPath) -> Result<String, TransactionDataError> {
    match value {
        Json::String(text) => Ok(text),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as a boolean.
pub(crate) fn boolean(value: Json, path: MemberPath) -> Result<bool, TransactionDataError> {
    match value {
        Json::Bool(b) => Ok(b),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as a number.
pub(crate) fn number(value: Json, path: MemberPath) -> Result<Number, TransactionDataError> {
    match value {
        Json::Number(number) => Ok(number),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as a JSON Schema `integer`: a number without a fractional part.
pub(crate) fn integer(value: Json, path: MemberPath) -> Result<Number, TransactionDataError> {
    match value {
        Json::Number(number) if number.is_integer() => Ok(number),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as the members of an object.
pub(crate) fn object(value: Json, path: MemberPath) -> Result<Fields, TransactionDataError> {
    match value {
        Json::Object(object) => Ok(object.into_fields()),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// `value` as the elements of an array.
pub(crate) fn array(value: Json, path: MemberPath) -> Result<Vec<Json>, TransactionDataError> {
    match value {
        Json::Array(items) => Ok(items),
        _ => Err(TransactionDataError::WrongType(path)),
    }
}

/// Member `name` of `fields`, read by `read` when present.
pub(crate) fn optional<T>(
    fields: &mut Fields,
    name: &str,
    path: MemberPath,
    read: impl FnOnce(Json, MemberPath) -> Result<T, TransactionDataError>,
) -> Result<Option<T>, TransactionDataError> {
    fields.take(name).map(|value| read(value, path)).transpose()
}
