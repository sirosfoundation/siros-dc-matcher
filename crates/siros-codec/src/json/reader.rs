//! The strict JSON reader.

use std::fmt;

use rustc_hash::FxHashSet;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::Number;

use super::JsonTextError;

/// The deepest nesting of objects and arrays a document may have.
pub const MAX_DEPTH: usize = 64;

/// One JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(JsonNumber),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object: its members in document order, each name once.
    Object(Vec<(String, Json)>),
}

/// A JSON number: the text its writer chose, which denotes a finite binary64 value.
#[derive(Debug, Clone, PartialEq)]
pub struct JsonNumber {
    text: String,
    number: Number,
}

impl JsonNumber {
    /// The text the writer chose.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The number the text denotes.
    #[must_use]
    pub fn number(&self) -> &Number {
        &self.number
    }

    /// The number the text denotes, taken.
    #[must_use]
    pub fn into_number(self) -> Number {
        self.number
    }

    /// Whether the value has no fractional part: a JSON Schema `integer`.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.number.is_i64()
            || self.number.is_u64()
            || self
                .number
                .as_f64()
                .is_some_and(|value| value.fract() == 0.0)
    }
}

/// Why bytes are no JSON value this reader holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ReadFault {
    /// The bytes are no JSON text.
    #[error("{0}")]
    Text(#[source] JsonTextError),
    /// A number has no finite binary64 value.
    #[error("a number beyond binary64")]
    NumberUnrepresentable,
    /// Objects and arrays nest deeper than [`MAX_DEPTH`].
    #[error("nested deeper than {MAX_DEPTH}")]
    TooDeep,
}

/// Why bytes are no JSON value whose objects name each member once.
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
pub enum JsonFault {
    /// The bytes are no JSON value this reader holds.
    #[error("{0}")]
    Read(#[source] ReadFault),
    /// An object repeats this member name.
    #[error("member {0:?} repeated")]
    RepeatedMember(String),
}

impl Json {
    /// The value `bytes` encode, alone and in UTF-8: members in document order, each object
    /// naming each member once.
    ///
    /// # Errors
    ///
    /// [`JsonFault`]: a text fault anywhere in the bytes comes first; else the first, in document
    /// order, of a number beyond binary64, nesting deeper than [`MAX_DEPTH`], and a member name an
    /// object repeats.
    pub fn parse_unique(bytes: &[u8]) -> Result<Self, JsonFault> {
        let raw: &RawValue = serde_json::from_slice(bytes).map_err(text)?;
        value(raw, 0)
    }

    /// The value of the member `name`, when this is an object that has one.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Self> {
        match self {
            Self::Object(members) => members
                .iter()
                .find(|(member, _)| member == name)
                .map(|(_, value)| value),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }
}

/// The fault of serde_json's `error`.
fn text(error: serde_json::Error) -> JsonFault {
    JsonFault::Read(ReadFault::Text(JsonTextError::of(&error)))
}

/// The value `raw` holds, `depth` levels below the document. The document's syntax is read
/// already: serde_json reads each part again only for its value, from its bytes, through the
/// one reader the document took.
fn value(raw: &RawValue, depth: usize) -> Result<Json, JsonFault> {
    let text_of = raw.get();
    let bytes = text_of.as_bytes();
    match bytes.first() {
        Some(b'{') => {
            let depth = nested(depth)?;
            let Members(members) = serde_json::from_slice(bytes).map_err(text)?;
            let mut names = FxHashSet::default();
            let members = members
                .iter()
                .map(|(name, raw)| {
                    if !names.insert(name.as_str()) {
                        return Err(JsonFault::RepeatedMember(name.clone()));
                    }
                    Ok((name.clone(), value(raw, depth)?))
                })
                .collect::<Result<_, JsonFault>>()?;
            Ok(Json::Object(members))
        }
        Some(b'[') => {
            let depth = nested(depth)?;
            let items: Vec<&RawValue> = serde_json::from_slice(bytes).map_err(text)?;
            let items = items
                .into_iter()
                .map(|raw| value(raw, depth))
                .collect::<Result<_, JsonFault>>()?;
            Ok(Json::Array(items))
        }
        Some(b'"') => Ok(Json::String(serde_json::from_slice(bytes).map_err(text)?)),
        Some(b't') => Ok(Json::Bool(true)),
        Some(b'f') => Ok(Json::Bool(false)),
        Some(b'n') => Ok(Json::Null),
        // serde_json read the text as a number of RFC 8259, Section 6; its value may lie beyond
        // binary64.
        _ => match serde_json::from_slice::<Number>(bytes) {
            Ok(number) => Ok(Json::Number(JsonNumber {
                text: text_of.to_owned(),
                number,
            })),
            Err(_) => Err(JsonFault::Read(ReadFault::NumberUnrepresentable)),
        },
    }
}

/// The depth of a value inside an object or array at `depth`.
fn nested(depth: usize) -> Result<usize, JsonFault> {
    if depth < MAX_DEPTH {
        Ok(depth + 1)
    } else {
        Err(JsonFault::Read(ReadFault::TooDeep))
    }
}

/// The members of an object as the document writes them, each value as its text.
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
