//! JSON values that keep their members in document order, with the repeated member names a
//! document holds.
//!
//! RFC 7519, Section 4 lets a JWT parser reject duplicate claim names, and a record a host
//! provisions names each member once: [`Json::parse_unique`] refuses a repeated name at every
//! level, and [`Json::repeated_member`] finds the first one.

use std::fmt;

use rustc_hash::FxHashSet;
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::error::Category;
use serde_json::Number;

/// One JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object: its members in document order, repeated names kept.
    Object(Vec<(String, Json)>),
}

/// What serde_json found in text that is no JSON value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JsonTextFault {
    /// Text that breaks the JSON syntax.
    Syntax,
    /// A value this reader holds no form of: a number beyond a 64-bit float.
    Value,
    /// The text ends inside a value.
    Eof,
}

/// Why bytes are no JSON text, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsonTextError {
    kind: JsonTextFault,
    line: usize,
    column: usize,
}

impl JsonTextError {
    /// What breaks the text.
    #[must_use]
    pub fn kind(self) -> JsonTextFault {
        self.kind
    }

    /// The line, from 1.
    #[must_use]
    pub fn line(self) -> usize {
        self.line
    }

    /// The column, from 1, or 0 at the start of a line.
    #[must_use]
    pub fn column(self) -> usize {
        self.column
    }
}

impl fmt::Display for JsonTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} at line {} column {}",
            self.kind, self.line, self.column
        )
    }
}

impl std::error::Error for JsonTextError {}

/// Why bytes are no JSON value whose objects name each member once.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum JsonFault {
    /// The bytes are no JSON text.
    Text(JsonTextError),
    /// An object repeats this member name.
    RepeatedMember(String),
}

impl fmt::Display for JsonFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(error) => error.fmt(f),
            Self::RepeatedMember(name) => write!(f, "member {name:?} repeated"),
        }
    }
}

impl std::error::Error for JsonFault {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Text(error) => Some(error),
            Self::RepeatedMember(_) => None,
        }
    }
}

impl Json {
    /// The value `bytes` encode, alone and in UTF-8, members in document order.
    ///
    /// # Errors
    ///
    /// [`JsonTextError`]: what serde_json found, and where.
    pub fn parse(bytes: &[u8]) -> Result<Self, JsonTextError> {
        serde_json::from_slice(bytes).map_err(|error| JsonTextError {
            kind: match error.classify() {
                Category::Syntax | Category::Io => JsonTextFault::Syntax,
                Category::Data => JsonTextFault::Value,
                Category::Eof => JsonTextFault::Eof,
            },
            line: error.line(),
            column: error.column(),
        })
    }

    /// The value `bytes` encode, each object naming each member once.
    ///
    /// # Errors
    ///
    /// [`JsonFault`]: text that is no JSON value, or the first repeated member name.
    pub fn parse_unique(bytes: &[u8]) -> Result<Self, JsonFault> {
        let json = Self::parse(bytes).map_err(JsonFault::Text)?;
        match json.repeated_member() {
            Some(name) => Err(JsonFault::RepeatedMember(name.to_owned())),
            None => Ok(json),
        }
    }

    /// The first member name an object of this value repeats, depth first in document order.
    #[must_use]
    pub fn repeated_member(&self) -> Option<&str> {
        match self {
            Self::Array(items) => items.iter().find_map(Self::repeated_member),
            Self::Object(members) => {
                let mut names = FxHashSet::default();
                members.iter().find_map(|(name, value)| {
                    if names.insert(name.as_str()) {
                        value.repeated_member()
                    } else {
                        Some(name.as_str())
                    }
                })
            }
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) => None,
        }
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

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E: Error>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Bool(v))
    }

    fn visit_i64<E: Error>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Number(v.into()))
    }

    fn visit_u64<E: Error>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Number(v.into()))
    }

    fn visit_f64<E: Error>(self, v: f64) -> Result<Json, E> {
        Number::from_f64(v)
            .map(Json::Number)
            .ok_or_else(|| E::custom("a number JSON cannot hold"))
    }

    fn visit_str<E: Error>(self, v: &str) -> Result<Json, E> {
        Ok(Json::String(v.to_owned()))
    }

    fn visit_string<E: Error>(self, v: String) -> Result<Json, E> {
        Ok(Json::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut members = Vec::new();
        while let Some(name) = map.next_key::<String>()? {
            members.push((name, map.next_value()?));
        }
        Ok(Json::Object(members))
    }
}
