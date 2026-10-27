//! JSON values that keep their members in document order and refuse a repeated member name.
//!
//! RFC 7519, Section 4 lets a JWT parser reject duplicate claim names; this reader rejects them
//! at every level, in the payload and in the disclosures.

use std::fmt;

use rustc_hash::FxHashSet;
use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::error::Category;
use serde_json::Number;

use crate::error::{JsonFault, JsonTextFault};

/// One JSON value.
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The value `bytes` encode, alone and in UTF-8, each object's member names unique.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, JsonFault> {
        let json: Self = serde_json::from_slice(bytes).map_err(|error| JsonFault::Text {
            kind: match error.classify() {
                Category::Syntax | Category::Io => JsonTextFault::Syntax,
                Category::Data => JsonTextFault::Value,
                Category::Eof => JsonTextFault::Eof,
            },
            line: error.line(),
            column: error.column(),
        })?;
        match json.repeated_member() {
            Some(name) => Err(JsonFault::RepeatedMember(name.to_owned())),
            None => Ok(json),
        }
    }

    /// The first member name an object of this value repeats, in document order.
    fn repeated_member(&self) -> Option<&str> {
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
