//! `trusted_authorities` (§6.1.1): the authorities a Verifier names for the issuer of a
//! Credential. Which credential an authority admits is the caller's to decide.

use core::fmt;

use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// The `type` of a trusted authority, as the Verifier sends it: `aki`, `etsi_tl`,
/// `openid_federation`, or a type of a later version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct AuthorityType(String);

impl AuthorityType {
    /// The type `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The type, as sent.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A value of a trusted authority, as the Verifier sends it: what identifies the authority
/// within its `type`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct AuthorityValue(String);

impl AuthorityValue {
    /// The value `text`.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The value, as sent.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An entry of `trusted_authorities`: a `type` and its `values`, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedAuthority {
    #[serde(rename = "type")]
    kind: AuthorityType,
    values: Vec<AuthorityValue>,
}

impl TrustedAuthority {
    /// `type`.
    #[must_use]
    pub fn kind(&self) -> &AuthorityType {
        &self.kind
    }

    /// `values`, at least one, in the Verifier's order.
    #[must_use]
    pub fn values(&self) -> &[AuthorityValue] {
        &self.values
    }
}

/// `trusted_authorities`: its entries, at least one, in the Verifier's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct TrustedAuthorities(Vec<TrustedAuthority>);

impl TrustedAuthorities {
    /// The entries.
    #[must_use]
    pub fn entries(&self) -> &[TrustedAuthority] {
        &self.0
    }

    /// The `trusted_authorities` member `value`: "a non-empty array of objects", each with a
    /// string `type` and a non-empty array of string `values` (§6.1.1).
    pub(crate) fn parse(value: &Value) -> Result<Self, TrustedAuthorityError> {
        let entries = value.as_array().ok_or(TrustedAuthorityError::NotArray)?;
        if entries.is_empty() {
            return Err(TrustedAuthorityError::Empty);
        }
        let mut parsed = Vec::with_capacity(entries.len());
        for entry in entries {
            parsed.push(TrustedAuthority::parse(entry)?);
        }
        Ok(Self(parsed))
    }
}

impl<'de> Deserialize<'de> for TrustedAuthorities {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&Value::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

impl TrustedAuthority {
    fn parse(entry: &Value) -> Result<Self, TrustedAuthorityError> {
        let entry = entry
            .as_object()
            .ok_or(TrustedAuthorityError::EntryNotObject)?;
        let Some(Value::String(kind)) = entry.get("type") else {
            return Err(TrustedAuthorityError::Type);
        };
        let Some(Value::Array(values)) = entry.get("values") else {
            return Err(TrustedAuthorityError::Values);
        };
        let mut parsed = Vec::with_capacity(values.len());
        for value in values {
            let Value::String(value) = value else {
                return Err(TrustedAuthorityError::Values);
            };
            parsed.push(AuthorityValue::new(value));
        }
        if parsed.is_empty() {
            return Err(TrustedAuthorityError::Values);
        }
        Ok(Self {
            kind: AuthorityType::new(kind),
            values: parsed,
        })
    }
}

/// Why a `trusted_authorities` member breaks §6.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustedAuthorityError {
    /// The member is not an array.
    NotArray,
    /// The array is empty.
    Empty,
    /// An entry is not an object.
    EntryNotObject,
    /// An entry's `type` is missing or not a string.
    Type,
    /// An entry's `values` is missing, empty, or holds something other than strings.
    Values,
}

impl TrustedAuthorityError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotArray => "trusted_authorities_not_array",
            Self::Empty => "trusted_authorities_empty",
            Self::EntryNotObject => "trusted_authority_not_object",
            Self::Type => "trusted_authority_type",
            Self::Values => "trusted_authority_values",
        }
    }
}

impl fmt::Display for TrustedAuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for TrustedAuthorityError {}
